from google import genai
from google.genai import types
from pydantic import BaseModel
import json
import os
import time
import numpy as np
from datetime import datetime, timezone

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
MODEL = "gemini-flash-latest"
EMBED_MODEL = "gemini-embedding-001"
TOP_K = 3  # how many similar past events to pull in as context

HISTORY_PATH = "history.json"


# ---------------------------------------------------------------------------
# Structured output schema - the Gemini SDK guarantees the response matches
# this shape exactly, so we no longer need to strip markdown fences or hope
# the model followed the "respond in JSON only" instruction correctly.
# ---------------------------------------------------------------------------
class ThreatAnalysis(BaseModel):
    threat_level: str  # CRITICAL, HIGH, MEDIUM, or LOW
    threat_type: str
    description: str
    action: str
    score: int  # 0-100


def load_events(path="events.json"):
    with open(path) as f:
        return json.load(f)


def load_history(path=HISTORY_PATH):
    """
    Load past scan history. If the file is missing, that's normal (first
    run). If it exists but is corrupted (e.g. a previous run crashed
    mid-write), don't let that take down the whole pipeline - start fresh
    with an empty history instead of crashing on JSONDecodeError.
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: {path} could not be read ({e}). Starting with empty history.")
        return []


def save_history_atomic(history, path=HISTORY_PATH):
    """
    Write via a temp file + atomic rename instead of writing directly to
    history.json. If the process dies mid-write (network hiccup, OOM kill,
    Ctrl-C), the original file is left untouched instead of ending up
    half-written and corrupted.
    """
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(history, f, indent=2)
    os.replace(tmp_path, path)  # atomic on POSIX and Windows


def embed_text(text):
    """Turn an event description into a vector so we can compare it against past events."""
    result = client.models.embed_content(model=EMBED_MODEL, contents=text)
    return result.embeddings[0].values


def build_past_event_index(history):
    """
    Flatten every event from every past scan into one list. Each of
    these events already carries a cached "embedding" field (saved the
    run it was first analyzed), so we never re-embed old events.
    """
    indexed = []
    for scan in history:
        for e in scan.get("events", []):
            if "embedding" in e:
                indexed.append(e)
    return indexed


def retrieve_similar_events(query_vec, past_index, k=TOP_K):
    """
    Retrieval step of RAG, vectorized with NumPy instead of pure-Python
    loops. With N past events, the old version ran N separate Python-level
    sqrt/sum loops; this does one matrix-vector multiply instead, which
    stays fast as history grows into the hundreds of entries.
    """
    if not past_index:
        return []

    query = np.asarray(query_vec, dtype=np.float64)
    matrix = np.asarray([e["embedding"] for e in past_index], dtype=np.float64)

    query_norm = np.linalg.norm(query)
    matrix_norms = np.linalg.norm(matrix, axis=1)
    # avoid divide-by-zero for any degenerate zero-vector rows
    denom = np.where((matrix_norms * query_norm) == 0, 1e-10, matrix_norms * query_norm)

    similarities = (matrix @ query) / denom
    top_k_idx = np.argsort(similarities)[::-1][:k]

    return [past_index[i] for i in top_k_idx]


def analyze_threat(event, similar_events, retries=2):
    context_block = ""
    if similar_events:
        context_lines = []
        for se in similar_events:
            context_lines.append(
                f"- Past event: {se.get('event_name')} | "
                f"Threat level given: {se.get('threat_level')} | "
                f"Action taken: {se.get('action')}"
            )
        context_block = (
            "\nHere are similar events seen in past scans and how they were classified:\n"
            + "\n".join(context_lines)
            + "\nUse this history for consistency, but still judge this event on its own facts.\n"
        )

    prompt = f"""You are a cloud security expert. Analyze this security event.

Event: {json.dumps(event)}
{context_block}
Classify the threat_level as CRITICAL, HIGH, MEDIUM, or LOW, and give a score
from 0 to 100 based on severity."""

    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=ThreatAnalysis,
    )

    for attempt in range(retries + 1):
        try:
            response = client.models.generate_content(
                model=MODEL, contents=prompt, config=config
            )
            # response.parsed is already a validated ThreatAnalysis instance -
            # no manual markdown-stripping or json.loads() needed.
            result: ThreatAnalysis = response.parsed
            return result.model_dump()
        except Exception as e:
            if attempt == retries:
                return {
                    "threat_level": "UNKNOWN",
                    "threat_type": "analysis_error",
                    "description": f"Could not analyze event: {str(e)[:150]}",
                    "action": "Retry manually or check API quota",
                    "score": 0,
                }
            time.sleep(5)


def run_sentinel():
    events = load_events()
    history = load_history()
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    past_index = build_past_event_index(history)

    results_list = []
    critical_count = high_count = 0

    for i, event in enumerate(events, 1):
        print(f"[Event {i}] Analyzing: {event.get('event')}...")

        try:
            event_vec = embed_text(json.dumps(event))
        except Exception as e:
            print(f"  Embedding failed, skipping retrieval for this event: {e}")
            event_vec = None

        similar_events = retrieve_similar_events(event_vec, past_index) if event_vec else []
        result = analyze_threat(event, similar_events)
        level = result["threat_level"]
        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1

        entry = {"event_name": event.get("event"), "raw_event": event, **result}
        if event_vec:
            entry["embedding"] = event_vec
        results_list.append(entry)
        time.sleep(2)

    output = {
        "scan_time": scan_time,
        "critical_count": critical_count,
        "high_count": high_count,
        "total_events": len(events),
        "events": results_list,
    }

    with open("results.json", "w") as f:
        json.dump(output, f, indent=2)

    history.append(output)
    history = history[-30:]
    save_history_atomic(history)

    build_dashboard(history)
    print("Saved results.json, history.json, and index.html")


def build_dashboard(history):
    rows = ""
    for scan in reversed(history):
        for e in scan["events"]:
            rows += f"""<tr>
<td>{scan['scan_time']}</td>
<td>{e['event_name']}</td>
<td class="level-{e['threat_level'].lower()}">{e['threat_level']}</td>
<td>{e.get('score', '-')}</td>
<td>{e.get('description', '')}</td>
</tr>"""
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cloud Security AI Sentinel - Dashboard</title>
<style>
body{{font-family:Arial, sans-serif; margin:2rem; background:#0e1117; color:#e6e6e6;}}
h1{{color:#4dabf7;}}
table{{width:100%; border-collapse:collapse; margin-top:1rem;}}
th,td{{padding:8px 12px; border-bottom:1px solid #333; text-align:left; font-size:14px;}}
th{{color:#4dabf7;}}
.level-critical{{color:#ff4d4f; font-weight:bold;}}
.level-high{{color:#ff9f43; font-weight:bold;}}
.level-medium{{color:#f1c40f;}}
.level-low{{color:#2ecc71;}}
.level-unknown{{color:#888;}}
.note{{color:#888; font-size:13px; margin-top:2rem;}}
</style></head>
<body>
<h1>Cloud Security AI Sentinel - Live Dashboard</h1>
<p>Automatically updated every 6 hours via GitHub Actions. Last {len(history)} scans shown.</p>
<table>
<tr><th>Scan Time</th><th>Event</th><th>Threat Level</th><th>Score</th><th>AI Analysis</th></tr>
{rows}
</table>
<p class="note">Note: events analyzed are simulated sample data (events.json), used to demonstrate an automated AI classification pipeline with retrieval-augmented context from scan history. Not connected to a live production cloud environment.</p>
</body></html>"""
    with open("index.html", "w") as f:
        f.write(html)


if __name__ == "__main__":
    run_sentinel()
