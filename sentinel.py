from google import genai
from google.genai import types
from pydantic import BaseModel
import json
import logging
import os
import time
import numpy as np
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'
)
logger = logging.getLogger("ai-sentinel")

MODEL = "gemini-3.5-flash-lite"
FALLBACK_MODEL = "gemini-3.8-flash"
EMBED_MODEL = "gemini-embedding-001"
TOP_K = 3
HISTORY_PATH = "history.json"


def get_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set.")
    return genai.Client(api_key=api_key)


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
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"{path} could not be read ({e}). Starting with empty history.")
        return []


def save_history_atomic(history, path=HISTORY_PATH):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(history, f, indent=2)
    os.replace(tmp_path, path)


def embed_text(client, text):
    result = client.models.embed_content(model=EMBED_MODEL, contents=text)
    return result.embeddings[0].values


def build_past_event_index(history):
    """Index only valid past events (ignore failed UNKNOWN scans) so RAG context stays clean."""
    indexed = []
    for scan in history:
        for e in scan.get("events", []):
            if "embedding" in e and e.get("threat_level") != "UNKNOWN":
                indexed.append(e)
    return indexed


def get_cached_embedding(event, past_index):
    """Reuse existing embedding if identical event was already embedded in past scans."""
    raw_str = json.dumps(event, sort_keys=True)
    for past_event in reversed(past_index):
        if json.dumps(past_event.get("raw_event", {}), sort_keys=True) == raw_str:
            return past_event["embedding"]
    return None


def retrieve_similar_events(query_vec, past_index, k=TOP_K):
    if not past_index or query_vec is None:
        return []

    query = np.asarray(query_vec, dtype=np.float64)
    matrix = np.asarray([e["embedding"] for e in past_index], dtype=np.float64)

    query_norm = np.linalg.norm(query)
    matrix_norms = np.linalg.norm(matrix, axis=1)
    denom = np.where((matrix_norms * query_norm) == 0, 1e-10, matrix_norms * query_norm)

    similarities = (matrix @ query) / denom
    top_k_idx = np.argsort(similarities)[::-1][:k]
    return [past_index[i] for i in top_k_idx]


def analyze_threat(client, event, similar_events, retries=3):
    context_block = ""
    if similar_events:
        context_lines = [
            f"- Past event: {se.get('event_name')} | "
            f"Threat level given: {se.get('threat_level')} | "
            f"Action taken: {se.get('action')}"
            for se in similar_events
        ]
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

    models_to_try = [MODEL, MODEL, FALLBACK_MODEL, FALLBACK_MODEL]
    for attempt in range(retries + 1):
        active_model = models_to_try[min(attempt, len(models_to_try) - 1)]
        start_time = time.time()
        try:
            response = client.models.generate_content(
                model=active_model, contents=prompt, config=config
            )
            latency_ms = round((time.time() - start_time) * 1000, 2)
            result: ThreatAnalysis = response.parsed
            logger.info(f"Analyzed '{event.get('event')}' via {active_model} in {latency_ms}ms")
            return result.model_dump()
        except Exception as e:
            wait_sec = 10 * (attempt + 1)
            logger.warning(f"Attempt {attempt + 1} failed ({active_model}): {str(e)[:80]}. Retrying in {wait_sec}s")
            if attempt == retries:
                return {
                    "threat_level": "UNKNOWN",
                    "threat_type": "analysis_error",
                    "description": f"Could not analyze event: {str(e)[:150]}",
                    "action": "Retry manually or check API quota",
                    "score": 0,
                }
            time.sleep(wait_sec)


def run_sentinel():
    client = get_client()
    events = load_events()
    history = load_history()
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    past_index = build_past_event_index(history)

    results_list = []
    critical_count = high_count = 0

    for i, event in enumerate(events, 1):
        logger.info(f"[Event {i}/{len(events)}] Processing: {event.get('event')}")

        event_vec = get_cached_embedding(event, past_index)
        if event_vec is not None:
            logger.info("Reused cached vector embedding (0 API quota used)")
        else:
            try:
                event_vec = embed_text(client, json.dumps(event))
            except Exception as e:
                logger.warning(f"Embedding failed, skipping retrieval: {e}")
                event_vec = None

        similar_events = retrieve_similar_events(event_vec, past_index)
        result = analyze_threat(client, event, similar_events)
        level = result["threat_level"]
        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1

        entry = {"event_name": event.get("event"), "raw_event": event, **result}
        if event_vec:
            entry["embedding"] = event_vec
        results_list.append(entry)
        time.sleep(5)

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
    logger.info("Successfully saved results.json, history.json, and index.html")


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
