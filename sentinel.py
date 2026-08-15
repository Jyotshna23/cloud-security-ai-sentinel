from google import genai
import json
import math
import os
import time
from datetime import datetime, timezone

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
MODEL = "gemini-flash-latest"
EMBED_MODEL = "gemini-embedding-001"
TOP_K = 3  # how many similar past events to pull in as context


def load_events(path="events.json"):
    with open(path) as f:
        return json.load(f)


def load_history(path="history.json"):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def embed_text(text):
    """Turn an event description into a vector so we can compare it against past events."""
    result = client.models.embed_content(model=EMBED_MODEL, contents=text)
    return result.embeddings[0].values


def cosine_similarity(vec_a, vec_b):
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0
    return dot / (norm_a * norm_b)


def build_past_event_index(history):
    """
    Flatten every event from every past scan into one list. Each of
    these events already carries a cached "embedding" field (saved the
    run it was first analyzed), so we never re-embed old events - that
    was what was burning through the free-tier quota before.
    """
    indexed = []
    for scan in history:
        for e in scan.get("events", []):
            if "embedding" in e:  # older entries saved before caching won't have this
                indexed.append(e)
    return indexed


def retrieve_similar_events(query_vec, past_index, k=TOP_K):
    """
    Retrieval step of RAG: compare the new event's embedding (computed
    once, by the caller) against cached embeddings of past events, and
    hand back the k most similar. No embedding calls happen in here -
    that's what keeps this cheap even as history grows.
    """
    if not past_index:
        return []

    scored = [(cosine_similarity(query_vec, e["embedding"]), e) for e in past_index]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:k]]


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

    prompt = f"""You are a cloud security expert. Analyze this security event and respond in JSON format only with no extra text or markdown:

Event: {json.dumps(event)}
{context_block}
Respond with exactly this JSON structure (replace placeholders with real values, do not copy example text literally):
{{"threat_level": "CRITICAL or HIGH or MEDIUM or LOW", "threat_type": "brief type", "description": "what this means", "action": "what to do", "score": <integer from 0 to 100 based on severity>}}"""

    for attempt in range(retries + 1):
        try:
            response = client.models.generate_content(model=MODEL, contents=prompt)
            text = response.text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
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

    # Cached embeddings only - no API calls happen here, so this is free
    # regardless of how large history has grown.
    past_index = build_past_event_index(history)

    results_list = []
    critical_count = high_count = 0

    for i, event in enumerate(events, 1):
        print(f"[Event {i}] Analyzing: {event.get('event')}...")

        # One embedding call per new event - used both to retrieve
        # similar past events now, and cached below so this same event
        # never needs to be re-embedded in a future run.
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
    with open("history.json", "w") as f:
        json.dump(history, f, indent=2)

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
