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
    Flatten every event from every past scan into one list, each tagged
    with an embedding, so a new event can be compared against everything
    that's ever been analyzed - not just the most recent scan.
    """
    indexed = []
    for scan in history:
        for e in scan.get("events", []):
            indexed.append(e)
    return indexed


def retrieve_similar_events(event, past_index, past_embeddings, k=TOP_K):
    """
    This is the retrieval step of RAG: instead of sending Gemini the raw
    event with no memory of anything before it, we find the k most
    similar past events (by embedding cosine similarity) and hand those
    over as context. That's what lets the model say "this matches a
    pattern seen before" instead of judging each event in isolation.
    """
    if not past_index:
        return []

    query_vec = embed_text(json.dumps(event))
    scored = []
    for i, past_event in enumerate(past_index):
        sim = cosine_similarity(query_vec, past_embeddings[i])
        scored.append((sim, past_event))

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

    # Build the retrieval index once per run, not once per event -
    # embedding every past event on every single event would be wasteful.
    past_index = build_past_event_index(history)
    past_embeddings = [embed_text(json.dumps(e)) for e in past_index] if past_index else []

    results_list = []
    critical_count = high_count = 0

    for i, event in enumerate(events, 1):
        print(f"[Event {i}] Analyzing: {event.get('event')}...")
        similar_events = retrieve_similar_events(event, past_index, past_embeddings)
        result = analyze_threat(event, similar_events)
        level = result["threat_level"]
        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1
        results_list.append({"event_name": event.get("event"), "raw_event": event, **result})
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
