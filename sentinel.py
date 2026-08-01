from google import genai
import json
import os
import time
from datetime import datetime, timezone

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
MODEL = "gemini-flash-latest"


def load_events(path="events.json"):
    with open(path) as f:
        return json.load(f)


def analyze_threat(event, retries=2):
    prompt = f"""You are a cloud security expert. Analyze this security event and respond in JSON format only with no extra text or markdown:

Event: {json.dumps(event)}

Respond with exactly this JSON:
{{"threat_level": "CRITICAL or HIGH or MEDIUM or LOW", "threat_type": "brief type", "description": "what this means", "action": "what to do", "score": 75}}"""
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
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    results_list = []
    critical_count = high_count = 0

    for i, event in enumerate(events, 1):
        print(f"[Event {i}] Analyzing: {event.get('event')}...")
        result = analyze_threat(event)
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

    history = []
    if os.path.exists("history.json"):
        with open("history.json") as f:
            history = json.load(f)
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
<p class="note">Note: events analyzed are simulated sample data (events.json), used to demonstrate an automated AI classification pipeline. Not connected to a live production cloud environment.</p>
</body></html>"""
    with open("index.html", "w") as f:
        f.write(html)


if __name__ == "__main__":
    run_sentinel()
