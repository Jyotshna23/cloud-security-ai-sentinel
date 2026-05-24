from google import genai
import json
from datetime import datetime
import os
import time

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

SAMPLE_EVENTS = [
    {"event": "Failed login attempt", "ip": "192.168.1.100", "attempts": 50},
    {"event": "Unusual data download", "ip": "10.0.0.55", "size_gb": 15.5},
    {"event": "Port scan detected", "ip": "172.16.0.200", "ports_scanned": 1000}
]

def analyze_threat(event):
    prompt = f"""You are a cloud security expert. Analyze this security event and respond in JSON format only with no extra text or markdown:

Event: {json.dumps(event)}

Respond with exactly this JSON:
{{"threat_level": "CRITICAL or HIGH or MEDIUM or LOW", "threat_type": "brief type", "description": "what this means", "action": "what to do", "score": 75}}"""

    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt
    )
    text = response.text.strip()
    text = text.replace('```json', '').replace('```', '').strip()
    return json.loads(text)

def run_sentinel():
    print("=" * 60)
    print("CLOUD SECURITY AI SENTINEL")
    print("=" * 60)
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Events Detected: {len(SAMPLE_EVENTS)}")
    print("=" * 60)

    critical_count = 0
    high_count = 0

    for i, event in enumerate(SAMPLE_EVENTS, 1):
        print(f"\n[Event {i}] Analyzing: {event['event']}...")
        time.sleep(3)
        result = analyze_threat(event)
        level = result['threat_level']
        if level == "CRITICAL":
            critical_count += 1
        elif level == "HIGH":
            high_count += 1
        print(f"Threat Level: {level} (Score: {result['score']}/100)")
        print(f"Type: {result['threat_type']}")
        print(f"Details: {result['description']}")
        print(f"Action: {result['action']}")
        print("-" * 60)

    print(f"\nSUMMARY REPORT")
    print(f"Critical Threats: {critical_count}")
    print(f"High Threats: {high_count}")
    print(f"Total Events Scanned: {len(SAMPLE_EVENTS)}")
    if critical_count > 0:
        print(f"\nALERT: {critical_count} CRITICAL threat(s) detected!")

if __name__ == "__main__":
    run_sentinel()
