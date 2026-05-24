import google.generativeai as genai
import json
from datetime import datetime
import os

genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

SAMPLE_EVENTS = [
    {"event": "Failed login attempt", "ip": "192.168.1.100", "attempts": 50, "time": "2024-01-15 10:30:00"},
    {"event": "Unusual data download", "ip": "10.0.0.55", "size_gb": 15.5, "time": "2024-01-15 11:00:00"},
    {"event": "Port scan detected", "ip": "172.16.0.200", "ports_scanned": 1000, "time": "2024-01-15 11:30:00"},
    {"event": "Normal user login", "ip": "192.168.1.50", "user": "john", "time": "2024-01-15 09:00:00"},
    {"event": "Config file modified", "ip": "10.0.0.10", "file": "/etc/passwd", "time": "2024-01-15 12:00:00"}
]

def analyze_threat(event):
    prompt = f"""You are a cloud security expert. Analyze this security event and respond in JSON format only with no extra text:

Event: {json.dumps(event)}

Respond with exactly this JSON:
{{
    "threat_level": "CRITICAL or HIGH or MEDIUM or LOW",
    "threat_type": "brief threat type",
    "description": "what this means",
    "action": "what to do",
    "score": 0
}}"""

    response = model.generate_content(prompt)
    text = response.text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text.strip())

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
        result = analyze_threat(event)

        level = result['threat_level']
        if level == "CRITICAL":
            critical_count += 1
            icon = "CRITICAL"
        elif level == "HIGH":
            high_count += 1
            icon = "HIGH"
        elif level == "MEDIUM":
            icon = "MEDIUM"
        else:
            icon = "LOW"

        print(f"Threat Level: {icon} (Score: {result['score']}/100)")
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
        print("Immediate action required!")

if __name__ == "__main__":
    run_sentinel()
