import anthropic
import json
from datetime import datetime

client = anthropic.Anthropic(api_key="YOUR_API_KEY_HERE")

SAMPLE_EVENTS = [
    {"event": "Failed login attempt", "ip": "192.168.1.100", "attempts": 50, "time": "2024-01-15 10:30:00"},
    {"event": "Unusual data download", "ip": "10.0.0.55", "size_gb": 15.5, "time": "2024-01-15 11:00:00"},
    {"event": "Port scan detected", "ip": "172.16.0.200", "ports_scanned": 1000, "time": "2024-01-15 11:30:00"},
    {"event": "Normal user login", "ip": "192.168.1.50", "user": "john", "time": "2024-01-15 09:00:00"},
    {"event": "Config file modified", "ip": "10.0.0.10", "file": "/etc/passwd", "time": "2024-01-15 12:00:00"}
]

def analyze_threat(event):
    prompt = f"""You are a cloud security expert. Analyze this security event and respond in JSON format only:
    
Event: {json.dumps(event)}

Respond with exactly this JSON structure:
{{
    "threat_level": "CRITICAL/HIGH/MEDIUM/LOW",
    "threat_type": "brief threat type",
    "description": "what this means in simple terms",
    "action": "what to do immediately",
    "score": 0-100
}}"""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return json.loads(message.content[0].text)

def run_sentinel():
    print("=" * 60)
    print("🛡️  CLOUD SECURITY AI SENTINEL")
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
            icon = "🔴"
        elif level == "HIGH":
            high_count += 1
            icon = "🟠"
        elif level == "MEDIUM":
            icon = "🟡"
        else:
            icon = "🟢"
        
        print(f"{icon} Threat Level: {level} (Score: {result['score']}/100)")
        print(f"   Type: {result['threat_type']}")
        print(f"   Details: {result['description']}")
        print(f"   Action: {result['action']}")
        print("-" * 60)
    
    print(f"\n📊 SUMMARY REPORT")
    print(f"   🔴 Critical Threats: {critical_count}")
    print(f"   🟠 High Threats: {high_count}")
    print(f"   Total Events Scanned: {len(SAMPLE_EVENTS)}")
    
    if critical_count > 0:
        print(f"\n🚨 ALERT: {critical_count} CRITICAL threat(s) detected!")
        print("   Immediate action required!")

if __name__ == "__main__":
    run_sentinel()
