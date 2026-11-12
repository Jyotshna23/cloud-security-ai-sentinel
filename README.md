# 🛡️ Cloud Security AI Sentinel

**An autonomous, self-improving threat classification pipeline — powered by Google Gemini, grounded by vectorized RAG memory, and running on autopilot.**

---

## 🚨 The Problem

Security teams drown in alert fatigue. Every failed login, privilege escalation, and unusual data transfer competes for attention — and manual triage does not scale. Most alerts are benign noise, while a small fraction represent real intrusions. The hard part is telling the difference **fast, deterministically, and consistently** across every scan.

## ⚡ What This Builds

Sentinel is an end-to-end automated pipeline that ingests raw security events, reasons over them with an LLM grounded in historical precedent, and publishes live reports with zero manual intervention:

- 🎯 **Deterministic Threat Scoring:** Classifies every event into `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` with a `0–100` risk score and concrete remediation steps enforced via **Pydantic** structured output schemas.
- 🧠 **Precedent-Grounded Memory:** A RAG layer embeds events (`gemini-embedding-001`) and retrieves the **top-3 (`TOP_K = 3`)** most similar past incidents via vectorized **NumPy cosine similarity**, ensuring consistent verdicts over time.
- ⚙️ **Zero-Touch Automation:** **GitHub Actions** triggers a fresh scan every 6 hours (`0 */6 * * *`), commits updated telemetry, and refreshes the live dashboard automatically.
- 🛡️ **Crash-Safe Persistence:** Uses atomic file writes (`os.replace` via `.tmp` staging) and corrupt-JSON recovery so partial writes never break the pipeline state.
- 💸 **Zero-Cost Embedding Cache:** Event vectors are computed **once** and cached inside a rolling 30-scan window in `history.json`, avoiding redundant API calls and staying well inside free-tier rate limits.

---

## 🧠 Why RAG, Not Just a Prompt

A plain LLM call scores every event in isolation — ask it about the same *kind* of incident twice on two different days, and you may get inconsistent severity ratings. In security operations, flip-flopping on identical evidence undermines trust.

Sentinel eliminates verdict drift with retrieval-augmented generation:

```text
  New security event (events.json)
          │
          ▼
  Generate vector embedding (gemini-embedding-001)
          │
          ▼
  Matrix cosine similarity against cached history (NumPy)
          │
          ▼
  Retrieve top-3 most similar past incidents (TOP_K = 3)
          │
          ▼
  Inject historical precedent into Gemini prompt
          │
          ▼
  Gemini outputs validated Pydantic ThreatAnalysis JSON
          │
          ├──► results.json (Latest scan telemetry)
          ├──► history.json (Rolling 30-scan memory + cached vectors)
          └──► index.html   (Auto-generated dark-mode dashboard)
```

---

## 📊 Sample Input & Structured Output

### Raw Event (`events.json`)
```json
{
  "event": "Unusual data download",
  "ip": "10.0.0.55",
  "size_gb": 15.5,
  "timestamp": "2026-08-01T02:05:00Z"
}
```

### AI Classification (`results.json`)
```json
{
  "event_name": "Unusual data download",
  "threat_level": "HIGH",
  "threat_type": "data_exfiltration",
  "score": 82,
  "description": "Large 15.5 GB outbound transfer from internal host 10.0.0.55 during off-peak hours.",
  "action": "Isolate host 10.0.0.55, revoke active session tokens, and audit VPC flow logs."
}
```

---

## 🛠️ Tech Stack

| Layer | Technology | Engineering Purpose |
| :--- | :--- | :--- |
| **LLM & Embeddings** | Google GenAI SDK (`google-genai`) | Event threat reasoning + `gemini-embedding-001` vector generation |
| **Schema Validation** | Pydantic (`BaseModel`) | Guaranteed structured JSON responses without brittle regex parsing |
| **Vector Retrieval** | NumPy (`numpy`) | Fast matrix-vector cosine similarity search over cached history |
| **Orchestration** | GitHub Actions (`sentinel.yml`) | Automated 6-hour cron execution & self-committing repository updates |
| **Core Pipeline** | Python 3.11 | Atomic file I/O, retry handling, and static HTML dashboard generation |
| **Secrets & Hosting** | GitHub Secrets & GitHub Pages | Secure API key injection and live auto-updating SOC dashboard |

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- A **Google Gemini API Key** from [Google AI Studio](https://google.com)

### Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com
   cd cloud-security-ai-sentinel
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set your API key**
   ```bash
   export GEMINI_API_KEY="your_api_key_here"   # Windows CMD: set GEMINI_API_KEY=your_api_key_here
   ```

4. **Execute the pipeline**
   ```bash
   python sentinel.py
   ```
   This processes `events.json`, updates `results.json` and `history.json`, and generates `index.html`.

---

## 🌍 Where This Pattern Is Actually Used

This project runs on simulated event telemetry (`events.json`) to demonstrate the architecture cleanly and reproducibly without requiring live cloud infrastructure credentials. In production environments (AWS GuardDuty, Microsoft Sentinel, GCP Security Command Center), SOC and DevSecOps teams use this exact **"Embed → Retrieve Precedent → Classify → Remediate"** pattern to automate Tier-1 alert triage at scale.

---

## 👩‍💻 Author

**Jyotshna Pogiri** — Python & GenAI Developer | DevSecOps & AI Security Enthusiast
- **GitHub:** [github.com/Jyotshna23](https://github.com/Jyotshna23)
- **LinkedIn:** [://linkedin.com](https://www.://linkedin.com)
- **Email:** [jahnavipogiri3@gmail.com](mailto:jahnavipogiri3@gmail.com)
