![Pipeline](https://github.com/Jyotshna23/cloud-security-ai-sentinel/actions/workflows/sentinel.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.9-blue)
![AI](https://img.shields.io/badge/AI-Gemini-orange)
![Architecture](https://img.shields.io/badge/Architecture-RAG-purple)
![Security](https://img.shields.io/badge/Security-Cloud-red)

# 🛡️ Cloud Security AI Sentinel

**An autonomous, self-improving threat classification pipeline — powered by Gemini, grounded by RAG, running on autopilot.**

---

## 🚨 The Problem

Security teams drown in alerts. Every failed login, every new admin role, every unusual data transfer competes for attention — and manual triage doesn't scale. Most of the noise is harmless. A little of it isn't. The hard part is telling the difference, fast, and consistently, every single time.

## ⚡ What This Builds

Sentinel is an end-to-end pipeline that reads raw security events, reasons about them with an LLM, and learns from its own history to stay consistent — without a human reviewing every line.

- 🎯 **Classifies** every event into CRITICAL / HIGH / MEDIUM / LOW with a numeric risk score and a concrete remediation step
- 🧠 **Remembers** — a RAG layer retrieves the most similar past incidents before scoring a new one, so today's judgment call stays consistent with last week's
- ⚙️ **Runs itself** — GitHub Actions triggers a fresh scan every 6 hours, no manual intervention
- 📊 **Reports live** — results publish straight to a GitHub Pages dashboard
- 💸 **Stays cheap** — embeddings are cached, not recomputed, keeping the pipeline well inside free-tier API limits even as history grows

## 🧠 Why RAG, Not Just a Prompt

A plain LLM call scores every event in isolation — ask it about the same *kind* of incident twice, on two different days, and you may get two different verdicts. That's a real problem for security triage: two analysts flip-flopping on identical evidence looks like inconsistency, not accuracy.

Sentinel fixes this with retrieval-augmented generation:

```
New event
    │
    ▼
Generate embedding (Gemini embeddings API)
    │
    ▼
Compare against cached embeddings of past events  ──►  cosine similarity
    │
    ▼
Retrieve top-K most similar past incidents
    │
    ▼
Inject as context  ──►  "here's how similar events were judged before"
    │
    ▼
Gemini classifies the new event, grounded in precedent
    │
    ▼
Result + its own embedding cached back into history.json
```

Every event's embedding is computed **once** and cached — so the pipeline never re-embeds the same history twice. That single design choice is what keeps this running reliably inside Gemini's free-tier rate limits instead of hitting `429` errors on every run.

## 🌍 Where This Pattern Is Actually Used

This project runs on simulated event data (`events.json`) to demonstrate the architecture cleanly and reproducibly — it isn't wired into a live production cloud environment. The pattern itself, though, mirrors real triage workflows: SOC analysts, DevOps teams, and cloud platform teams all use similar "retrieve precedent → classify → act" pipelines to cut down manual alert review at scale.

## 🛠️ Tech Stack

| Layer | Tool | Role |
|---|---|---|
| Reasoning | Google Gemini API | Event classification + structured output |
| Memory | Gemini Embeddings + cosine similarity | RAG retrieval over scan history |
| Orchestration | GitHub Actions | Scheduled runs, every 6 hours |
| Core logic | Python | Pipeline, retrieval, dashboard generation |
| Secrets | GitHub Secrets | API key management |
| Delivery | GitHub Pages | Live, auto-updating dashboard |

## 📊 Pipeline, Step by Step

1. `events.json` — the security events to analyze for this run
2. Each event is embedded once; cosine similarity against cached history surfaces the most similar past incidents
3. Gemini classifies the event, using both the raw details and the retrieved precedent, returning strict structured JSON
4. Results land in `results.json`, get appended to `history.json` (rolling 30-scan window, embeddings included), and render to `index.html`
5. GitHub Actions runs the whole cycle on schedule and commits the refreshed dashboard back to the repo — no human in the loop

## 👩‍💻 Author

**Jyotshna Pogiri** — Software Engineer | AI Security Enthusiast
GitHub: https://github.com/Jyotshna23
Email: jahnavipogiri3@gmail.com
