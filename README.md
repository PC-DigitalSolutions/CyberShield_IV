# CyberShield AI — El Guardián 🦅🛡️

**Real-time AI threat-intelligence backend for the 2026 FIFA World Cup.**

CyberShield continuously monitors live World Cup news for cyber threats — ticket scams, phishing, data breaches, deepfakes, DDoS — classifies each one through a multi-gate triage system, and lets anyone ask **El Guardián** (an LLM security director) to break down any threat in plain language, grounded in live tournament data.

> This is the **FastAPI backend**. The Next.js dashboard lives at **[cybershield-dashboard](https://github.com/PC-DigitalSolutions/cybershield-dashboard)**.

---

## Why it's interesting

Most "AI security" demos call an LLM on every event and burn through quota. CyberShield uses a **two-stage pipeline**:

1. **Always-on, free triage** — a background loop polls Google News RSS every 75s, filters to World-Cup-only stories, and classifies each headline into one of four security gates using fast keyword logic. No LLM cost.
2. **On-demand intelligence** — the Gemini LLM only fires when a human actually asks about a threat, and it's fed a **live intel feed** (current threats, fixtures, standings) so it answers from real data instead of guessing.

The result: a live threat picture that runs 24/7 for free, with deep AI analysis available the instant it's needed.

---

## The CNS — four specialist gates

`ElGuardianCNS` routes every signal through a Central Nervous System of four agents, with a severity hierarchy and multi-gate escalation:

| Gate | Agent | Domain |
|------|-------|--------|
| **A** | 🥅 Anti-Scammer Goalie | Ticket fraud, phishing, scams, financial manipulation |
| **B** | ⚖️ Sideline Referee | Data privacy & compliance (GDPR / LGPD / LFPDPPP), breaches |
| **C** | 🛡️ Red Card Sentinel | Deepfakes, synthetic media, disinformation |
| **D** | 📡 Las Barras Bravas Triage | DDoS, traffic floods, bot swarms, telemetry surges |

El Guardián gives the human-facing verdict and dispatches the right specialist, which files its own technical report.

---

## API

| Endpoint | What it does |
|----------|--------------|
| `GET /status` | CNS health + registered gates |
| `GET /analyze?signal=…` | El Guardián verdict + engaged specialist reports (LLM, on demand) |
| `GET /threats/live` | Rolling live threat + intel feed (auto-classified, with per-threat agent + recommendation) |
| `GET /matches` | Live/upcoming/standings via football-data.org + **per-match CyberShield threat assessment** |
| `GET /route`, `GET /utr` | Raw CNS routing + Unified Threat Report |

---

## Tech stack

- **Python 3.11**, **FastAPI**, **Uvicorn**
- **Google Gemini** (`google-genai`, `gemini-flash-latest`, override via `GEMINI_MODEL`) for El Guardián + specialists
- **Google News RSS** (live threat feed) · **football-data.org** (live match data)
- Stdlib-only ingestion (`urllib`, `xml.etree`) — no heavy scraping deps

---

## Run it locally

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# set your keys (never commit these)
$env:CYBERSHIELD_API_KEY = "your-gemini-key"      # https://aistudio.google.com/apikey
$env:FOOTBALL_DATA_TOKEN = "your-football-token"  # https://football-data.org

.\start_backend.example.ps1   # or: uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/status to confirm it's live.

### Docker

```bash
docker build -t cybershield .
docker run -p 8000:8000 -e CYBERSHIELD_API_KEY=… -e FOOTBALL_DATA_TOKEN=… cybershield
```

Deployment guide (Render + Vercel + custom domain): see the dashboard repo's `DEPLOYMENT.md`.

---

## Architecture

```
Google News RSS ─┐
                 ├─► LiveThreatMonitor ──► CNS gates (keyword triage) ──► /threats/live
football-data ───┘         (every 75s, free)                                  │
                                                                              ▼
   User asks ──► /analyze ──► El Guardián (Gemini) + live intel feed ──► specialist agents
                                  (on demand only)
```

---

## Roadmap

- [ ] Per-fixture host-city/venue mapping (official WC2026 schedule source)
- [ ] Rate limiting on `/analyze` for public deployment
- [ ] Persistent threat history + trend charts

---

Built by **PC Digital Solutions**. · *Strength. Vigilance. Intelligence.*
