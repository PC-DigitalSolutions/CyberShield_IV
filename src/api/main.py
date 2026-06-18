import asyncio
import json
import os
import time
import urllib.request
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

load_dotenv()

from src.core.router import ElGuardianCNS
from src.core.live_monitor import LiveThreatMonitor
from src.agents.guardian_agent import ElGuardian
from src.agents import specialists

cns = ElGuardianCNS()
guardian = ElGuardian()
monitor = LiveThreatMonitor(cns)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start the live World Cup threat monitor in the background.
    task = asyncio.create_task(monitor.run_forever())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="CyberShield API", lifespan=lifespan)

# Local dev origins + any deployed frontend(s) listed in FRONTEND_ORIGIN
# (comma-separated). The regex also auto-allows Vercel preview/prod domains.
_allowed = ["http://localhost:3000"]
_extra = os.environ.get("FRONTEND_ORIGIN", "")
_allowed += [o.strip() for o in _extra.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed,
    allow_origin_regex=r"https://.*\.vercel\.app|http://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}):3000",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_URL = os.environ.get("FRONTEND_ORIGIN", "").split(",")[0].strip() or "http://localhost:3000"

static_dir = os.path.join("backend", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    """The real dashboard lives in the Next.js app."""
    return RedirectResponse(FRONTEND_URL)


@app.get("/status")
async def status():
    return cns.status()


@app.get("/threats/live")
async def threats_live(limit: int = Query(default=25, ge=1, le=80)):
    """Rolling feed of live World Cup threats + intel, sourced from Google News
    RSS and classified through the CNS gates. Polled by the dashboard."""
    return monitor.snapshot(limit)


def _live_context() -> str:
    """Real-time tournament context fed to El Guardián so it can answer schedule,
    standings, and threat questions from live data instead of guessing."""
    parts = []

    snap = monitor.snapshot(limit=80)
    threats = [t for t in snap.get("threats", []) if t.get("kind") == "threat"]
    if threats:
        lines = [f"- [{t['severity']}] {t['title']} (handled by {t['agent']})" for t in threats[:5]]
        parts.append(f"ACTIVE THREATS ({snap.get('active_threats', 0)} live now):\n" + "\n".join(lines))

    data = _matches_cache.get("data")
    if data and data.get("source") == "live":
        up = data.get("upcoming") or []
        if up:
            lines = []
            for m in up[:6]:
                lvl = (m.get("threat") or {}).get("level", "")
                grp = m.get("group", "")
                lines.append(
                    f"- {m['home']['name']} vs {m['away']['name']} — {m.get('utcDate', 'TBD')} UTC"
                    f"{(' · ' + grp) if grp else ''}{(' · CyberShield threat: ' + lvl) if lvl else ''}"
                )
            parts.append("UPCOMING FIXTURES (no host city in feed — dates/teams/groups only):\n" + "\n".join(lines))
        st = data.get("standings") or []
        if st:
            lines = []
            for g in st[:12]:
                top = ", ".join(
                    f"{r['team']['code'] or r['team']['name']} ({r['points']}pts)"
                    for r in g.get("table", [])[:2]
                )
                lines.append(f"- {g['group']}: {top}")
            parts.append("STANDINGS (top 2 per group):\n" + "\n".join(lines))

    return "\n\n".join(parts)


@app.get("/analyze")
async def analyze(signal: str = Query(default="")):
    """Primary endpoint — El Guardián gives the verdict, then each triggered
    gate's specialist agent delivers its own report."""
    gates = cns.detect_gates(signal)
    engaged = [f'{cns.registry.agents[g]["name"]} ({g})' for g in gates]
    context = _live_context()

    def specialist_report(gate: str):
        try:
            scanner = cns.registry.run_agent(gate, signal)
            scanner.pop("raw", None)
        except Exception:
            scanner = None
        return specialists.respond(gate, signal, scanner)

    results = await asyncio.gather(
        asyncio.to_thread(guardian.analyze, signal, engaged or None, context or None),
        *(asyncio.to_thread(specialist_report, g) for g in gates),
    )

    agents = [
        {"gate": g, "agent": cns.registry.agents[g]["name"], "response": r}
        for g, r in zip(gates, results[1:])
        if r
    ]
    return {
        "status": "ok",
        "signal": signal,
        "response": results[0],
        "gates": gates,
        "primary_gate": cns.choose_primary_gate(gates) if gates else None,
        "agents": agents,
    }


FOOTBALL_API = "https://api.football-data.org/v4/competitions/WC/matches"
_matches_cache: dict = {"ts": 0.0, "data": None}


def _fetch_matches(status: str, token: str) -> dict:
    req = urllib.request.Request(
        f"{FOOTBALL_API}?status={status}",
        headers={"X-Auth-Token": token},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _fetch_scorers(token: str) -> dict:
    req = urllib.request.Request(
        f"https://api.football-data.org/v4/competitions/WC/scorers?limit=8",
        headers={"X-Auth-Token": token},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _team(t: dict) -> dict:
    return {
        "name": t.get("shortName") or t.get("name") or "TBD",
        "code": t.get("tla") or "",
        "crest": t.get("crest") or "",
    }


def _fetch_standings(token: str) -> dict:
    """Group standings. Swallows errors so a standings outage never takes the
    whole /matches response down."""
    try:
        req = urllib.request.Request(
            "https://api.football-data.org/v4/competitions/WC/standings",
            headers={"X-Auth-Token": token},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


_STAGE_BONUS = {
    "FINAL": 45,
    "THIRD_PLACE": 24,
    "SEMI_FINALS": 35,
    "QUARTER_FINALS": 26,
    "LAST_16": 18,
    "GROUP_STAGE": 6,
}

# (score floor, level) — first match wins, highest first
_THREAT_LEVELS = [(82, "SEVERE"), (62, "HIGH"), (44, "ELEVATED"), (30, "GUARDED"), (0, "LOW")]


def _assess_match(up: dict, threats: list, active_total: int) -> dict:
    """CyberShield's per-match threat assessment — blends match prominence,
    kickoff proximity, live-feed correlation (does any active threat name a
    team in this fixture?), and the overall threat climate."""
    score = 22 + _STAGE_BONUS.get(up.get("stage") or "", 8)

    utc = up.get("utcDate")
    if utc:
        try:
            from datetime import datetime, timezone
            kickoff = datetime.fromisoformat(utc.replace("Z", "+00:00"))
            hours = (kickoff - datetime.now(timezone.utc)).total_seconds() / 3600
            if 0 <= hours <= 24:
                score += 22
            elif hours <= 72:
                score += 12
            elif hours <= 168:
                score += 5
        except Exception:
            pass

    names = [n.lower() for n in (up["home"]["name"], up["away"]["name"]) if len(n) > 2]
    hits = sum(1 for t in threats if any(n in (t.get("title") or "").lower() for n in names))
    score += min(18, hits * 9)
    score += min(12, active_total // 10)
    score = max(0, min(100, score))

    level = next(name for floor, name in _THREAT_LEVELS if score >= floor)

    counts: dict = {}
    for t in threats:
        g = t.get("primary_gate")
        if g:
            counts[g] = counts.get(g, 0) + 1
    dom_gate = max(counts, key=counts.get) if counts else "Gate A"
    try:
        agent = cns.registry.agents[dom_gate]["name"]
    except Exception:
        agent = "El Guardián"

    return {"level": level, "score": int(score), "gate": dom_gate, "agent": agent, "feed_hits": hits}


@app.get("/matches")
async def matches():
    """Live + upcoming World Cup matches via football-data.org.
    Returns {"source": "demo"} when no token is configured so the
    frontend falls back to its built-in demo fixtures."""
    token = os.environ.get("FOOTBALL_DATA_TOKEN", "")
    if not token:
        return {"source": "demo", "reason": "FOOTBALL_DATA_TOKEN not set"}

    now = time.time()
    if _matches_cache["data"] and now - _matches_cache["ts"] < 60:
        return _matches_cache["data"]

    try:
        live_raw, sched_raw, finished_raw, scorers_raw, stand_raw = await asyncio.gather(
            asyncio.to_thread(_fetch_matches, "LIVE", token),
            asyncio.to_thread(_fetch_matches, "SCHEDULED", token),
            asyncio.to_thread(_fetch_matches, "FINISHED", token),
            asyncio.to_thread(_fetch_scorers, token),
            asyncio.to_thread(_fetch_standings, token),
        )
        live = [
            {
                "home": _team(m["homeTeam"]),
                "away": _team(m["awayTeam"]),
                "score": {
                    "home": m["score"]["fullTime"]["home"],
                    "away": m["score"]["fullTime"]["away"],
                },
                "status": m.get("status", ""),
                "minute": m.get("minute"),
                "stage": m.get("stage", ""),
                "group": (m.get("group") or "").replace("_", " "),
                "venue": m.get("venue") or "",
                "utcDate": m.get("utcDate"),
            }
            for m in live_raw.get("matches", [])
        ]
        upcoming = [
            {
                "home": _team(m["homeTeam"]),
                "away": _team(m["awayTeam"]),
                "stage": m.get("stage", ""),
                "group": (m.get("group") or "").replace("_", " "),
                "venue": m.get("venue") or "",
                "utcDate": m.get("utcDate"),
            }
            for m in sorted(sched_raw.get("matches", []), key=lambda m: m.get("utcDate") or "")[:6]
        ]
        results = [
            {
                "home": _team(m["homeTeam"]),
                "away": _team(m["awayTeam"]),
                "score": {
                    "home": m["score"]["fullTime"]["home"],
                    "away": m["score"]["fullTime"]["away"],
                },
                "winner": m["score"].get("winner"),
                "stage": m.get("stage", ""),
                "group": (m.get("group") or "").replace("_", " "),
                "utcDate": m.get("utcDate"),
            }
            for m in sorted(
                finished_raw.get("matches", []),
                key=lambda m: m.get("utcDate") or "",
                reverse=True,
            )[:6]
        ]
        scorers = [
            {
                "name": s["player"].get("name") or "",
                "team": (s.get("team") or {}).get("tla") or "",
                "crest": (s.get("team") or {}).get("crest") or "",
                "goals": s.get("goals") or 0,
            }
            for s in scorers_raw.get("scorers", [])[:6]
        ]
        standings = []
        for grp in stand_raw.get("standings", []):
            if grp.get("type") and grp.get("type") != "TOTAL":
                continue
            standings.append(
                {
                    "group": (grp.get("group") or "").replace("_", " ").title(),
                    "table": [
                        {
                            "position": r.get("position"),
                            "team": _team(r.get("team") or {}),
                            "played": r.get("playedGames"),
                            "won": r.get("won"),
                            "draw": r.get("draw"),
                            "lost": r.get("lost"),
                            "points": r.get("points"),
                            "gd": r.get("goalDifference"),
                        }
                        for r in grp.get("table", [])
                    ],
                }
            )

        # Attach CyberShield's per-match threat assessment to each upcoming game.
        snap = monitor.snapshot(limit=80)
        feed_threats = snap.get("threats", [])
        active_total = snap.get("active_threats", 0)
        for up in upcoming:
            up["threat"] = _assess_match(up, feed_threats, active_total)

        data = {
            "source": "live",
            "live": live,
            "upcoming": upcoming,
            "results": results,
            "scorers": scorers,
            "standings": standings,
        }
        _matches_cache["ts"] = now
        _matches_cache["data"] = data
        return data
    except Exception as exc:
        return {"source": "demo", "reason": f"football-data error: {exc}"}


@app.get("/route")
async def route(signal: str = Query(default="")):
    """CNS gate routing with UTR."""
    return cns.route_to_agent(signal)


@app.get("/utr")
async def utr(signal: str = Query(default="")):
    return cns.generate_utr(signal)
