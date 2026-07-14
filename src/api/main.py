import asyncio
import json
import os
import time
import urllib.request
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from collections import defaultdict, deque
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from starlette.staticfiles import StaticFiles

load_dotenv()

from src.core.router import ElGuardianCNS
from src.core.live_monitor import LiveThreatMonitor
from src.core.community import SCAM_TYPES, stories, validate_story
from src.agents.guardian_agent import ElGuardian
from src.agents import goalie_chat, media, specialists

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
    allow_origin_regex=r"https://.*\.vercel\.app|http://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}):\d{2,5}",
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


@app.post("/analyze/file")
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    note: str = Form(""),
):
    """El Guardián reads an uploaded photo, PDF, or video and gives its verdict,
    then any triggered specialist gate adds its playbook. Files are analyzed in
    memory and never stored."""
    if not _allow(f"file:{_client_ip(request)}", limit=10, window_s=600):
        raise HTTPException(status_code=429, detail="Too many uploads — give the shield a minute.")
    raw = await file.read()
    try:
        kind = media.validate(file.content_type or "", len(raw))
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    context = _live_context()

    def run_guardian() -> str:
        client = guardian._get_client()
        with media.MediaAttachment(client, raw, file.content_type) as parts:
            return guardian.analyze(note, engaged=None, context=context or None, media=parts)

    try:
        verdict = await asyncio.to_thread(run_guardian)
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"El Guardián's vision core is offline: {exc}")

    # The gates are keyword-driven, so read them off the note + what El Guardián
    # saw in the file — that lets the right specialist chime in on the evidence.
    signal_for_gates = f"{note} {verdict}".strip()
    gates = cns.detect_gates(signal_for_gates)

    def specialist_report(gate: str):
        try:
            scanner = cns.registry.run_agent(gate, signal_for_gates)
            scanner.pop("raw", None)
        except Exception:
            scanner = None
        return specialists.respond(gate, signal_for_gates, scanner)

    results = (
        await asyncio.gather(*(asyncio.to_thread(specialist_report, g) for g in gates))
        if gates else []
    )
    agents = [
        {"gate": g, "agent": cns.registry.agents[g]["name"], "response": r}
        for g, r in zip(gates, results)
        if r
    ]
    return {
        "status": "ok",
        "signal": note or f"[{kind} attached for analysis]",
        "response": verdict,
        "gates": gates,
        "primary_gate": cns.choose_primary_gate(gates) if gates else None,
        "agents": agents,
    }


# ── Rate limiting (troll shield) — sliding window per client IP ──────────
_rate_hits: dict = defaultdict(deque)


def _allow(key: str, limit: int, window_s: int) -> bool:
    now = time.time()
    dq = _rate_hits[key]
    while dq and dq[0] < now - window_s:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else None) or (
        request.client.host if request.client else "unknown"
    )


def _admin_ok(key: str, request: Request) -> bool:
    """Admin endpoints: require ADMIN_KEY when set; otherwise localhost only."""
    admin_key = os.environ.get("ADMIN_KEY", "")
    if admin_key:
        return key == admin_key
    return _client_ip(request) in ("127.0.0.1", "::1", "localhost")


def _lang_guess(text: str) -> str:
    """Rough EN/ES telemetry hint — never stored with the text itself."""
    t = f" {text.lower()} "
    es = sum(t.count(f" {w} ") for w in ("que", "para", "pero", "esto", "boleto", "estafa", "dinero", "gracias"))
    es += sum(text.count(c) for c in "áéíóúñ¿¡")
    return "es" if es >= 2 else "en"


class ChatTurn(BaseModel):
    role: str = "user"
    text: str = ""


class GoalieChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: list[ChatTurn] = []


class GoalieReportIn(BaseModel):
    story: str = Field(min_length=20, max_length=4000)
    scam_type: str = "other"
    language: str = ""
    consent: bool = False


@app.post("/goalie/chat")
async def goalie_chat_turn(body: GoalieChatIn, request: Request):
    """The Anti-Scammer Goalie's own chat lane — multi-turn, grounded in
    community-reported scam stories. History travels with the request."""
    if not _allow(f"chat:{_client_ip(request)}", limit=20, window_s=600):
        raise HTTPException(status_code=429, detail="The Goalie needs a breather — try again in a few minutes.")
    matches = stories.match(body.message)
    intel = goalie_chat.build_intel_block(matches, stories.stats())
    history = [t.model_dump() for t in body.history]
    response = await asyncio.to_thread(
        goalie_chat.chat, body.message, history, intel
    )
    stories.log_event(
        "chat",
        lang=_lang_guess(body.message),
        msg_len=len(body.message),
        turns=len(history),
        matches=len(matches),
    )
    return {
        "status": "ok",
        "agent": "Anti-Scammer Goalie",
        "gate": "Gate A",
        "response": response,
        "community_matches": len(matches),
    }


@app.post("/goalie/chat/file")
async def goalie_chat_file(
    request: Request,
    file: UploadFile = File(...),
    message: str = Form(""),
    history: str = Form("[]"),
):
    """The Goalie's chat lane with an attached photo, PDF, or video — it reads the
    file as evidence and answers in the same turn. History arrives as a JSON
    string alongside the multipart file. Nothing is stored."""
    if not _allow(f"chat:{_client_ip(request)}", limit=20, window_s=600):
        raise HTTPException(status_code=429, detail="The Goalie needs a breather — try again in a few minutes.")
    raw = await file.read()
    try:
        media.validate(file.content_type or "", len(raw))
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    try:
        parsed = json.loads(history) if history else []
    except (ValueError, TypeError):
        parsed = []
    hist = [
        {"role": t.get("role", "user"), "text": t.get("text", "")}
        for t in (parsed if isinstance(parsed, list) else [])
        if isinstance(t, dict)
    ][-12:]

    matches = stories.match(message or "")
    intel = goalie_chat.build_intel_block(matches, stories.stats())

    def run_goalie() -> str:
        client = specialists._get_client()
        with media.MediaAttachment(client, raw, file.content_type) as parts:
            return goalie_chat.chat(message, hist, intel, media=parts)

    try:
        response = await asyncio.to_thread(run_goalie)
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"The Goalie's vision core is offline: {exc}")

    stories.log_event(
        "chat_file",
        lang=_lang_guess(message or ""),
        msg_len=len(message or ""),
        turns=len(hist),
        matches=len(matches),
    )
    return {
        "status": "ok",
        "agent": "Anti-Scammer Goalie",
        "gate": "Gate A",
        "response": response,
        "community_matches": len(matches),
    }


@app.post("/goalie/report")
async def goalie_report(body: GoalieReportIn, request: Request):
    """Consented, anonymized community scam-story submission. Stories are
    PII-scrubbed on write and feed the Goalie's chat intel."""
    if not body.consent:
        raise HTTPException(status_code=400, detail="consent required")
    if not _allow(f"report:{_client_ip(request)}", limit=5, window_s=3600):
        raise HTTPException(status_code=429, detail="Wall limit reached — try again in an hour.")
    reason = validate_story(body.story)
    if reason:
        stories.log_event("report_rejected", scam_type=body.scam_type)
        raise HTTPException(status_code=422, detail=reason)
    story_id = stories.add(body.story, body.scam_type, body.language, source="form")
    stories.log_event(
        "report",
        scam_type=body.scam_type,
        lang=body.language or _lang_guess(body.story),
        story_len=len(body.story),
    )
    return {"status": "ok", "id": story_id, **stories.stats()}


@app.get("/goalie/stories")
async def goalie_stories(limit: int = Query(default=20, ge=1, le=50)):
    """Anonymized community scam-story wall + counts."""
    return {
        "status": "ok",
        "scam_types": SCAM_TYPES,
        "stories": stories.recent(limit),
        **stories.stats(),
    }


@app.get("/goalie/beta-report")
async def goalie_beta_report(request: Request, key: str = Query(default=""),
                             days: int = Query(default=14, ge=1, le=90)):
    """Beta program report — what testers are doing, aggregated metadata only
    (no chat/story text, no IPs). Protected: ADMIN_KEY, or localhost in dev."""
    if not _admin_ok(key, request):
        raise HTTPException(status_code=403, detail="not authorized")
    return stories.beta_report(days)


@app.post("/goalie/stories/{story_id}/hide")
async def goalie_hide_story(story_id: int, request: Request, key: str = Query(default="")):
    """Moderation: soft-remove a story from the public wall."""
    if not _admin_ok(key, request):
        raise HTTPException(status_code=403, detail="not authorized")
    if not stories.hide(story_id):
        raise HTTPException(status_code=404, detail="story not found")
    stories.log_event("story_hidden", story_id=story_id)
    return {"status": "ok", "hidden": story_id, **stories.stats()}


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
