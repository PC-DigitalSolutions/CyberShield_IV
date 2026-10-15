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
    # Start the live event/concert threat monitor in the background.
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
    """Rolling feed of live event/concert threats + intel, sourced from Google News
    RSS and classified through the CNS gates. Polled by the dashboard."""
    return monitor.snapshot(limit)


@app.get("/threats/history")
async def threats_history(
    limit: int = Query(default=100, ge=1, le=1000),
    kind: str = Query(default="", description="Filter to 'threat' or 'intel'"),
):
    """Durable archive of every event/concert headline the monitor has assessed,
    newest first. Append-only JSONL that survives restarts — unlike the
    in-memory /threats/live window."""
    return monitor.history(limit, kind or None)


def _live_context() -> str:
    """Real-time threat context fed to El Guardián so it can answer from the live
    monitor's active threats instead of guessing."""
    parts = []

    snap = monitor.snapshot(limit=80)
    threats = [t for t in snap.get("threats", []) if t.get("kind") == "threat"]
    if threats:
        lines = [f"- [{t['severity']}] {t['title']} (handled by {t['agent']})" for t in threats[:5]]
        parts.append(f"ACTIVE THREATS ({snap.get('active_threats', 0)} live now):\n" + "\n".join(lines))

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
        kind, _mime = media.validate(file.content_type or "", len(raw), file.filename or "")
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    context = _live_context()

    def run_guardian() -> str:
        client = guardian._get_client()
        with media.MediaAttachment(client, raw, file.content_type, file.filename or "") as parts:
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


@app.post("/sentinel/chat")
async def goalie_chat_turn(body: GoalieChatIn, request: Request):
    """The Anti-Scam Sentinel's own chat lane — multi-turn, grounded in
    community-reported scam stories. History travels with the request."""
    if not _allow(f"chat:{_client_ip(request)}", limit=20, window_s=600):
        raise HTTPException(status_code=429, detail="The Anti-Scam Sentinel needs a breather — try again in a few minutes.")
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
        "agent": "Anti-Scam Sentinel",
        "gate": "Gate A",
        "response": response,
        "community_matches": len(matches),
    }


@app.post("/sentinel/chat/file")
async def goalie_chat_file(
    request: Request,
    file: UploadFile = File(...),
    message: str = Form(""),
    history: str = Form("[]"),
):
    """The Anti-Scam Sentinel's chat lane with an attached photo, PDF, or video — it reads the
    file as evidence and answers in the same turn. History arrives as a JSON
    string alongside the multipart file. Nothing is stored."""
    if not _allow(f"chat:{_client_ip(request)}", limit=20, window_s=600):
        raise HTTPException(status_code=429, detail="The Anti-Scam Sentinel needs a breather — try again in a few minutes.")
    raw = await file.read()
    try:
        media.validate(file.content_type or "", len(raw), file.filename or "")
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
        with media.MediaAttachment(client, raw, file.content_type, file.filename or "") as parts:
            return goalie_chat.chat(message, hist, intel, media=parts)

    try:
        response = await asyncio.to_thread(run_goalie)
    except media.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"The Anti-Scam Sentinel's vision core is offline: {exc}")

    stories.log_event(
        "chat_file",
        lang=_lang_guess(message or ""),
        msg_len=len(message or ""),
        turns=len(hist),
        matches=len(matches),
    )
    return {
        "status": "ok",
        "agent": "Anti-Scam Sentinel",
        "gate": "Gate A",
        "response": response,
        "community_matches": len(matches),
    }


@app.post("/sentinel/report")
async def goalie_report(body: GoalieReportIn, request: Request):
    """Consented, anonymized community scam-story submission. Stories are
    PII-scrubbed on write and feed the Anti-Scam Sentinel's chat intel."""
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


@app.get("/sentinel/stories")
async def goalie_stories(limit: int = Query(default=20, ge=1, le=50)):
    """Anonymized community scam-story wall + counts."""
    return {
        "status": "ok",
        "scam_types": SCAM_TYPES,
        "stories": stories.recent(limit),
        **stories.stats(),
    }


@app.get("/sentinel/beta-report")
async def goalie_beta_report(request: Request, key: str = Query(default=""),
                             days: int = Query(default=14, ge=1, le=90)):
    """Beta program report — what testers are doing, aggregated metadata only
    (no chat/story text, no IPs). Protected: ADMIN_KEY, or localhost in dev."""
    if not _admin_ok(key, request):
        raise HTTPException(status_code=403, detail="not authorized")
    return stories.beta_report(days)


@app.post("/sentinel/stories/{story_id}/hide")
async def goalie_hide_story(story_id: int, request: Request, key: str = Query(default="")):
    """Moderation: soft-remove a story from the public wall."""
    if not _admin_ok(key, request):
        raise HTTPException(status_code=403, detail="not authorized")
    if not stories.hide(story_id):
        raise HTTPException(status_code=404, detail="story not found")
    stories.log_event("story_hidden", story_id=story_id)
    return {"status": "ok", "hidden": story_id, **stories.stats()}



@app.get("/route")
async def route(signal: str = Query(default="")):
    """CNS gate routing with UTR."""
    return cns.route_to_agent(signal)


@app.get("/utr")
async def utr(signal: str = Query(default="")):
    return cns.generate_utr(signal)


# ---------------------------------------------------------------------------
# IAM: assess-login (Sentinel Task 02)
# ---------------------------------------------------------------------------
import json as _json
import pathlib as _pathlib

_SEED_PATH = _pathlib.Path(__file__).parent.parent.parent / "data" / "iam" / "baselines.json"
_IAM_SEED: dict = _json.loads(_SEED_PATH.read_text(encoding="utf-8"))

from src.iam.assess import assess_login as _assess_login_fn


class LoginAlert(BaseModel):
    user_id: str
    ip: str
    device_id: str
    geo: str
    timestamp: str


@app.post("/iam/assess-login", operation_id="assess_login")
async def iam_assess_login(alert: LoginAlert):
    """
    Score a suspicious-login alert against the user's baseline.

    Checks impossible travel (haversine), threat-listed IP, new device,
    and off-hours access.  Returns risk_score, risk_level, flags, baseline,
    and a plain-language explanation.  Raises HTTP 404 for unknown users.
    """
    try:
        return _assess_login_fn(alert.model_dump(), _IAM_SEED)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown user")
