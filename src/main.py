from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os

from src.goalie import AntiScammerGoalie
from src.referee import SidelineReferee
from src.sentinel import RedCardSentinel
from src.triage import LasBarrasBravasTriage
from src.core.router import ElGuardianCNS
from src.utils.utr import generate_unified_report

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.agents = {
        "goalie": AntiScammerGoalie(),
        "referee": SidelineReferee(),
        "sentinel": RedCardSentinel(),
        "triage": LasBarrasBravasTriage(),
    }
    app.state.cns = ElGuardianCNS()
    yield

app = FastAPI(title="CyberShield AI", version="2.0", lifespan=lifespan)

# Check if static/templates exist to avoid crashes
if os.path.exists("backend/static"):
    app.mount("/static", StaticFiles(directory="backend/static"), name="static")

templates = None
if os.path.exists("backend/templates"):
    templates = Jinja2Templates(directory="backend/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if templates:
        return templates.TemplateResponse("dashboard.html", {"request": request, "mission": "World Cup 2026", "status": "ACTIVE"})
    return "<h1>CyberShield Active</h1><p>Template folder missing, but backend is LIVE.</p>"

@app.post("/api/analyze")
async def analyze(payload: BaseModel):
    return {"status": "System Online"}
