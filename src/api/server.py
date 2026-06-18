from fastapi import FastAPI, Request, APIRouter, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from src.core.router import ElGuardianCNS

app = FastAPI()
api_router = APIRouter()
cns = ElGuardianCNS()

static_dir = os.path.join("backend", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def read_interface():
    # Force loading dashboard.html explicitly
    html_path = os.path.join("backend", "templates", "dashboard.html")
    if not os.path.exists(html_path):
        return {
            "status": "error",
            "message": "Could not find dashboard.html inside backend/templates/"
        }
    return FileResponse(html_path)

@app.get("/status")
async def get_status():
    return cns.status()

@app.get("/analyze")
async def run_analyze(signal: str = Query(..., description="The signal message to evaluate")):
    return cns.route_to_agent(signal)

@app.get("/route")
async def run_route(signal: str = Query(..., description="The routing compliance signal")):
    return cns.route_to_agent(signal)

@app.get("/utr")
async def fetch_utr(signal: str = Query(..., description="The data to compile into a Unified Threat Report")):
    return cns.generate_utr(signal)
