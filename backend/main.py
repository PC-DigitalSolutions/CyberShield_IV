from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.server import api_router
from src.core.identity import system_identity

app = FastAPI(title="CyberShield_IV")

app.mount("/static", StaticFiles(directory="backend/static"), name="static")
templates = Jinja2Templates(directory="backend/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

app.include_router(api_router, prefix="/api")

@app.get("/identity")
async def identity():
    return {"identity": system_identity}
