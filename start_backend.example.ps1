# CyberShield backend launcher (safe to commit — no secrets).
#
# Setup: set your key once in the environment, then run this script.
#   $env:CYBERSHIELD_API_KEY = "your-new-gemini-key"
#   $env:FOOTBALL_DATA_TOKEN = "your-football-data-token"
#
# (The real start_backend.ps1 is gitignored so a hardcoded key never leaks.)

if (-not $env:CYBERSHIELD_API_KEY) {
    Write-Host "CYBERSHIELD_API_KEY is not set. Set it before launching." -ForegroundColor Yellow
    exit 1
}

Set-Location $PSScriptRoot
.venv\Scripts\uvicorn.exe src.api.main:app --host 127.0.0.1 --port 8000
