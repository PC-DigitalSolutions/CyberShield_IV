from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

app = FastAPI(title="CyberShield AI API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:3001","http://127.0.0.1:3000","http://127.0.0.1:3001"],
    allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["*"],
)

# Simulated threat signature database for the protection mission
THREAT_SIGNATURES = {
    "sql_injection": ["SELECT", "UNION", "DROP", "' OR '1'='1"],
    "ddos_pattern": ["flood", "amplification", "botnet_burst"],
    "unauthorized_access": ["brute_force", "admin_bypass", "privilege_escalation"]
}

@app.get("/")
def read_root():
    return {"status": "online", "system": "CyberShield AI - El Guardián V2"}

@app.get("/analyze")
async def analyze(
    signal: str = Query(..., description="The raw signal payload to analyze"),
    source_ip: str = Query("Unknown", description="Origin IP of the signal")
):
    signal_upper = signal.upper()
    detected_threat = "None"
    risk_level = "Low"
    action = "Monitor"

    # Core threat evaluation engine
    for threat_type, signatures in THREAT_SIGNATURES.items():
        if any(sig in signal_upper or sig in signal for sig in signatures):
            detected_threat = threat_type
            
            # Escalate risk based on threat type
            if threat_type == "sql_injection":
                risk_level = "Critical"
                action = "Immediate IP Block & Alert SOC"
            else:
                risk_level = "High"
                action = "Rate Limit & Flag"
            break

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mission_context": "2026 FIFA World Cup Security",
        "signal_data": {
            "received_payload": signal,
            "source_ip": source_ip
        },
        "analysis_result": {
            "threat_classification": detected_threat,
            "risk_level": risk_level,
            "recommended_action": action
        }
    }
