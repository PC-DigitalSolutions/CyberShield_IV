import uuid
from datetime import datetime

def generate_unified_report(goalie_res, referee_res, sentinel_res, triage_res):
    """
    Merges agent outputs into a single authoritative report.
    """
    threat_count = 0
    if goalie_res.get("status") == "THREAT DETECTED": threat_count += 1
    if referee_res.get("status") == "VIOLATION": threat_count += 1
    if sentinel_res.get("status") == "RED CARD": threat_count += 1
    if triage_res.get("status") == "TACTICAL ALERT": threat_count += 1

    severity = "LOW"
    if threat_count == 1: severity = "MEDIUM"
    if threat_count >= 2: severity = "HIGH"
    if threat_count >= 3: severity = "CRITICAL"

    report = {
        "incident_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "summary": f"Detected {threat_count} concurrent security anomalies.",
        "goalie": goalie_res,
        "referee": referee_res,
        "sentinel": sentinel_res,
        "triage": triage_res,
        "recommended_actions": [],
        "signature": "Strength. Vigilance. Intelligence. CyberShield AI (El Guardian)."
    }

    if severity in ["HIGH", "CRITICAL"]:
        report["recommended_actions"] = ["ISOLATE_NETWORK", "REVOKE_SESSION", "ESCALATE_TO_COMMAND"]
    else:
        report["recommended_actions"] = ["MONITOR_PERSISTENCE"]

    return report
