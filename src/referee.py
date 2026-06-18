class SidelineReferee:
    def __init__(self):
        self.name = "Sideline Referee"
        self.signature = "Strength. Vigilance. Intelligence. | CyberShield AI — El Guardián."

    def check_compliance(self, origin: str, destination: str):
        origin = origin.strip().upper()
        destination = destination.strip().upper()

        # Mexico LFPDPPP Check
        if origin == "MEXICO" and destination != "MEXICO":
            return {"status": "VIOLATION", "law": "Mexico Federal Law (LFPDPPP)", "action": "AUDIT"}
        
        # EU GDPR Check
        if origin in ["EU", "GERMANY", "FRANCE", "SPAIN"] and destination not in ["EU", "USA"]:
            return {"status": "HIGH RISK", "law": "GDPR (Article 44)", "action": "ENFORCE_ENCRYPTION"}

        return {"status": "COMPLIANT", "action": "PLAY ON"}

# Entrypoint for AgentRegistry
def evaluate(text: str):
    agent = SidelineReferee()
    lowered = (text or "").lower()

    # A reported data incident is never "COMPLIANT" — this check takes priority
    # over the routine cross-border transfer logic below.
    breach_terms = [
        "breach", "leak", "leaked", "exposed", "exposure", "stolen",
        "hacked", "unauthorized access", "data dump", "compromis", "exfiltrat",
    ]
    pii_terms = [
        "passport", "personal data", "personal details", "identity",
        "credential", "private data", "customer data", "fan data", "id details",
    ]
    if any(t in lowered for t in breach_terms):
        sensitive = any(t in lowered for t in pii_terms)
        return {
            "status": "VIOLATION" if sensitive else "HIGH RISK",
            "law": "GDPR Art. 33/34 · LGPD · Mexico LFPDPPP (breach notification)",
            "action": "CONTAIN_AND_NOTIFY",
            "data_class": "sensitive PII" if sensitive else "personal data",
        }

    # Routine cross-border transfer checks
    if "mexico" in lowered:
        return agent.check_compliance("MEXICO", "USA")
    if "gdpr" in lowered or "europe" in lowered:
        return agent.check_compliance("EU", "ASIA")
    return agent.check_compliance("USA", "USA")
