from src.shared_intel import intel

class RedCardSentinel:
    def __init__(self):
        self.name = "Red Card Sentinel"
        self.signature = "Strength. Vigilance. Intelligence. | CyberShield AI — El Guardián."

    def authenticate(self, ai_generated: bool, metadata: dict = None):
        is_synthetic = ai_generated or intel.check_media_integrity(metadata or {})
        
        if is_synthetic:
            return {
                "status": "RED CARD",
                "classification": "Synthetic Media Detected",
                "action": "LOCKOUT & ESCALATE"
            }

        return {
            "status": "VERIFIED",
            "classification": "Authentic Media",
            "action": "ALLOW"
        }

# Entrypoint for AgentRegistry
def detect(text: str):
    agent = RedCardSentinel()
    # If explicitly flagged or signature matched
    ai_flagged = "deepfake" in text.lower() or "ai-generated" in text.lower()
    return agent.authenticate(ai_generated=ai_flagged, metadata={"signature": text})
