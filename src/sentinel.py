from src.shared_intel import intel

class RedCardSentinel:
    def __init__(self):
        self.name = "Red Card Sentinel"

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
