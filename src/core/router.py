class ElGuardianCNS:
    """
    ElGuardianCNS - Central Nervous System Routing Logic (Phase II)
    Designed by Copilot, Built by The Builder.
    """
    def __init__(self):
        self.version = "Phase II - Gated Logic"

    def route_to_agent(self, query: str):
        q = query.lower()

        # Gate A: Anti-Scammer Goalie
        scam_indicators = ["urgent", "password", "code", "verify", "click", "transfer", "bank", "login", "win", "prize"]
        if any(word in q for word in scam_indicators):
            return "goalie"

        # Gate B: Sideline Referee
        compliance_terms = ["origin", "destination", "transfer", "policy", "law", "regulation", "governance", "mexico", "eu", "gdpr"]
        if any(word in q for word in compliance_terms):
            return "referee"

        # Gate C: Red Card Sentinel
        media_terms = ["image", "video", "ai-generated", "deepfake", "authentic", "synthetic", "photo", "face"]
        if any(word in q for word in media_terms):
            return "sentinel"

        # Gate D: Las Barras Bravas Triage
        triage_terms = ["alert", "spike", "traffic", "incident", "overload", "threshold", "ddos", "attack"]
        if any(word in q for word in triage_terms):
            return "triage"

        return "goalie"
