from src.shared_intel import intel


class AntiScammerGoalie:
    def __init__(self):
        self.name = "Anti-Scammer Goalie"
        self.signature = "Strength. Vigilance. Intelligence. | CyberShield AI — El Guardián."

    def status(self):
        return f"[{self.name}] VIGILANT\n{self.signature}"

    def scan_intent(self, message: str):
        analysis = intel.analyze_any_language(message)

        if analysis.get("error"):
            return {
                "status": "ERROR",
                "message": analysis["error"]
            }

        threats = analysis.get("threats", [])
        if threats:
            return {
                "status": "THREAT DETECTED",
                "detected_language": analysis.get("detected_lang", "unknown"),
                "translated_text": analysis.get("translated_text", ""),
                "flagged_keywords": threats,
                "action": "BLOCK & REPORT"
            }

        return {
            "status": "CLEAR",
            "detected_language": analysis.get("detected_lang", "unknown"),
            "translated_text": analysis.get("translated_text", ""),
            "flagged_keywords": []
        }


if __name__ == "__main__":
    agent = AntiScammerGoalie()
    print(agent.status())

# Entrypoint for AgentRegistry
def scan(text: str):
    agent = AntiScammerGoalie()
    return agent.scan_intent(text)
