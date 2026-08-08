from src.sentinel import detect as sentinel_detect
from src.goalie import scan as goalie_scan
from src.referee import evaluate as referee_evaluate
from src.triage import process as triage_process


class AgentRegistry:
    """
    AgentRegistry - Connects CNS gates to actual agent functions.
    """

    def __init__(self):
        self.registry = {
            "Gate C": {
                "agent": "Deepfake Sentinel",
                "handler": sentinel_detect,
            },
            "Gate A": {
                "agent": "Anti-Scam Sentinel",
                "handler": goalie_scan,
            },
            "Gate B": {
                "agent": "Compliance Sentinel",
                "handler": referee_evaluate,
            },
            "Gate D": {
                "agent": "Infrastructure Sentinel",
                "handler": triage_process,
            },
        }

    def run_agent(self, gate: str, signal: str):
        entry = self.registry.get(gate)

        if not entry:
            return {
                "agent": "Unknown",
                "severity": "Unknown",
                "recommended_actions": ["Human analyst review required"],
                "result": None,
            }

        handler = entry["handler"]
        result = handler(signal)

        # Normalize output for CNS
        return {
            "agent": entry["agent"],
            "severity": result.get("status", "Unknown"),
            "recommended_actions": [result.get("action", "Review")],
            "mitre_attack_id": result.get("mitre_attack_id"),
            "result": result,
        }

