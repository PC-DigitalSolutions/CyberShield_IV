import re
import uuid
from typing import Any, Dict, List

from src.agents import AgentRegistry
from src.utils.utr import build_utr


class ElGuardianCNS:
    """
    ElGuardianCNS - CyberShield_IV Central Nervous System

    Phase III:
    - Routes signals through Gate A/B/C/D
    - Uses Primary Arbiter conflict resolution
    - Applies severity hierarchy:
      Sentinel > Goalie > Referee > Triage
    - Generates Unified Threat Report on routed events
    """

    def __init__(self):
        self.version = "Phase III - CNS Integrated Routing"
        self.registry = AgentRegistry()

        self.severity_hierarchy = [
            "Gate C",  # Red Card Sentinel
            "Gate A",  # Anti-Scammer Goalie
            "Gate B",  # Sideline Referee
            "Gate D",  # Las Barras Bravas Triage
        ]

        self.gate_keywords = {
            "Gate A": [
                "scam",
                "phish",
                "phishing",
                "fraud",
                "money",
                "payment",
                "wallet",
                "ticket",
                "credential",
                "login link",
                "prize",
                "fee",
                "won",
                "winner",
                "giveaway",
                "free tickets",
                "verify your",
                "suspicious link",
            ],
            "Gate B": [
                "compliance",
                "privacy",
                "data",
                "gdpr",
                "lgpd",
                "access",
                "unauthorized access",
                "egress",
                "origin",
                "destination",
                "zero trust",
            ],
            "Gate C": [
                "deepfake",
                "fake video",
                "synthetic media",
                "media",
                "video",
                "image",
                "metadata",
                "manipulated",
                "ai-generated",
                "broadcast",
            ],
            "Gate D": [
                "spike",
                "traffic",
                "anomaly",
                "crowd",
                "surge",
                "ddos",
                "bot",
                "flood",
                "telemetry",
                "rate limit",
            ],
        }

    def status(self) -> Dict[str, Any]:
        return {
            "status": "online",
            "system": "CyberShield_IV",
            "cns": "ElGuardianCNS",
            "version": self.version,
            "registered_gates": list(self.gate_keywords.keys()),
            "severity_hierarchy": self.severity_hierarchy,
        }

    def detect_gates(self, signal: str) -> List[str]:
        text = (signal or "").lower()
        triggered = []

        for gate, keywords in self.gate_keywords.items():
            if any(re.search(rf"\b{re.escape(keyword)}\b", text) for keyword in keywords):
                triggered.append(gate)

        return triggered

    def choose_primary_gate(self, triggered_gates: List[str]) -> str:
        for gate in self.severity_hierarchy:
            if gate in triggered_gates:
                return gate

        return triggered_gates[0] if triggered_gates else None

    def route_to_agent(self, query: str) -> Dict[str, Any]:
        signal = query or ""
        triggered_gates = self.detect_gates(signal)

        if not triggered_gates:
            return {
                "status": "clear",
                "message": "No CNS gate triggered.",
                "signal": signal,
                "triggered_gates": [],
                "utr": None,
            }

        primary_gate = self.choose_primary_gate(triggered_gates)
        escalation_required = len(triggered_gates) > 1

        agent_outputs = {}

        for gate in triggered_gates:
            result = self.registry.run_agent(gate, signal)
            agent_outputs[gate] = result

        primary_result = agent_outputs.get(primary_gate, {})
        primary_agent = primary_result.get("agent", "Unknown Agent")

        recommended_actions = primary_result.get(
            "recommended_actions",
            ["Human analyst review required"],
        )

        if escalation_required:
            recommended_actions = list(dict.fromkeys(
                recommended_actions + [
                    "Escalate multi-gate threat to Unified Threat Report",
                    "Require Human-in-the-Loop review",
                ]
            ))

        utr = build_utr(
            report_id=f"CS-IV-{uuid.uuid4().hex[:8].upper()}",
            severity=primary_result.get("severity", "High"),
            agent_outputs=agent_outputs,
            recommended_actions=recommended_actions,
            mitre_attack_id=primary_result.get("mitre_attack_id"),
            triggered_gates=triggered_gates,
            primary_gate=primary_gate,
            primary_agent=primary_agent,
            escalation_required=escalation_required,
        )

        return {
            "status": "routed",
            "signal": signal,
            "triggered_gates": triggered_gates,
            "primary_gate": primary_gate,
            "primary_agent": primary_agent,
            "conflict_resolution": {
                "escalation_required": escalation_required,
                "hierarchy": self.severity_hierarchy,
                "rule": "Sentinel > Goalie > Referee > Triage",
            },
            "utr": utr,
        }

    def generate_utr(self, query: str) -> Dict[str, Any]:
        routed = self.route_to_agent(query)
        return routed.get("utr")
