import importlib
from typing import Any, Dict


class AgentRegistry:
    """
    AgentRegistry bridges ElGuardianCNS to the existing CyberShield_IV agents.

    IMPORTANT:
    Existing agents live at:
    - src/goalie.py
    - src/referee.py
    - src/sentinel.py
    - src/triage.py

    This registry imports those files and does not recreate or overwrite them.
    """

    def __init__(self):
        self.agents = {
            "Gate A": {
                "name": "Anti-Scammer Goalie",
                "module_path": "src.goalie",
                "mitre_attack_id": "T1566",
                "default_severity": "High",
                "default_actions": [
                    "Flag suspected scam",
                    "Isolate suspicious link or transaction",
                    "Notify fraud analyst",
                ],
            },
            "Gate B": {
                "name": "Sideline Referee",
                "module_path": "src.referee",
                "mitre_attack_id": "T1020",
                "default_severity": "Medium",
                "default_actions": [
                    "Verify data origin and destination",
                    "Apply Zero Trust policy check",
                    "Log compliance event",
                ],
            },
            "Gate C": {
                "name": "Red Card Sentinel",
                "module_path": "src.sentinel",
                "mitre_attack_id": "T1608.005",
                "default_severity": "Critical",
                "default_actions": [
                    "Quarantine suspicious media",
                    "Request authenticity verification",
                    "Escalate to human analyst",
                ],
            },
            "Gate D": {
                "name": "Las Barras Bravas Triage",
                "module_path": "src.triage",
                "mitre_attack_id": "T1498",
                "default_severity": "High",
                "default_actions": [
                    "Monitor anomaly spike",
                    "Activate rate limiting if needed",
                    "Escalate crowd-scale telemetry alert",
                ],
            },
        }

    def get_agent(self, gate: str) -> Dict[str, Any]:
        return self.agents.get(gate)

    def run_agent(self, gate: str, signal: str) -> Dict[str, Any]:
        agent = self.get_agent(gate)

        if not agent:
            return {
                "agent": "Unknown",
                "gate": gate,
                "status": "error",
                "output": "No agent registered for this gate.",
                "severity": "Unknown",
                "recommended_actions": ["Review CNS registry"],
                "mitre_attack_id": None,
            }

        module = None

        try:
            module = importlib.import_module(agent["module_path"])
        except Exception as exc:
            return self._fallback_result(
                gate=gate,
                agent=agent,
                signal=signal,
                note=f"Agent module import failed: {exc}",
            )

        callable_names = [
            "analyze",
            "process",
            "run",
            "scan",
            "detect",
            "evaluate",
            "main",
        ]

        for name in callable_names:
            fn = getattr(module, name, None)
            if callable(fn):
                try:
                    raw = fn(signal)
                    return self._normalize_result(gate, agent, raw)
                except TypeError:
                    try:
                        raw = fn()
                        return self._normalize_result(gate, agent, raw)
                    except Exception as exc:
                        return self._fallback_result(
                            gate=gate,
                            agent=agent,
                            signal=signal,
                            note=f"Agent callable '{name}' failed: {exc}",
                        )
                except Exception as exc:
                    return self._fallback_result(
                        gate=gate,
                        agent=agent,
                        signal=signal,
                        note=f"Agent callable '{name}' failed: {exc}",
                    )

        return self._fallback_result(
            gate=gate,
            agent=agent,
            signal=signal,
            note="No standard callable found. Registry fallback used.",
        )

    def _normalize_result(self, gate: str, agent: Dict[str, Any], raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            output = raw.get("output") or raw.get("result") or raw.get("message") or str(raw)
            severity = raw.get("severity", agent["default_severity"])
            actions = (
                raw.get("recommended_actions")
                or raw.get("actions")
                or agent["default_actions"]
            )
            mitre = raw.get("mitre_attack_id", agent["mitre_attack_id"])

            return {
                "agent": agent["name"],
                "gate": gate,
                "status": raw.get("status", "completed"),
                "output": output,
                "severity": severity,
                "recommended_actions": actions,
                "mitre_attack_id": mitre,
                "raw": raw,
            }

        return {
            "agent": agent["name"],
            "gate": gate,
            "status": "completed",
            "output": str(raw),
            "severity": agent["default_severity"],
            "recommended_actions": agent["default_actions"],
            "mitre_attack_id": agent["mitre_attack_id"],
            "raw": raw,
        }

    def _fallback_result(
        self,
        gate: str,
        agent: Dict[str, Any],
        signal: str,
        note: str,
    ) -> Dict[str, Any]:
        return {
            "agent": agent["name"],
            "gate": gate,
            "status": "fallback",
            "output": f"{agent['name']} assigned to signal: {signal}",
            "severity": agent["default_severity"],
            "recommended_actions": agent["default_actions"],
            "mitre_attack_id": agent["mitre_attack_id"],
            "note": note,
        }
