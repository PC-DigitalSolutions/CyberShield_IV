from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UnifiedThreatReport(BaseModel):
    report_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    severity: str
    agent_outputs: Dict[str, Any]
    recommended_actions: List[str]
    signature: str = "CS-IV_SIG_VERIFIED"
    mitre_attack_id: Optional[str] = None
    triggered_gates: List[str] = []
    primary_gate: Optional[str] = None
    primary_agent: Optional[str] = None
    escalation_required: bool = False
    analyst_override_status: str = "pending_review"


def build_utr(
    report_id: str,
    severity: str,
    agent_outputs: Dict[str, Any],
    recommended_actions: List[str],
    mitre_attack_id: Optional[str] = None,
    triggered_gates: Optional[List[str]] = None,
    primary_gate: Optional[str] = None,
    primary_agent: Optional[str] = None,
    escalation_required: bool = False,
) -> Dict[str, Any]:
    report = UnifiedThreatReport(
        report_id=report_id,
        severity=severity,
        agent_outputs=agent_outputs,
        recommended_actions=recommended_actions,
        mitre_attack_id=mitre_attack_id,
        triggered_gates=triggered_gates or [],
        primary_gate=primary_gate,
        primary_agent=primary_agent,
        escalation_required=escalation_required,
    )

    if hasattr(report, "model_dump"):
        return report.model_dump()

    return report.dict()
