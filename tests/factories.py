"""Plain data builders shared by the unit tests"""

from __future__ import annotations

from soc_triage.config import Settings
from soc_triage.models import (
    Action,
    ClassifiedAlert,
    Decision,
    Enrichment,
    GuardrailResult,
    RawAlert,
    RetrievedIncident,
    Severity,
    TriageResult,
)


def make_alert(**overrides) -> RawAlert:
    data = {"event_id": "11111111-2222-3333-4444-555555555555", "event_type": "process_create",
            "description": "process_create; Image=C:\\Windows\\System32\\cmd.exe"}
    data.update(overrides)
    return RawAlert.model_validate(data)


def make_classified(severity: Severity = Severity.LOW, confidence: float = 0.9, alert: RawAlert | None = None) -> ClassifiedAlert:
    return ClassifiedAlert(alert=alert or make_alert(), severity=severity, rationale="because", confidence=confidence)


def make_incident(score: float = 0.9, event_type: str | None = "process_create", incident_id: str = "inc-1",
                  summary: str = "process_create | Sysmon", metadata: dict | None = None) -> RetrievedIncident:
    return RetrievedIncident(incident_id=incident_id, summary=summary, score=score, event_type=event_type,
                             metadata=metadata or {})


def make_enrichment(max_score: float = 0.9, weak: bool = False, incidents: list[RetrievedIncident] | None = None) -> Enrichment:
    if incidents is None:
        incidents = [make_incident(score=max_score)]
    return Enrichment(incidents=incidents, max_score=max_score, weak_retrieval=weak)


def make_decision(action: Action = Action.ESCALATE_TO_ANALYST, confidence: float = 0.9, reasoning: str = "because") -> Decision:
    return Decision(action=action, reasoning=reasoning, confidence=confidence)


def make_guardrail(action: Action = Action.ESCALATE_TO_ANALYST, **kw) -> GuardrailResult:
    return GuardrailResult(final_action=action, **kw)


def make_result(status: str = "escalated", severity: Severity = Severity.MEDIUM, action: Action = Action.ESCALATE_TO_ANALYST,
                alert: RawAlert | None = None, enrichment: Enrichment | None = None, guardrail: GuardrailResult | None = None,
                decision: Decision | None = None) -> TriageResult:
    alert = alert or make_alert()
    return TriageResult(
        alert_id=alert.event_id,
        classification=make_classified(severity, alert=alert),
        enrichment=enrichment or make_enrichment(),
        proposed=decision or make_decision(action),
        guardrail=guardrail or make_guardrail(action),
        status=status,
    )


def make_settings(**overrides) -> Settings:
    base = {"min_retrieval_score": 0.35, "min_intake_confidence": 0.6, "min_decision_confidence": 0.8,
            "top_k": 3, "llm_timeout_s": 30.0, "llm_max_retries": 2}
    base.update(overrides)
    return Settings(**base)
