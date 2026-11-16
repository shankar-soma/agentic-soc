from __future__ import annotations

from soc_triage.config import Settings
from soc_triage.models import (
    Action,
    ClassifiedAlert,
    Decision,
    Enrichment,
    GuardrailResult,
    RawAlert,
    Severity,
)

_NEEDS_EVIDENCE = {Action.SUPPRESS_AS_FALSE_POSITIVE, Action.AUTO_REMEDIATE}


def _is_crown_jewel(alert: RawAlert) -> bool:
    return (alert.asset_criticality or "").lower() == "crown-jewel"


def apply_guardrails(
    *,
    alert: RawAlert,
    classified: ClassifiedAlert,
    enrichment: Enrichment,
    proposed: Decision,
    injection_flags: list[str],
    settings: Settings,
) -> GuardrailResult:
    action = proposed.action
    reasons: list[str] = []
    requires_approval = False

    # High and Critical alerts cannot be suppressed, regardless of confidence.
    if action == Action.SUPPRESS_AS_FALSE_POSITIVE and classified.severity in (Severity.CRITICAL, Severity.HIGH):
        action = Action.ESCALATE_TO_ANALYST
        reasons.append(f"{classified.severity.value} alerts are never suppressed")

    # Check eligibility before routing an auto-remediation proposal to approval.
    if action in _NEEDS_EVIDENCE:
        if enrichment.weak_retrieval:
            same_type = any(i.event_type == alert.event_type for i in enrichment.incidents)
            detail = ("no same-event-type match" if not same_type else
                      f"best score {enrichment.max_score:.2f} below {settings.min_retrieval_score:.2f}")
            reasons.append(f"weak retrieval ({detail})")
        if classified.confidence < settings.min_intake_confidence:
            reasons.append(f"low classifier confidence ({classified.confidence:.2f})")
        if injection_flags:
            reasons.append(f"injection-like content in alert: {', '.join(injection_flags)}")
        if action == Action.AUTO_REMEDIATE:
            if proposed.confidence < settings.min_decision_confidence:
                reasons.append(f"low decision confidence ({proposed.confidence:.2f} < {settings.min_decision_confidence:.2f})")
            if _is_crown_jewel(alert):
                reasons.append("crown-jewel asset: auto_remediate blocked")
        if reasons:
            action = Action.ESCALATE_TO_ANALYST

    # Only an eligible High or Critical proposal reaches the approval queue.
    if action == Action.AUTO_REMEDIATE and classified.severity in (Severity.CRITICAL, Severity.HIGH):
        requires_approval = True
        reasons.append(f"{classified.severity.value} severity: eligible auto_remediate requires human approval")

    return GuardrailResult(
        final_action=action,
        overridden=action != proposed.action,
        reasons=reasons,
        requires_human_approval=requires_approval,
    )
