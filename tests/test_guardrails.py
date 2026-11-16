"""Unit tests for soc_triage/guardrails.py"""

import pytest

from soc_triage.guardrails import _is_crown_jewel, apply_guardrails
from soc_triage.models import Action, Severity
from factories import (
    make_alert,
    make_classified,
    make_decision,
    make_enrichment,
    make_incident,
    make_settings,
)

SUPPRESS = Action.SUPPRESS_AS_FALSE_POSITIVE
AUTO = Action.AUTO_REMEDIATE
ESCALATE = Action.ESCALATE_TO_ANALYST


def run(action, *, severity=Severity.LOW, intake_conf=0.9, decision_conf=0.9, weak=False, max_score=0.9,
        incidents=None, flags=None, alert=None, settings=None):
    alert = alert or make_alert()
    return apply_guardrails(
        alert=alert,
        classified=make_classified(severity, intake_conf, alert),
        enrichment=make_enrichment(max_score=max_score, weak=weak, incidents=incidents),
        proposed=make_decision(action, decision_conf),
        injection_flags=flags or [],
        settings=settings or make_settings(),
    )


class TestIsCrownJewel:
    @pytest.mark.parametrize("value, expected", [
        ("crown-jewel", True), ("Crown-Jewel", True), ("CROWN-JEWEL", True),
        ("server", False), ("workstation", False), ("", False), (None, False), ("crown jewel", False),
    ])
    def test_values(self, value, expected):
        assert _is_crown_jewel(make_alert(asset_criticality=value)) is expected


class TestEscalateProposalIsNeverChanged:
    @pytest.mark.parametrize("severity", list(Severity))
    def test_escalate_passes_through_untouched(self, severity):
        g = run(ESCALATE, severity=severity)
        assert g.final_action == ESCALATE and g.overridden is False and g.reasons == []
        assert g.requires_human_approval is False

    def test_escalate_is_untouched_even_with_every_risk_signal(self):
        g = run(ESCALATE, weak=True, intake_conf=0.0, flags=["role_override"], incidents=[])
        assert g.final_action == ESCALATE and g.reasons == [] and g.overridden is False


class TestSuppressRules:
    @pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
    def test_high_and_critical_are_never_suppressed(self, severity):
        g = run(SUPPRESS, severity=severity)
        assert g.final_action == ESCALATE and g.overridden is True
        assert g.reasons == [f"{severity.value} alerts are never suppressed"]
        assert g.requires_human_approval is False

    def test_suppressing_critical_with_other_problems_reports_only_the_first_rule(self):
        # Once escalated by rule 1 the evidence block no longer runs.
        g = run(SUPPRESS, severity=Severity.CRITICAL, weak=True, flags=["role_override"])
        assert g.reasons == ["Critical alerts are never suppressed"]

    @pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW])
    def test_clean_medium_or_low_suppression_is_allowed(self, severity):
        g = run(SUPPRESS, severity=severity)
        assert g.final_action == SUPPRESS and g.overridden is False and g.reasons == []

    def test_weak_retrieval_blocks_suppression(self):
        g = run(SUPPRESS, weak=True, max_score=0.1)
        assert g.final_action == ESCALATE and g.overridden is True
        assert any(r.startswith("weak retrieval") for r in g.reasons)

    def test_weak_retrieval_reason_says_no_same_event_type_when_types_differ(self):
        incidents = [make_incident(event_type="network_connection")]
        g = run(SUPPRESS, weak=True, incidents=incidents)
        assert g.reasons[0] == "weak retrieval (no same-event-type match)"

    def test_weak_retrieval_reason_includes_score_and_threshold_when_types_match(self):
        g = run(SUPPRESS, weak=True, max_score=0.2, incidents=[make_incident(score=0.2)])
        assert g.reasons[0] == "weak retrieval (best score 0.20 below 0.35)"

    def test_weak_retrieval_with_no_incidents_reports_no_same_type(self):
        g = run(SUPPRESS, weak=True, max_score=0.0, incidents=[])
        assert "no same-event-type match" in g.reasons[0]

    def test_intake_confidence_exactly_at_threshold_is_accepted(self):
        assert run(SUPPRESS, intake_conf=0.6).final_action == SUPPRESS

    def test_intake_confidence_just_below_threshold_blocks(self):
        g = run(SUPPRESS, intake_conf=0.59)
        assert g.final_action == ESCALATE and g.reasons == ["low classifier confidence (0.59)"]

    def test_threshold_comes_from_settings(self):
        strict = make_settings(min_intake_confidence=0.95)
        assert run(SUPPRESS, intake_conf=0.9, settings=strict).final_action == ESCALATE

    def test_any_injection_flag_blocks_suppression_and_lists_flags(self):
        g = run(SUPPRESS, flags=["action_directive", "role_override"])
        assert g.final_action == ESCALATE
        assert g.reasons == ["injection-like content in alert: action_directive, role_override"]

    def test_decision_confidence_is_not_required_for_suppression(self):
        assert run(SUPPRESS, decision_conf=0.0).final_action == SUPPRESS

    def test_reasons_accumulate_in_rule_order(self):
        g = run(SUPPRESS, weak=True, max_score=0.1, intake_conf=0.1, flags=["role_override"])
        assert [r.split(" ")[0] for r in g.reasons] == ["weak", "low", "injection-like"]


class TestAutoRemediateRules:
    def test_clean_low_severity_proposal_is_allowed_without_approval(self):
        g = run(AUTO, severity=Severity.LOW)
        assert g.final_action == AUTO and g.overridden is False and g.reasons == []
        assert g.requires_human_approval is False

    def test_medium_severity_proposal_is_allowed_without_approval(self):
        g = run(AUTO, severity=Severity.MEDIUM)
        assert g.final_action == AUTO and g.requires_human_approval is False

    @pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
    def test_eligible_high_or_critical_proposal_requires_human_approval(self, severity):
        g = run(AUTO, severity=severity)
        assert g.final_action == AUTO and g.requires_human_approval is True
        assert g.reasons == [f"{severity.value} severity: eligible auto_remediate requires human approval"]
        assert g.overridden is False

    @pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
    def test_ineligible_high_or_critical_proposal_is_escalated_not_queued_for_approval(self, severity):
        g = run(AUTO, severity=severity, decision_conf=0.1)
        assert g.final_action == ESCALATE and g.requires_human_approval is False and g.overridden is True

    def test_decision_confidence_exactly_at_threshold_is_accepted(self):
        assert run(AUTO, decision_conf=0.8).final_action == AUTO

    def test_decision_confidence_just_below_threshold_blocks(self):
        g = run(AUTO, decision_conf=0.79)
        assert g.final_action == ESCALATE
        assert g.reasons == ["low decision confidence (0.79 < 0.80)"]

    def test_decision_confidence_threshold_comes_from_settings(self):
        assert run(AUTO, decision_conf=0.5, settings=make_settings(min_decision_confidence=0.4)).final_action == AUTO

    @pytest.mark.parametrize("value", ["crown-jewel", "Crown-Jewel"])
    def test_crown_jewel_assets_are_never_auto_remediated(self, value):
        g = run(AUTO, alert=make_alert(asset_criticality=value))
        assert g.final_action == ESCALATE and "crown-jewel asset: auto_remediate blocked" in g.reasons

    @pytest.mark.parametrize("value", [None, "server", "workstation"])
    def test_other_asset_tiers_are_not_blocked(self, value):
        assert run(AUTO, alert=make_alert(asset_criticality=value)).final_action == AUTO

    def test_weak_retrieval_blocks_auto_remediation(self):
        assert run(AUTO, weak=True).final_action == ESCALATE

    def test_low_intake_confidence_blocks_auto_remediation(self):
        assert run(AUTO, intake_conf=0.2).final_action == ESCALATE

    def test_injection_flags_block_auto_remediation(self):
        assert run(AUTO, flags=["benign_directive"]).final_action == ESCALATE

    def test_all_failures_are_reported_together(self):
        g = run(AUTO, weak=True, max_score=0.1, intake_conf=0.1, decision_conf=0.1, flags=["role_override"],
                alert=make_alert(asset_criticality="crown-jewel"))
        assert len(g.reasons) == 5 and g.final_action == ESCALATE

    def test_decision_confidence_check_applies_only_to_auto_remediation(self):
        # A suppress proposal with a poor decision confidence has no decision-confidence reason.
        g = run(SUPPRESS, decision_conf=0.0, weak=True, max_score=0.1)
        assert not any("decision confidence" in r for r in g.reasons)


class TestOverriddenFlag:
    @pytest.mark.parametrize("action, kwargs, expected", [
        (ESCALATE, {}, False),
        (SUPPRESS, {}, False),
        (SUPPRESS, {"severity": Severity.HIGH}, True),
        (AUTO, {}, False),
        (AUTO, {"decision_conf": 0.0}, True),
    ])
    def test_overridden_is_true_exactly_when_the_action_changed(self, action, kwargs, expected):
        assert run(action, **kwargs).overridden is expected
