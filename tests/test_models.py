"""Unit tests for soc_triage/models.py"""

import pytest
from pydantic import ValidationError

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


class TestEnums:
    def test_severity_values_are_the_four_tiers(self):
        assert {s.value for s in Severity} == {"Critical", "High", "Medium", "Low"}

    def test_action_values_are_the_three_actions(self):
        assert {a.value for a in Action} == {"auto_remediate", "escalate_to_analyst", "suppress_as_false_positive"}

    def test_enums_compare_equal_to_their_string_values(self):
        assert Severity.HIGH == "High"
        assert Action.AUTO_REMEDIATE == "auto_remediate"

    @pytest.mark.parametrize("bad", ["critical", "CRITICAL", "Urgent", "", None])
    def test_severity_rejects_anything_but_exact_value(self, bad):
        with pytest.raises(ValueError):
            Severity(bad)

    @pytest.mark.parametrize("bad", ["AUTO_REMEDIATE", "delete_host", "", None])
    def test_action_rejects_unknown_values(self, bad):
        with pytest.raises(ValueError):
            Action(bad)


class TestRawAlert:
    def test_event_id_is_required(self):
        with pytest.raises(ValidationError):
            RawAlert.model_validate({})

    def test_event_id_must_be_a_string(self):
        with pytest.raises(ValidationError):
            RawAlert.model_validate({"event_id": 5})

    def test_minimal_alert_defaults(self):
        a = RawAlert(event_id="x")
        assert a.description == ""
        for name in ("timestamp", "event_type", "source", "severity", "raw_log", "action", "alert_type", "category",
                     "user", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_duration_us",
                     "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "process_id", "parent_process",
                     "cloud_service", "asset_criticality"):
            assert getattr(a, name) is None, name

    def test_extra_fields_are_kept(self):
        a = RawAlert.model_validate({"event_id": "x", "vendor_field": "keep me"})
        assert a.model_extra == {"vendor_field": "keep me"}

    def test_timestamp_parses_iso_string(self):
        a = RawAlert(event_id="x", timestamp="2026-01-02T03:04:05Z")
        assert (a.timestamp.year, a.timestamp.month, a.timestamp.hour) == (2026, 1, 3)

    def test_invalid_timestamp_is_rejected(self):
        with pytest.raises(ValidationError):
            RawAlert(event_id="x", timestamp="yesterday-ish")

    def test_numeric_strings_are_coerced_for_int_fields(self):
        assert RawAlert(event_id="x", src_port="443").src_port == 443

    @pytest.mark.parametrize("field", ["src_port", "dst_port", "process_id", "fwd_bytes", "bwd_packets"])
    def test_non_numeric_value_for_int_field_is_rejected(self, field):
        with pytest.raises(ValidationError):
            RawAlert.model_validate({"event_id": "x", field: "not-a-number"})

    def test_zero_is_a_valid_port_and_stays_zero(self):
        assert RawAlert(event_id="x", dst_port=0).dst_port == 0


class TestClassifiedAlert:
    def _alert(self):
        return RawAlert(event_id="x")

    @pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
    def test_confidence_bounds_inclusive(self, confidence):
        c = ClassifiedAlert(alert=self._alert(), severity=Severity.LOW, rationale="r", confidence=confidence)
        assert c.confidence == confidence

    @pytest.mark.parametrize("confidence", [-0.01, 1.01, 5, -1])
    def test_confidence_out_of_range_rejected(self, confidence):
        with pytest.raises(ValidationError):
            ClassifiedAlert(alert=self._alert(), severity=Severity.LOW, rationale="r", confidence=confidence)

    def test_severity_must_be_a_valid_tier(self):
        with pytest.raises(ValidationError):
            ClassifiedAlert(alert=self._alert(), severity="high", rationale="r", confidence=0.5)

    def test_backend_defaults_to_unknown(self):
        c = ClassifiedAlert(alert=self._alert(), severity="High", rationale="r", confidence=0.5)
        assert c.backend == "unknown"

    @pytest.mark.parametrize("missing", ["alert", "severity", "rationale", "confidence"])
    def test_required_fields(self, missing):
        data = {"alert": self._alert(), "severity": "High", "rationale": "r", "confidence": 0.5}
        data.pop(missing)
        with pytest.raises(ValidationError):
            ClassifiedAlert.model_validate(data)


class TestRetrievedIncident:
    def test_defaults(self):
        i = RetrievedIncident(incident_id="a", summary="s", score=0.5)
        assert i.event_type is None and i.metadata == {}

    def test_metadata_default_is_not_shared_between_instances(self):
        a = RetrievedIncident(incident_id="a", summary="s", score=0.5)
        b = RetrievedIncident(incident_id="b", summary="s", score=0.5)
        a.metadata["k"] = 1
        assert b.metadata == {}

    def test_score_is_required_and_numeric(self):
        with pytest.raises(ValidationError):
            RetrievedIncident(incident_id="a", summary="s")
        with pytest.raises(ValidationError):
            RetrievedIncident(incident_id="a", summary="s", score="high")

    def test_negative_scores_are_allowed(self):
        # Cosine similarity can be negative; the model must not reject it.
        assert RetrievedIncident(incident_id="a", summary="s", score=-0.2).score == -0.2


class TestEnrichment:
    def test_all_fields_required(self):
        with pytest.raises(ValidationError):
            Enrichment(incidents=[], max_score=0.0)
        with pytest.raises(ValidationError):
            Enrichment(incidents=[], weak_retrieval=True)

    def test_empty_incident_list_is_valid(self):
        e = Enrichment(incidents=[], max_score=0.0, weak_retrieval=True)
        assert e.incidents == []


class TestDecision:
    def test_confidence_defaults_to_zero(self):
        assert Decision(action=Action.ESCALATE_TO_ANALYST, reasoning="r").confidence == 0.0

    @pytest.mark.parametrize("confidence", [-0.1, 1.1])
    def test_confidence_bounds(self, confidence):
        with pytest.raises(ValidationError):
            Decision(action=Action.ESCALATE_TO_ANALYST, reasoning="r", confidence=confidence)

    def test_action_must_be_valid(self):
        with pytest.raises(ValidationError):
            Decision(action="nuke", reasoning="r")

    def test_cited_ids_default_is_not_shared(self):
        a = Decision(action=Action.ESCALATE_TO_ANALYST, reasoning="r")
        b = Decision(action=Action.ESCALATE_TO_ANALYST, reasoning="r")
        a.cited_incident_ids.append("x")
        assert b.cited_incident_ids == []

    def test_reasoning_is_required(self):
        with pytest.raises(ValidationError):
            Decision(action=Action.ESCALATE_TO_ANALYST)


class TestGuardrailResult:
    def test_defaults(self):
        g = GuardrailResult(final_action=Action.ESCALATE_TO_ANALYST)
        assert g.overridden is False and g.reasons == [] and g.requires_human_approval is False

    def test_final_action_is_required(self):
        with pytest.raises(ValidationError):
            GuardrailResult()


class TestTriageResult:
    def _kwargs(self):
        alert = RawAlert(event_id="abc")
        return dict(
            alert_id="abc",
            classification=ClassifiedAlert(alert=alert, severity=Severity.LOW, rationale="r", confidence=0.5),
            enrichment=Enrichment(incidents=[], max_score=0.0, weak_retrieval=True),
            proposed=Decision(action=Action.ESCALATE_TO_ANALYST, reasoning="r"),
            guardrail=GuardrailResult(final_action=Action.ESCALATE_TO_ANALYST),
            status="escalated",
        )

    def test_builds_with_all_fields(self):
        assert TriageResult(**self._kwargs()).status == "escalated"

    @pytest.mark.parametrize("missing", ["alert_id", "classification", "enrichment", "proposed", "guardrail", "status"])
    def test_every_field_is_required(self, missing):
        kwargs = self._kwargs()
        kwargs.pop(missing)
        with pytest.raises(ValidationError):
            TriageResult(**kwargs)

    def test_model_copy_update_does_not_mutate_original(self):
        original = TriageResult(**self._kwargs())
        copy = original.model_copy(update={"status": "approved_by:me"})
        assert original.status == "escalated" and copy.status == "approved_by:me"
