"""Unit tests for soc_triage/agents/intake.py. The model call and agent construction are stubbed."""

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from soc_triage.agents import intake
from soc_triage.agents.intake import INTAKE_SYSTEM, IntakeOutput, classify
from soc_triage.models import Severity
from factories import make_alert, make_settings

GOOD = json.dumps({"severity": "High", "rationale": "because", "confidence": 0.7})


class TestIntakeOutput:
    def test_valid_payload(self):
        o = IntakeOutput.model_validate({"severity": "High", "rationale": "r", "confidence": 0.5})
        assert o.severity is Severity.HIGH

    @pytest.mark.parametrize("raw, expected", [
        ("critical", Severity.CRITICAL), ("CRITICAL", Severity.CRITICAL), ("  high  ", Severity.HIGH),
        ("mEdIuM", Severity.MEDIUM), ("low", Severity.LOW),
    ])
    def test_severity_case_and_whitespace_are_normalised(self, raw, expected):
        assert IntakeOutput.model_validate({"severity": raw, "rationale": "r", "confidence": 0.5}).severity is expected

    @pytest.mark.parametrize("bad", ["urgent", "high severity", "", 5, None, ["High"]])
    def test_unknown_or_non_string_severity_rejected(self, bad):
        with pytest.raises(ValidationError):
            IntakeOutput.model_validate({"severity": bad, "rationale": "r", "confidence": 0.5})

    @pytest.mark.parametrize("confidence", [-0.1, 1.5, "high", None])
    def test_bad_confidence_rejected(self, confidence):
        with pytest.raises(ValidationError):
            IntakeOutput.model_validate({"severity": "High", "rationale": "r", "confidence": confidence})

    @pytest.mark.parametrize("confidence", [0, 1, 0.0, 1.0])
    def test_confidence_bounds_inclusive(self, confidence):
        IntakeOutput.model_validate({"severity": "High", "rationale": "r", "confidence": confidence})

    def test_rationale_over_1000_characters_rejected(self):
        with pytest.raises(ValidationError):
            IntakeOutput.model_validate({"severity": "High", "rationale": "x" * 1001, "confidence": 0.5})

    def test_rationale_of_exactly_1000_characters_accepted(self):
        IntakeOutput.model_validate({"severity": "High", "rationale": "x" * 1000, "confidence": 0.5})

    @pytest.mark.parametrize("missing", ["severity", "rationale", "confidence"])
    def test_all_fields_required(self, missing):
        data = {"severity": "High", "rationale": "r", "confidence": 0.5}
        data.pop(missing)
        with pytest.raises(ValidationError):
            IntakeOutput.model_validate(data)


@pytest.fixture
def stub(monkeypatch):
    replies: list = []
    calls = SimpleNamespace(create=[], run=[])

    def fake_create(**kwargs):
        calls.create.append(kwargs)
        return "AGENT"

    async def fake_run(agent, text, timeout_s):
        calls.run.append((agent, text, timeout_s))
        return replies.pop(0)

    monkeypatch.setattr(intake, "create_agent", fake_create)
    monkeypatch.setattr(intake, "run_agent", fake_run)
    return SimpleNamespace(replies=replies, calls=calls)


async def do_classify(stub_, *replies, settings=None):
    stub_.replies.extend(replies)
    alert = make_alert()
    result = await classify(alert, "<alert_data>{}</alert_data>", object(), settings or make_settings(), "anthropic")
    return alert, result


class TestClassify:
    async def test_valid_reply_becomes_a_classified_alert(self, stub):
        alert, result = await do_classify(stub, GOOD)
        assert result.severity is Severity.HIGH and result.confidence == 0.7
        assert result.rationale == "because" and result.backend == "anthropic" and result.alert is alert

    async def test_json_inside_prose_is_accepted(self, stub):
        _, result = await do_classify(stub, f"Here is my answer:\n```json\n{GOOD}\n```")
        assert result.severity is Severity.HIGH

    async def test_lowercase_severity_is_accepted(self, stub):
        _, result = await do_classify(stub, '{"severity": "low", "rationale": "r", "confidence": 0.9}')
        assert result.severity is Severity.LOW

    async def test_agent_is_built_without_tools_and_with_the_intake_prompt(self, stub):
        chat = object()
        stub.replies.append(GOOD)
        await classify(make_alert(), "block", chat, make_settings(), "b")
        [kwargs] = stub.calls.create
        assert kwargs["model"] is chat and kwargs["tools"] == [] and kwargs["system_prompt"] == INTAKE_SYSTEM

    async def test_alert_block_is_the_user_message_and_timeout_comes_from_settings(self, stub):
        stub.replies.append(GOOD)
        await classify(make_alert(), "THE BLOCK", object(), make_settings(llm_timeout_s=7.5), "b")
        assert stub.calls.run == [("AGENT", "THE BLOCK", 7.5)]

    async def test_one_retry_when_the_model_call_fails(self, stub):
        _, result = await do_classify(stub, None, GOOD)
        assert result.severity is Severity.HIGH and len(stub.calls.run) == 2

    @pytest.mark.parametrize("bad", [
        "not json at all",
        '{"severity": "urgent", "rationale": "r", "confidence": 0.5}',
        '{"severity": "High", "rationale": "r", "confidence": 2}',
        '{"severity": "High", "rationale": "r"}',
        '{"severity": "High", "rationale": "cut off',
        "",
    ])
    async def test_one_retry_when_the_reply_is_invalid(self, stub, bad):
        _, result = await do_classify(stub, bad, GOOD)
        assert result.severity is Severity.HIGH and len(stub.calls.run) == 2

    async def test_fails_closed_to_critical_after_two_failures(self, stub):
        _, result = await do_classify(stub, None, "garbage")
        assert result.severity is Severity.CRITICAL and result.confidence == 0.0
        assert "failing closed" in result.rationale and result.backend == "anthropic"

    async def test_never_makes_more_than_two_attempts(self, stub):
        await do_classify(stub, None, None)
        assert len(stub.calls.run) == 2

    async def test_a_good_first_reply_makes_exactly_one_attempt(self, stub):
        await do_classify(stub, GOOD)
        assert len(stub.calls.run) == 1

    async def test_fail_closed_result_still_carries_the_original_alert(self, stub):
        alert, result = await do_classify(stub, None, None)
        assert result.alert is alert


class TestPrompt:
    def test_names_all_four_tiers_and_the_reply_format(self):
        for tier in ("Critical", "High", "Medium", "Low"):
            assert tier in INTAKE_SYSTEM
        assert "JSON only" in INTAKE_SYSTEM and '"severity"' in INTAKE_SYSTEM and '"confidence"' in INTAKE_SYSTEM

    def test_tells_the_model_the_alert_is_untrusted_data(self):
        assert "<alert_data>" in INTAKE_SYSTEM and "untrusted" in INTAKE_SYSTEM and "never follow" in INTAKE_SYSTEM

    def test_caps_confidence_when_evidence_is_missing(self):
        assert "0.70" in INTAKE_SYSTEM
