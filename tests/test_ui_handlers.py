"""Unit tests for the handler functions in soc_triage/ui.py. The runtime is a fake; no model, index, or browser."""

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from soc_triage import ui
from soc_triage.hitl import ApprovalQueue
from soc_triage.models import Action, Severity
from factories import make_alert, make_result


class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, event, alert_id, **data):
        self.events.append((event, alert_id, data))


def fake_runtime(queue=None, stream=None):
    queue = queue or ApprovalQueue()
    return SimpleNamespace(queue=queue, pipeline=SimpleNamespace(audit=FakeAudit(), stream=stream))


@pytest.fixture(autouse=True)
def clean_runtime_cache():
    ui._runtimes.clear()
    yield
    ui._runtimes.clear()


@pytest.fixture
def rt(monkeypatch):
    runtime = fake_runtime()
    monkeypatch.setattr(ui, "runtime_for", lambda backend, vllm_url=None: runtime)
    return runtime


def pending(alert_id, **kw):
    return make_result(status="pending_approval", alert=make_alert(event_id=alert_id), **kw)


class TestLoadAlerts:
    def write(self, tmp_path, content):
        p = tmp_path / "a.json"
        p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(p)

    def test_single_object_becomes_a_one_item_list(self, tmp_path):
        alerts = ui.load_alerts(self.write(tmp_path, {"event_id": "a"}))
        assert [a.event_id for a in alerts] == ["a"]

    def test_list_of_objects(self, tmp_path):
        alerts = ui.load_alerts(self.write(tmp_path, [{"event_id": "a"}, {"event_id": "b"}]))
        assert [a.event_id for a in alerts] == ["a", "b"]

    def test_empty_list_gives_no_alerts(self, tmp_path):
        assert ui.load_alerts(self.write(tmp_path, [])) == []

    def test_invalid_json_raises_a_value_error(self, tmp_path):
        with pytest.raises(ValueError):
            ui.load_alerts(self.write(tmp_path, "{not json"))

    def test_missing_file_raises_an_os_error(self, tmp_path):
        with pytest.raises(OSError):
            ui.load_alerts(str(tmp_path / "missing.json"))

    def test_item_without_event_id_raises_a_validation_error(self, tmp_path):
        with pytest.raises(ValidationError):
            ui.load_alerts(self.write(tmp_path, [{"description": "no id"}]))

    def test_one_bad_item_rejects_the_whole_file(self, tmp_path):
        with pytest.raises(ValidationError):
            ui.load_alerts(self.write(tmp_path, [{"event_id": "a"}, {"nope": 1}]))

    def test_a_json_scalar_is_rejected(self, tmp_path):
        with pytest.raises(ValidationError):
            ui.load_alerts(self.write(tmp_path, "5"))


class TestRuntimeFor:
    @pytest.fixture
    def builds(self, monkeypatch):
        calls = []

        def fake_build(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(id=len(calls))

        monkeypatch.setattr(ui, "build_runtime", fake_build)
        return calls

    @pytest.mark.parametrize("backend", ["", "mock", "ANTHROPIC", None])
    def test_unknown_backend_is_rejected_before_building_anything(self, builds, backend):
        with pytest.raises(ValueError):
            ui.runtime_for(backend)
        assert builds == []

    def test_runtime_is_built_once_per_backend_and_then_cached(self, builds):
        first = ui.runtime_for("anthropic")
        assert ui.runtime_for("anthropic") is first and len(builds) == 1

    def test_different_backends_get_different_runtimes(self, builds):
        assert ui.runtime_for("anthropic") is not ui.runtime_for("gpt")
        assert len(builds) == 2

    def test_vllm_runtimes_are_cached_per_endpoint(self, builds):
        a = ui.runtime_for("vllm", "https://a.ngrok-free.app")
        assert ui.runtime_for("vllm", "https://a.ngrok-free.app/v1") is a
        assert ui.runtime_for("vllm", "https://b.ngrok-free.app") is not a
        assert len(builds) == 2

    def test_vllm_with_a_bad_url_is_rejected(self, builds):
        with pytest.raises(ValueError):
            ui.runtime_for("vllm", "https://evil.com")
        assert builds == []

    def test_build_arguments_are_forwarded(self, builds):
        ui.runtime_for("vllm", "https://a.ngrok-free.app")
        assert builds == [{"backend": "vllm", "vllm_url": "https://a.ngrok-free.app"}]

    def test_a_failed_build_is_not_cached(self, monkeypatch):
        attempts = []

        def flaky(**kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("ANTHROPIC_API_KEY is not set")
            return "ok"

        monkeypatch.setattr(ui, "build_runtime", flaky)
        with pytest.raises(RuntimeError):
            ui.runtime_for("anthropic")
        assert ui.runtime_for("anthropic") == "ok"


class TestDemoChoices:
    @pytest.fixture
    def dirs(self, tmp_path, monkeypatch):
        recorded, synthetic = tmp_path / "otrf", tmp_path / "synth"
        recorded.mkdir(), synthetic.mkdir()
        monkeypatch.setattr(ui, "DEMO_DIR", recorded)
        monkeypatch.setattr(ui, "SYNTHETIC_DEMO_DIR", synthetic)
        return recorded, synthetic

    def test_empty_folders_give_no_choices(self, dirs):
        assert ui.demo_choices() == []

    def test_known_recorded_alerts_get_friendly_labels_and_path_values(self, dirs):
        recorded, _ = dirs
        (recorded / "mimikatz.json").write_text("{}")
        [(label, value)] = ui.demo_choices()
        assert label == "Mimikatz · Credential access" and value == str(recorded / "mimikatz.json")

    def test_unknown_recorded_alert_is_title_cased(self, dirs):
        recorded, _ = dirs
        (recorded / "my_new_case.json").write_text("{}")
        assert ui.demo_choices()[0][0] == "My New Case"

    def test_synthetic_alerts_are_labelled_synthetic(self, dirs):
        _, synthetic = dirs
        (synthetic / "low_browser_setting.json").write_text("{}")
        (synthetic / "other_case.json").write_text("{}")
        labels = [label for label, _ in ui.demo_choices()]
        assert "Browser setting cleanup (Synthetic)" in labels and "Other Case (Synthetic)" in labels

    def test_recorded_alerts_come_before_synthetic_ones_and_each_group_is_sorted(self, dirs):
        recorded, synthetic = dirs
        for name in ("wmi", "bitsadmin"):
            (recorded / f"{name}.json").write_text("{}")
        (synthetic / "zeta.json").write_text("{}")
        (synthetic / "alpha.json").write_text("{}")
        labels = [label for label, _ in ui.demo_choices()]
        assert labels[:2] == ["BITSAdmin download · Process activity", "WMI · Remote execution"]
        assert labels[2:] == ["Alpha (Synthetic)", "Zeta (Synthetic)"]

    def test_non_json_files_are_ignored(self, dirs):
        recorded, _ = dirs
        (recorded / "notes.txt").write_text("x")
        assert ui.demo_choices() == []


def first(gen):
    return next(gen)


class TestRunConsoleEarlyExits:
    def test_nothing_selected(self):
        out = first(ui.run_console(None, "anthropic"))
        assert "Choose an alert first" in out[0] and out[2] == []

    def test_a_demo_path_outside_the_allowed_folders_is_ignored(self, tmp_path):
        evil = tmp_path / "x.json"
        evil.write_text("{}")
        out = first(ui.run_console(None, "anthropic", demo_path=str(evil)))
        assert "Choose an alert first" in out[0]

    def test_missing_backend(self, tmp_path):
        f = tmp_path / "a.json"
        f.write_text('{"event_id": "a"}')
        assert "Choose a model" in first(ui.run_console(str(f), None))[0]

    def test_unreadable_file(self, tmp_path):
        assert "Could not read the alert" in first(ui.run_console(str(tmp_path / "missing.json"), "anthropic"))[0]

    def test_invalid_json_file(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{oops")
        assert "Could not read the alert" in first(ui.run_console(str(f), "anthropic"))[0]

    def test_model_configuration_error_is_shown_not_raised(self, tmp_path, monkeypatch):
        f = tmp_path / "a.json"
        f.write_text('{"event_id": "a"}')

        def boom(backend, vllm_url=None):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        monkeypatch.setattr(ui, "runtime_for", boom)
        frames = list(ui.run_console(str(f), "anthropic"))
        assert "Preparing triage" in frames[0][0]
        assert "Model unavailable" in frames[-1][0] and "ANTHROPIC_API_KEY" in frames[-1][0]

    def test_each_early_exit_yields_exactly_one_frame(self):
        assert len(list(ui.run_console(None, "anthropic"))) == 1

    def test_every_frame_has_the_five_expected_parts(self):
        assert len(first(ui.run_console(None, "anthropic"))) == 5


class TestRunConsoleStreaming:
    def stream_for(self, events):
        async def gen():
            for event in events:
                yield event

        return lambda alert: gen()

    def run(self, tmp_path, monkeypatch, events, alerts=({"event_id": "abcdef12-0000"},)):
        f = tmp_path / "a.json"
        f.write_text(json.dumps(list(alerts)))
        runtime = fake_runtime(stream=self.stream_for(events))
        monkeypatch.setattr(ui, "runtime_for", lambda backend, vllm_url=None: runtime)
        return list(ui.run_console(str(f), "anthropic")), runtime

    def terminal_events(self, status="escalated"):
        result = make_result(status=status, alert=make_alert(event_id="abcdef12-0000"))
        return [("start", "sanitize", None), ("done", "sanitize", {"injection_flags": []}),
                ("start", "escalate", None), ("done", "escalate", {"result": result})], result

    def test_yields_progress_frames_ending_with_the_summary_row(self, tmp_path, monkeypatch):
        events, result = self.terminal_events()
        frames, _ = self.run(tmp_path, monkeypatch, events)
        assert len(frames) > 2
        summary = frames[-1][2]
        assert len(summary) == 1 and summary[0][0] == "abcdef12"
        assert summary[0][2] == Severity.MEDIUM.value and summary[0][5] == "Queued for analyst review"

    def test_summary_rows_use_title_cased_actions(self, tmp_path, monkeypatch):
        events, _ = self.terminal_events()
        row = self.run(tmp_path, monkeypatch, events)[0][-1][2][0]
        assert row[3] == "Escalate To Analyst" and row[4] == "Escalate To Analyst"

    def test_findings_panel_is_the_pending_placeholder_until_an_alert_finishes(self, tmp_path, monkeypatch):
        events, _ = self.terminal_events()
        frames, _ = self.run(tmp_path, monkeypatch, events)
        assert "Assessment pending" in frames[0][1] and "Assessment pending" not in frames[-1][1]

    def test_a_started_stage_is_shown_as_active_then_done(self, tmp_path, monkeypatch):
        events, _ = self.terminal_events()
        frames, _ = self.run(tmp_path, monkeypatch, events)
        timelines = [f[0] for f in frames]
        assert any('class="soc-stage active"' in t for t in timelines)
        assert 'class="soc-stage done"' in timelines[-1]

    def test_route_nodes_all_map_to_the_single_route_stage(self, tmp_path, monkeypatch):
        events, _ = self.terminal_events()
        frames, _ = self.run(tmp_path, monkeypatch, events)
        assert "Queued for analyst review" in frames[-1][0]

    def test_a_stream_without_a_route_node_produces_no_summary_row(self, tmp_path, monkeypatch):
        events = [("start", "sanitize", None), ("done", "sanitize", {"injection_flags": []})]
        frames, _ = self.run(tmp_path, monkeypatch, events)
        assert frames[-1][2] == []

    def test_multiple_alerts_are_processed_in_order(self, tmp_path, monkeypatch):
        events, _ = self.terminal_events()
        alerts = [{"event_id": "abcdef12-0000"}, {"event_id": "abcdef12-0000"}]
        frames, _ = self.run(tmp_path, monkeypatch, events, alerts=alerts)
        assert len(frames[-1][2]) == 2 and frames[-1][0].count("soc-timeline-run") == 2

    def test_an_empty_alert_list_yields_a_frame_and_finishes(self, tmp_path, monkeypatch):
        frames, _ = self.run(tmp_path, monkeypatch, [], alerts=())
        assert frames[-1][2] == []


class TestReviewCard:
    def test_approval_card_shows_confidence_and_approval_route(self):
        html = ui._review_card(pending("abcdef123456"), approval=True)
        assert "Alert abcdef12" in html and "Decision confidence 90%" in html and "Approval required" in html

    def test_review_card_shows_the_final_action_and_no_confidence(self):
        html = ui._review_card(make_result(status="escalated", alert=make_alert(event_id="abcdef123456")), approval=False)
        assert "Escalate To Analyst" in html and "Decision confidence" not in html

    def test_proposed_action_is_humanised(self):
        html = ui._review_card(pending("a", action=Action.AUTO_REMEDIATE), approval=True)
        assert "Proposed: Auto Remediate" in html

    def test_reasons_are_listed_only_when_present(self):
        from factories import make_guardrail
        with_checks = ui._review_card(pending("a", guardrail=make_guardrail(reasons=["why"])), approval=True)
        without = ui._review_card(pending("a"), approval=True)
        assert "<li>why</li>" in with_checks and "Routing checks" not in without

    def test_reasoning_and_reasons_are_escaped(self):
        from factories import make_decision, make_guardrail
        bad = "<script>x</script>"
        html = ui._review_card(pending("a", decision=make_decision(reasoning=bad),
                                       guardrail=make_guardrail(reasons=[bad])), approval=True)
        assert "<script>" not in html


class TestQueueRows:
    @pytest.mark.parametrize("fn", [ui.queue_rows, ui.review_rows])
    @pytest.mark.parametrize("backend", ["", None, "mock"])
    def test_invalid_backend_returns_empty_string(self, fn, backend):
        assert fn(backend) == ""

    @pytest.mark.parametrize("fn", [ui.queue_rows, ui.review_rows])
    @pytest.mark.parametrize("exc", [RuntimeError("x"), ValueError("y")])
    def test_runtime_errors_return_empty_string(self, fn, exc, monkeypatch):
        def boom(backend, vllm_url=None):
            raise exc

        monkeypatch.setattr(ui, "runtime_for", boom)
        assert fn("anthropic") == ""

    def test_empty_approval_queue_message(self, rt):
        assert "No alerts awaiting remediation approval." in ui.queue_rows("anthropic")

    def test_empty_review_queue_message(self, rt):
        assert "No alerts awaiting analyst review." in ui.review_rows("anthropic")

    def test_pending_alerts_render_one_card_each(self, rt):
        rt.queue.enqueue(pending("aaaaaaaa1"))
        rt.queue.enqueue(pending("bbbbbbbb2"))
        assert ui.queue_rows("anthropic").count("soc-review-card") == 2

    def test_review_alerts_render_one_card_each(self, rt):
        rt.queue.add_review(make_result(alert=make_alert(event_id="aaaaaaaa1")))
        assert ui.review_rows("anthropic").count("soc-review-card") == 1

    def test_the_two_views_do_not_show_each_others_alerts(self, rt):
        rt.queue.enqueue(pending("aaaaaaaa1"))
        assert "No alerts awaiting analyst review." in ui.review_rows("anthropic")


class TestDecideQueue:
    def test_invalid_backend(self):
        assert ui.decide_queue("a", "", True, "me") == ("Choose an LLM backend first.", "")

    def test_runtime_error_is_reported(self, monkeypatch):
        def boom(backend, vllm_url=None):
            raise RuntimeError("no key")

        monkeypatch.setattr(ui, "runtime_for", boom)
        assert ui.decide_queue("a", "anthropic", True, "me")[0] == "Model unavailable: no key"

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_id_asks_for_one(self, rt, blank):
        assert "Enter a full alert id" in ui.decide_queue(blank, "anthropic", True, "me")[0]

    def test_no_match(self, rt):
        assert "No single pending alert matches" in ui.decide_queue("zzz", "anthropic", True, "me")[0]

    def test_ambiguous_prefix_matches_nothing(self, rt):
        rt.queue.enqueue(pending("abc111"))
        rt.queue.enqueue(pending("abc222"))
        message, _ = ui.decide_queue("abc", "anthropic", True, "me")
        assert "No single pending alert matches" in message and len(rt.queue.pending()) == 2

    def test_unique_prefix_approves_and_audits(self, rt):
        rt.queue.enqueue(pending("abc111"))
        rt.queue.enqueue(pending("xyz999"))
        message, _ = ui.decide_queue("abc", "anthropic", True, "dana")
        assert "approved_by:dana" in message and [r.alert_id for r in rt.queue.pending()] == ["xyz999"]
        assert rt.pipeline.audit.events == [("remediation_approved", "abc111", {"approver": "dana"})]

    def test_reject_audits_a_rejection(self, rt):
        rt.queue.enqueue(pending("abc111"))
        message, _ = ui.decide_queue("abc111", "anthropic", False, "dana")
        assert "rejected_by:dana" in message
        assert rt.pipeline.audit.events[0][0] == "remediation_rejected"

    def test_blank_approver_defaults_to_analyst(self, rt):
        rt.queue.enqueue(pending("abc111"))
        assert "approved_by:analyst" in ui.decide_queue("abc111", "anthropic", True, "")[0]

    def test_id_whitespace_is_trimmed(self, rt):
        rt.queue.enqueue(pending("abc111"))
        assert "approved_by" in ui.decide_queue("  abc111  ", "anthropic", True, "me")[0]

    def test_returned_view_reflects_the_new_queue_state(self, rt):
        rt.queue.enqueue(pending("abc111"))
        _, view = ui.decide_queue("abc111", "anthropic", True, "me")
        assert "No alerts awaiting remediation approval." in view

    def test_nothing_is_audited_when_nothing_was_decided(self, rt):
        ui.decide_queue("missing", "anthropic", True, "me")
        assert rt.pipeline.audit.events == []


class TestAcknowledgeReview:
    def review(self, alert_id):
        return make_result(status="escalated", alert=make_alert(event_id=alert_id))

    def test_invalid_backend(self):
        assert ui.acknowledge_review("a", "", "me") == ("Choose a model first.", "")

    def test_blank_id_asks_for_one(self, rt):
        assert "Enter an alert ID" in ui.acknowledge_review(" ", "anthropic", "me")[0]

    def test_no_match(self, rt):
        assert "No single alert matches" in ui.acknowledge_review("zzz", "anthropic", "me")[0]

    def test_ambiguous_prefix_matches_nothing(self, rt):
        rt.queue.add_review(self.review("abc111"))
        rt.queue.add_review(self.review("abc222"))
        assert "No single alert matches" in ui.acknowledge_review("abc", "anthropic", "me")[0]
        assert len(rt.queue.review()) == 2

    def test_unique_prefix_acknowledges_and_audits(self, rt):
        rt.queue.add_review(self.review("abc111"))
        message, _ = ui.acknowledge_review("abc", "anthropic", "sam")
        assert "acknowledged_by:sam" in message and rt.queue.review() == []
        assert rt.pipeline.audit.events == [("analyst_acknowledged", "abc111", {"analyst": "sam"})]

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_analyst_name_defaults_to_analyst(self, rt, blank):
        rt.queue.add_review(self.review("abc111"))
        assert "acknowledged_by:analyst" in ui.acknowledge_review("abc111", "anthropic", blank)[0]

    def test_analyst_name_is_trimmed(self, rt):
        rt.queue.add_review(self.review("abc111"))
        assert "acknowledged_by:sam" in ui.acknowledge_review("abc111", "anthropic", "  sam ")[0]

    def test_only_the_review_queue_is_searched(self, rt):
        rt.queue.enqueue(pending("abc111"))
        assert "No single alert matches" in ui.acknowledge_review("abc111", "anthropic", "sam")[0]
