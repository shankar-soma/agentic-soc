"""Unit tests for soc_triage/ui_present.py"""

import pytest

from soc_triage import ui_present as p
from soc_triage.models import Action, Severity
from factories import (
    make_alert,
    make_classified,
    make_decision,
    make_enrichment,
    make_guardrail,
    make_incident,
    make_result,
)

XSS = "<script>alert(1)</script>"


class TestConstants:
    def test_stage_keys_are_unique_ordered_and_end_with_route(self):
        keys = [k for k, _, _ in p.STAGES]
        assert keys == ["sanitize", "intake", "enrich", "decide", "apply_guardrails", "route"]
        assert len(set(keys)) == len(keys)

    def test_route_nodes_match_the_graph_terminal_steps(self):
        assert p.ROUTE_NODES == {"simulate_remediation", "suppress", "escalate", "hitl"}

    def test_route_labels_cover_every_status_the_graph_can_produce(self):
        assert set(p.ROUTE_LABELS) == {"pending_approval", "escalated", "suppressed", "simulated_remediation"}


class TestEsc:
    @pytest.mark.parametrize("raw, expected", [
        ("<b>", "&lt;b&gt;"), ("a & b", "a &amp; b"), ('say "hi"', "say &quot;hi&quot;"), ("it's", "it&#x27;s"),
        (5, "5"), (None, "None"),
    ])
    def test_escapes_html_and_coerces_to_string(self, raw, expected):
        assert p.esc(raw) == expected


class TestActivity:
    @pytest.mark.parametrize("event, label", [
        ("process_create", "Process started"), ("network_connection", "Network connection"),
        ("file_create", "File created"),
    ])
    def test_known_event_types_have_friendly_labels(self, event, label):
        assert p.activity(event) == label

    @pytest.mark.parametrize("event, label", [
        ("process_access", "Process access"), ("remote_thread_create", "Remote thread created"),
        ("dns_query", "DNS lookup"), ("registry_change", "Registry change"),
        ("registry_value_change", "Registry value changed"), ("logon_success", "Sign-in succeeded"),
        ("logon_failure", "Sign-in failed"), ("service_installed", "Service installed"),
        ("audit_log_cleared", "Audit log cleared"), ("share_access", "Network share access"),
    ])
    def test_every_ingested_event_type_has_a_friendly_label(self, event, label):
        assert p.activity(event) == label

    def test_every_event_type_the_ingest_can_produce_has_a_label(self):
        # Guards against the two modules drifting apart again (this is how three labels went unused before).
        from soc_triage.rag.ingest_otrf import ACTIVITY
        missing = set(ACTIVITY.values()) - set(p.ACTIVITY_LABELS)
        assert not missing, f"event types with no friendly label: {sorted(missing)}"

    def test_no_label_is_defined_for_an_event_type_that_is_never_produced(self):
        from soc_triage.rag.ingest_otrf import ACTIVITY
        assert set(p.ACTIVITY_LABELS) <= set(ACTIVITY.values())

    def test_unknown_event_type_is_humanised(self):
        assert p.activity("some_new_event_kind") == "Some new event kind"

    @pytest.mark.parametrize("empty", [None, ""])
    def test_missing_event_type_gets_a_generic_label(self, empty):
        assert p.activity(empty) == "Security event"


class TestProgram:
    @pytest.mark.parametrize("text, expected", [
        ("process_create; Image=C:\\Windows\\System32\\cmd.exe; CommandLine=x", "cmd.exe"),
        ("Image=C:\\a\\b.exe", "b.exe"),
        ("x | Image=C:\\a\\b.exe | y", "b.exe"),
        ("process_create;   Image=C:/Users/me/tool.exe", "tool.exe"),
        ("image=C:\\a\\Lower.exe", "Lower.exe"),
        ("Image= C:\\a\\spaced.exe ;", "spaced.exe"),
    ])
    def test_extracts_the_executable_name(self, text, expected):
        assert p.program(text) == expected

    @pytest.mark.parametrize("text", [
        "", "no image here", "ParentImage=C:\\p.exe", "SourceImage=C:\\s.exe; TargetImage=C:\\t.exe",
        "Image=", "Image=;", "Image= ;",
    ])
    def test_returns_none_when_there_is_no_usable_image(self, text):
        assert p.program(text) is None

    def test_prefers_the_image_field_over_parent_image(self):
        assert p.program("ParentImage=C:\\p.exe; Image=C:\\child.exe") == "child.exe"

    def test_very_long_names_are_cut_to_70_characters(self):
        assert len(p.program("Image=C:\\" + "a" * 200 + ".exe")) == 70


class TestAlertTitle:
    def test_program_and_activity(self):
        alert = make_alert(event_type="process_create", description="Image=C:\\x\\bitsadmin.exe")
        assert p.alert_title(alert) == "bitsadmin.exe - Process started"

    def test_activity_only_when_no_program(self):
        assert p.alert_title(make_alert(event_type="dns_query", description="QueryName=x")) == "DNS lookup"

    def test_no_event_type_and_no_program(self):
        assert p.alert_title(make_alert(event_type=None, description="")) == "Security event"


class TestPanels:
    def test_empty_panel_escapes_both_texts(self):
        html = p.empty_panel(XSS, XSS)
        assert "<script>" not in html and "&lt;script&gt;" in html

    def test_empty_panel_contains_title_and_description(self):
        html = p.empty_panel("Title here", "Description here")
        assert "Title here" in html and "Description here" in html

    def test_preparing_panel_mentions_the_first_run_delay(self):
        assert "first run" in p.preparing_panel()


class TestTimeline:
    def test_no_runs_shows_the_empty_state(self):
        assert "Ready for an alert" in p.timeline([])

    def test_a_run_with_no_progress_shows_every_stage_waiting(self):
        html = p.timeline([{"alert": make_alert(), "stages": {}}])
        assert html.count("Waiting") == len(p.STAGES) and "✓" not in html

    def test_active_stage_shows_its_in_progress_copy(self):
        html = p.timeline([{"alert": make_alert(), "stages": {"intake": ("active", "")}}])
        assert "Calling the intake agent…" in html and 'class="soc-stage active"' in html

    def test_done_stage_shows_its_note_and_a_checkmark(self):
        html = p.timeline([{"alert": make_alert(), "stages": {"sanitize": ("done", "Input checked")}}])
        assert "Input checked" in html and "✓" in html and 'class="soc-stage done"' in html

    def test_stage_notes_are_escaped(self):
        html = p.timeline([{"alert": make_alert(), "stages": {"sanitize": ("done", XSS)}}])
        assert "<script>" not in html

    def test_alert_title_and_short_id_are_shown_and_escaped(self):
        alert = make_alert(event_id="abcdefghij-long-id", description="Image=C:\\a\\" + XSS + ".exe")
        html = p.timeline([{"alert": alert, "stages": {}}])
        assert "Alert abcdefgh" in html and "abcdefghij" not in html and "<script>" not in html

    def test_one_card_per_run(self):
        runs = [{"alert": make_alert(event_id=f"id{i}-xxxxxx"), "stages": {}} for i in range(3)]
        assert p.timeline(runs).count("soc-timeline-run") == 3

    def test_stages_appear_in_pipeline_order(self):
        html = p.timeline([{"alert": make_alert(), "stages": {}}])
        positions = [html.index(label) for _, label, _ in p.STAGES]
        assert positions == sorted(positions)


class TestStageNote:
    def test_sanitize_without_flags(self):
        assert p.stage_note("sanitize", {"injection_flags": []}) == "Input checked and prepared"

    def test_sanitize_with_flags(self):
        assert p.stage_note("sanitize", {"injection_flags": ["role_override"]}) == "Suspicious instructions flagged"

    def test_sanitize_with_missing_key(self):
        assert p.stage_note("sanitize", {}) == "Input checked and prepared"

    def test_intake_shows_severity_and_whole_percent_confidence(self):
        out = {"classified": make_classified(Severity.HIGH, 0.7)}
        assert p.stage_note("intake", out) == "High severity · 70% confidence"

    def test_enrich_shows_count_and_three_decimal_similarity(self):
        out = {"enrichment": make_enrichment(max_score=0.91234)}
        assert p.stage_note("enrich", out) == "1 related events found · best similarity 0.912"

    def test_enrich_with_nothing_found(self):
        out = {"enrichment": make_enrichment(max_score=0.0, weak=True, incidents=[])}
        assert p.stage_note("enrich", out) == "0 related events found · best similarity 0.000"

    def test_decide_humanises_the_action(self):
        out = {"proposed": make_decision(Action.SUPPRESS_AS_FALSE_POSITIVE, 0.85)}
        assert p.stage_note("decide", out) == "Proposed suppress as false positive · 85% confidence"

    def test_guardrail_requiring_approval(self):
        out = {"guardrail": make_guardrail(Action.AUTO_REMEDIATE, requires_human_approval=True)}
        assert p.stage_note("apply_guardrails", out) == "Safety checks passed; human approval required"

    def test_guardrail_that_changed_the_proposal(self):
        out = {"guardrail": make_guardrail(overridden=True)}
        assert p.stage_note("apply_guardrails", out) == "Safety rules adjusted the proposal"

    def test_guardrail_that_changed_nothing(self):
        assert p.stage_note("apply_guardrails", {"guardrail": make_guardrail()}) == "Safety rules passed"

    def test_approval_takes_precedence_over_override_in_the_note(self):
        out = {"guardrail": make_guardrail(overridden=True, requires_human_approval=True)}
        assert p.stage_note("apply_guardrails", out) == "Safety checks passed; human approval required"

    @pytest.mark.parametrize("status", list(p.ROUTE_LABELS))
    def test_route_nodes_use_the_route_label_for_the_status(self, status):
        assert p.stage_note("hitl", {"result": make_result(status=status)}) == p.ROUTE_LABELS[status]

    def test_unknown_status_is_humanised(self):
        assert p.stage_note("escalate", {"result": make_result(status="queued_digest")}) == "Queued digest"


class TestRecordCard:
    def test_shows_program_activity_and_three_decimal_score(self):
        inc = make_incident(score=0.91834, summary="process_create; Image=C:\\a\\cmd.exe", event_type="process_create")
        html = p.record_card(inc)
        assert "cmd.exe · Process started" in html and "0.918 similarity" in html

    def test_without_a_program_only_the_activity_is_the_title(self):
        html = p.record_card(make_incident(summary="no image", event_type="network_connection"))
        assert "<strong>Network connection</strong>" in html

    def test_details_line_uses_host_capture_and_event_code(self):
        inc = make_incident(metadata={"hostname": "WS01", "capture": "psexec_run", "event_code": 10})
        assert "WS01 · Psexec Run · Event 10" in p.record_card(inc)

    def test_missing_metadata_uses_the_default_source_label(self):
        assert "Recorded Windows Event" in p.record_card(make_incident(metadata={}))

    def test_event_code_zero_is_treated_as_absent(self):
        assert "Event 0" not in p.record_card(make_incident(metadata={"event_code": 0}))

    def test_summary_and_metadata_are_escaped_everywhere(self):
        html = p.record_card(make_incident(summary=XSS, metadata={"hostname": XSS}))
        assert "<script>" not in html

    def test_the_indexed_record_json_is_included(self):
        html = p.record_card(make_incident(incident_id="inc-77"))
        assert "View indexed record JSON" in html and "inc-77" in html


class TestResultCard:
    def render(self, **kw):
        result = make_result(**kw)
        return p.result_card(result, result.classification.alert)

    @pytest.mark.parametrize("severity", list(Severity))
    def test_severity_class_matches_the_tier(self, severity):
        assert f"soc-metric {severity.value.lower()}" in self.render(severity=severity)

    def test_pending_approval_is_labelled_proposed_and_points_to_the_approval_tab(self):
        html = self.render(status="pending_approval", action=Action.AUTO_REMEDIATE)
        assert "Proposed action" in html and "Approval queue" in html and "Waiting for human approval" in html

    def test_escalated_points_to_analyst_review(self):
        html = self.render(status="escalated")
        assert "Final action" in html and "Analyst review tab" in html

    def test_suppressed_has_no_destination_hint(self):
        html = self.render(status="suppressed", action=Action.SUPPRESS_AS_FALSE_POSITIVE)
        assert "Suppressed as false positive" in html and "tab to review" not in html

    def test_confidences_are_shown_as_whole_percentages(self):
        html = self.render(decision=make_decision(confidence=0.85))
        assert "90%" in html and "85%" in html

    def test_no_incidents_shows_a_message(self):
        html = self.render(enrichment=make_enrichment(0.0, True, []))
        assert "No related records were found in Qdrant." in html

    def test_incidents_render_as_cards(self):
        enrichment = make_enrichment(incidents=[make_incident(incident_id="a"), make_incident(incident_id="b")])
        assert self.render(enrichment=enrichment).count('class="soc-match"') == 2

    def test_no_guardrail_reasons_shows_the_no_changes_message(self):
        assert "No guardrail changes were needed." in self.render()

    def test_guardrail_reasons_are_listed_and_escaped(self):
        html = self.render(guardrail=make_guardrail(reasons=["first", XSS]))
        assert "<li>first</li>" in html and "<script>" not in html

    def test_reasoning_and_alert_json_are_escaped(self):
        result = make_result(alert=make_alert(description=XSS), decision=make_decision(reasoning=XSS))
        html = p.result_card(result, result.classification.alert)
        assert "<script>" not in html

    def test_unknown_source_falls_back_to_a_label(self):
        assert "Unknown source" in self.render(alert=make_alert(source=None))

    def test_known_source_is_shown(self):
        assert "Microsoft-Windows-Sysmon" in self.render(alert=make_alert(source="Microsoft-Windows-Sysmon"))

    def test_original_alert_json_is_included(self):
        assert "View original alert JSON" in self.render()

    def test_unknown_status_is_humanised_not_a_crash(self):
        assert "Queued digest" in self.render(status="queued_digest")
