"""Unit tests for soc_triage/rag/text.py (summarize)."""

import pytest

from soc_triage.rag.text import summarize
from factories import make_alert


def test_joins_fields_in_a_fixed_order_with_pipes():
    alert = make_alert(event_type="process_create", source="Sysmon", severity="low", alert_type="T1105",
                       category="Windows telemetry", action="process_create", description="did a thing")
    assert summarize(alert) == "process_create | Sysmon | low | T1105 | Windows telemetry | process_create | did a thing"


def test_missing_and_empty_fields_are_skipped_without_blank_separators():
    alert = make_alert(event_type="e", source=None, severity="", alert_type=None, category=None, action=None,
                       description="d")
    assert summarize(alert) == "e | d"


def test_alert_with_nothing_useful_gives_an_empty_string():
    from soc_triage.models import RawAlert
    assert summarize(RawAlert(event_id="x")) == ""


def test_only_description_present():
    from soc_triage.models import RawAlert
    assert summarize(RawAlert(event_id="x", description="just this")) == "just this"


def test_same_alert_always_gives_the_same_text():
    alert = make_alert(description="stable")
    assert summarize(alert) == summarize(alert)


def test_the_event_id_is_not_part_of_the_text():
    a = make_alert(event_id="aaa", description="same")
    b = make_alert(event_id="bbb", description="same")
    assert summarize(a) == summarize(b)


@pytest.mark.parametrize("field", ["user", "src_ip", "dst_ip", "raw_log", "asset_criticality"])
def test_fields_outside_the_summary_do_not_change_it(field):
    base = summarize(make_alert(description="same"))
    assert summarize(make_alert(description="same", **{field: "something"})) == base
