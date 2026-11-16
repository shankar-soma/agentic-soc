"""Unit tests for soc_triage/audit.py."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from soc_triage.audit import AuditLog


def read(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def test_creates_missing_parent_directories(tmp_path):
    target = tmp_path / "a" / "b" / "audit.jsonl"
    AuditLog(target)
    assert target.parent.is_dir()


def test_accepts_str_and_path(tmp_path):
    assert AuditLog(str(tmp_path / "x.jsonl")).path == tmp_path / "x.jsonl"
    assert AuditLog(tmp_path / "y.jsonl").path == tmp_path / "y.jsonl"


def test_record_writes_one_json_line_with_core_fields(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("intake", "alert-1", severity="High")
    [line] = read(log.path)
    assert line["event"] == "intake" and line["alert_id"] == "alert-1" and line["severity"] == "High"


def test_timestamp_is_utc_iso_8601(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("e", "a")
    ts = datetime.fromisoformat(read(log.path)[0]["ts"])
    assert ts.tzinfo is not None and ts.utcoffset().total_seconds() == 0
    assert abs((datetime.now(timezone.utc) - ts).total_seconds()) < 60


def test_records_append_in_order_and_never_overwrite(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.record(f"e{i}", "a")
    assert [r["event"] for r in read(log.path)] == ["e0", "e1", "e2"]


def test_a_second_log_instance_appends_to_the_same_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("first", "a")
    AuditLog(path).record("second", "a")
    assert [r["event"] for r in read(path)] == ["first", "second"]


def test_non_json_values_are_stringified_not_dropped(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("e", "a", when=datetime(2026, 1, 2), where=Path("/tmp/x"))
    line = read(log.path)[0]
    assert "2026-01-02" in line["when"] and "x" in line["where"]


def test_lists_and_nested_values_round_trip(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("guardrail", "a", reasons=["r1", "r2"], nested={"k": [1, 2]})
    line = read(log.path)[0]
    assert line["reasons"] == ["r1", "r2"] and line["nested"] == {"k": [1, 2]}


def test_unicode_survives(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("e", "a", note="résumé – 日本語")
    assert read(log.path)[0]["note"] == "résumé – 日本語"


def test_each_record_is_exactly_one_line_even_with_newlines_in_values(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("e", "a", note="line1\nline2")
    assert len(log.path.read_text(encoding="utf-8").splitlines()) == 1


def test_concurrent_writers_never_interleave_a_line(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    def work(n):
        for i in range(25):
            log.record("e", f"t{n}", i=i, payload="x" * 200)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lines = read(log.path)  # raises if any line is corrupt
    assert len(lines) == 8 * 25
