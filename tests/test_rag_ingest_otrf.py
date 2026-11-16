"""Unit tests for the pure functions in soc_triage/rag/ingest_otrf.py. The network is faked; main() is not run."""

import hashlib
import io
import json
import uuid
import zipfile

import pytest
from pydantic import ValidationError

from soc_triage.rag import ingest_otrf as otrf
from soc_triage.rag.ingest_otrf import (
    ACTIVITY,
    BASE,
    CAPTURES,
    CONTEXT_FIELDS,
    DEMO_CAPTURE_NAMES,
    SECURITY_IDS,
    SIGNAL_IDS,
    SYSMON_IDS,
    event_to_alert,
    fetch_capture,
    read_events,
)

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def line(**row) -> str:
    base = {"EventID": 1, "Channel": SYSMON, "Message": "Process Create"}
    base.update(row)
    return json.dumps(base)


def body(*lines: str) -> str:
    return "\n".join(lines) + "\n"


class TestConstants:
    def test_there_are_eight_captures_and_each_has_a_zip_path(self):
        assert len(CAPTURES) == 8 and all(p.endswith(".zip") for p in CAPTURES.values())

    def test_demo_captures_are_all_real_captures(self):
        assert set(DEMO_CAPTURE_NAMES) <= set(CAPTURES) and len(DEMO_CAPTURE_NAMES) == 5

    def test_every_event_id_that_can_be_selected_has_an_activity_label(self):
        # Otherwise event_to_alert would raise KeyError on a selected event.
        assert SIGNAL_IDS <= set(ACTIVITY)

    def test_signal_ids_are_the_union_of_sysmon_security_and_7045(self):
        assert SIGNAL_IDS == SYSMON_IDS | SECURITY_IDS | {7045}

    def test_base_url_points_at_the_otrf_repository(self):
        assert BASE.startswith("https://raw.githubusercontent.com/OTRF/Security-Datasets/")


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestFetchCapture:
    def test_cache_hit_returns_cached_bytes_without_touching_the_network(self, tmp_path, monkeypatch):
        (tmp_path / "wmi.zip").write_bytes(b"cached-bytes")
        monkeypatch.setattr(otrf.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network used"))
        assert fetch_capture("wmi", tmp_path) == b"cached-bytes"

    def test_cache_miss_downloads_validates_and_caches(self, tmp_path, monkeypatch):
        data = zip_bytes({"a.json": "{}"})
        seen = {}

        def fake_urlopen(url, timeout):
            seen["url"], seen["timeout"] = url, timeout
            return FakeResponse(data)

        monkeypatch.setattr(otrf.urllib.request, "urlopen", fake_urlopen)
        assert fetch_capture("wmi", tmp_path) == data
        assert (tmp_path / "wmi.zip").read_bytes() == data
        assert seen == {"url": f"{BASE}/{CAPTURES['wmi']}", "timeout": 60}

    def test_a_non_zip_download_is_rejected_and_not_cached(self, tmp_path, monkeypatch):
        monkeypatch.setattr(otrf.urllib.request, "urlopen", lambda url, timeout: FakeResponse(b"<html>404</html>"))
        with pytest.raises(ValueError, match="Invalid ZIP"):
            fetch_capture("wmi", tmp_path)
        assert not (tmp_path / "wmi.zip").exists()

    def test_unknown_capture_name_raises_key_error(self, tmp_path):
        with pytest.raises(KeyError):
            fetch_capture("not-a-capture", tmp_path)

    def test_download_errors_propagate(self, tmp_path, monkeypatch):
        def boom(url, timeout):
            raise TimeoutError("slow")

        monkeypatch.setattr(otrf.urllib.request, "urlopen", boom)
        with pytest.raises(TimeoutError):
            fetch_capture("wmi", tmp_path)


def row(**overrides):
    base = {"EventID": 1, "Channel": SYSMON, "Message": "Process Create", "Image": "C:\\x.exe",
            "CommandLine": "x.exe /a", "AccountName": "bob", "ParentImage": "C:\\p.exe", "ProcessId": "123",
            "@timestamp": "2020-09-01T10:00:00.000Z"}
    base.update(overrides)
    return base


class TestEventToAlert:
    def test_event_id_is_a_deterministic_uuid5_of_capture_and_key(self):
        a = event_to_alert("wmi", "f.json:3", row())
        b = event_to_alert("wmi", "f.json:3", row())
        assert a.event_id == b.event_id == str(uuid.uuid5(uuid.NAMESPACE_URL, "otrf:wmi:f.json:3"))

    def test_different_capture_or_key_gives_a_different_id(self):
        base = event_to_alert("wmi", "f.json:3", row()).event_id
        assert event_to_alert("psexec", "f.json:3", row()).event_id != base
        assert event_to_alert("wmi", "f.json:4", row()).event_id != base

    @pytest.mark.parametrize("code", sorted(SIGNAL_IDS))
    def test_every_selectable_event_code_converts(self, code):
        assert event_to_alert("wmi", "k", row(EventID=code)).event_type == ACTIVITY[code]

    def test_event_type_action_and_category(self):
        a = event_to_alert("wmi", "k", row(EventID=10))
        assert (a.event_type, a.action, a.category) == ("process_access", "process_access", "Windows telemetry")

    def test_event_id_given_as_a_string_is_accepted(self):
        assert event_to_alert("wmi", "k", row(EventID="10")).event_type == "process_access"

    def test_unknown_event_code_raises_key_error(self):
        with pytest.raises(KeyError):
            event_to_alert("wmi", "k", row(EventID=9999))

    def test_missing_event_id_raises_key_error(self):
        data = row()
        data.pop("EventID")
        with pytest.raises(KeyError):
            event_to_alert("wmi", "k", data)

    def test_siem_severity_is_none_because_recorded_events_have_no_label(self):
        assert event_to_alert("wmi", "k", row()).severity is None

    def test_description_starts_with_the_activity_and_lists_present_context_fields(self):
        d = event_to_alert("wmi", "k", row()).description
        assert d.startswith("process_create; ") and "Image=C:\\x.exe" in d and "CommandLine=x.exe /a" in d
        assert "raw_message=Process Create" in d

    def test_empty_or_missing_context_fields_are_left_out(self):
        d = event_to_alert("wmi", "k", row(Image="", CommandLine=None)).description
        parts = d.split("; ")
        assert not any(p.startswith("Image=") for p in parts)
        assert not any(p.startswith("CommandLine=") for p in parts)

    def test_long_context_values_are_cut_to_450_characters(self):
        d = event_to_alert("wmi", "k", row(CommandLine="c" * 800)).description
        assert "CommandLine=" + "c" * 450 + ";" in d and "c" * 451 not in d

    def test_message_whitespace_is_collapsed_and_cut_to_900_characters(self):
        d = event_to_alert("wmi", "k", row(Message="a \n\n   b" + " x" * 1000)).description
        assert "raw_message=a b x" in d
        assert len(d.split("raw_message=")[1]) <= 900

    def test_whole_description_never_exceeds_1900_characters(self):
        fields = {name: "v" * 450 for name in CONTEXT_FIELDS}
        a = event_to_alert("wmi", "k", row(Message="m" * 2000, **fields))
        assert len(a.description) <= 1900

    @pytest.mark.parametrize("overrides, expected", [
        ({"Channel": "Security"}, "Security"),
        ({"Channel": None, "SourceName": "Service Control Manager"}, "Service Control Manager"),
        ({"Channel": None, "SourceName": None}, "Windows event log"),
        ({"Channel": "", "SourceName": ""}, "Windows event log"),
    ])
    def test_source_prefers_channel_then_source_name_then_a_default(self, overrides, expected):
        assert event_to_alert("wmi", "k", row(**overrides)).source == expected

    @pytest.mark.parametrize("overrides, expected", [
        ({}, "bob"),
        ({"AccountName": None, "TargetUserName": "carol"}, "carol"),
        ({"AccountName": None, "SubjectUserName": "dave"}, "dave"),
        ({"AccountName": None, "TargetUserName": "carol", "SubjectUserName": "dave"}, "carol"),
        ({"AccountName": None}, None),
    ])
    def test_user_precedence(self, overrides, expected):
        assert event_to_alert("wmi", "k", row(**overrides)).user == expected

    @pytest.mark.parametrize("value, expected", [("123", 123), (456, 456), ("12a", None), ("", None), (None, None)])
    def test_process_id_is_kept_only_when_numeric(self, value, expected):
        assert event_to_alert("wmi", "k", row(ProcessId=value)).process_id == expected

    def test_missing_process_id_gives_none(self):
        data = row()
        data.pop("ProcessId")
        assert event_to_alert("wmi", "k", data).process_id is None

    def test_parent_process_comes_from_parent_image(self):
        assert event_to_alert("wmi", "k", row()).parent_process == "C:\\p.exe"

    def test_timestamp_is_parsed(self):
        assert event_to_alert("wmi", "k", row()).timestamp.year == 2020

    def test_invalid_timestamp_is_rejected(self):
        with pytest.raises(ValidationError):
            event_to_alert("wmi", "k", row(**{"@timestamp": "not a time"}))


class TestReadEvents:
    def test_valid_sysmon_event_is_returned_with_provenance(self):
        text = body(line(EventID=1, RecordNumber=7, Hostname="host1"))
        [(alert, meta)] = read_events("wmi", zip_bytes({"f.json": text}), 10)
        assert alert.event_type == "process_create"
        assert meta["capture"] == "wmi" and meta["event_code"] == 1 and meta["hostname"] == "host1"
        assert meta["source_record_number"] == 7 and meta["source_url"] == f"{BASE}/{CAPTURES['wmi']}"

    def test_provenance_hash_is_the_sha256_of_the_raw_line(self):
        raw = line(EventID=1)
        [(_, meta)] = read_events("wmi", zip_bytes({"f.json": body(raw)}), 10)
        assert meta["source_sha256"] == hashlib.sha256((raw + "\n").encode()).hexdigest()

    @pytest.mark.parametrize("channel, code", [
        (SYSMON, 10), ("Security", 4688), ("Security", 1102), ("System", 7045),
    ])
    def test_accepted_channel_and_code_pairs(self, channel, code):
        data = zip_bytes({"f.json": body(line(EventID=code, Channel=channel))})
        assert len(read_events("wmi", data, 10)) == 1

    @pytest.mark.parametrize("channel, code", [
        (SYSMON, 4688),          # security id on the sysmon channel
        ("Security", 1),         # sysmon id on the security channel
        ("System", 7036),        # wrong system event
        ("Application", 1),      # unknown channel
        (None, 1), ("", 1),
    ])
    def test_rejected_channel_and_code_pairs(self, channel, code):
        data = zip_bytes({"f.json": body(line(EventID=code, Channel=channel))})
        assert read_events("wmi", data, 10) == []

    def test_event_without_a_message_is_skipped(self):
        data = zip_bytes({"f.json": body(line(Message=""), line(Message=None))})
        assert read_events("wmi", data, 10) == []

    @pytest.mark.parametrize("bad", [
        "not json", "{truncated", '{"EventID": "abc", "Channel": "x"}', "",
        "[]", "null", "123", '"a string"', "true", "[{}]",   # valid JSON, but not an event object
    ])
    def test_malformed_lines_are_skipped_without_failing_the_file(self, bad):
        data = zip_bytes({"f.json": body(bad, line(EventID=1))})
        assert len(read_events("wmi", data, 10)) == 1

    def test_non_json_files_in_the_archive_are_ignored(self):
        data = zip_bytes({"readme.txt": body(line()), "f.json": body(line())})
        assert len(read_events("wmi", data, 10)) == 1

    def test_stops_at_the_per_capture_limit(self):
        data = zip_bytes({"f.json": body(*[line() for _ in range(10)])})
        assert len(read_events("wmi", data, 3)) == 3

    def test_limit_applies_across_multiple_files(self):
        data = zip_bytes({"a.json": body(line(), line()), "b.json": body(line(), line())})
        assert len(read_events("wmi", data, 3)) == 3

    def test_ids_are_stable_across_runs(self):
        data = zip_bytes({"f.json": body(line(), line(EventID=10))})
        first = [a.event_id for a, _ in read_events("wmi", data, 10)]
        second = [a.event_id for a, _ in read_events("wmi", data, 10)]
        assert first == second and len(set(first)) == 2

    def test_same_content_in_two_captures_gets_different_ids(self):
        data = zip_bytes({"f.json": body(line())})
        assert read_events("wmi", data, 10)[0][0].event_id != read_events("psexec", data, 10)[0][0].event_id

    def test_empty_archive_returns_nothing(self):
        assert read_events("wmi", zip_bytes({}), 10) == []

    def test_a_corrupt_zip_raises(self):
        with pytest.raises(zipfile.BadZipFile):
            read_events("wmi", b"not a zip", 10)
