"""Ingest recorded OTRF Windows telemetry into an isolated Qdrant collection.

Source: https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import urllib.request
import uuid
import zipfile
from collections import Counter
from pathlib import Path

from soc_triage.models import RawAlert
from soc_triage.rag.embedder import get_embedder
from soc_triage.rag.text import summarize
from soc_triage.rag.store import IncidentStore

COLLECTION = "otrf_recorded_events_v1"
BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"
CAPTURES = {
    "mimikatz": "credential_access/host/empire_mimikatz_logonpasswords.zip",
    "psexec": "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
    "wmi": "lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip",
    "bitsadmin": "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
    "mshta": "defense_evasion/host/cmd_mshta_javascript_getobject_sct.zip",
    "wevtutil": "defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path.zip",
    "psremoting": "lateral_movement/host/empire_psremoting_stager.zip",
    "smbexec": "lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip",
}
SYSMON_IDS = {1, 3, 8, 10, 11, 12, 13, 22}
SECURITY_IDS = {1102, 4624, 4625, 4688, 4697, 5145}
SIGNAL_IDS = SYSMON_IDS | SECURITY_IDS | {7045}
DEMO_CAPTURE_NAMES = ("mimikatz", "psexec", "wmi", "bitsadmin", "wevtutil")
ACTIVITY = {
    1: "process_create", 3: "network_connection", 8: "remote_thread_create",
    10: "process_access", 11: "file_create", 12: "registry_change",
    13: "registry_value_change", 22: "dns_query", 1102: "audit_log_cleared",
    4624: "logon_success", 4625: "logon_failure", 4688: "process_create",
    4697: "service_installed", 5145: "share_access", 7045: "service_installed",
}
CONTEXT_FIELDS = (
    "Image", "CommandLine", "ParentImage", "ParentCommandLine", "SourceImage",
    "TargetImage", "NewProcessName", "ProcessCommandLine", "ServiceName",
    "ServiceFileName", "TargetObject", "Details", "DestinationHostname",
    "DestinationIp", "GrantedAccess", "TargetFilename", "QueryName",
)


def fetch_capture(name: str, cache: Path) -> bytes:
    path = cache / f"{name}.zip"
    if path.exists():
        return path.read_bytes()
    url = f"{BASE}/{CAPTURES[name]}"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ValueError(f"Invalid ZIP from {url}")
    path.write_bytes(data)
    return data


def event_to_alert(name: str, source_key: str, row: dict) -> RawAlert:
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"otrf:{name}:{source_key}"))
    event_code = int(row["EventID"])
    fields = [f"{key}={str(row[key])[:450]}" for key in CONTEXT_FIELDS if row.get(key)]
    message = " ".join(str(row.get("Message") or "").split())[:900]
    description = f"{ACTIVITY[event_code]}; " + "; ".join(fields) + f"; raw_message={message}"
    return RawAlert.model_validate({
        "event_id": event_id,
        "timestamp": row.get("@timestamp"),
        "event_type": ACTIVITY[event_code],
        "source": str(row.get("Channel") or row.get("SourceName") or "Windows event log"),
        "severity": None,
        "description": description[:1900],
        "action": ACTIVITY[event_code],
        "category": "Windows telemetry",
        "user": row.get("AccountName") or row.get("TargetUserName") or row.get("SubjectUserName"),
        "parent_process": row.get("ParentImage"),
        "process_id": row.get("ProcessId") if str(row.get("ProcessId", "")).isdigit() else None,
    })


def read_events(name: str, data: bytes, per_capture: int) -> list[tuple[RawAlert, dict]]:
    output = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for filename in archive.namelist():
            if not filename.endswith(".json"):
                continue
            with archive.open(filename) as stream:
                for line_number, line in enumerate(stream):
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            continue
                        code = int(row.get("EventID", -1))
                    except (ValueError, TypeError, json.JSONDecodeError):
                        continue
                    channel = str(row.get("Channel") or "").lower()
                    valid = (
                        ("sysmon" in channel and code in SYSMON_IDS)
                        or (channel == "security" and code in SECURITY_IDS)
                        or (channel == "system" and code == 7045)
                    )
                    if not valid or not row.get("Message"):
                        continue
                    alert = event_to_alert(name, f"{filename}:{line_number}", row)
                    output.append((alert, {
                        "capture": name,
                        "source_url": f"{BASE}/{CAPTURES[name]}",
                        "event_code": code,
                        "hostname": row.get("Hostname"),
                        "source_record_number": row.get("RecordNumber"),
                        "source_sha256": hashlib.sha256(line).hexdigest(),
                    }))
                    if len(output) >= per_capture:
                        return output
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:6333")
    parser.add_argument("--collection", default=COLLECTION)
    parser.add_argument("--out", type=Path, default=Path("data/otrf"))
    parser.add_argument("--per-capture", type=int, default=1200)
    parser.add_argument("--batch", type=int, default=128)
    args = parser.parse_args()
    if args.per_capture < 2:
        parser.error("--per-capture must be at least 2")
    args.out.mkdir(parents=True, exist_ok=True)
    cache = args.out / "source_zips"
    cache.mkdir(exist_ok=True)

    records = []
    sources = {}
    for name in CAPTURES:
        data = fetch_capture(name, cache)
        sources[name] = {"url": f"{BASE}/{CAPTURES[name]}", "zip_sha256": hashlib.sha256(data).hexdigest()}
        items = read_events(name, data, args.per_capture)
        print(f"{name}: {len(items)} selected events", flush=True)
        records.extend(items)

    preferred = {"mimikatz": 10, "psexec": 7045, "wmi": 4688, "bitsadmin": 1, "wevtutil": 1}
    terms = {"mimikatz": ("lsass",), "psexec": ("service",), "wmi": ("wmiprvse", "wmi"),
             "bitsadmin": ("bitsadmin",), "wevtutil": ("wevtutil",)}
    demo = []
    for name in DEMO_CAPTURE_NAMES:
        matches = [(alert, meta) for alert, meta in records if meta["capture"] == name]
        if not matches:
            raise RuntimeError(f"No demo candidate in {name}")
        def rank(item: tuple[RawAlert, dict]) -> tuple[int, str]:
            alert, meta = item
            content = alert.description.lower()
            score = (10 if meta["event_code"] == preferred[name] else 0)
            score += 5 * sum(term in content for term in terms[name])
            score += min(len(content), 1900) // 500
            return score, alert.event_id
        demo.append(max(matches, key=rank))
    held_out_ids = {alert.event_id for alert, _ in demo}
    index_records = [(alert, meta) for alert, meta in records if alert.event_id not in held_out_ids]

    demo_path = args.out / "demo_holdout.jsonl"
    demo_dir = args.out / "demo_alerts"
    demo_dir.mkdir(exist_ok=True)
    with demo_path.open("w", encoding="utf-8") as stream:
        for alert, meta in demo:
            stream.write(json.dumps({"alert": alert.model_dump(mode="json"), "provenance": meta}) + "\n")
            (demo_dir / f"{meta['capture']}.json").write_text(
                json.dumps(alert.model_dump(mode="json"), indent=2), encoding="utf-8"
            )
    manifest = {
        "collection": args.collection,
        "source": "OTRF Security-Datasets lab-captured Windows event logs",
        "disposition_labels": "none; event-level records only",
        "sources": sources,
        "selected_event_count": len(records),
        "indexed_event_count": len(index_records),
        "demo_holdout_ids": sorted(held_out_ids),
        "event_codes": dict(Counter(str(meta["event_code"]) for _, meta in index_records)),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    embedder = get_embedder("fastembed")
    store = IncidentStore(collection=args.collection, dim=embedder.dim, url=args.url)
    if store.client.collection_exists(args.collection) and store.count() > 0:
        raise RuntimeError(f"Collection {args.collection} already has points; choose a new --collection")
    store.ensure_collection()
    for offset in range(0, len(index_records), args.batch):
        batch = index_records[offset:offset + args.batch]
        texts = [summarize(alert) for alert, _ in batch]
        vectors = embedder.embed(texts)
        store.upsert(
            ids=[alert.event_id for alert, _ in batch],
            vectors=vectors,
            payloads=[{"summary": text, "event_id": alert.event_id, "event_type": alert.event_type, **meta}
                      for (alert, meta), text in zip(batch, texts, strict=True)],
        )
        print(f"indexed {min(offset + len(batch), len(index_records))}/{len(index_records)}", flush=True)
    count = store.count()
    if count != len(index_records):
        raise RuntimeError(f"Indexed count {count} does not match selected records {len(index_records)}")
    for alert, _ in demo:
        if store.client.retrieve(args.collection, [alert.event_id]):
            raise RuntimeError(f"Holdout event was indexed: {alert.event_id}")
    store.close()
    print(f"Done: {count} points in {args.collection}; five holdouts in {demo_dir}")


if __name__ == "__main__":
    main()
