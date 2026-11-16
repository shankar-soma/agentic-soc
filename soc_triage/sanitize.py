"""Need to clean alert content before any LLM sees it to remove any injection attacks"""

from __future__ import annotations

import json
import re
import unicodedata

from soc_triage.models import RawAlert

MAX_FIELD_CHARS = 2000

INJECTION_PATTERNS: dict[str, str] = {
    "ignore_instructions": r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|prompts?)",
    "disregard_instructions": r"disregard\s+.{0,40}instructions",
    "role_override": r"\byou\s+are\s+now\b",
    "system_prompt_probe": r"system\s+prompt",
    "delimiter_forgery": r"</?alert_data>",
    "action_directive": r"auto[_\s-]?remediate",
    "benign_directive": r"(mark|label)\s+(this|it)\s+as\s+(benign|false\s+positive)",
}

_ALERT_FIELDS = (
    "event_id", "timestamp", "event_type", "source", "description",
    "raw_log", "action", "alert_type", "category", "user", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "flow_duration_us", "fwd_packets", "bwd_packets",
    "fwd_bytes", "bwd_bytes", "process_id", "parent_process", "cloud_service", "asset_criticality",
)


def sanitize_text(text: str | None) -> tuple[str, list[str]]:
    """Return (clean_text, injection_flags) for one field."""
    if not text:
        return "", []
    clean = unicodedata.normalize("NFKC", str(text))
    clean = "".join(ch for ch in clean if ch.isprintable() or ch in "\n\t")
    clean = clean[:MAX_FIELD_CHARS]
    flags = [name for name, pat in INJECTION_PATTERNS.items() if re.search(pat, clean, re.IGNORECASE)]
    clean = re.sub(r"</?alert_data>", "[removed-tag]", clean, flags=re.IGNORECASE)
    return clean, flags


def redact_cef_severity(raw: str) -> str:
    """CEF puts severity in the 7th pipe-delimited field. Blank it so the label can't leak."""
    parts = raw.split("|")
    if len(parts) >= 7:
        parts[6] = "[redacted]"
        return "|".join(parts)
    return raw


def alert_block(alert: RawAlert) -> tuple[str, list[str]]:
    """Serialise the alert into a delimited, sanitised JSON block. Returns (block, flags)."""
    data: dict[str, str] = {}
    all_flags: set[str] = set()
    for name in _ALERT_FIELDS:
        value = getattr(alert, name, None)
        if value is None:
            continue
        if name == "raw_log":
            value = redact_cef_severity(str(value))
        clean, flags = sanitize_text(str(value))
        all_flags.update(flags)
        data[name] = clean
    body = json.dumps(data, indent=2, sort_keys=True)
    return f"<alert_data>\n{body}\n</alert_data>", sorted(all_flags)
