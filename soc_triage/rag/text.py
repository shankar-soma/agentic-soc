"""Text representation shared by OTRF ingestion and retrieval."""

from __future__ import annotations

from soc_triage.models import RawAlert


def summarize(alert: RawAlert) -> str:
    parts = [
        alert.event_type,
        alert.source,
        alert.severity,
        alert.alert_type,
        alert.category,
        alert.action,
        alert.description,
    ]
    return " | ".join(p for p in parts if p)
