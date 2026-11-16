"""In memory queue for remediation approval and analyst review"""

from __future__ import annotations

import threading

from soc_triage.models import TriageResult


class ApprovalQueue:
    def __init__(self) -> None:
        self._pending: dict[str, TriageResult] = {}
        self._review: dict[str, TriageResult] = {}
        self._lock = threading.Lock()

    def enqueue(self, result: TriageResult) -> None:
        with self._lock:
            self._pending[result.alert_id] = result

    def add_review(self, result: TriageResult) -> None:
        with self._lock:
            self._review[result.alert_id] = result

    def review(self) -> list[TriageResult]:
        with self._lock:
            return list(self._review.values())

    def acknowledge(self, alert_id: str, analyst: str) -> TriageResult:
        with self._lock:
            result = self._review.pop(alert_id)
        return result.model_copy(update={"status": f"acknowledged_by:{analyst}"})

    def pending(self) -> list[TriageResult]:
        with self._lock:
            return list(self._pending.values())

    def approve(self, alert_id: str, approver: str) -> TriageResult:
        with self._lock:
            result = self._pending.pop(alert_id)
        return result.model_copy(update={"status": f"approved_by:{approver}"})

    def reject(self, alert_id: str, approver: str) -> TriageResult:
        with self._lock:
            result = self._pending.pop(alert_id)
        return result.model_copy(update={"status": f"rejected_by:{approver}"})
