from __future__ import annotations

import html
import json
import re
from pathlib import PureWindowsPath

from soc_triage.models import RawAlert, RetrievedIncident, TriageResult

STAGES = (
    ("sanitize", "Sanitize alert", "Checking the input…"),
    ("intake", "Intake agent", "Calling the intake agent…"),
    ("enrich", "Context enrichment", "Searching related recorded events…"),
    ("decide", "Decision agent", "Calling the decision agent…"),
    ("apply_guardrails", "Safety checks", "Applying guardrails…"),
    ("route", "Route alert", "Sending the result to its destination…"),
)
ROUTE_NODES = {"simulate_remediation", "suppress", "escalate", "hitl"}
ROUTE_LABELS = {
    "pending_approval": "Waiting for human approval",
    "escalated": "Queued for analyst review",
    "suppressed": "Suppressed as false positive",
    "simulated_remediation": "Remediation simulated; no host action taken",
}
ACTIVITY_LABELS = {
    "process_create": "Process started",
    "process_access": "Process access",
    "remote_thread_create": "Remote thread created",
    "network_connection": "Network connection",
    "dns_query": "DNS lookup",
    "file_create": "File created",
    "registry_change": "Registry change",
    "registry_value_change": "Registry value changed",
    "logon_success": "Sign-in succeeded",
    "logon_failure": "Sign-in failed",
    "service_installed": "Service installed",
    "audit_log_cleared": "Audit log cleared",
    "share_access": "Network share access",
}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def activity(event_type: str | None) -> str:
    return ACTIVITY_LABELS.get(event_type or "", (event_type or "Security event").replace("_", " ").capitalize())


def program(text: str) -> str | None:
    match = re.search(r"(?:^|[;|])\s*Image=([^;|]+)", text, re.IGNORECASE)
    if not match:
        return None
    return PureWindowsPath(match.group(1).strip()).name[:70] or None


def alert_title(alert: RawAlert) -> str:
    name = program(alert.description)
    return f"{name} - {activity(alert.event_type)}" if name else activity(alert.event_type)


def empty_panel(title: str, description: str) -> str:
    return f'<div class="soc-panel"><div class="soc-empty"><strong>{esc(title)}</strong><span>{esc(description)}</span></div></div>'


def preparing_panel() -> str:
    return ('<div class="soc-panel"><h3>Investigation</h3>'
            '<div class="soc-stage active"><span class="dot"></span><div>'
            '<strong>Preparing triage</strong><small>Loading the embedding model and connecting to Qdrant. '
            'The first run can take longer; later runs reuse the loaded model.</small></div></div></div>')


def timeline(runs: list[dict]) -> str:
    if not runs:
        return empty_panel("Ready for an alert", "Choose an example or upload JSON, then run triage.")
    cards = []
    for run in runs:
        alert: RawAlert = run["alert"]
        stages = []
        for key, label, active_copy in STAGES:
            state, note = run["stages"].get(key, ("pending", ""))
            detail = active_copy if state == "active" else note if state == "done" else "Waiting"
            icon = "✓" if state == "done" else ""
            stages.append(
                f'<div class="soc-stage {state}"><span class="dot">{icon}</span>'
                f'<div><strong>{label}</strong><small>{esc(detail)}</small></div></div>'
            )
        cards.append(
            '<div class="soc-timeline-run">'
            f'<div class="soc-alert-head"><strong>{esc(alert_title(alert))}</strong>'
            f'<span>Alert {esc(alert.event_id[:8])}</span></div>'
            f'<div class="soc-timeline">{"".join(stages)}</div></div>'
        )
    return '<div class="soc-panel"><h3>Live activity</h3>' + "".join(cards) + "</div>"


def stage_note(node: str, out: dict) -> str:
    if node == "sanitize":
        return "Suspicious instructions flagged" if out.get("injection_flags") else "Input checked and prepared"
    if node == "intake":
        c = out["classified"]
        return f"{c.severity.value} severity · {c.confidence:.0%} confidence"
    if node == "enrich":
        e = out["enrichment"]
        return f"{len(e.incidents)} related events found · best similarity {e.max_score:.3f}"
    if node == "decide":
        proposed = out["proposed"]
        return f"Proposed {proposed.action.value.replace('_', ' ')} · {proposed.confidence:.0%} confidence"
    if node == "apply_guardrails":
        guardrail = out["guardrail"]
        if guardrail.requires_human_approval:
            return "Safety checks passed; human approval required"
        return "Safety rules adjusted the proposal" if guardrail.overridden else "Safety rules passed"
    result: TriageResult = out["result"]
    return ROUTE_LABELS.get(result.status, result.status.replace("_", " ").capitalize())


def record_card(incident: RetrievedIncident) -> str:
    meta = incident.metadata
    name = program(incident.summary)
    title = f"{name} · {activity(incident.event_type)}" if name else activity(incident.event_type)
    source = str(meta.get("capture") or "Recorded Windows event").replace("_", " ").title()
    host = meta.get("hostname")
    code = meta.get("event_code")
    details = " · ".join(str(x) for x in (host, source, f"Event {code}" if code else None) if x)
    stored = {"id": incident.incident_id, "score": incident.score, "event_type": incident.event_type,
              "summary": incident.summary, "metadata": incident.metadata}
    record_json = json.dumps(stored, indent=2, ensure_ascii=False, default=str)
    return (
        '<div class="soc-match"><div class="soc-match-top">'
        f'<strong>{esc(title)}</strong><span class="score">{incident.score:.3f} similarity</span></div>'
        f'<div class="meta">{esc(details)}</div>'
        '<details><summary>View indexed record JSON</summary>'
        f'<pre>{esc(record_json)}</pre></details></div>'
    )


def result_card(result: TriageResult, alert: RawAlert) -> str:
    severity = result.classification.severity.value
    route = ROUTE_LABELS.get(result.status, result.status.replace("_", " ").capitalize())
    destination = ("Open the Approval queue tab to review it." if result.status == "pending_approval" else
                   "Open the Analyst review tab to review it." if result.status == "escalated" else "")
    action_label = "Proposed action" if result.status == "pending_approval" else "Final action"
    matches = "".join(record_card(i) for i in result.enrichment.incidents)
    if not matches:
        matches = '<p>No related records were found in Qdrant.</p>'
    checks = "".join(f"<li>{esc(reason)}</li>" for reason in result.guardrail.reasons)
    checks = f"<ul>{checks}</ul>" if checks else "<p>No guardrail changes were needed.</p>"
    alert_json = json.dumps(alert.model_dump(mode="json"), indent=2, ensure_ascii=False)
    return (
        '<div class="soc-panel">'
        f'<div class="soc-alert-head"><strong>{esc(alert_title(alert))}</strong>'
        f'<span>Alert {esc(result.alert_id[:8])} · {esc(alert.source or "Unknown source")}</span></div>'
        '<div class="soc-metrics">'
        f'<div class="soc-metric {severity.lower()}"><span>Severity</span><strong>{esc(severity)}</strong></div>'
        f'<div class="soc-metric"><span>{action_label}</span><strong>{esc(result.guardrail.final_action.value.replace("_", " ").title())}</strong></div>'
        f'<div class="soc-metric"><span>Intake confidence</span><strong>{result.classification.confidence:.0%}</strong></div>'
        f'<div class="soc-metric"><span>Decision confidence</span><strong>{result.proposed.confidence:.0%}</strong></div>'
        '</div>'
        f'<div class="soc-route"><strong>{esc(route)}</strong> {esc(destination)}</div>'
        '<div class="soc-result-section"><h4>Why the decision agent chose this</h4>'
        f'<p>{esc(result.proposed.reasoning)}</p></div>'
        '<div class="soc-result-section"><h4>Safety checks</h4>' + checks + '</div>'
        '<div class="soc-result-section"><h4>Related recorded events</h4>'
        '<p>Closest telemetry matches from Qdrant. Similarity is context, not a verified outcome.</p>'
        + matches + '</div>'
        '<div class="soc-result-section"><details class="soc-alert-raw"><summary>View original alert JSON</summary>'
        f'<pre>{esc(alert_json)}</pre></details></div></div>'
    )
