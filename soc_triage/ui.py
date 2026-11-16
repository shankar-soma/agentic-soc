"""SOC triage console to upload SIEM alerts, watch the agents run, read the findings"""

from __future__ import annotations

import asyncio
from html import escape
import json
from pathlib import Path

import gradio as gr

from soc_triage.models import RawAlert, TriageResult
from soc_triage.runtime import Runtime, build_runtime
from soc_triage.llm.chat import vllm_base_url
from soc_triage.ui_style import UI_CSS
from soc_triage import ui_present as present

DEMO_DIR = Path("data/otrf/demo_alerts")
SYNTHETIC_DEMO_DIR = Path("data/synthetic_demo_alerts")
_runtimes: dict[tuple[str, str], Runtime] = {}

def runtime_for(backend: str, vllm_url: str | None = None) -> Runtime:
    if backend not in {"anthropic", "gpt", "vllm"}:
        raise ValueError("Choose Anthropic, GPT, or vLLM before processing an alert")
    endpoint = vllm_base_url(vllm_url) if backend == "vllm" else ""
    key = (backend, endpoint)
    if key not in _runtimes:
        _runtimes[key] = build_runtime(backend=backend, vllm_url=vllm_url)
    return _runtimes[key]


def load_alerts(path: str) -> list[RawAlert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    return [RawAlert.model_validate(item) for item in items]


def run_console(path: str | None, backend: str, demo_path: str | None = None, vllm_url: str | None = None):
    """Stream stage starts/completions, findings, and queue state to the UI."""
    allowed_demos = {str(p) for folder in (DEMO_DIR, SYNTHETIC_DEMO_DIR) for p in folder.glob("*.json")}
    if not path and demo_path not in allowed_demos:
        demo_path = None
    selected = path or demo_path
    if not selected:
        yield (present.empty_panel("Choose an alert first", "Upload JSON or select a recorded example."),
               present.empty_panel("No result yet", "The assessment will appear here."), [], "", "")
        return
    if backend not in {"anthropic", "gpt", "vllm"}:
        yield (present.empty_panel("Choose a model", "Select Anthropic, GPT, or vLLM before running triage."),
               present.empty_panel("No result yet", "The assessment will appear here."), [], "", "")
        return
    try:
        alerts = load_alerts(selected)
    except (OSError, ValueError) as exc:
        yield (present.empty_panel("Could not read the alert", str(exc)),
               present.empty_panel("No result yet", "The assessment will appear here."), [], "", "")
        return
    yield (present.preparing_panel(),
           present.empty_panel("Assessment pending", "Results appear as each alert finishes."), [], "", "")
    try:
        rt = runtime_for(backend, vllm_url)
    except (RuntimeError, ValueError) as exc:
        yield (present.empty_panel("Model unavailable", str(exc)),
               present.empty_panel("No result yet", "Check the model configuration and try again."), [], "", "")
        return
    runs: list[dict] = []
    findings_parts: list[str] = []
    summary: list[list[str]] = []
    pending = present.empty_panel("Assessment pending", "Results appear as each alert finishes.")

    def snapshot():
        return (present.timeline(runs), "<div style='height:12px'></div>".join(findings_parts) or pending,
                summary, queue_rows(backend, vllm_url), review_rows(backend, vllm_url))

    loop = asyncio.new_event_loop()
    try:
        for alert in alerts:
            run = {"alert": alert, "stages": {}}
            runs.append(run)
            result = None
            stream = rt.pipeline.stream(alert).__aiter__()
            yield snapshot()
            while True:
                try:
                    kind, node, out = loop.run_until_complete(stream.__anext__())
                except StopAsyncIteration:
                    break
                key = "route" if node in present.ROUTE_NODES else node
                if kind == "start":
                    run["stages"][key] = ("active", "")
                else:
                    run["stages"][key] = ("done", present.stage_note(node, out))
                    if node in present.ROUTE_NODES:
                        result = out["result"]
                yield snapshot()
            if result is not None:
                findings_parts.append(present.result_card(result, alert))
                summary.append([
                    result.alert_id[:8],
                    present.alert_title(alert),
                    result.classification.severity.value,
                    result.proposed.action.value.replace("_", " ").title(),
                    result.guardrail.final_action.value.replace("_", " ").title(),
                    present.ROUTE_LABELS.get(result.status, result.status),
                ])
            yield snapshot()
    finally:
        loop.close()


def _review_card(result: TriageResult, *, approval: bool) -> str:
    proposed = result.proposed.action.value.replace("_", " ").title()
    final = result.guardrail.final_action.value.replace("_", " ").title()
    reason = escape(result.proposed.reasoning)
    checks = "".join(f"<li>{escape(item)}</li>" for item in result.guardrail.reasons)
    checks_html = f"<div class='soc-review-checks'><strong>Routing checks</strong><ul>{checks}</ul></div>" if checks else ""
    confidence = f" · Decision confidence {result.proposed.confidence:.0%}" if approval else ""
    return (
        '<article class="soc-review-card">'
        f'<div class="soc-review-head"><strong>Alert {escape(result.alert_id[:8])}</strong>'
        f'<span>{escape(result.classification.severity.value)}{confidence}</span></div>'
        f'<div class="soc-review-action">Proposed: {escape(proposed)} · Route: {escape("Approval required" if approval else final)}</div>'
        '<details><summary>View full reason</summary>'
        f'<p>{reason}</p>{checks_html}</details></article>'
    )


def queue_rows(backend: str, vllm_url: str | None = None) -> str:
    if backend not in {"anthropic", "gpt", "vllm"}:
        return ""
    try:
        rt = runtime_for(backend, vllm_url)
    except (RuntimeError, ValueError):
        return ""
    pending = rt.queue.pending()
    return '<div class="soc-review-list">' + ("".join(_review_card(r, approval=True) for r in pending) or "<p>No alerts awaiting remediation approval.</p>") + "</div>"


def review_rows(backend: str, vllm_url: str | None = None) -> str:
    if backend not in {"anthropic", "gpt", "vllm"}:
        return ""
    try:
        rt = runtime_for(backend, vllm_url)
    except (RuntimeError, ValueError):
        return ""
    reviews = rt.queue.review()
    return '<div class="soc-review-list">' + ("".join(_review_card(r, approval=False) for r in reviews) or "<p>No alerts awaiting analyst review.</p>") + "</div>"


def acknowledge_review(alert_id: str, backend: str, analyst: str, vllm_url: str | None = None):
    if backend not in {"anthropic", "gpt", "vllm"}:
        return "Choose a model first.", ""
    try:
        rt = runtime_for(backend, vllm_url)
    except (RuntimeError, ValueError) as exc:
        return f"Model unavailable: {exc}", ""
    if not alert_id.strip():
        return "Enter an alert ID from Analyst review.", review_rows(backend, vllm_url)
    matches = [r for r in rt.queue.review() if r.alert_id.startswith(alert_id.strip())]
    if len(matches) != 1:
        return f"No single alert matches `{alert_id}`.", review_rows(backend, vllm_url)
    full_id = matches[0].alert_id
    who = analyst.strip() or "analyst"
    out = rt.queue.acknowledge(full_id, who)
    rt.pipeline.audit.record("analyst_acknowledged", full_id, analyst=who)
    return f"Recorded **{out.status}** for `{full_id[:8]}`.", review_rows(backend, vllm_url)


def decide_queue(alert_id: str, backend: str, approve: bool, approver: str, vllm_url: str | None = None):
    if backend not in {"anthropic", "gpt", "vllm"}:
        return "Choose an LLM backend first.", ""
    try:
        rt = runtime_for(backend, vllm_url)
    except (RuntimeError, ValueError) as exc:
        return f"Model unavailable: {exc}", ""
    if not alert_id.strip():
        return "Enter a full alert id from the queue.", queue_rows(backend, vllm_url)
    matches = [r for r in rt.queue.pending() if r.alert_id.startswith(alert_id.strip())]
    if len(matches) != 1:
        return f"No single pending alert matches `{alert_id}`.", queue_rows(backend, vllm_url)
    full_id = matches[0].alert_id
    who = approver or "analyst"
    out = rt.queue.approve(full_id, who) if approve else rt.queue.reject(full_id, who)
    rt.pipeline.audit.record("remediation_approved" if approve else "remediation_rejected", full_id, approver=who)
    return f"Recorded **{out.status}** for `{full_id[:8]}`.", queue_rows(backend, vllm_url)


THEME = gr.themes.Base(primary_hue="blue", neutral_hue="slate")

HERO_HTML = """<div class="soc-header">
  <h1>SOC alert triage</h1>
  <p>Choose an alert, follow the agents, and review the final decision.</p>
  </div>"""


def demo_choices() -> list[tuple[str, str]]:
    names = {"bitsadmin": "BITSAdmin download · Process activity",
             "mimikatz": "Mimikatz · Credential access",
             "psexec": "PsExec · Remote service",
             "wevtutil": "Wevtutil · Event log change",
             "wmi": "WMI · Remote execution"}
    recorded = [(names.get(p.stem, p.stem.replace("_", " ").title()), str(p)) for p in sorted(DEMO_DIR.glob("*.json"))]
    synthetic_names = {
        "low_browser_setting": "Browser setting cleanup (Synthetic)",
        "medium_user_startup": "User startup entry cleanup (Synthetic)",
    }
    synthetic = [(synthetic_names.get(p.stem, f"{p.stem.replace('_', ' ').title()} (Synthetic)"), str(p))
                 for p in sorted(SYNTHETIC_DEMO_DIR.glob("*.json"))]
    return recorded + synthetic


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="SOC Alert Triage", fill_width=True) as demo:
        gr.HTML(HERO_HTML)
        with gr.Tabs(elem_classes=["soc-tabs"]):
            with gr.Tab("Investigate"):
                gr.HTML('<div class="soc-section"><h2>New investigation</h2><p>Select a model and an alert. A JSON file takes priority over an example.</p></div>')
                with gr.Row(equal_height=True):
                    backend = gr.Dropdown(
                        [("Anthropic", "anthropic"), ("GPT", "gpt"), ("Qwen3 (vLLM)", "vllm")],
                        value=None, label="Model", scale=1,
                    )
                    demo_choice = gr.Dropdown(choices=demo_choices(), value=None, label="Example alert", scale=2)
                    upload = gr.UploadButton("Upload JSON file", type="filepath", file_types=[".json"],
                                             size="md", scale=1)
                upload_status = gr.Textbox(value="No file selected", interactive=False, show_label=False)
                upload.upload(lambda p: Path(p).name if p else "No file selected",
                              inputs=upload, outputs=upload_status, queue=False)
                vllm_url = gr.Textbox(label="Public vLLM URL", placeholder="https://your-name.ngrok-free.app", visible=False)
                backend.change(lambda b: gr.update(visible=b == "vllm"), [backend], [vllm_url])
                with gr.Row():
                    run_btn = gr.Button("Investigate alert", variant="primary", size="md", scale=0, min_width=180)
                gr.HTML('<div class="soc-section"><h2>Investigation</h2><p>Active stages update as the agents work. The assessment appears when routing finishes.</p></div>')
                with gr.Row(equal_height=False):
                    with gr.Column(scale=1):
                        trace = gr.HTML(value=present.timeline([]), label="Activity")
                    with gr.Column(scale=1):
                        findings = gr.HTML(value=present.empty_panel("Assessment pending", "The final action and related events will appear here."), label="Assessment")

                with gr.Accordion("Batch overview", open=False):
                    summary = gr.Dataframe(
                        headers=["Alert", "Activity", "Severity", "Proposed", "Final", "Destination"],
                        interactive=False, wrap=True, elem_classes=["soc-table"],
                    )

            approval_tab = gr.Tab("Approval queue")
            with approval_tab:
                gr.HTML('<div class="soc-section"><h2>Approval queue</h2><p>Eligible High and Critical auto remediation proposals await human approval. Ineligible proposals and direct escalations appear in Analyst review.</p></div>')
                with gr.Group(elem_classes=["soc-card"]):
                    queue_tbl = gr.HTML(value='<div class="soc-review-list"><p>No alerts awaiting remediation approval.</p></div>')
                with gr.Row(equal_height=True):
                    with gr.Group(elem_classes=["soc-card"]):
                        gr.Markdown("Review an alert using the first eight characters of its ID.")
                        alert_id = gr.Textbox(label="Alert ID", placeholder="e.g. dbfdc080")
                        approver = gr.Textbox(label="Analyst name", placeholder="John Doe")
                        with gr.Row():
                            approve_btn = gr.Button("Approve", variant="primary")
                            reject_btn = gr.Button("Reject", variant="stop")
                    with gr.Group(elem_classes=["soc-card"]):
                        gr.Markdown("**Queue status**  \nThis demo queue is in memory. Restarting the app clears it.")
                        status = gr.Markdown("No approval selected. The table refreshes when you open this tab.")
                        refresh = gr.Button("Refresh approval queue")
                approve_btn.click(lambda a, b, n, u: decide_queue(a, b, True, n, u), [alert_id, backend, approver, vllm_url], [status, queue_tbl])
                reject_btn.click(lambda a, b, n, u: decide_queue(a, b, False, n, u), [alert_id, backend, approver, vllm_url], [status, queue_tbl])
                refresh.click(queue_rows, [backend, vllm_url], [queue_tbl])
                approval_tab.select(queue_rows, [backend, vllm_url], [queue_tbl])

            review_tab = gr.Tab("Analyst review")
            with review_tab:
                gr.HTML('<div class="soc-section"><h2>Analyst review</h2><p>Every alert routed to an analyst appears here, regardless of severity. Acknowledge it after reviewing.</p></div>')
                with gr.Group(elem_classes=["soc-card"]):
                    review_tbl = gr.HTML(value='<div class="soc-review-list"><p>No alerts awaiting analyst review.</p></div>')
                with gr.Row(equal_height=True):
                    review_id = gr.Textbox(label="Alert ID", placeholder="First eight characters are enough")
                    analyst = gr.Textbox(label="Analyst name", placeholder="John Doe")
                acknowledge_btn = gr.Button("Acknowledge review")
                review_status = gr.Markdown("Enter an alert ID from the review cards above.")
                acknowledge_btn.click(acknowledge_review, [review_id, backend, analyst, vllm_url], [review_status, review_tbl])
                review_refresh = gr.Button("Refresh analyst review")
                review_refresh.click(review_rows, [backend, vllm_url], [review_tbl])
                review_tab.select(review_rows, [backend, vllm_url], [review_tbl])
        primed = run_btn.click(lambda: present.preparing_panel(), outputs=trace,
                               queue=False, show_progress="hidden")
        primed.then(run_console, [upload, backend, demo_choice, vllm_url],
                    [trace, findings, summary, queue_tbl, review_tbl], show_progress="minimal")
    return demo


if __name__ == "__main__":
    build_ui().launch(server_name="0.0.0.0", server_port=7860, theme=THEME, css=UI_CSS)
