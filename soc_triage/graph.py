""" Triage DAG w/ LangGraph """

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from langchain_core.language_models.chat_models import BaseChatModel

from soc_triage.agents.decision import decide, make_search_tool
from soc_triage.agents.enrichment import enrich
from soc_triage.agents.intake import classify
from soc_triage.audit import AuditLog
from soc_triage.config import Settings
from soc_triage.guardrails import apply_guardrails
from soc_triage.hitl import ApprovalQueue
from soc_triage.models import (
    Action,
    ClassifiedAlert,
    Decision,
    Enrichment,
    GuardrailResult,
    RawAlert,
    TriageResult,
)
from soc_triage.rag.embedder import Embedder
from soc_triage.rag.store import IncidentStore
from soc_triage.sanitize import alert_block


class TriageState(TypedDict, total=False):
    alert: RawAlert
    alert_block: str
    injection_flags: list[str]
    classified: ClassifiedAlert
    enrichment: Enrichment
    proposed: Decision
    guardrail: GuardrailResult
    result: TriageResult


class TriagePipeline:
    def __init__(
        self,
        *,
        intake_llm: BaseChatModel,
        decision_llm: BaseChatModel,
        backend: str,
        embedder: Embedder,
        store: IncidentStore,
        settings: Settings,
        audit: AuditLog,
        queue: ApprovalQueue,
    ) -> None:
        self.intake_llm = intake_llm
        self.decision_llm = decision_llm
        self.backend = backend
        self.search_tool = make_search_tool(embedder, store, settings.top_k)
        self.embedder = embedder
        self.store = store
        self.settings = settings
        self.audit = audit
        self.queue = queue
        self._graph = self._build()

    # Nodes
    async def _sanitize(self, state: TriageState) -> dict[str, Any]:
        block, flags = alert_block(state["alert"])
        self.audit.record("sanitized", state["alert"].event_id, injection_flags=flags)
        return {"alert_block": block, "injection_flags": flags}

    async def _intake(self, state: TriageState) -> dict[str, Any]:
        classified = await classify(state["alert"], state["alert_block"], self.intake_llm, self.settings, self.backend)
        self.audit.record(
            "intake",
            state["alert"].event_id,
            severity=classified.severity.value,
            confidence=classified.confidence,
            backend=classified.backend,
        )
        return {"classified": classified}

    async def _enrich(self, state: TriageState) -> dict[str, Any]:
        enrichment = await enrich(state["alert"], self.embedder, self.store, self.settings)
        self.audit.record(
            "enrich",
            state["alert"].event_id,
            max_score=enrichment.max_score,
            weak_retrieval=enrichment.weak_retrieval,
            incident_ids=[i.incident_id for i in enrichment.incidents],
        )
        return {"enrichment": enrichment}

    async def _decide(self, state: TriageState) -> dict[str, Any]:
        proposed = await decide(
            state["classified"],
            state["enrichment"],
            state["alert_block"],
            self.decision_llm,
            self.settings,
            self.search_tool,
        )
        self.audit.record("decide", state["alert"].event_id, proposed=proposed.action.value, confidence=proposed.confidence)
        return {"proposed": proposed}

    async def _apply_guardrails(self, state: TriageState) -> dict[str, Any]:
        guardrail = apply_guardrails(
            alert=state["alert"],
            classified=state["classified"],
            enrichment=state["enrichment"],
            proposed=state["proposed"],
            injection_flags=state["injection_flags"],
            settings=self.settings,
        )
        self.audit.record(
            "guardrail",
            state["alert"].event_id,
            final_action=guardrail.final_action.value,
            overridden=guardrail.overridden,
            reasons=guardrail.reasons,
            requires_human_approval=guardrail.requires_human_approval,
        )
        return {"guardrail": guardrail}

    def _finish(self, state: TriageState, status: str) -> dict[str, Any]:
        result = TriageResult(
            alert_id=state["alert"].event_id,
            classification=state["classified"],
            enrichment=state["enrichment"],
            proposed=state["proposed"],
            guardrail=state["guardrail"],
            status=status,
        )
        return {"result": result}

    async def _simulate_remediation(self, state: TriageState) -> dict[str, Any]:
        # No EDR or SOAR integration is configured; record the proposed action only.
        self.audit.record("remediation_simulated", state["alert"].event_id, action=Action.AUTO_REMEDIATE.value)
        return self._finish(state, "simulated_remediation")

    async def _suppress(self, state: TriageState) -> dict[str, Any]:
        self.audit.record("suppress", state["alert"].event_id)
        return self._finish(state, "suppressed")

    async def _escalate(self, state: TriageState) -> dict[str, Any]:
        out = self._finish(state, "escalated")
        self.queue.add_review(out["result"])
        self.audit.record("escalate", state["alert"].event_id)
        return out

    async def _hitl(self, state: TriageState) -> dict[str, Any]:
        out = self._finish(state, "pending_approval")
        self.queue.enqueue(out["result"])
        self.audit.record("hitl_enqueued", state["alert"].event_id)
        return out

    # Routing
    @staticmethod
    def _route(state: TriageState) -> str:
        g = state["guardrail"]
        if g.requires_human_approval:
            return "hitl"
        if g.final_action == Action.AUTO_REMEDIATE:
            return "simulate_remediation"
        if g.final_action == Action.SUPPRESS_AS_FALSE_POSITIVE:
            return "suppress"
        return "escalate"

    # Graph
    def _build(self):
        g = StateGraph(TriageState)
        g.add_node("sanitize", self._sanitize)
        g.add_node("intake", self._intake)
        g.add_node("enrich", self._enrich)
        g.add_node("decide", self._decide)
        g.add_node("apply_guardrails", self._apply_guardrails)
        g.add_node("simulate_remediation", self._simulate_remediation)
        g.add_node("suppress", self._suppress)
        g.add_node("escalate", self._escalate)
        g.add_node("hitl", self._hitl)

        g.add_edge(START, "sanitize")
        g.add_edge("sanitize", "intake")
        g.add_edge("intake", "enrich")
        g.add_edge("enrich", "decide")
        g.add_edge("decide", "apply_guardrails")
        g.add_conditional_edges(
            "apply_guardrails",
            self._route,
            {"simulate_remediation": "simulate_remediation", "suppress": "suppress", "escalate": "escalate", "hitl": "hitl"},
        )
        for terminal in ("simulate_remediation", "suppress", "escalate", "hitl"):
            g.add_edge(terminal, END)
        return g.compile()

    async def stream(self, alert: RawAlert):
        async for mode, chunk in self._graph.astream({"alert": alert}, stream_mode=["tasks", "updates"]):
            if mode == "tasks":
                if "input" in chunk:
                    yield "start", chunk["name"], None
            else:
                for node, out in chunk.items():
                    yield "done", node, out

    async def run(self, alert: RawAlert) -> TriageResult:
        out = await self._graph.ainvoke({"alert": alert})
        return out["result"]
