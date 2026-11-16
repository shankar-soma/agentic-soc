"""Unit tests for soc_triage/graph.py. Every collaborator (agents, guardrails, sanitizer, queue, audit) is a stub,
so these tests check only what the graph itself does: routing, state hand-off, side effects, and stream translation."""

from types import SimpleNamespace

import pytest

from soc_triage import graph as graph_module
from soc_triage.graph import TriagePipeline
from soc_triage.models import Action, TriageResult
from factories import (
    make_alert,
    make_classified,
    make_decision,
    make_enrichment,
    make_guardrail,
    make_settings,
)


class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, event, alert_id, **data):
        self.events.append((event, alert_id, data))


class FakeQueue:
    def __init__(self):
        self.enqueued, self.reviews = [], []

    def enqueue(self, result):
        self.enqueued.append(result)

    def add_review(self, result):
        self.reviews.append(result)


@pytest.fixture
def pipe():
    audit, queue = FakeAudit(), FakeQueue()
    p = TriagePipeline(intake_llm="INTAKE", decision_llm="DECISION", backend="test", embedder="EMB", store="STORE",
                       settings=make_settings(), audit=audit, queue=queue)
    p.audit, p.queue = audit, queue
    return p


def state(**overrides):
    alert = make_alert()
    base = {
        "alert": alert, "alert_block": "<alert_data>x</alert_data>", "injection_flags": [],
        "classified": make_classified(alert=alert), "enrichment": make_enrichment(),
        "proposed": make_decision(), "guardrail": make_guardrail(),
    }
    base.update(overrides)
    return base


class TestConstruction:
    def test_dependencies_are_stored(self, pipe):
        assert (pipe.intake_llm, pipe.decision_llm, pipe.backend) == ("INTAKE", "DECISION", "test")
        assert (pipe.embedder, pipe.store) == ("EMB", "STORE")

    def test_a_search_tool_is_built_for_the_decision_agent(self, pipe):
        assert pipe.search_tool.name == "search_similar_incidents"

    def test_graph_has_exactly_the_expected_steps(self, pipe):
        names = set(pipe._graph.get_graph().nodes) - {"__start__", "__end__"}
        assert names == {"sanitize", "intake", "enrich", "decide", "apply_guardrails",
                         "simulate_remediation", "suppress", "escalate", "hitl"}

    def test_steps_run_in_the_fixed_order(self, pipe):
        edges = {(e.source, e.target) for e in pipe._graph.get_graph().edges}
        for a, b in [("__start__", "sanitize"), ("sanitize", "intake"), ("intake", "enrich"),
                     ("enrich", "decide"), ("decide", "apply_guardrails")]:
            assert (a, b) in edges

    def test_guardrails_branch_to_every_route_and_each_route_ends_the_run(self, pipe):
        edges = {(e.source, e.target) for e in pipe._graph.get_graph().edges}
        for route in ("simulate_remediation", "suppress", "escalate", "hitl"):
            assert ("apply_guardrails", route) in edges and (route, "__end__") in edges

    def test_no_step_can_skip_the_guardrails(self, pipe):
        edges = {(e.source, e.target) for e in pipe._graph.get_graph().edges}
        assert ("decide", "apply_guardrails") in edges
        assert not any(src == "decide" and tgt != "apply_guardrails" for src, tgt in edges)


class TestRoute:
    @pytest.mark.parametrize("action, approval, expected", [
        (Action.AUTO_REMEDIATE, False, "simulate_remediation"),
        (Action.SUPPRESS_AS_FALSE_POSITIVE, False, "suppress"),
        (Action.ESCALATE_TO_ANALYST, False, "escalate"),
        (Action.AUTO_REMEDIATE, True, "hitl"),
        (Action.ESCALATE_TO_ANALYST, True, "hitl"),
        (Action.SUPPRESS_AS_FALSE_POSITIVE, True, "hitl"),
    ])
    def test_route_for_each_guardrail_outcome(self, action, approval, expected):
        s = state(guardrail=make_guardrail(action, requires_human_approval=approval))
        assert TriagePipeline._route(s) == expected

    def test_human_approval_takes_priority_over_the_action(self):
        s = state(guardrail=make_guardrail(Action.SUPPRESS_AS_FALSE_POSITIVE, requires_human_approval=True))
        assert TriagePipeline._route(s) == "hitl"

    def test_a_missing_guardrail_result_is_an_error_not_a_default_route(self):
        with pytest.raises(KeyError):
            TriagePipeline._route({})


class TestFinish:
    def test_builds_a_triage_result_from_state(self, pipe):
        s = state()
        r = pipe._finish(s, "escalated")["result"]
        assert isinstance(r, TriageResult) and r.status == "escalated" and r.alert_id == s["alert"].event_id
        assert r.classification is s["classified"] and r.enrichment is s["enrichment"]
        assert r.proposed is s["proposed"] and r.guardrail is s["guardrail"]

    def test_missing_state_raises(self, pipe):
        s = state()
        s.pop("guardrail")
        with pytest.raises(KeyError):
            pipe._finish(s, "escalated")


class TestTerminalNodes:
    async def test_hitl_queues_for_approval_and_audits(self, pipe):
        out = await pipe._hitl(state())
        assert out["result"].status == "pending_approval"
        assert pipe.queue.enqueued == [out["result"]] and pipe.queue.reviews == []
        assert pipe.audit.events[0][0] == "hitl_enqueued"

    async def test_escalate_queues_for_analyst_review_and_audits(self, pipe):
        out = await pipe._escalate(state())
        assert out["result"].status == "escalated"
        assert pipe.queue.reviews == [out["result"]] and pipe.queue.enqueued == []
        assert pipe.audit.events[0][0] == "escalate"

    async def test_suppress_touches_no_queue_and_audits(self, pipe):
        out = await pipe._suppress(state())
        assert out["result"].status == "suppressed"
        assert pipe.queue.enqueued == [] and pipe.queue.reviews == []
        assert pipe.audit.events[0][0] == "suppress"

    async def test_simulated_remediation_touches_no_queue_and_records_the_action(self, pipe):
        out = await pipe._simulate_remediation(state())
        assert out["result"].status == "simulated_remediation"
        assert pipe.queue.enqueued == [] and pipe.queue.reviews == []
        event, alert_id, data = pipe.audit.events[0]
        assert event == "remediation_simulated" and data == {"action": "auto_remediate"}

    @pytest.mark.parametrize("node", ["_hitl", "_escalate", "_suppress", "_simulate_remediation"])
    async def test_audit_events_are_keyed_by_the_alert_id(self, pipe, node):
        s = state()
        await getattr(pipe, node)(s)
        assert pipe.audit.events[0][1] == s["alert"].event_id


class TestAnalysisNodes:
    async def test_sanitize_stores_block_and_flags_and_audits_flags(self, pipe, monkeypatch):
        monkeypatch.setattr(graph_module, "alert_block", lambda alert: ("BLOCK", ["role_override"]))
        out = await pipe._sanitize({"alert": make_alert()})
        assert out == {"alert_block": "BLOCK", "injection_flags": ["role_override"]}
        assert pipe.audit.events[0][0] == "sanitized" and pipe.audit.events[0][2] == {"injection_flags": ["role_override"]}

    async def test_intake_passes_the_right_inputs_and_audits_the_result(self, pipe, monkeypatch):
        seen = {}
        classified = make_classified()

        async def fake_classify(alert, block, llm, settings, backend):
            seen.update(block=block, llm=llm, backend=backend, settings=settings)
            return classified

        monkeypatch.setattr(graph_module, "classify", fake_classify)
        out = await pipe._intake(state())
        assert out == {"classified": classified}
        assert seen["block"] == "<alert_data>x</alert_data>" and seen["llm"] == "INTAKE" and seen["backend"] == "test"
        _, _, data = pipe.audit.events[0]
        assert data["severity"] == classified.severity.value and data["confidence"] == classified.confidence

    async def test_enrich_uses_the_embedder_and_store_and_audits_ids_and_weakness(self, pipe, monkeypatch):
        seen = {}
        enrichment = make_enrichment(max_score=0.4, weak=True)

        async def fake_enrich(alert, embedder, store, settings):
            seen.update(embedder=embedder, store=store)
            return enrichment

        monkeypatch.setattr(graph_module, "enrich", fake_enrich)
        out = await pipe._enrich(state())
        assert out == {"enrichment": enrichment} and (seen["embedder"], seen["store"]) == ("EMB", "STORE")
        _, _, data = pipe.audit.events[0]
        assert data["weak_retrieval"] is True and data["max_score"] == 0.4
        assert data["incident_ids"] == [i.incident_id for i in enrichment.incidents]

    async def test_decide_uses_the_decision_model_and_search_tool_and_audits(self, pipe, monkeypatch):
        seen = {}
        proposed = make_decision(Action.AUTO_REMEDIATE, 0.85)

        async def fake_decide(classified, enrichment, block, llm, settings, tool):
            seen.update(block=block, llm=llm, tool=tool)
            return proposed

        monkeypatch.setattr(graph_module, "decide", fake_decide)
        out = await pipe._decide(state())
        assert out == {"proposed": proposed}
        assert seen["llm"] == "DECISION" and seen["tool"] is pipe.search_tool
        _, _, data = pipe.audit.events[0]
        assert data == {"proposed": "auto_remediate", "confidence": 0.85}

    async def test_guardrails_receive_the_full_context_and_the_audit_records_the_outcome(self, pipe, monkeypatch):
        seen = {}
        outcome = make_guardrail(Action.ESCALATE_TO_ANALYST, overridden=True, reasons=["why"])

        def fake_guardrails(**kwargs):
            seen.update(kwargs)
            return outcome

        monkeypatch.setattr(graph_module, "apply_guardrails", fake_guardrails)
        s = state(injection_flags=["role_override"])
        out = await pipe._apply_guardrails(s)
        assert out == {"guardrail": outcome}
        assert seen["injection_flags"] == ["role_override"] and seen["settings"] is pipe.settings
        assert seen["alert"] is s["alert"] and seen["proposed"] is s["proposed"]
        _, _, data = pipe.audit.events[0]
        assert data["final_action"] == "escalate_to_analyst" and data["overridden"] is True
        assert data["reasons"] == ["why"] and data["requires_human_approval"] is False


class FakeGraph:
    def __init__(self, chunks=None, invoke_result=None):
        self.chunks, self.invoke_result, self.input = chunks or [], invoke_result, None

    async def astream(self, payload, stream_mode):
        self.input, self.mode = payload, stream_mode
        for chunk in self.chunks:
            yield chunk

    async def ainvoke(self, payload):
        self.input = payload
        return self.invoke_result


class TestStream:
    async def collect(self, pipe, chunks):
        pipe._graph = FakeGraph(chunks)
        return [item async for item in pipe.stream(make_alert())]

    async def test_task_start_becomes_a_start_event(self, pipe):
        out = await self.collect(pipe, [("tasks", {"name": "intake", "input": {}})])
        assert out == [("start", "intake", None)]

    async def test_task_end_events_are_ignored(self, pipe):
        assert await self.collect(pipe, [("tasks", {"name": "intake", "result": []})]) == []

    async def test_updates_become_done_events_with_the_node_output(self, pipe):
        out = await self.collect(pipe, [("updates", {"intake": {"classified": 1}})])
        assert out == [("done", "intake", {"classified": 1})]

    async def test_one_update_with_several_nodes_yields_each(self, pipe):
        out = await self.collect(pipe, [("updates", {"a": {"x": 1}, "b": {"y": 2}})])
        assert out == [("done", "a", {"x": 1}), ("done", "b", {"y": 2})]

    async def test_order_is_preserved(self, pipe):
        chunks = [("tasks", {"name": "s", "input": {}}), ("updates", {"s": {}}),
                  ("tasks", {"name": "t", "input": {}}), ("updates", {"t": {}})]
        assert [(k, n) for k, n, _ in await self.collect(pipe, chunks)] == [
            ("start", "s"), ("done", "s"), ("start", "t"), ("done", "t")]

    async def test_graph_is_asked_for_task_and_update_events_with_the_alert(self, pipe):
        await self.collect(pipe, [])
        assert pipe._graph.mode == ["tasks", "updates"] and set(pipe._graph.input) == {"alert"}


class TestRun:
    async def test_returns_the_result_from_the_final_state(self, pipe):
        sentinel = object()
        pipe._graph = FakeGraph(invoke_result={"result": sentinel})
        assert await pipe.run(make_alert()) is sentinel

    async def test_a_run_that_never_produced_a_result_is_an_error(self, pipe):
        pipe._graph = FakeGraph(invoke_result={})
        with pytest.raises(KeyError):
            await pipe.run(make_alert())
