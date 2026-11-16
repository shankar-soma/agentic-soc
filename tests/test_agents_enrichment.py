"""Unit tests for soc_triage/agents/enrichment.py. Embedder and store are fakes."""

import logging

import pytest

from soc_triage.agents.enrichment import enrich
from factories import make_alert, make_incident, make_settings


class FakeEmbedder:
    def __init__(self, exc=None):
        self.exc, self.seen = exc, []

    def embed(self, texts):
        self.seen.append(texts)
        if self.exc:
            raise self.exc
        return [[0.5, 0.5]]


class FakeStore:
    def __init__(self, hits=None, exc=None):
        self.hits, self.exc, self.calls = hits or [], exc, []

    def search(self, vector, top_k):
        self.calls.append((vector, top_k))
        if self.exc:
            raise self.exc
        return self.hits


async def run(alert=None, hits=None, embedder=None, store=None, settings=None):
    store = store or FakeStore(hits)
    return await enrich(alert or make_alert(event_type="process_create"), embedder or FakeEmbedder(), store,
                        settings or make_settings())


class TestSuccessfulLookup:
    async def test_returns_the_incidents_unchanged(self):
        hits = [make_incident(0.9, incident_id="a"), make_incident(0.8, incident_id="b")]
        e = await run(hits=hits)
        assert [i.incident_id for i in e.incidents] == ["a", "b"]

    async def test_max_score_is_the_highest_score_regardless_of_order(self):
        e = await run(hits=[make_incident(0.5), make_incident(0.95), make_incident(0.7)])
        assert e.max_score == 0.95

    async def test_strong_same_type_match_is_not_weak(self):
        assert (await run(hits=[make_incident(0.9)])).weak_retrieval is False

    async def test_score_exactly_at_threshold_is_not_weak(self):
        assert (await run(hits=[make_incident(0.35)])).weak_retrieval is False

    async def test_score_just_below_threshold_is_weak(self):
        assert (await run(hits=[make_incident(0.349)])).weak_retrieval is True

    async def test_threshold_comes_from_settings(self):
        e = await run(hits=[make_incident(0.5)], settings=make_settings(min_retrieval_score=0.6))
        assert e.weak_retrieval is True

    async def test_high_score_but_no_matching_event_type_is_weak(self):
        e = await run(hits=[make_incident(0.99, event_type="network_connection")])
        assert e.weak_retrieval is True and e.max_score == 0.99

    async def test_one_matching_event_type_among_others_is_enough(self):
        hits = [make_incident(0.9, event_type="network_connection"), make_incident(0.8, event_type="process_create")]
        assert (await run(hits=hits)).weak_retrieval is False

    async def test_no_incidents_is_weak_with_zero_score(self):
        e = await run(hits=[])
        assert e.incidents == [] and e.max_score == 0.0 and e.weak_retrieval is True

    async def test_event_type_comparison_is_exact_and_case_sensitive(self):
        e = await run(hits=[make_incident(0.9, event_type="Process_Create")])
        assert e.weak_retrieval is True

    async def test_missing_event_type_on_both_sides_counts_as_a_match(self):
        e = await run(alert=make_alert(event_type=None), hits=[make_incident(0.9, event_type=None)])
        assert e.weak_retrieval is False


class TestWhatIsSentToTheCollaborators:
    async def test_embeds_exactly_one_text_built_from_the_alert(self):
        embedder = FakeEmbedder()
        await run(alert=make_alert(event_type="process_create", description="runs bitsadmin"), embedder=embedder)
        [[query]] = embedder.seen
        assert "process_create" in query and "runs bitsadmin" in query

    async def test_searches_with_the_vector_and_top_k_from_settings(self):
        store = FakeStore([])
        await run(store=store, settings=make_settings(top_k=7))
        assert store.calls == [([0.5, 0.5], 7)]


class TestFailClosed:
    async def test_embedder_failure_returns_weak_empty_enrichment(self):
        e = await run(embedder=FakeEmbedder(exc=RuntimeError("model missing")))
        assert e.incidents == [] and e.max_score == 0.0 and e.weak_retrieval is True

    async def test_store_failure_returns_weak_empty_enrichment(self):
        e = await run(store=FakeStore(exc=ConnectionError("qdrant down")))
        assert e.incidents == [] and e.max_score == 0.0 and e.weak_retrieval is True

    async def test_failure_is_logged(self, caplog):
        with caplog.at_level(logging.WARNING, logger="soc_triage"):
            await run(store=FakeStore(exc=ConnectionError("qdrant down")))
        assert "enrichment unavailable" in caplog.text

    async def test_store_is_not_queried_if_embedding_failed(self):
        store = FakeStore([])
        await run(embedder=FakeEmbedder(exc=RuntimeError("x")), store=store)
        assert store.calls == []
