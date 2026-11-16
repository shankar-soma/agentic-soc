"""Unit tests for soc_triage/rag/store.py (IncidentStore). The Qdrant client is replaced by a fake."""

from types import SimpleNamespace

import pytest
from qdrant_client.http import models as qm

from soc_triage.rag import store as store_module
from soc_triage.rag.store import IncidentStore


class FakeClient:
    instances: list = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.exists = False
        self.created, self.upserts, self.queries, self.count_calls = [], [], [], []
        self.points = []
        self.closed = False
        FakeClient.instances.append(self)

    def collection_exists(self, name):
        return self.exists

    def create_collection(self, collection_name, vectors_config):
        self.created.append((collection_name, vectors_config))

    def upsert(self, collection_name, points):
        self.upserts.append((collection_name, points))

    def query_points(self, **kwargs):
        self.queries.append(kwargs)
        return SimpleNamespace(points=self.points)

    def count(self, name, exact):
        self.count_calls.append((name, exact))
        return SimpleNamespace(count=42)

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_qdrant(monkeypatch):
    FakeClient.instances = []
    monkeypatch.setattr(store_module, "QdrantClient", FakeClient)


def make_store(**kw):
    s = IncidentStore(collection="events", dim=4, **kw)
    return s, s.client


class TestConstruction:
    def test_url_selects_server_mode_with_a_long_timeout(self):
        _, client = make_store(url="http://q:6333")
        assert client.kwargs == {"url": "http://q:6333", "timeout": 120}

    def test_no_url_selects_embedded_mode_at_the_given_path(self):
        _, client = make_store(path="/data/q")
        assert client.kwargs == {"path": "/data/q"}

    def test_embedded_mode_defaults_to_dot_qdrant(self):
        _, client = make_store()
        assert client.kwargs == {"path": "./.qdrant"}

    def test_url_wins_over_path(self):
        _, client = make_store(url="http://q:6333", path="/ignored")
        assert "path" not in client.kwargs

    def test_empty_url_string_falls_back_to_embedded(self):
        _, client = make_store(url="", path="/p")
        assert client.kwargs == {"path": "/p"}

    def test_collection_and_dim_are_stored(self):
        s, _ = make_store()
        assert (s.collection, s.dim) == ("events", 4)


class TestEnsureCollection:
    def test_creates_a_cosine_collection_of_the_right_size_when_missing(self):
        s, client = make_store()
        s.ensure_collection()
        [(name, params)] = client.created
        assert name == "events" and params.size == 4 and params.distance == qm.Distance.COSINE

    def test_does_nothing_when_the_collection_exists(self):
        s, client = make_store()
        client.exists = True
        s.ensure_collection()
        assert client.created == []


class TestUpsert:
    def test_builds_one_point_per_item_with_id_vector_and_payload(self):
        s, client = make_store()
        s.upsert(["a", "b"], [[1, 0, 0, 0], [0, 1, 0, 0]], [{"k": 1}, {"k": 2}])
        [(name, points)] = client.upserts
        assert name == "events" and [p.id for p in points] == ["a", "b"]
        assert [p.payload for p in points] == [{"k": 1}, {"k": 2}]
        assert points[1].vector == [0, 1, 0, 0]

    def test_mismatched_lengths_raise_and_nothing_is_sent(self):
        s, client = make_store()
        with pytest.raises(ValueError):
            s.upsert(["a", "b"], [[1, 0, 0, 0]], [{"k": 1}, {"k": 2}])
        assert client.upserts == []

    def test_empty_batch_sends_an_empty_point_list(self):
        s, client = make_store()
        s.upsert([], [], [])
        assert client.upserts == [("events", [])]


class TestSearch:
    def point(self, pid="p1", score=0.9, payload=None):
        return SimpleNamespace(id=pid, score=score, payload=payload if payload is not None else {"summary": "s"})

    def test_query_uses_vector_limit_and_payload(self):
        s, client = make_store()
        s.search([1, 0, 0, 0], top_k=5)
        assert client.queries == [{"collection_name": "events", "query": [1, 0, 0, 0], "limit": 5, "with_payload": True}]

    def test_default_top_k_is_three(self):
        s, client = make_store()
        s.search([1, 0, 0, 0])
        assert client.queries[0]["limit"] == 3

    def test_no_results_returns_an_empty_list(self):
        s, _ = make_store()
        assert s.search([1, 0, 0, 0]) == []

    def test_points_become_retrieved_incidents(self):
        s, client = make_store()
        client.points = [self.point("p1", 0.91, {"summary": "text", "event_type": "process_create", "capture": "wmi"})]
        [inc] = s.search([1, 0, 0, 0])
        assert (inc.incident_id, inc.score, inc.summary, inc.event_type) == ("p1", 0.91, "text", "process_create")
        assert inc.metadata == {"event_type": "process_create", "capture": "wmi"}

    def test_integer_point_ids_become_strings(self):
        s, client = make_store()
        client.points = [self.point(pid=7)]
        assert s.search([1, 0, 0, 0])[0].incident_id == "7"

    def test_missing_summary_becomes_empty_string(self):
        s, client = make_store()
        client.points = [self.point(payload={"event_type": "x"})]
        assert s.search([1, 0, 0, 0])[0].summary == ""

    def test_missing_event_type_is_none(self):
        s, client = make_store()
        client.points = [self.point(payload={"summary": "s"})]
        assert s.search([1, 0, 0, 0])[0].event_type is None

    def test_none_values_are_dropped_from_metadata_and_summary_is_not_duplicated_there(self):
        s, client = make_store()
        client.points = [self.point(payload={"summary": "s", "hostname": None, "event_code": 10})]
        assert s.search([1, 0, 0, 0])[0].metadata == {"event_code": 10}

    def test_order_from_qdrant_is_preserved(self):
        s, client = make_store()
        client.points = [self.point("a", 0.9), self.point("b", 0.8), self.point("c", 0.7)]
        assert [i.incident_id for i in s.search([1, 0, 0, 0])] == ["a", "b", "c"]

    def test_score_is_converted_to_float(self):
        s, client = make_store()
        client.points = [self.point(score=1)]
        assert isinstance(s.search([1, 0, 0, 0])[0].score, float)


def test_count_asks_for_an_exact_count_and_returns_the_number():
    s, client = make_store()
    assert s.count() == 42 and client.count_calls == [("events", True)]


def test_close_closes_the_client():
    s, client = make_store()
    s.close()
    assert client.closed is True
