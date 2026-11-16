"""Unit tests for soc_triage/runtime.py. Every dependency build_runtime constructs is replaced by a recorder."""

from types import SimpleNamespace

import pytest

from soc_triage import runtime as rt
from soc_triage.runtime import Runtime, build_runtime
from factories import make_settings


@pytest.fixture
def wired(monkeypatch):
    seen = SimpleNamespace(chat=[], stores=[], pipelines=[], audits=[], embedder_kinds=[], ensured=[])
    settings = make_settings(intake_model="intake-m", decision_model="decision-m", collection="coll",
                             qdrant_url="http://q:6333", qdrant_path="/p")

    def fake_chat(s, model, backend, vllm_url=None):
        seen.chat.append((model, backend, vllm_url))
        return f"chat:{model}"

    def fake_embedder(kind):
        seen.embedder_kinds.append(kind)
        return SimpleNamespace(dim=99)

    class FakeStore:
        def __init__(self, **kwargs):
            seen.stores.append(kwargs)

        def ensure_collection(self):
            seen.ensured.append(True)

    class FakePipeline:
        def __init__(self, **kwargs):
            seen.pipelines.append(kwargs)

    class FakeAudit:
        def __init__(self, path):
            seen.audits.append(path)

    monkeypatch.setattr(rt, "default_settings", settings)
    monkeypatch.setattr(rt, "build_chat_model", fake_chat)
    monkeypatch.setattr(rt, "get_embedder", fake_embedder)
    monkeypatch.setattr(rt, "IncidentStore", FakeStore)
    monkeypatch.setattr(rt, "TriagePipeline", FakePipeline)
    monkeypatch.setattr(rt, "AuditLog", FakeAudit)
    seen.settings = settings
    return seen


def test_builds_separate_models_for_intake_and_decision(wired):
    build_runtime(backend="anthropic")
    assert wired.chat == [("intake-m", "anthropic", None), ("decision-m", "anthropic", None)]


def test_vllm_url_is_forwarded_to_both_models(wired):
    build_runtime(backend="vllm", vllm_url="https://x.ngrok-free.app")
    assert [c[2] for c in wired.chat] == ["https://x.ngrok-free.app"] * 2


def test_uses_the_fastembed_embedder(wired):
    build_runtime(backend="anthropic")
    assert wired.embedder_kinds == ["fastembed"]


def test_store_is_built_from_settings_with_the_embedder_dimension_and_prepared(wired):
    build_runtime(backend="anthropic")
    assert wired.stores == [{"collection": "coll", "dim": 99, "url": "http://q:6333", "path": "/p"}]
    assert wired.ensured == [True]


@pytest.mark.parametrize("path, expected", [(None, "./audit.jsonl"), ("/tmp/x.jsonl", "/tmp/x.jsonl")])
def test_audit_log_path_defaults_to_the_working_directory(wired, path, expected):
    build_runtime(backend="anthropic", **({"audit_path": path} if path else {}))
    assert wired.audits == [expected]


def test_pipeline_receives_every_dependency(wired):
    build_runtime(backend="gpt")
    [kwargs] = wired.pipelines
    assert kwargs["intake_llm"] == "chat:intake-m" and kwargs["decision_llm"] == "chat:decision-m"
    assert kwargs["backend"] == "gpt" and kwargs["settings"] is wired.settings
    assert {"embedder", "store", "audit", "queue"} <= set(kwargs)


def test_returns_a_runtime_that_shares_the_same_objects_as_the_pipeline(wired):
    result = build_runtime(backend="gpt")
    [kwargs] = wired.pipelines
    assert isinstance(result, Runtime)
    assert result.queue is kwargs["queue"] and result.intake_llm == "chat:intake-m"
    assert result.decision_llm == "chat:decision-m" and result.backend == "gpt" and result.settings is wired.settings


def test_a_model_configuration_error_stops_the_build_before_any_store_is_touched(wired, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    monkeypatch.setattr(rt, "build_chat_model", boom)
    with pytest.raises(RuntimeError):
        build_runtime(backend="anthropic")
    assert wired.stores == [] and wired.pipelines == []


def test_backend_is_a_required_keyword_argument():
    with pytest.raises(TypeError):
        build_runtime()
