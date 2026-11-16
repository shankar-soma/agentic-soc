"""Unit tests for soc_triage/rag/embedder.py. fastembed is replaced by a fake."""

import math
import sys
from types import SimpleNamespace

import pytest

from soc_triage.rag import embedder as emb
from soc_triage.rag.embedder import FastEmbedEmbedder, HashingEmbedder, get_embedder


def norm(vec):
    return math.sqrt(sum(v * v for v in vec))


class TestHashingEmbedder:
    def test_default_dimension_is_512(self):
        assert HashingEmbedder().dim == 512 and len(HashingEmbedder().embed(["x"])[0]) == 512

    def test_custom_dimension_is_respected(self):
        assert len(HashingEmbedder(dim=16).embed(["hello world"])[0]) == 16

    def test_vectors_are_unit_length(self):
        assert norm(HashingEmbedder().embed(["process start by cmd.exe"])[0]) == pytest.approx(1.0)

    def test_empty_text_gives_the_zero_vector_not_a_crash(self):
        vec = HashingEmbedder(dim=8).embed([""])[0]
        assert vec == [0.0] * 8

    def test_text_with_no_alphanumeric_tokens_gives_the_zero_vector(self):
        assert set(HashingEmbedder(dim=8).embed(["!!! ---"])[0]) == {0.0}

    def test_same_text_gives_the_same_vector(self):
        e = HashingEmbedder()
        assert e.embed(["abc def"]) == e.embed(["abc def"])

    def test_case_is_ignored(self):
        e = HashingEmbedder()
        assert e.embed(["Process CREATE"]) == e.embed(["process create"])

    def test_word_order_is_ignored(self):
        e = HashingEmbedder()
        assert e.embed(["alpha beta gamma"]) == e.embed(["gamma alpha beta"])

    def test_punctuation_is_ignored(self):
        e = HashingEmbedder()
        assert e.embed(["alpha-beta, gamma!"]) == e.embed(["alpha beta gamma"])

    def test_different_texts_give_different_vectors(self):
        e = HashingEmbedder()
        assert e.embed(["lsass dump"]) != e.embed(["browser update"])

    def test_identical_text_has_cosine_similarity_one(self):
        e = HashingEmbedder()
        a, b = e.embed(["credential dump lsass"])[0], e.embed(["credential dump lsass"])[0]
        assert sum(x * y for x, y in zip(a, b)) == pytest.approx(1.0)

    def test_batch_returns_one_vector_per_input_in_order(self):
        e = HashingEmbedder()
        out = e.embed(["one", "two", "three"])
        assert len(out) == 3 and out[1] == e.embed(["two"])[0]

    def test_empty_batch_returns_empty_list(self):
        assert HashingEmbedder().embed([]) == []

    def test_tokens_are_alphanumeric_runs(self):
        e = HashingEmbedder()
        assert e.embed(["abc123"]) != e.embed(["abc 123"])


class FakeTextEmbedding:
    seen_model = None

    def __init__(self, model_name):
        FakeTextEmbedding.seen_model = model_name

    def embed(self, texts):
        for i, _ in enumerate(texts):
            yield SimpleNamespace(tolist=lambda i=i: [float(i), 0.5])


class TestFastEmbedEmbedder:
    @pytest.fixture(autouse=True)
    def fake_fastembed(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "fastembed", SimpleNamespace(TextEmbedding=FakeTextEmbedding))

    def test_loads_the_bge_small_model(self):
        FastEmbedEmbedder()
        assert FakeTextEmbedding.seen_model == "BAAI/bge-small-en-v1.5"

    def test_dimension_is_384(self):
        assert FastEmbedEmbedder.dim == 384

    def test_returns_plain_python_lists_in_input_order(self):
        assert FastEmbedEmbedder().embed(["a", "b"]) == [[0.0, 0.5], [1.0, 0.5]]

    def test_empty_batch_returns_empty_list(self):
        assert FastEmbedEmbedder().embed([]) == []


class TestGetEmbedder:
    @pytest.fixture(autouse=True)
    def fresh_cache(self):
        get_embedder.cache_clear()
        yield
        get_embedder.cache_clear()

    def test_hashing_kind_returns_the_hashing_embedder(self):
        assert isinstance(get_embedder("hashing"), HashingEmbedder)

    def test_results_are_cached_per_kind(self):
        assert get_embedder("hashing") is get_embedder("hashing")

    def test_default_kind_is_fastembed(self, monkeypatch):
        monkeypatch.setattr(emb, "FastEmbedEmbedder", lambda: "FAST")
        assert get_embedder() == "FAST"

    def test_any_other_kind_falls_back_to_fastembed(self, monkeypatch):
        monkeypatch.setattr(emb, "FastEmbedEmbedder", lambda: "FAST")
        assert get_embedder("something-else") == "FAST"
