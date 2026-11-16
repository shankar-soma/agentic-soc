"""Unit tests for soc_triage/llm/chat.py. No network: httpx and the provider packages are faked."""

import sys
from types import SimpleNamespace

import httpx
import pytest

from soc_triage.llm import chat
from soc_triage.llm.chat import build_chat_model, discover_vllm_model, vllm_base_url
from factories import make_settings


class TestVllmBaseUrl:
    @pytest.mark.parametrize("url, expected", [
        ("https://abc.ngrok-free.app", "https://abc.ngrok-free.app/v1"),
        ("https://abc.ngrok-free.app/", "https://abc.ngrok-free.app/v1"),
        ("https://abc.ngrok-free.app/v1", "https://abc.ngrok-free.app/v1"),
        ("https://abc.ngrok-free.app/v1/", "https://abc.ngrok-free.app/v1"),
        ("  https://abc.ngrok-free.app  ", "https://abc.ngrok-free.app/v1"),
        ("HTTPS://ABC.NGROK-FREE.APP", "https://abc.ngrok-free.app/v1"),
        ("https://x.ngrok-free.dev", "https://x.ngrok-free.dev/v1"),
        ("https://x.ngrok.app", "https://x.ngrok.app/v1"),
        ("https://x.ngrok.dev", "https://x.ngrok.dev/v1"),
        ("https://x.ngrok.io", "https://x.ngrok.io/v1"),
    ])
    def test_accepts_https_ngrok_hosts(self, url, expected):
        assert vllm_base_url(url) == expected

    @pytest.mark.parametrize("url", [
        None, "", "   ", "abc.ngrok-free.app",
        "http://abc.ngrok-free.app",                         # not https
        "https://evil.com", "https://localhost:8000", "https://10.0.0.5",
        "https://ngrok-free.app",                            # no subdomain label
        "https://abc.ngrok-free.app.evil.com",               # suffix trick
        "https://evil-ngrok.io", "https://myngrok.io",       # not a real subdomain boundary
        "https://user:pw@abc.ngrok-free.app",                # credentials
        "https://user@abc.ngrok-free.app",
        "https://abc.ngrok-free.app:8443",                   # explicit port
        "https://abc.ngrok-free.app:notaport",
        "https://abc.ngrok-free.app?x=1",                    # query
        "https://abc.ngrok-free.app/#frag",                  # fragment
        "https://abc.ngrok-free.app/v1/chat/completions",    # extra path
        "https://abc.ngrok-free.app/other",
        "https://[::1",                                      # unparseable
        "ftp://abc.ngrok-free.app",
    ])
    def test_rejects_everything_else_with_a_clear_message(self, url):
        with pytest.raises(ValueError, match="public HTTPS ngrok URL"):
            vllm_base_url(url)


class FakeResponse:
    def __init__(self, payload=None, raise_exc=None, json_exc=None):
        self.payload, self.raise_exc, self.json_exc = payload, raise_exc, json_exc

    def raise_for_status(self):
        if self.raise_exc:
            raise self.raise_exc

    def json(self):
        if self.json_exc:
            raise self.json_exc
        return self.payload


@pytest.fixture
def fake_get(monkeypatch):
    discover_vllm_model.cache_clear()
    calls = []
    state = SimpleNamespace(response=FakeResponse({"data": [{"id": "my-model"}]}), exc=None)

    def get(url, **kwargs):
        calls.append((url, kwargs))
        if state.exc:
            raise state.exc
        return state.response

    monkeypatch.setattr(chat.httpx, "get", get)
    state.calls = calls
    yield state
    discover_vllm_model.cache_clear()


class TestDiscoverVllmModel:
    def test_returns_the_first_model_id(self, fake_get):
        fake_get.response = FakeResponse({"data": [{"id": "first"}, {"id": "second"}]})
        assert discover_vllm_model("https://h/v1", "key") == "first"

    def test_calls_the_models_endpoint_with_bearer_auth_and_no_redirects(self, fake_get):
        discover_vllm_model("https://h/v1", "secret")
        [(url, kwargs)] = fake_get.calls
        assert url == "https://h/v1/models" and kwargs["headers"] == {"Authorization": "Bearer secret"}
        assert kwargs["follow_redirects"] is False and kwargs["timeout"] == 12

    def test_result_is_cached_per_url_and_key(self, fake_get):
        discover_vllm_model("https://h/v1", "k")
        discover_vllm_model("https://h/v1", "k")
        assert len(fake_get.calls) == 1
        discover_vllm_model("https://h/v1", "other-key")
        assert len(fake_get.calls) == 2

    @pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.HTTPError("boom")])
    def test_network_errors_become_runtime_errors(self, fake_get, exc):
        fake_get.exc = exc
        with pytest.raises(RuntimeError, match="Could not read the vLLM model"):
            discover_vllm_model("https://h/v1", "k")

    def test_http_error_status_becomes_a_runtime_error(self, fake_get):
        fake_get.response = FakeResponse(raise_exc=httpx.HTTPError("401"))
        with pytest.raises(RuntimeError):
            discover_vllm_model("https://h/v1", "k")

    @pytest.mark.parametrize("payload", [
        {}, {"data": []}, {"data": "nope"}, {"data": [1]}, {"data": [{}]}, {"data": [{"id": 5}]}, {"data": None},
    ])
    def test_malformed_model_lists_raise_instead_of_returning_garbage(self, fake_get, payload):
        fake_get.response = FakeResponse(payload)
        with pytest.raises((RuntimeError, ValueError)):
            discover_vllm_model("https://h/v1", "k")

    @pytest.mark.parametrize("payload", [[], [{"id": "m"}], None, "text", 5])
    def test_non_object_json_is_reported_as_a_clean_error(self, fake_get, payload):
        # The UI only catches RuntimeError and ValueError, so nothing else may escape.
        fake_get.response = FakeResponse(payload)
        with pytest.raises(ValueError, match="no model ID"):
            discover_vllm_model("https://h/v1", "k")

    def test_invalid_json_body_raises_a_value_error(self, fake_get):
        fake_get.response = FakeResponse(json_exc=ValueError("bad json"))
        with pytest.raises((RuntimeError, ValueError)):
            discover_vllm_model("https://h/v1", "k")


class Recorder:
    """Stands in for ChatAnthropic / ChatOpenAI and records constructor arguments."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs


@pytest.fixture
def fake_providers(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_anthropic", SimpleNamespace(ChatAnthropic=Recorder))
    monkeypatch.setitem(sys.modules, "langchain_openai", SimpleNamespace(ChatOpenAI=Recorder))


class TestBuildChatModel:
    def test_anthropic_requires_a_key(self, fake_providers):
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            build_chat_model(make_settings(anthropic_api_key=None), "m", "anthropic")

    def test_anthropic_empty_key_counts_as_missing(self, fake_providers):
        with pytest.raises(RuntimeError):
            build_chat_model(make_settings(anthropic_api_key=""), "m", "anthropic")

    def test_anthropic_is_configured_from_settings(self, fake_providers):
        s = make_settings(anthropic_api_key="k", llm_timeout_s=12.0, llm_max_retries=4)
        assert build_chat_model(s, "claude-x", "anthropic").kwargs == {
            "model": "claude-x", "api_key": "k", "max_tokens": 1024, "timeout": 12.0, "max_retries": 4}

    def test_gpt_requires_a_key(self, fake_providers):
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
            build_chat_model(make_settings(openai_api_key=None), "m", "gpt")

    def test_gpt_uses_the_openai_model_from_settings_not_the_model_argument(self, fake_providers):
        s = make_settings(openai_api_key="k", openai_model="gpt-test")
        kwargs = build_chat_model(s, "ignored-model", "gpt").kwargs
        assert kwargs["model"] == "gpt-test" and kwargs["temperature"] == 0 and kwargs["api_key"] == "k"

    def test_vllm_rejects_a_bad_url_before_doing_anything_else(self, fake_providers):
        with pytest.raises(ValueError):
            build_chat_model(make_settings(), "m", "vllm", vllm_url="https://evil.com")

    def test_vllm_uses_the_configured_model_without_discovery(self, fake_providers, monkeypatch):
        monkeypatch.setattr(chat, "discover_vllm_model", lambda *a: pytest.fail("should not discover"))
        s = make_settings(vllm_model="served-model", vllm_api_key="vk", llm_timeout_s=10.0)
        kwargs = build_chat_model(s, "m", "vllm", vllm_url="https://abc.ngrok-free.app").kwargs
        assert kwargs["model"] == "served-model" and kwargs["base_url"] == "https://abc.ngrok-free.app/v1"
        assert kwargs["api_key"] == "vk" and kwargs["timeout"] == 20.0 and kwargs["temperature"] == 0

    def test_vllm_discovers_the_model_when_none_is_configured(self, fake_providers, monkeypatch):
        seen = {}

        def discover(base_url, key):
            seen["args"] = (base_url, key)
            return "discovered"

        monkeypatch.setattr(chat, "discover_vllm_model", discover)
        kwargs = build_chat_model(make_settings(vllm_model="", vllm_api_key=None), "m", "vllm",
                                  vllm_url="https://abc.ngrok-free.app/v1").kwargs
        assert kwargs["model"] == "discovered" and seen["args"] == ("https://abc.ngrok-free.app/v1", "EMPTY")
        assert kwargs["api_key"] == "EMPTY"

    @pytest.mark.parametrize("backend", ["", "mock", "ANTHROPIC", "openai", None])
    def test_unknown_backend_raises_value_error(self, fake_providers, backend):
        with pytest.raises(ValueError, match="Unknown model backend"):
            build_chat_model(make_settings(), "m", backend)
