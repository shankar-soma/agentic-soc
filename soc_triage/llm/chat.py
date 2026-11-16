"""LangChain chat models for the configured external backend."""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

import httpx

from langchain_core.language_models.chat_models import BaseChatModel

from soc_triage.config import Settings

NGROK_SUFFIXES = (".ngrok-free.app", ".ngrok-free.dev", ".ngrok.app", ".ngrok.dev", ".ngrok.io")


def vllm_base_url(public_url: str | None) -> str:
    """Accept a public HTTPS ngrok endpoint and append the OpenAI API prefix."""
    try:
        parsed = urlparse((public_url or "").strip().rstrip("/"))
        host = (parsed.hostname or "").lower()
        valid = (
            parsed.scheme == "https" and host.endswith(NGROK_SUFFIXES)
            and not parsed.username and not parsed.password and parsed.port is None
            and not parsed.query and not parsed.fragment and parsed.path in ("", "/v1")
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Enter the public HTTPS ngrok URL for your vLLM server")
    return f"https://{host}/v1"


@lru_cache(maxsize=16)
def discover_vllm_model(base_url: str, api_key: str) -> str:
    """Read the model ID served by vLLM; no alert content is sent."""
    try:
        response = httpx.get(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=12,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
        models = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(models, list) or not models or not isinstance(models[0], dict) or not isinstance(models[0].get("id"), str):
            raise ValueError("vLLM returned no model ID from /v1/models")
        return models[0]["id"]
    except (httpx.HTTPError, KeyError, TypeError) as exc:
        raise RuntimeError(f"Could not read the vLLM model from /v1/models: {exc}") from exc


def build_chat_model(settings: Settings, model: str, backend: str, *, vllm_url: str | None = None) -> BaseChatModel:
    if backend == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=model,
            api_key=settings.anthropic_api_key,
            max_tokens=1024,
            timeout=settings.llm_timeout_s,
            max_retries=settings.llm_max_retries,
        )
    if backend == "gpt":
        if not settings.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=0,
            timeout=settings.llm_timeout_s,
            max_retries=settings.llm_max_retries,
        )
    if backend == "vllm":
        from langchain_openai import ChatOpenAI

        base_url = vllm_base_url(vllm_url)
        api_key = settings.vllm_api_key or "EMPTY"
        model_id = settings.vllm_model or discover_vllm_model(base_url, api_key)
        return ChatOpenAI(
            model=model_id, base_url=base_url, api_key=api_key,
            temperature=0, timeout=settings.llm_timeout_s * 2,
            max_retries=settings.llm_max_retries,
        )
    raise ValueError(f"Unknown model backend: {backend!r}")
