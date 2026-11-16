"""Shared helpers for agents for running LangChain agent and parse JSON reply"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

log = logging.getLogger("soc_triage")


def extract_json(text: str) -> dict[str, Any]:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in model output")
    value = json.loads(text[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("model JSON is not an object")
    return value


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return str(content)


def system_message(text: str, chat_model: Any) -> Any:
    from langchain_core.messages import SystemMessage

    if getattr(chat_model, "_llm_type", "") == "anthropic-chat":
        return SystemMessage(content=[{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}])
    return text


async def run_agent(agent: Any, user_text: str, timeout_s: float) -> str | None:
    try:
        result = await asyncio.wait_for(
            agent.ainvoke(
                {"messages": [{"role": "user", "content": user_text}]},
            ),
            timeout=timeout_s,
        )
        return _text_of(result["messages"][-1].content)
    except Exception as exc:
        log.warning("agent run failed: %r", exc)
        return None
