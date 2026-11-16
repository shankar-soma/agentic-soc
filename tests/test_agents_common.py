"""Unit tests for soc_triage/agents/common.py."""

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from langchain_core.messages import SystemMessage

from soc_triage.agents.common import _text_of, extract_json, run_agent, system_message


class TestExtractJson:
    def test_plain_object(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_object_surrounded_by_prose(self):
        assert extract_json('Sure! Here you go: {"a": 1} Hope that helps.') == {"a": 1}

    def test_object_inside_markdown_fences(self):
        assert extract_json('```json\n{"a": {"b": [1, 2]}}\n```') == {"a": {"b": [1, 2]}}

    def test_nested_objects_are_returned_whole(self):
        assert extract_json('{"outer": {"inner": 1}}') == {"outer": {"inner": 1}}

    def test_braces_inside_string_values_are_fine(self):
        assert extract_json('{"a": "x } y { z"}') == {"a": "x } y { z"}

    @pytest.mark.parametrize("text", ["", "no json here", "[1, 2, 3]", "just } a closing brace", "} {"])
    def test_text_without_an_object_raises_value_error(self, text):
        with pytest.raises(ValueError):
            extract_json(text)

    def test_malformed_json_raises_value_error(self):
        with pytest.raises(ValueError):
            extract_json('{"a": 1,}')

    def test_two_separate_objects_are_rejected_not_merged(self):
        with pytest.raises(ValueError):
            extract_json('{"a": 1} and then {"b": 2}')

    def test_truncated_output_raises(self):
        with pytest.raises(ValueError):
            extract_json('{"severity": "High", "rationale": "cut off mid')


class TestTextOf:
    def test_string_passes_through(self):
        assert _text_of("hello") == "hello"

    def test_list_of_text_blocks_is_joined(self):
        assert _text_of([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]) == "ab"

    def test_non_text_blocks_and_non_dicts_are_skipped(self):
        content = [{"type": "tool_use", "text": "x"}, "stray", {"type": "text", "text": "keep"}, 5]
        assert _text_of(content) == "keep"

    def test_text_block_without_text_key_contributes_nothing(self):
        assert _text_of([{"type": "text"}]) == ""

    def test_empty_list_is_empty_string(self):
        assert _text_of([]) == ""

    def test_other_types_are_stringified(self):
        assert _text_of(42) == "42"
        assert _text_of(None) == "None"


class TestSystemMessage:
    def test_plain_text_for_non_anthropic_models(self):
        assert system_message("rules", SimpleNamespace(_llm_type="openai-chat")) == "rules"

    def test_plain_text_when_model_has_no_type(self):
        assert system_message("rules", object()) == "rules"

    def test_anthropic_gets_a_cacheable_system_message(self):
        msg = system_message("rules", SimpleNamespace(_llm_type="anthropic-chat"))
        assert isinstance(msg, SystemMessage)
        assert msg.content == [{"type": "text", "text": "rules", "cache_control": {"type": "ephemeral"}}]


class FakeAgent:
    def __init__(self, result=None, exc=None, delay=0.0):
        self.result, self.exc, self.delay, self.payload = result, exc, delay, None

    async def ainvoke(self, payload):
        self.payload = payload
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.result


def reply(content):
    return {"messages": [SimpleNamespace(content="ignored first"), SimpleNamespace(content=content)]}


class TestRunAgent:
    async def test_returns_the_last_message_text(self):
        assert await run_agent(FakeAgent(reply("final")), "hi", 5) == "final"

    async def test_sends_the_user_text_as_a_single_user_message(self):
        agent = FakeAgent(reply("x"))
        await run_agent(agent, "the alert", 5)
        assert agent.payload == {"messages": [{"role": "user", "content": "the alert"}]}

    async def test_block_content_is_flattened(self):
        agent = FakeAgent(reply([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]))
        assert await run_agent(agent, "hi", 5) == "ab"

    async def test_timeout_returns_none(self):
        assert await run_agent(FakeAgent(reply("late"), delay=1.0), "hi", 0.01) is None

    async def test_exception_returns_none_and_is_logged(self, caplog):
        with caplog.at_level(logging.WARNING, logger="soc_triage"):
            assert await run_agent(FakeAgent(exc=ConnectionError("down")), "hi", 5) is None
        assert "agent run failed" in caplog.text

    @pytest.mark.parametrize("bad_result", [{}, {"messages": []}, None])
    async def test_malformed_agent_result_returns_none(self, bad_result):
        assert await run_agent(FakeAgent(bad_result), "hi", 5) is None

    async def test_empty_reply_text_is_returned_as_empty_string_not_none(self):
        assert await run_agent(FakeAgent(reply("")), "hi", 5) == ""
