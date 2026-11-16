"""Unit tests for soc_triage/config.py: dotenv loading and Settings defaults."""

import dataclasses
import os

import pytest

from soc_triage.config import Settings, _env, _load_dotenv

SETTING_ENV = ["INTAKE_MODEL", "DECISION_MODEL", "OPENAI_MODEL", "VLLM_MODEL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
               "VLLM_API_KEY", "QDRANT_URL", "QDRANT_PATH", "QDRANT_COLLECTION"]


@pytest.fixture
def clean_env(monkeypatch):
    for name in SETTING_ENV:
        monkeypatch.delenv(name, raising=False)


class TestEnvHelper:
    def test_returns_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("X_UNIT_TEST_VAR", raising=False)
        assert _env("X_UNIT_TEST_VAR", "fallback") == "fallback"

    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("X_UNIT_TEST_VAR", "real")
        assert _env("X_UNIT_TEST_VAR", "fallback") == "real"

    def test_empty_string_counts_as_set(self, monkeypatch):
        monkeypatch.setenv("X_UNIT_TEST_VAR", "")
        assert _env("X_UNIT_TEST_VAR", "fallback") == ""


class TestLoadDotenv:
    def _write(self, tmp_path, text):
        p = tmp_path / ".env"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_sets_variables_that_are_not_already_set(self, tmp_path, monkeypatch):
        monkeypatch.delenv("UT_A", raising=False)
        _load_dotenv(self._write(tmp_path, "UT_A=hello\n"))
        assert os.environ["UT_A"] == "hello"

    def test_does_not_override_existing_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("UT_B", "from-shell")
        _load_dotenv(self._write(tmp_path, "UT_B=from-file\n"))
        assert os.environ["UT_B"] == "from-shell"

    def test_ignores_comments_blank_lines_and_lines_without_equals(self, tmp_path, monkeypatch):
        for name in ("UT_C", "UT_D"):
            monkeypatch.delenv(name, raising=False)
        _load_dotenv(self._write(tmp_path, "# comment\n\nnot a pair\nUT_C=1\n  # indented comment\nUT_D=2\n"))
        assert os.environ["UT_C"] == "1" and os.environ["UT_D"] == "2"
        assert "not a pair" not in os.environ

    def test_strips_surrounding_quotes_and_whitespace(self, tmp_path, monkeypatch):
        for name in ("UT_E", "UT_F", "UT_G"):
            monkeypatch.delenv(name, raising=False)
        _load_dotenv(self._write(tmp_path, 'UT_E = "double"\nUT_F=\'single\'\nUT_G =  spaced  \n'))
        assert (os.environ["UT_E"], os.environ["UT_F"], os.environ["UT_G"]) == ("double", "single", "spaced")

    def test_value_may_contain_equals_signs(self, tmp_path, monkeypatch):
        monkeypatch.delenv("UT_H", raising=False)
        _load_dotenv(self._write(tmp_path, "UT_H=a=b=c\n"))
        assert os.environ["UT_H"] == "a=b=c"

    def test_empty_value_is_set_as_empty_string(self, tmp_path, monkeypatch):
        monkeypatch.delenv("UT_I", raising=False)
        _load_dotenv(self._write(tmp_path, "UT_I=\n"))
        assert os.environ["UT_I"] == ""

    def test_missing_file_is_silently_ignored(self, tmp_path):
        _load_dotenv(str(tmp_path / "does-not-exist.env"))  # must not raise


class TestSettingsDefaults:
    def test_thresholds_and_limits(self, clean_env):
        s = Settings()
        assert (s.top_k, s.min_retrieval_score, s.min_intake_confidence, s.min_decision_confidence) == (3, 0.35, 0.6, 0.8)
        assert (s.llm_timeout_s, s.llm_max_retries) == (30.0, 2)

    def test_default_models_and_collection(self, clean_env):
        s = Settings()
        assert s.intake_model == "claude-haiku-5-5" and s.decision_model == "claude-sonnet-5-5"
        assert s.openai_model == "gpt-4.1-mini" and s.vllm_model == ""
        assert s.collection == "otrf_recorded_events_v1" and s.qdrant_path == "./.qdrant"

    def test_api_keys_default_to_none(self, clean_env):
        s = Settings()
        assert s.anthropic_api_key is None and s.openai_api_key is None and s.vllm_api_key is None

    def test_environment_overrides_are_read_at_construction(self, clean_env, monkeypatch):
        monkeypatch.setenv("QDRANT_COLLECTION", "other")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        s = Settings()
        assert s.collection == "other" and s.anthropic_api_key == "k"

    @pytest.mark.parametrize("raw, expected", [("", None), ("http://localhost:6333", "http://localhost:6333")])
    def test_empty_qdrant_url_means_embedded_mode(self, clean_env, monkeypatch, raw, expected):
        monkeypatch.setenv("QDRANT_URL", raw)
        assert Settings().qdrant_url == expected

    def test_settings_are_immutable(self, clean_env):
        with pytest.raises(dataclasses.FrozenInstanceError):
            Settings().top_k = 9

    def test_explicit_arguments_override_environment(self, clean_env, monkeypatch):
        monkeypatch.setenv("INTAKE_MODEL", "from-env")
        assert Settings(intake_model="explicit").intake_model == "explicit"
