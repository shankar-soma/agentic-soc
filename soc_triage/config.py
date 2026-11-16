"""Runtime settings + environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _load_dotenv(path: str = ".env") -> None:
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


_load_dotenv()


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    intake_model: str = field(default_factory=lambda: _env("INTAKE_MODEL", "claude-haiku-5-5"))
    decision_model: str = field(default_factory=lambda: _env("DECISION_MODEL", "claude-sonnet-5-5"))
    openai_model: str = field(default_factory=lambda: _env("OPENAI_MODEL", "gpt-4.1-mini"))
    vllm_model: str = field(default_factory=lambda: _env("VLLM_MODEL", ""))
    anthropic_api_key: str | None = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY"))
    openai_api_key: str | None = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY"))
    vllm_api_key: str | None = field(default_factory=lambda: os.environ.get("VLLM_API_KEY"))
    
    # Use Qdrant server, otherwise embedded local mode
    qdrant_url: str | None = field(default_factory=lambda: os.environ.get("QDRANT_URL") or None)
    qdrant_path: str = field(default_factory=lambda: _env("QDRANT_PATH", "./.qdrant"))
    collection: str = field(default_factory=lambda: _env("QDRANT_COLLECTION", "otrf_recorded_events_v1"))
    top_k: int = 3
    
    # Below this score means guardrails will block decision agent from suppress/auto_remediate
    min_retrieval_score: float = 0.35
    min_intake_confidence: float = 0.6
    min_decision_confidence: float = 0.8
    llm_timeout_s: float = 30.0
    llm_max_retries: int = 2


settings = Settings()
