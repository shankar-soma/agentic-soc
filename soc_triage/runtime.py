"""Build the full pipeline and its UI runtime from settings"""

from __future__ import annotations

from dataclasses import dataclass

from soc_triage.audit import AuditLog
from soc_triage.config import Settings, settings as default_settings
from soc_triage.graph import TriagePipeline
from soc_triage.hitl import ApprovalQueue
from langchain_core.language_models.chat_models import BaseChatModel

from soc_triage.llm.chat import build_chat_model
from soc_triage.rag.embedder import Embedder, get_embedder
from soc_triage.rag.store import IncidentStore


@dataclass
class Runtime:
    pipeline: TriagePipeline
    queue: ApprovalQueue
    store: IncidentStore
    intake_llm: BaseChatModel
    decision_llm: BaseChatModel
    backend: str
    settings: Settings


def build_runtime(*, backend: str, audit_path: str = "./audit.jsonl", vllm_url: str | None = None) -> Runtime:
    settings = default_settings
    intake_llm = build_chat_model(settings, settings.intake_model, backend, vllm_url=vllm_url)
    decision_llm = build_chat_model(settings, settings.decision_model, backend, vllm_url=vllm_url)
    embedder: Embedder = get_embedder("fastembed")
    store = IncidentStore(
        collection=settings.collection,
        dim=embedder.dim,
        url=settings.qdrant_url,
        path=settings.qdrant_path,
    )
    store.ensure_collection()
    queue = ApprovalQueue()
    pipeline = TriagePipeline(
        intake_llm=intake_llm,
        decision_llm=decision_llm,
        backend=backend,
        embedder=embedder,
        store=store,
        settings=settings,
        audit=AuditLog(audit_path),
        queue=queue,
    )
    return Runtime(
        pipeline=pipeline, queue=queue, store=store, intake_llm=intake_llm, decision_llm=decision_llm, backend=backend, settings=settings
    )
