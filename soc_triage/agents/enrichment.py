"""Context enrichment agent for RAG lookup of the top-3 most similar historical incidents"""

from __future__ import annotations

import asyncio
import logging

from soc_triage.config import Settings
from soc_triage.models import Enrichment, RawAlert
from soc_triage.rag.embedder import Embedder
from soc_triage.rag.text import summarize
from soc_triage.rag.store import IncidentStore

log = logging.getLogger("soc_triage")


async def enrich(
    alert: RawAlert,
    embedder: Embedder,
    store: IncidentStore,
    settings: Settings,
) -> Enrichment:
    query = summarize(alert)
    try:
        vector = (await asyncio.to_thread(embedder.embed, [query]))[0]
        incidents = await asyncio.to_thread(store.search, vector, settings.top_k)
    except Exception as exc:
        log.warning("enrichment unavailable, failing closed: %s", exc)
        return Enrichment(incidents=[], max_score=0.0, weak_retrieval=True)
    max_score = max((i.score for i in incidents), default=0.0)
    same_event_type = any(i.event_type == alert.event_type for i in incidents)
    return Enrichment(
        incidents=incidents,
        max_score=max_score,
        weak_retrieval=max_score < settings.min_retrieval_score or not same_event_type,
    )
