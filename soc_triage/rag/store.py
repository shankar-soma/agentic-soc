"""Qdrant-backed recorded-event store with cosine similarity scores."""

from __future__ import annotations

from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from soc_triage.models import RetrievedIncident


class IncidentStore:
    def __init__(self, collection: str, dim: int, url: str | None = None, path: str | None = None) -> None:
        if url:
            self.client = QdrantClient(url=url, timeout=120)
        else:
            self.client = QdrantClient(path=path or "./.qdrant")
        self.collection = collection
        self.dim = dim

    def ensure_collection(self) -> None:
        if self.client.collection_exists(self.collection):
            return
        self.client.create_collection(
            collection_name=self.collection,
            vectors_config=qm.VectorParams(size=self.dim, distance=qm.Distance.COSINE),
        )

    def upsert(self, ids: list[str], vectors: list[list[float]], payloads: list[dict[str, Any]]) -> None:
        self.client.upsert(
            collection_name=self.collection,
            points=[
                qm.PointStruct(id=pid, vector=vec, payload=pl)
                for pid, vec, pl in zip(ids, vectors, payloads, strict=True)
            ],
        )

    def search(
        self,
        vector: list[float],
        top_k: int = 3,
    ) -> list[RetrievedIncident]:
        result = self.client.query_points(
            collection_name=self.collection,
            query=vector,
            limit=top_k,
            with_payload=True,
        )
        return [
            RetrievedIncident(
                incident_id=str(p.id),
                summary=p.payload.get("summary", ""),
                score=float(p.score),
                event_type=p.payload.get("event_type"),
                metadata={k: v for k, v in p.payload.items() if k != "summary" and v is not None},
            )
            for p in result.points
        ]

    def count(self) -> int:
        return self.client.count(self.collection, exact=True).count

    def close(self) -> None:
        self.client.close()
