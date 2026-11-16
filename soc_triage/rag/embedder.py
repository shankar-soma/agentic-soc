"""Text embedders"""

from __future__ import annotations

import hashlib
import math
import re
from functools import lru_cache
from typing import Protocol


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    name = "hashing"

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for tok in re.findall(r"[a-z0-9]+", text.lower()):
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
            vec[h % self.dim] += 1.0 if (h >> 1) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class FastEmbedEmbedder:
    """BAAI/bge-small-en-v1.5 via fastembed ONNX CPU"""

    name = "fastembed:BAAI/bge-small-en-v1.5"
    dim = 384

    def __init__(self) -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self._model.embed(texts)]


@lru_cache(maxsize=2)
def get_embedder(kind: str = "fastembed") -> Embedder:
    if kind == "hashing":
        return HashingEmbedder()
    return FastEmbedEmbedder()
