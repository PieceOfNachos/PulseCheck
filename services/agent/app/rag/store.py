"""Qdrant-backed knowledge base over runbooks and past incidents."""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import ClassVar

from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from app.config import settings
from app.contracts import RetrievedDoc
from app.rag.chunker import chunk_markdown

RUNBOOKS = "runbooks"
PAST_INCIDENTS = "past_incidents"


def _point_id(key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, key))


class KnowledgeBase:
    """Runbook chunks and resolved incidents, searchable by semantic similarity."""

    _embedders: ClassVar[dict[str, TextEmbedding]] = {}
    _dims: ClassVar[dict[str, int]] = {}
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self, url: str = settings.qdrant_url, embed_model: str = settings.embed_model
    ) -> None:
        self.url = url
        self.embed_model = embed_model
        self.client = QdrantClient(":memory:") if url == ":memory:" else QdrantClient(url=url)
        self._ready = False

    # ── embeddings ──
    @property
    def embedder(self) -> TextEmbedding:
        """Load the embedding model once per process and share it across instances."""
        with self._lock:
            model = self._embedders.get(self.embed_model)
            if model is None:
                model = TextEmbedding(model_name=self.embed_model)
                self._embedders[self.embed_model] = model
                self._dims[self.embed_model] = len(next(iter(model.embed(["probe"]))))
            return model

    @property
    def dim(self) -> int:
        """Vector size reported by the model itself rather than hardcoded."""
        _ = self.embedder
        return self._dims[self.embed_model]

    def _embed_passages(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self.embedder.passage_embed(texts)]

    def _embed_query(self, text: str) -> list[float]:
        return next(iter(self.embedder.query_embed(text))).tolist()

    # ── collections ──
    def ensure_collections(self) -> None:
        """Create the runbook and incident collections if they don't exist yet."""
        for name in (RUNBOOKS, PAST_INCIDENTS):
            if not self.client.collection_exists(name):
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=qm.VectorParams(size=self.dim, distance=qm.Distance.COSINE),
                )
        self._ready = True

    def _ensure(self) -> None:
        if not self._ready:
            self.ensure_collections()

    # ── indexing ──
    def index_runbook(self, text: str, source: str) -> int:
        """Chunk, embed and upsert one runbook, replacing any earlier version of it."""
        self._ensure()
        chunks = chunk_markdown(text, source)
        self.client.delete(
            collection_name=RUNBOOKS,
            points_selector=qm.FilterSelector(filter=_match("source", source)),
        )
        if not chunks:
            return 0
        vectors = self._embed_passages([f"{c['title']}\n{c['text']}" for c in chunks])
        self.client.upsert(
            collection_name=RUNBOOKS,
            points=[
                qm.PointStruct(id=_point_id(f"{source}#{i}"), vector=vec, payload=chunk)
                for i, (chunk, vec) in enumerate(zip(chunks, vectors))
            ],
        )
        return len(chunks)

    def index_runbooks_dir(self, path: str | Path) -> int:
        """Index every ``*.md`` file in ``path``; returns the total chunk count."""
        total = 0
        for file in sorted(Path(path).glob("*.md")):
            total += self.index_runbook(file.read_text(encoding="utf-8"), file.name)
        return total

    def index_incident(self, incident_id: str, user_id: str, text: str, category: str) -> None:
        """Store a resolved incident summary so its owner can retrieve it later."""
        self._ensure()
        title = f"Past {category} incident {incident_id}"
        vector = self._embed_passages([f"{title}\n{text}"])[0]
        self.client.upsert(
            collection_name=PAST_INCIDENTS,
            points=[
                qm.PointStruct(
                    id=_point_id(incident_id),
                    vector=vector,
                    payload={
                        "source": f"incident:{incident_id}",
                        "title": title,
                        "text": text,
                        "user_id": user_id,
                        "category": category,
                    },
                )
            ],
        )

    # ── retrieval ──
    def search(self, query: str, k: int = 3, user_id: str | None = None) -> list[RetrievedDoc]:
        """Top-k runbook chunks plus this user's past incidents, merged by score."""
        self._ensure()
        vector = self._embed_query(query)
        hits = self._query(RUNBOOKS, vector, k)
        if user_id is not None:
            hits += self._query(PAST_INCIDENTS, vector, k, _match("user_id", user_id))
        hits.sort(key=lambda p: p.score, reverse=True)
        return [_to_doc(p) for p in hits[:k]]

    def _query(
        self, collection: str, vector: list[float], k: int, flt: qm.Filter | None = None
    ) -> list[qm.ScoredPoint]:
        response = self.client.query_points(
            collection_name=collection,
            query=vector,
            query_filter=flt,
            limit=k,
            with_payload=True,
        )
        return list(response.points)


def _match(key: str, value: str) -> qm.Filter:
    return qm.Filter(must=[qm.FieldCondition(key=key, match=qm.MatchValue(value=value))])


def _to_doc(point: qm.ScoredPoint) -> RetrievedDoc:
    payload = point.payload or {}
    return RetrievedDoc(
        source=str(payload.get("source", "")),
        title=str(payload.get("title", "")),
        text=str(payload.get("text", "")),
        score=float(point.score),
    )


__all__ =["KnowledgeBase", "RUNBOOKS", "PAST_INCIDENTS"]
