"""Mongo persistence for incidents and monitors, plus an in-memory stand-in for tests."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from functools import lru_cache
from types import SimpleNamespace
from typing import Any, Iterable

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient
from pymongo.database import Database

from app.config import settings


@lru_cache(maxsize=1)
def get_db() -> Database:
    """Shared database handle (the client connects lazily)."""
    client: MongoClient = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    return client[settings.mongo_db]


def to_object_id(value: Any) -> ObjectId | None:
    """Parse a Mongo ObjectId, returning ``None`` for anything invalid."""
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentRepo:
    """Incidents keyed by ``alertEventId`` (stored as ``_id``, exposed as ``id``)."""

    def __init__(self, collection: Any) -> None:
        self.collection = collection

    @staticmethod
    def _serialise(doc: dict | None) -> dict | None:
        if doc is None:
            return None
        out = {k: v for k, v in doc.items() if k != "_id"}
        return {"id": str(doc["_id"]), **out}

    def upsert(self, doc: dict) -> None:
        """Insert or update an incident; ``createdAt`` is only written on insert."""
        fields = dict(doc)
        incident_id = fields.pop("id", None) or fields.pop("_id")
        fields.pop("_id", None)
        created = fields.pop("createdAt", None) or _now()
        fields["updatedAt"] = _now()
        self.collection.update_one(
            {"_id": incident_id},
            {"$set": fields, "$setOnInsert": {"createdAt": created}},
            upsert=True,
        )

    def exists(self, incident_id: str) -> bool:
        """True if any user's incident already uses this id."""
        return self.collection.find_one({"_id": incident_id}, {"_id": 1}) is not None

    def get(self, incident_id: str, user_id: str) -> dict | None:
        return self._serialise(self.collection.find_one({"_id": incident_id, "userId": user_id}))

    def list(self, user_id: str) -> list[dict]:
        docs = self.collection.find({"userId": user_id}, sort=[("createdAt", -1)])
        return [self._serialise(d) for d in docs]


class MonitorRepo:
    """Read and pause the monitors owned by the Node monitoring service."""

    def __init__(self, collection: Any) -> None:
        self.collection = collection

    @staticmethod
    def _owner_filter(monitor_id: str, user_id: str) -> dict | None:
        mid, uid = to_object_id(monitor_id), to_object_id(user_id)
        return None if mid is None or uid is None else {"_id": mid, "userId": uid}

    def get_owned(self, monitor_id: str, user_id: str) -> dict | None:
        query = self._owner_filter(monitor_id, user_id)
        doc = self.collection.find_one(query) if query else None
        if doc is None:
            return None
        return {**doc, "_id": str(doc["_id"]), "userId": str(doc["userId"])}

    def pause(self, monitor_id: str, user_id: str) -> bool:
        """Set ``active=false``; only matches a monitor owned by ``user_id``."""
        query = self._owner_filter(monitor_id, user_id)
        if query is None:
            return False
        result = self.collection.update_one(
            query, {"$set": {"active": False, "updatedAt": datetime.now(timezone.utc)}}
        )
        return result.matched_count == 1


# ── In-memory collection ──────────────────────────────────────────────────────


def _get_path(doc: dict, key: str) -> Any:
    value: Any = doc
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


_MISSING = object()


def _match_value(value: Any, cond: Any) -> bool:
    if isinstance(cond, dict) and cond and all(k.startswith("$") for k in cond):
        for op, arg in cond.items():
            present = value is not _MISSING
            if op == "$eq" and not (present and value == arg):
                return False
            if op == "$ne" and present and value == arg:
                return False
            if op == "$in" and not (present and value in arg):
                return False
            if op == "$nin" and present and value in arg:
                return False
            if op == "$exists" and present != bool(arg):
                return False
            if op in ("$gt", "$gte", "$lt", "$lte"):
                if not present or value is None:
                    return False
                if op == "$gt" and not value > arg:
                    return False
                if op == "$gte" and not value >= arg:
                    return False
                if op == "$lt" and not value < arg:
                    return False
                if op == "$lte" and not value <= arg:
                    return False
        return True
    return value is not _MISSING and value == cond


def _matches(doc: dict, query: dict | None) -> bool:
    return all(_match_value(_get_path(doc, k), v) for k, v in (query or {}).items())


def _project(doc: dict, projection: dict | None) -> dict:
    if not projection:
        return doc
    include = {k for k, v in projection.items() if v and k != "_id"}
    if include:
        out = {k: doc[k] for k in include if k in doc}
        if projection.get("_id", 1) and "_id" in doc:
            out["_id"] = doc["_id"]
        return out
    return {k: v for k, v in doc.items() if projection.get(k, 1)}


def _sort_key(value: Any) -> tuple:
    return (value is None or value is _MISSING, value if value not in (None, _MISSING) else 0)


class _Cursor(list):
    """A list that also supports pymongo's chained ``sort``/``limit``."""

    def sort(self, key: Any, direction: int = 1) -> "_Cursor":  # type: ignore[override]
        keys = key if isinstance(key, list) else [(key, direction)]
        items = list(self)
        for field, dirn in reversed(keys):
            items.sort(key=lambda d: _sort_key(_get_path(d, field)), reverse=dirn < 0)
        return _Cursor(items)

    def limit(self, n: int) -> "_Cursor":
        return _Cursor(self[:n]) if n else self


class InMemoryCollection:
    """Enough of the pymongo ``Collection`` API for tests and offline evals."""

    def __init__(self, docs: Iterable[dict] = ()) -> None:
        self.docs: list[dict] = []
        for doc in docs:
            self.insert_one(doc)

    def insert_one(self, doc: dict) -> SimpleNamespace:
        stored = copy.deepcopy(doc)
        stored.setdefault("_id", ObjectId())
        if any(d["_id"] == stored["_id"] for d in self.docs):
            raise ValueError(f"duplicate _id {stored['_id']!r}")
        self.docs.append(stored)
        doc.setdefault("_id", stored["_id"])
        return SimpleNamespace(inserted_id=stored["_id"])

    def find(
        self,
        filter: dict | None = None,
        projection: dict | None = None,
        sort: list[tuple[str, int]] | None = None,
        limit: int = 0,
    ) -> _Cursor:
        cursor = _Cursor(
            _project(copy.deepcopy(d), projection) for d in self.docs if _matches(d, filter)
        )
        if sort:
            cursor = cursor.sort(sort)
        return cursor.limit(limit)

    def find_one(self, filter: dict | None = None, *args: Any, **kwargs: Any) -> dict | None:
        found = self.find(filter, *args, **kwargs).limit(1)
        return found[0] if found else None

    def _apply(self, doc: dict, update: dict, inserting: bool) -> None:
        for key, value in update.get("$set", {}).items():
            doc[key] = copy.deepcopy(value)
        if inserting:
            for key, value in update.get("$setOnInsert", {}).items():
                doc[key] = copy.deepcopy(value)
        for key, value in update.get("$inc", {}).items():
            doc[key] = doc.get(key, 0) + value
        for key, value in update.get("$push", {}).items():
            doc.setdefault(key, []).append(copy.deepcopy(value))
        for key in update.get("$unset", {}):
            doc.pop(key, None)

    def update_one(self, filter: dict, update: dict, upsert: bool = False) -> SimpleNamespace:
        for doc in self.docs:
            if _matches(doc, filter):
                before = copy.deepcopy(doc)
                self._apply(doc, update, inserting=False)
                return SimpleNamespace(
                    matched_count=1, modified_count=int(doc != before), upserted_id=None
                )
        if not upsert:
            return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=None)
        new = {k: v for k, v in filter.items() if not isinstance(v, dict)}
        self._apply(new, update, inserting=True)
        inserted = self.insert_one(new).inserted_id
        return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=inserted)

    def replace_one(self, filter: dict, replacement: dict, upsert: bool = False) -> SimpleNamespace:
        for i, doc in enumerate(self.docs):
            if _matches(doc, filter):
                self.docs[i] = {"_id": doc["_id"], **copy.deepcopy(replacement)}
                return SimpleNamespace(matched_count=1, modified_count=1, upserted_id=None)
        if not upsert:
            return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=None)
        new = {**{k: v for k, v in filter.items() if not isinstance(v, dict)}, **replacement}
        inserted = self.insert_one(new).inserted_id
        return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=inserted)

    def delete_many(self, filter: dict | None = None) -> SimpleNamespace:
        before = len(self.docs)
        self.docs = [d for d in self.docs if not _matches(d, filter)]
        return SimpleNamespace(deleted_count=before - len(self.docs))

    def count_documents(self, filter: dict | None = None) -> int:
        return sum(1 for d in self.docs if _matches(d, filter))

    def create_index(self, *args: Any, **kwargs: Any) -> str:
        return "noop"
