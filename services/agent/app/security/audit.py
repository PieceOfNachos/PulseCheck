"""Append-only audit trail for everything the agent does on an incident.

Works with a pymongo ``Collection`` or any stand-in exposing ``insert_one(doc)`` and
``find(filter)``. Sorting happens in Python so the stand-in can stay trivial.
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel

MAX_STRING = 1000
REDACTED = "[redacted]"

_SENSITIVE_KEY = re.compile(r"key|token|secret|password|authorization", re.IGNORECASE)
_BEARER = re.compile(r"(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)

_seq_lock = threading.Lock()
_last_seq = 0


def _next_seq() -> int:
    """Strictly increasing nanosecond stamp; wall-clock ``at`` can repeat on coarse clocks."""
    global _last_seq
    with _seq_lock:
        _last_seq = max(time.time_ns(), _last_seq + 1)
        return _last_seq


def _is_sensitive(key: object, value: Any) -> bool:
    # Counters such as ``tokens_used`` match the pattern but are not secrets.
    if isinstance(value, (bool, int, float)) or value is None:
        return False
    return isinstance(key, str) and bool(_SENSITIVE_KEY.search(key))


def _clean_str(value: str) -> str:
    value = _BEARER.sub(rf"\1{REDACTED}", value)
    if len(value) > MAX_STRING:
        value = f"{value[:MAX_STRING]}...[truncated {len(value) - MAX_STRING} chars]"
    return value


def sanitize(value: Any) -> Any:
    """Recursively redact secret-looking keys and truncate long strings."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, dict):
        return {
            str(k): REDACTED if _is_sensitive(k, v) else sanitize(v) for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return _clean_str(value)
    return value


class AuditLog:
    """Audit entries look like ``{incident_id, user_id, event, at, seq, data}``."""

    def __init__(self, collection: Any) -> None:
        self.collection = collection

    def record(self, incident_id: str, user_id: str, event: str, **data: Any) -> None:
        entry = {
            "incident_id": incident_id,
            "user_id": user_id,
            "event": event,
            "at": datetime.now(timezone.utc).isoformat(),
            "seq": _next_seq(),
            "data": sanitize(data),
        }
        # pymongo adds "_id" to the dict it is given; keep ours untouched.
        self.collection.insert_one(dict(entry))

    def list(self, incident_id: str) -> list[dict]:
        """Entries for one incident, oldest first, without Mongo's ``_id``."""
        docs = [
            {k: v for k, v in doc.items() if k != "_id"}
            for doc in self.collection.find({"incident_id": incident_id})
        ]
        docs.sort(key=lambda d: (str(d.get("at", "")), d.get("seq", 0)))
        return docs
