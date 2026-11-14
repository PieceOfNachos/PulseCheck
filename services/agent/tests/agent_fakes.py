"""Test doubles shared by the graph and API tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from bson import ObjectId

from app.contracts import AlertEvent, Evidence, RetrievedDoc
from app.graph import Deps
from app.llm import FakeLLM
from app.security.audit import AuditLog
from app.store import IncidentRepo, InMemoryCollection, MonitorRepo
from app.tools.probes import TOOL_NAMES

USER_ID = str(ObjectId())
OTHER_USER_ID = str(ObjectId())
MONITOR_ID = str(ObjectId())


def make_alert(**overrides) -> AlertEvent:
    fields = {
        "alertEventId": str(ObjectId()),
        "monitorId": MONITOR_ID,
        "userId": USER_ID,
        "monitorName": "Payments API",
        "monitorUrl": "https://payments.example.com/health",
        "type": "DOWN",
        "statusCode": 503,
        "latencyMs": 42,
        "errorMessage": "Expected 200, got 503",
        "timestamp": "2026-11-13T10:00:00.000Z",
    }
    return AlertEvent(**{**fields, **overrides})


class CannedProbes:
    """Returns fixed evidence per tool and records which tools ran."""

    def __init__(self, canned: dict[str, str] | None = None) -> None:
        self.canned = canned or {}
        self.calls: list[str] = []
        for name in TOOL_NAMES:
            setattr(self, name, self._make(name))

    def _make(self, name: str):
        def run(alert: AlertEvent) -> Evidence:
            self.calls.append(name)
            return Evidence(tool=name, summary=self.canned.get(name, f"{name}: nothing unusual"))

        return run


class StubKB:
    def __init__(self) -> None:
        self.indexed: list[tuple[str, str, str, str]] = []
        self.searches: list[tuple[str, str | None]] = []

    def search(self, query: str, k: int = 3, user_id: str | None = None) -> list[RetrievedDoc]:
        self.searches.append((query, user_id))
        return [
            RetrievedDoc(
                source="server-errors-5xx.md",
                title="Server errors",
                text="Check upstream health and recent deploys.",
                score=0.9,
            )
        ]

    def index_incident(self, incident_id: str, user_id: str, text: str, category: str) -> None:
        self.indexed.append((incident_id, user_id, text, category))

    def index_runbook(self, text: str, source: str) -> int:
        return 2


@dataclass
class Harness:
    deps: Deps
    probes: CannedProbes
    kb: StubKB
    monitors: InMemoryCollection
    published: list[tuple[str, dict]] = field(default_factory=list)


def make_harness(probes: CannedProbes | None = None, llm=None, monitor_owner: str = USER_ID) -> Harness:
    probes = probes or CannedProbes()
    kb = StubKB()
    monitors = InMemoryCollection(
        [{"_id": ObjectId(MONITOR_ID), "userId": ObjectId(monitor_owner), "active": True}]
    )
    published: list[tuple[str, dict]] = []
    deps = Deps(
        llm=llm or FakeLLM(),
        probes=probes,
        kb=kb,
        incidents=IncidentRepo(InMemoryCollection()),
        monitors=MonitorRepo(monitors),
        audit=AuditLog(InMemoryCollection()),
        publish=lambda channel, payload: published.append((channel, payload)),
    )
    return Harness(deps, probes, kb, monitors, published)
