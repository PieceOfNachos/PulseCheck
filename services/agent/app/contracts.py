"""Shared data contracts for the incident agent.

Every module (graph, rag, security, api) builds against these types, so they are the
single source of truth for what flows between nodes, the API, and storage.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, TypedDict

from pydantic import BaseModel, Field


# ── Inbound event (Redis "alert:status-change", published by the monitoring service) ──
class AlertEvent(BaseModel):
    alertEventId: str
    monitorId: str
    userId: str
    monitorName: str
    monitorUrl: str
    type: str  # "DOWN" | "RECOVERED" — the agent only handles DOWN
    statusCode: Optional[int] = None
    latencyMs: Optional[int] = None
    errorMessage: Optional[str] = None
    timestamp: str


# ── Triage ──
class Category(str, Enum):
    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    CONNECTION = "connection"  # refused / reset
    SERVER_ERROR = "server_error"  # 5xx
    CLIENT_ERROR = "client_error"  # 4xx other than auth
    AUTH = "auth"  # 401 / 403
    UNKNOWN = "unknown"


# ── Investigation ──
class Evidence(BaseModel):
    tool: str  # e.g. "probe_endpoint", "check_dns"
    summary: str  # short, human-readable finding
    data: dict[str, Any] = Field(default_factory=dict)


# ── RAG ──
class RetrievedDoc(BaseModel):
    source: str  # runbook file name or "incident:<id>"
    title: str
    text: str
    score: float


# ── Diagnosis (structured LLM output) ──
class Diagnosis(BaseModel):
    category: Category
    root_cause: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    cited_sources: list[str] = Field(default_factory=list)


# ── Actions ──
class ActionName(str, Enum):
    PAUSE_MONITOR = "pause_monitor"
    ESCALATE = "escalate"
    NO_ACTION = "no_action"


ALLOWED_ACTIONS: frozenset[str] = frozenset(a.value for a in ActionName)


class ProposedAction(BaseModel):
    action: str  # validated against ALLOWED_ACTIONS by security.allowlist, NOT trusted
    reason: str


class ActionPlan(BaseModel):
    actions: list[ProposedAction] = Field(default_factory=list)


class ActionResult(BaseModel):
    action: str
    ok: bool
    detail: str = ""


# ── Incident lifecycle ──
class IncidentStatus(str, Enum):
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RESOLVED = "RESOLVED"  # actions executed (or none approved)
    FAILED = "FAILED"


class ApprovalDecision(BaseModel):
    approved: bool
    actions: list[str] = Field(default_factory=list)  # subset of proposed actions
    approver: str  # userId from JWT, or AUTO_RECOVERY_APPROVER


# Approver recorded when a RECOVERED alert closes an incident still awaiting approval.
# The decision is always a rejection, so nothing runs.
AUTO_RECOVERY_APPROVER = "system:auto-recovery"


# ── Verification (deterministic groundedness check between diagnoser and planner) ──
class Verification(BaseModel):
    grounded: bool  # every citation was retrieved, and at least one when docs were retrieved
    dropped_citations: list[str] = Field(default_factory=list)  # cited but never retrieved
    low_confidence: bool  # final confidence < settings.min_action_confidence


# ── Persisted incident (Mongo collection "incidents", _id == alertEventId) ──
# GET /api/agent/incidents        -> list[IncidentDoc] (no "audit")
# GET /api/agent/incidents/{id}   -> IncidentDoc + {"audit": list[audit entries]}
class IncidentDoc(BaseModel):
    id: str  # alertEventId (stored as Mongo _id, serialised as "id")
    userId: str
    monitorId: str
    monitorName: str
    monitorUrl: str
    status: IncidentStatus
    category: Optional[Category] = None
    evidence: list[Evidence] = Field(default_factory=list)
    retrieved: list[RetrievedDoc] = Field(default_factory=list)
    diagnosis: Optional[Diagnosis] = None  # citations and confidence as adjusted by verifier
    verification: Optional[Verification] = None
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    rejected_actions: list[ProposedAction] = Field(default_factory=list)
    decision: Optional[ApprovalDecision] = None
    results: list[ActionResult] = Field(default_factory=list)
    tokens_used: int = 0
    error: Optional[str] = None
    createdAt: str  # ISO-8601
    updatedAt: str  # ISO-8601


# ── LangGraph state ──
class IncidentState(TypedDict, total=False):
    incident_id: str  # == alertEventId; also the LangGraph thread_id
    alert: dict  # AlertEvent.model_dump()
    category: str  # Category value
    evidence: list[dict]  # Evidence.model_dump()
    retrieved: list[dict]  # RetrievedDoc.model_dump()
    diagnosis: dict  # Diagnosis.model_dump()
    verification: dict  # Verification.model_dump()
    proposed_actions: list[dict]  # ProposedAction.model_dump(), already allowlist-filtered
    rejected_actions: list[dict]  # proposals dropped by the allowlist (kept for audit)
    decision: dict  # ApprovalDecision.model_dump()
    results: list[dict]  # ActionResult.model_dump()
    tool_calls: int
    tokens_used: int
    status: str  # IncidentStatus value
    error: str
