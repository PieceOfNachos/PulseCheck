"""The incident graph: triage → investigate → research → diagnose → plan → approve → act.

Orchestration is a fixed LangGraph ``StateGraph``; the model is only consulted inside the
investigator, diagnoser and planner nodes. Every node persists the incident and writes to
the audit log, and every side effect waits behind ``human_gate``.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from langgraph.errors import GraphBubbleUp
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from app.config import settings
from app.contracts import (
    ActionName,
    ActionResult,
    AlertEvent,
    ApprovalDecision,
    Category,
    Diagnosis,
    Evidence,
    IncidentState,
    IncidentStatus,
    ProposedAction,
    RetrievedDoc,
)
from app.llm import LLM
from app.security.allowlist import filter_actions, validate_approved
from app.security.audit import AuditLog
from app.security.budget import Budget
from app.store import IncidentRepo, MonitorRepo
from app.tools.probes import TOOL_NAMES, Probes

log = logging.getLogger(__name__)

ESCALATION_CHANNEL = "agent:escalation"


class IncidentNotFound(LookupError):
    """No incident with that id is visible to the caller."""


class InvalidIncidentState(RuntimeError):
    """The incident cannot take the requested transition (e.g. not awaiting approval)."""


@dataclass
class Deps:
    llm: LLM
    probes: Probes
    kb: Any  # app.rag.store.KnowledgeBase or anything with search / index_incident
    incidents: IncidentRepo
    monitors: MonitorRepo
    audit: AuditLog
    publish: Callable[[str, dict], None]


# ── Triage ────────────────────────────────────────────────────────────────────

_ERROR_PATTERNS: list[tuple[Category, re.Pattern[str]]] = [
    (Category.TIMEOUT, re.compile(r"ECONNABORTED|ETIMEDOUT|ESOCKETTIMEDOUT|timeout|timed out", re.I)),
    (Category.DNS, re.compile(r"ENOTFOUND|EAI_AGAIN|getaddrinfo|dns|name not resolved", re.I)),
    (
        Category.TLS,
        re.compile(r"CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|EPROTO|ssl|tls|certificate", re.I),
    ),
    (
        Category.CONNECTION,
        re.compile(r"ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE|socket hang up", re.I),
    ),
]


def triage(alert: AlertEvent) -> Category:
    """Classify an alert from its status code and error message (pure, no I/O)."""
    code = alert.statusCode
    if code is not None:
        if code in (401, 403):
            return Category.AUTH
        if 500 <= code <= 599:
            return Category.SERVER_ERROR
        if 400 <= code <= 499:
            return Category.CLIENT_ERROR
    message = alert.errorMessage or ""
    for category, pattern in _ERROR_PATTERNS:
        if pattern.search(message):
            return category
    return Category.UNKNOWN


# ── Persistence helpers ───────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _incident_doc(state: IncidentState) -> dict:
    alert = state["alert"]
    return {
        "id": state["incident_id"],
        "userId": alert["userId"],
        "monitorId": alert["monitorId"],
        "monitorName": alert["monitorName"],
        "monitorUrl": alert["monitorUrl"],
        "status": state.get("status", IncidentStatus.INVESTIGATING.value),
        "category": state.get("category"),
        "evidence": state.get("evidence", []),
        "retrieved": state.get("retrieved", []),
        "diagnosis": state.get("diagnosis"),
        "proposed_actions": state.get("proposed_actions", []),
        "rejected_actions": state.get("rejected_actions", []),
        "decision": state.get("decision"),
        "results": state.get("results", []),
        "tokens_used": state.get("tokens_used", 0),
        "error": state.get("error"),
    }


def _dump(items: list[Any]) -> list[dict]:
    return [i.model_dump(mode="json") for i in items]


# ── Nodes ─────────────────────────────────────────────────────────────────────


class _Nodes:
    def __init__(self, deps: Deps) -> None:
        self.deps = deps

    def persist(self, state: IncidentState) -> None:
        self.deps.incidents.upsert(_incident_doc(state))

    def audit(self, state: IncidentState, event: str, **data: Any) -> None:
        self.deps.audit.record(state["incident_id"], state["alert"]["userId"], event, **data)

    def wrap(self, name: str, fn: Callable[[IncidentState], dict]) -> Callable[[IncidentState], dict]:
        """Audit entry, persist after, and turn any failure into a FAILED incident."""

        def run(state: IncidentState) -> dict:
            self.audit(state, "node", node=name)
            try:
                update = fn(state) or {}
            except GraphBubbleUp:
                raise
            except Exception as exc:
                log.exception("incident %s failed in %s", state["incident_id"], name)
                update = {"status": IncidentStatus.FAILED.value, "error": f"{name}: {exc}"}
                self.audit(state, "error", node=name, error=str(exc))
            self.persist({**state, **update})
            return update

        return run

    def budget(self, state: IncidentState) -> Budget:
        return Budget(
            settings.max_tool_calls,
            settings.token_budget,
            tool_calls=state.get("tool_calls", 0),
            tokens_used=state.get("tokens_used", 0),
        )

    def charge(self, state: IncidentState, budget: Budget, node: str, tokens: int) -> None:
        """Charge model tokens; raises ``BudgetExceeded`` (failing the incident) when over."""
        try:
            budget.charge_tokens(tokens)
        finally:
            self.audit(state, "tokens", node=node, tokens=tokens, total=budget.tokens_used)

    # nodes

    def triage(self, state: IncidentState) -> dict:
        category = triage(AlertEvent(**state["alert"]))
        self.audit(state, "triage", category=category.value)
        return {"category": category.value}

    def investigator(self, state: IncidentState) -> dict:
        alert = AlertEvent(**state["alert"])
        category = Category(state["category"])
        evidence = [Evidence(**e) for e in state.get("evidence", [])]
        budget = self.budget(state)

        try:
            for _ in range(settings.max_tool_calls + 1):
                if not budget.can_call_tool():
                    self.audit(state, "budget", limit="tool_calls", tool_calls=budget.tool_calls)
                    break
                names, tokens = self.deps.llm.choose_tools(alert, category, evidence)
                self.charge(state, budget, "investigator", tokens)
                if not names:
                    break
                for name in names:
                    if name not in TOOL_NAMES:
                        self.audit(state, "unknown_tool", tool=name)
                        continue
                    if not budget.can_call_tool():
                        self.audit(state, "budget", limit="tool_calls", skipped=name)
                        break
                    budget.charge_tool()
                    evidence.append(self._run_tool(state, name, alert))
        finally:
            state_counts = {"tool_calls": budget.tool_calls, "tokens_used": budget.tokens_used}
            state.update(state_counts)  # keeps counters if the loop raises
        return {"evidence": _dump(evidence), **state_counts}

    def _run_tool(self, state: IncidentState, name: str, alert: AlertEvent) -> Evidence:
        start = time.perf_counter()
        try:
            result = getattr(self.deps.probes, name)(alert)
        except Exception as exc:
            result = Evidence(tool=name, summary=f"{name} failed: {type(exc).__name__}: {exc}")
        duration_ms = round((time.perf_counter() - start) * 1000)
        self.audit(state, "tool_call", tool=name, duration_ms=duration_ms, summary=result.summary)
        return result

    def researcher(self, state: IncidentState) -> dict:
        alert = AlertEvent(**state["alert"])
        parts = [state["category"], alert.errorMessage or ""]
        parts += [e["summary"][:200] for e in state.get("evidence", [])]
        query = " ".join(p for p in parts if p)[:1000]
        try:
            docs = self.deps.kb.search(query, k=3, user_id=alert.userId)
        except Exception as exc:
            log.warning("retrieval failed for %s: %s", state["incident_id"], exc)
            self.audit(state, "retrieval_failed", error=str(exc))
            docs = []
        self.audit(state, "retrieved", sources=[d.source for d in docs])
        return {"retrieved": _dump(docs)}

    def diagnoser(self, state: IncidentState) -> dict:
        budget = self.budget(state)
        diagnosis, tokens = self.deps.llm.diagnose(
            AlertEvent(**state["alert"]),
            Category(state["category"]),
            [Evidence(**e) for e in state.get("evidence", [])],
            [RetrievedDoc(**d) for d in state.get("retrieved", [])],
        )
        state["tokens_used"] = budget.tokens_used + tokens
        self.charge(state, budget, "diagnoser", tokens)
        self.audit(
            state, "diagnosis", category=diagnosis.category.value, confidence=diagnosis.confidence
        )
        return {"diagnosis": diagnosis.model_dump(mode="json"), "tokens_used": budget.tokens_used}

    def planner(self, state: IncidentState) -> dict:
        budget = self.budget(state)
        plan, tokens = self.deps.llm.plan(
            AlertEvent(**state["alert"]),
            Diagnosis(**state["diagnosis"]),
            [Evidence(**e) for e in state.get("evidence", [])],
        )
        state["tokens_used"] = budget.tokens_used + tokens
        self.charge(state, budget, "planner", tokens)
        allowed, rejected = filter_actions(plan.actions)
        if rejected:
            self.audit(state, "actions_rejected", actions=_dump(rejected))
        self.audit(state, "actions_proposed", actions=[a.action for a in allowed])
        return {
            "proposed_actions": _dump(allowed),
            "rejected_actions": _dump(rejected),
            "tokens_used": budget.tokens_used,
        }

    def human_gate(self, state: IncidentState) -> dict:
        awaiting = {"status": IncidentStatus.AWAITING_APPROVAL.value}
        self.persist({**state, **awaiting})
        raw = interrupt(
            {"incident_id": state["incident_id"], "proposed_actions": state["proposed_actions"]}
        )
        decision = ApprovalDecision.model_validate(raw)
        self.audit(
            state,
            "approval_decision",
            approved=decision.approved,
            actions=decision.actions,
            approver=decision.approver,
        )
        return {**awaiting, "decision": decision.model_dump(mode="json")}

    def executor(self, state: IncidentState) -> dict:
        alert = AlertEvent(**state["alert"])
        decision = ApprovalDecision(**state["decision"])
        proposed = [a["action"] for a in state.get("proposed_actions", [])]

        names: list[str] = []
        if decision.approved and decision.approver == alert.userId:
            names = validate_approved(decision.actions, proposed)
        elif decision.approved:
            self.audit(state, "approval_refused", approver=decision.approver)

        results = [self._execute(state, alert, name) for name in names]
        for r in results:
            self.audit(state, "action", action=r.action, ok=r.ok, detail=r.detail)
        return {"results": _dump(results)}

    def _execute(self, state: IncidentState, alert: AlertEvent, name: str) -> ActionResult:
        try:
            if name == ActionName.PAUSE_MONITOR.value:
                ok = self.deps.monitors.pause(alert.monitorId, alert.userId)
                detail = "Monitor paused." if ok else "Monitor not found for this user."
                return ActionResult(action=name, ok=ok, detail=detail)
            if name == ActionName.ESCALATE.value:
                self.deps.publish(
                    ESCALATION_CHANNEL,
                    {
                        "incidentId": state["incident_id"],
                        "userId": alert.userId,
                        "monitorId": alert.monitorId,
                        "monitorName": alert.monitorName,
                        "monitorUrl": alert.monitorUrl,
                        "category": state.get("category"),
                        "diagnosis": state.get("diagnosis"),
                        "timestamp": _now(),
                    },
                )
                return ActionResult(action=name, ok=True, detail=f"Published to {ESCALATION_CHANNEL}.")
            if name == ActionName.NO_ACTION.value:
                return ActionResult(action=name, ok=True, detail="Nothing to do.")
            return ActionResult(action=name, ok=False, detail="Action is not allowlisted.")
        except Exception as exc:
            log.exception("action %s failed for %s", name, state["incident_id"])
            return ActionResult(action=name, ok=False, detail=f"{type(exc).__name__}: {exc}")

    def reporter(self, state: IncidentState) -> dict:
        alert = AlertEvent(**state["alert"])
        diagnosis = state.get("diagnosis") or {}
        executed = [r["action"] for r in state.get("results", []) if r.get("ok")]
        text = "\n".join(
            [
                f"Incident on {alert.monitorName} ({alert.monitorUrl})",
                f"Category: {diagnosis.get('category', state.get('category'))}",
                f"Error: {alert.errorMessage or 'n/a'} (status {alert.statusCode or 'n/a'})",
                f"Root cause: {diagnosis.get('root_cause', 'unknown')}",
                "Evidence: " + "; ".join(e["summary"][:200] for e in state.get("evidence", [])),
                f"Actions taken: {', '.join(executed) or 'none'}",
            ]
        )
        try:
            self.deps.kb.index_incident(state["incident_id"], alert.userId, text, state["category"])
        except Exception as exc:
            log.warning("indexing incident %s failed: %s", state["incident_id"], exc)
            self.audit(state, "index_failed", error=str(exc))
        self.audit(state, "resolved", actions=executed)
        return {"status": IncidentStatus.RESOLVED.value}


# ── Graph ─────────────────────────────────────────────────────────────────────


def _failed(state: IncidentState) -> bool:
    return state.get("status") == IncidentStatus.FAILED.value


def _then(target: str) -> Callable[[IncidentState], str]:
    return lambda state: END if _failed(state) else target


def _after_planner(state: IncidentState) -> str:
    if _failed(state):
        return END
    actions = {a["action"] for a in state.get("proposed_actions", [])}
    return "reporter" if actions <= {ActionName.NO_ACTION.value} else "human_gate"


def build_graph(deps: Deps, checkpointer: BaseCheckpointSaver | None = None) -> Any:
    """Compile the incident graph with ``checkpointer`` (required for ``interrupt``)."""
    nodes = _Nodes(deps)
    order = ["triage", "investigator", "researcher", "diagnoser", "planner"]
    graph = StateGraph(IncidentState)
    for name in [*order, "human_gate", "executor", "reporter"]:
        graph.add_node(name, nodes.wrap(name, getattr(nodes, name)))

    graph.add_edge(START, "triage")
    for current, nxt in zip(order, order[1:]):
        graph.add_conditional_edges(current, _then(nxt), [nxt, END])
    graph.add_conditional_edges("planner", _after_planner, ["human_gate", "reporter", END])
    graph.add_conditional_edges("human_gate", _then("executor"), ["executor", END])
    graph.add_conditional_edges("executor", _then("reporter"), ["reporter", END])
    graph.add_edge("reporter", END)
    return graph.compile(checkpointer=checkpointer or MemorySaver())


class IncidentAgent:
    """Runs one graph thread per alert event and resumes it on a human decision."""

    def __init__(self, deps: Deps, checkpointer: BaseCheckpointSaver | None = None) -> None:
        self.deps = deps
        self.graph = build_graph(deps, checkpointer)
        self._nodes = _Nodes(deps)
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)

    def _lock(self, incident_id: str) -> threading.Lock:
        with self._guard:
            return self._locks[incident_id]

    @staticmethod
    def _config(incident_id: str) -> dict:
        return {"configurable": {"thread_id": incident_id}}

    def _fail(self, state: IncidentState, error: str) -> None:
        self._nodes.audit(state, "error", error=error)
        self._nodes.persist({**state, "status": IncidentStatus.FAILED.value, "error": error})

    def start(self, alert: AlertEvent) -> dict:
        """Run the graph for a DOWN alert; returns the existing incident if already started."""
        incident_id = alert.alertEventId
        with self._lock(incident_id):
            if self.deps.incidents.exists(incident_id):
                return self.deps.incidents.get(incident_id, alert.userId) or {}

            state: IncidentState = {
                "incident_id": incident_id,
                "alert": alert.model_dump(mode="json"),
                "status": IncidentStatus.INVESTIGATING.value,
                "tool_calls": 0,
                "tokens_used": 0,
            }
            self._nodes.persist(state)
            self._nodes.audit(state, "started", monitor=alert.monitorName, url=alert.monitorUrl)
            try:
                self.graph.invoke(state, self._config(incident_id))
            except Exception as exc:
                log.exception("incident %s crashed", incident_id)
                self._fail(state, f"graph: {exc}")
            return self.deps.incidents.get(incident_id, alert.userId) or {}

    def resume(self, incident_id: str, decision: ApprovalDecision) -> dict:
        """Apply a human decision. Only the owner may decide, and only while awaiting approval."""
        with self._lock(incident_id):
            incident = self.deps.incidents.get(incident_id, decision.approver)
            if incident is None or incident["userId"] != decision.approver:
                raise IncidentNotFound(incident_id)
            if incident["status"] != IncidentStatus.AWAITING_APPROVAL.value:
                raise InvalidIncidentState(f"incident is {incident['status']}, not awaiting approval")

            config = self._config(incident_id)
            if "human_gate" not in self.graph.get_state(config).next:
                state = self._state_from_doc(incident)
                self._fail(state, "approval checkpoint is missing; the incident cannot be resumed")
                raise InvalidIncidentState("approval checkpoint is missing")
            try:
                self.graph.invoke(Command(resume=decision.model_dump(mode="json")), config)
            except Exception as exc:
                log.exception("incident %s crashed on resume", incident_id)
                self._fail(self._state_from_doc(incident), f"graph: {exc}")
            return self.deps.incidents.get(incident_id, decision.approver) or {}

    @staticmethod
    def _state_from_doc(doc: dict) -> IncidentState:
        alert = {k: doc[k] for k in ("userId", "monitorId", "monitorName", "monitorUrl")}
        state = {k: v for k, v in doc.items() if k in IncidentState.__annotations__}
        return {**state, "incident_id": doc["id"], "alert": alert}  # type: ignore[typeddict-item]
