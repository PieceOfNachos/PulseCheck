"""The incident graph: triage → investigate → research → diagnose → verify → plan → approve → act.

Orchestration is a fixed LangGraph ``StateGraph``; the model is only consulted inside the
investigator, diagnoser and planner nodes. Every node persists the incident and writes to
the audit log, and every side effect waits behind ``human_gate``.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import zlib
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
    AUTO_RECOVERY_APPROVER,
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
    Verification,
)
from app.llm import LLM
from app.security.allowlist import filter_actions, validate_approved
from app.security.audit import AuditLog
from app.security.budget import Budget, BudgetExceeded
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
        "verification": state.get("verification"),
        "proposed_actions": state.get("proposed_actions", []),
        "rejected_actions": state.get("rejected_actions", []),
        "decision": state.get("decision"),
        "results": state.get("results", []),
        "tokens_used": state.get("tokens_used", 0),
        "error": state.get("error"),
    }


def _dump(items: list[Any]) -> list[dict]:
    return [i.model_dump(mode="json") for i in items]


def _budget(state: IncidentState) -> Budget:
    return Budget.from_settings(state.get("tool_calls", 0), state.get("tokens_used", 0))


def _spent(exc: BaseException) -> dict[str, int]:
    """Counters carried by a budget failure, so they outlive the node that raised."""
    if isinstance(exc, BudgetExceeded):
        return {"tool_calls": exc.tool_calls, "tokens_used": exc.tokens_used}
    return {}


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
                update = {
                    "status": IncidentStatus.FAILED.value,
                    "error": f"{name}: {exc}",
                    **_spent(exc),
                }
                self.audit(state, "error", node=name, error=str(exc))
            self.persist({**state, **update})
            return update

        return run

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
        budget = _budget(state)

        for _ in range(budget.max_tool_calls + 1):
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
        return {
            "evidence": _dump(evidence),
            "tool_calls": budget.tool_calls,
            "tokens_used": budget.tokens_used,
        }

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
        budget = _budget(state)
        diagnosis, tokens = self.deps.llm.diagnose(
            AlertEvent(**state["alert"]),
            Category(state["category"]),
            [Evidence(**e) for e in state.get("evidence", [])],
            [RetrievedDoc(**d) for d in state.get("retrieved", [])],
        )
        self.charge(state, budget, "diagnoser", tokens)
        self.audit(
            state, "diagnosis", category=diagnosis.category.value, confidence=diagnosis.confidence
        )
        return {"diagnosis": diagnosis.model_dump(mode="json"), "tokens_used": budget.tokens_used}

    def verifier(self, state: IncidentState) -> dict:
        """Drop citations the researcher never retrieved; distrust a diagnosis citing nothing.

        Deterministic on purpose: the model is not asked to grade its own grounding.
        """
        diagnosis = Diagnosis(**state["diagnosis"])
        retrieved = {d["source"] for d in state.get("retrieved", [])}
        kept = [s for s in diagnosis.cited_sources if s in retrieved]
        dropped = [s for s in diagnosis.cited_sources if s not in retrieved]
        if dropped:
            self.audit(state, "ungrounded_citation", sources=dropped)

        confidence = diagnosis.confidence
        if retrieved and not kept:
            confidence = round(confidence * 0.5, 4)
        verification = Verification(
            grounded=not dropped and (bool(kept) or not retrieved),
            dropped_citations=dropped,
            low_confidence=confidence < settings.min_action_confidence,
        )
        self.audit(
            state,
            "verification",
            **verification.model_dump(),
            confidence=confidence,
            original_confidence=diagnosis.confidence,
        )
        diagnosis = diagnosis.model_copy(update={"cited_sources": kept, "confidence": confidence})
        return {
            "diagnosis": diagnosis.model_dump(mode="json"),
            "verification": verification.model_dump(mode="json"),
        }

    def planner(self, state: IncidentState) -> dict:
        budget = _budget(state)
        diagnosis = Diagnosis(**state["diagnosis"])
        plan, tokens = self.deps.llm.plan(
            AlertEvent(**state["alert"]),
            diagnosis,
            [Evidence(**e) for e in state.get("evidence", [])],
        )
        self.charge(state, budget, "planner", tokens)
        allowed, rejected = filter_actions(plan.actions)
        if (state.get("verification") or {}).get("low_confidence"):
            allowed, held = self._hold_for_low_confidence(state, diagnosis, allowed)
            rejected += held
        if rejected:
            self.audit(state, "actions_rejected", actions=_dump(rejected))
        self.audit(state, "actions_proposed", actions=[a.action for a in allowed])
        return {
            "proposed_actions": _dump(allowed),
            "rejected_actions": _dump(rejected),
            "tokens_used": budget.tokens_used,
        }

    def _hold_for_low_confidence(
        self, state: IncidentState, diagnosis: Diagnosis, allowed: list[ProposedAction]
    ) -> tuple[list[ProposedAction], list[ProposedAction]]:
        """Below the confidence floor only escalate / no_action may be proposed."""
        safe = {ActionName.ESCALATE.value, ActionName.NO_ACTION.value}
        keep = [a for a in allowed if a.action in safe]
        held = [a for a in allowed if a.action not in safe]
        if not held:
            return keep, []

        floor = settings.min_action_confidence
        prefix = f"low confidence ({diagnosis.confidence:.2f} < {floor:.2f})"
        held = [ProposedAction(action=a.action, reason=f"{prefix}: {a.reason}") for a in held]
        if not keep:
            # The model wanted to act, so a human should still hear about it.
            reason = "Diagnosis confidence is too low to act on; the owner should review it."
            keep = [ProposedAction(action=ActionName.ESCALATE.value, reason=reason)]
        self.audit(
            state,
            "low_confidence",
            confidence=diagnosis.confidence,
            threshold=floor,
            held=[a.action for a in held],
        )
        return keep, held

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
    order = ["triage", "investigator", "researcher", "diagnoser", "verifier", "planner"]
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


LOCK_STRIPES = 64

INTERRUPTED_ERROR = "Interrupted by a service restart before the investigation finished"


class IncidentAgent:
    """Runs one graph thread per alert event and resumes it on a human decision."""

    def __init__(self, deps: Deps, checkpointer: BaseCheckpointSaver | None = None) -> None:
        self.deps = deps
        self.graph = build_graph(deps, checkpointer)
        # Striped rather than one lock per id so the table stays bounded; two incidents
        # that land on the same stripe merely serialise.
        self._locks = [threading.Lock() for _ in range(LOCK_STRIPES)]

    def _lock(self, incident_id: str) -> threading.Lock:
        return self._locks[zlib.crc32(incident_id.encode()) % LOCK_STRIPES]

    @staticmethod
    def _config(incident_id: str) -> dict:
        return {"configurable": {"thread_id": incident_id}}

    def _fail(
        self, incident_id: str, user_id: str, error: str, exc: BaseException | None = None
    ) -> None:
        """Flag the incident FAILED, keeping everything the nodes already persisted."""
        self.deps.audit.record(incident_id, user_id, "error", error=error)
        tokens = _spent(exc).get("tokens_used") if exc else None
        self.deps.incidents.mark_failed(incident_id, error, tokens_used=tokens)

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
            self.deps.incidents.upsert(_incident_doc(state))
            self.deps.audit.record(
                incident_id, alert.userId, "started", monitor=alert.monitorName, url=alert.monitorUrl
            )
            try:
                self.graph.invoke(state, self._config(incident_id))
            except Exception as exc:
                log.exception("incident %s crashed", incident_id)
                self._fail(incident_id, alert.userId, f"graph: {exc}", exc)
            return self.deps.incidents.get(incident_id, alert.userId) or {}

    def resume(self, incident_id: str, decision: ApprovalDecision) -> dict:
        """Apply a human decision. Only the owner may decide, and only while awaiting approval."""
        with self._lock(incident_id):
            incident = self.deps.incidents.get(incident_id, decision.approver)
            if incident is None or incident["userId"] != decision.approver:
                raise IncidentNotFound(incident_id)
            return self._resume_locked(incident, decision)

    def _resume_locked(self, incident: dict, decision: ApprovalDecision) -> dict:
        incident_id, user_id = incident["id"], incident["userId"]
        if incident["status"] != IncidentStatus.AWAITING_APPROVAL.value:
            raise InvalidIncidentState(f"incident is {incident['status']}, not awaiting approval")

        config = self._config(incident_id)
        if "human_gate" not in self.graph.get_state(config).next:
            error = "approval checkpoint is missing; the incident cannot be resumed"
            self._fail(incident_id, user_id, error)
            raise InvalidIncidentState("approval checkpoint is missing")
        try:
            self.graph.invoke(Command(resume=decision.model_dump(mode="json")), config)
        except Exception as exc:
            log.exception("incident %s crashed on resume", incident_id)
            self._fail(incident_id, user_id, f"graph: {exc}", exc)
        return self.deps.incidents.get(incident_id, user_id) or {}

    def close_on_recovery(self, monitor_id: str, user_id: str) -> list[str]:
        """Reject every pending proposal for a monitor that is back UP; returns closed ids.

        Approving later would act on a healthy monitor (e.g. pause it), so the graph is
        resumed with a system rejection: nothing runs and the incident is RESOLVED. This
        is the one internal path that decides without the owner. An investigation still
        running holds the incident lock, so it is closed as soon as it reaches the gate.
        """
        decision = ApprovalDecision(approved=False, actions=[], approver=AUTO_RECOVERY_APPROVER)
        closed: list[str] = []
        for incident_id in self.deps.incidents.open_for_monitor(monitor_id, user_id):
            with self._lock(incident_id):
                incident = self.deps.incidents.get(incident_id, user_id)
                if not incident or incident["status"] != IncidentStatus.AWAITING_APPROVAL.value:
                    continue
                self.deps.audit.record(
                    incident_id, user_id, "auto_closed_on_recovery", monitor_id=monitor_id
                )
                try:
                    self._resume_locked(incident, decision)
                except InvalidIncidentState as exc:
                    log.warning("could not auto-close incident %s: %s", incident_id, exc)
                    continue
                closed.append(incident_id)
        return closed

    def fail_interrupted(self, before: str | None = None) -> list[str]:
        """Fail investigations orphaned by a restart; pub/sub will not redeliver their alerts.

        Run once at boot, before the subscriber starts. With a single agent replica every
        incident still INVESTIGATING and last touched before ``before`` has no live runner.
        """
        failed = self.deps.incidents.fail_interrupted(before or _now(), INTERRUPTED_ERROR)
        for item in failed:
            self.deps.audit.record(item["id"], item["userId"], "error", error=INTERRUPTED_ERROR)
        return [item["id"] for item in failed]
