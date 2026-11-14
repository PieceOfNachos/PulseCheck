"""HTTP API and Redis subscriber for the incident agent service."""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Annotated, Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel, Field, ValidationError

from app.config import settings
from app.contracts import AlertEvent, ApprovalDecision
from app.graph import Deps, IncidentAgent, IncidentNotFound, InvalidIncidentState
from app.security.auth import user_id_from_auth_header

log = logging.getLogger("agent")

ALERT_CHANNEL = "alert:status-change"
MAX_RUNBOOK_CHARS = 50_000


class ApproveBody(BaseModel):
    actions: list[str] = Field(default_factory=list, max_length=10)


class RunbookBody(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=MAX_RUNBOOK_CHARS)


# ── Wiring ────────────────────────────────────────────────────────────────────


def build_deps() -> Deps:
    """Production dependencies: Mongo, Redis, Qdrant and the configured model."""
    import redis

    from app.llm import get_llm
    from app.rag.store import KnowledgeBase
    from app.security.audit import AuditLog
    from app.store import IncidentRepo, MonitorRepo, get_db
    from app.tools.probes import RealProbes

    db = get_db()
    publisher = redis.Redis.from_url(settings.redis_url)
    kb = KnowledgeBase()
    try:
        kb.ensure_collections()
        log.info("indexed %d runbook chunks", kb.index_runbooks_dir(settings.runbooks_dir))
    except Exception:
        log.exception("runbook indexing failed; continuing without seed runbooks")

    return Deps(
        llm=get_llm(),
        probes=RealProbes(db),
        kb=kb,
        incidents=IncidentRepo(db["incidents"]),
        monitors=MonitorRepo(db["monitors"]),
        audit=AuditLog(db["agent_audit"]),
        publish=lambda channel, payload: publisher.publish(channel, json.dumps(payload)),
    )


def build_checkpointer() -> BaseCheckpointSaver:
    """Mongo-backed checkpoints so paused incidents survive restarts; memory as fallback."""
    try:
        from langgraph.checkpoint.mongodb import MongoDBSaver
        from pymongo import MongoClient

        client: MongoClient = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000)
        return MongoDBSaver(client, db_name=settings.mongo_db)
    except Exception as exc:
        log.warning("Mongo checkpointer unavailable (%s); using in-memory checkpoints", exc)
        return MemorySaver()


def handle_alert_message(agent: IncidentAgent, raw: bytes | str) -> None:
    """Start an incident on DOWN, close pending ones on RECOVERED; never raises."""
    try:
        alert = AlertEvent.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as exc:
        log.warning("ignoring malformed alert message: %s", exc)
        return
    if alert.type == "RECOVERED":
        try:
            closed = agent.close_on_recovery(alert.monitorId, alert.userId)
            if closed:
                log.info("monitor %s recovered; closed %s", alert.monitorId, ", ".join(closed))
        except Exception:
            log.exception("closing incidents for recovered monitor %s failed", alert.monitorId)
        return
    if alert.type != "DOWN":
        return
    try:
        incident = agent.start(alert)
        log.info("incident %s -> %s", alert.alertEventId, incident.get("status"))
    except Exception:
        log.exception("incident %s failed to start", alert.alertEventId)


def subscribe_alerts(agent: IncidentAgent, stop: threading.Event, workers: int = 4) -> None:
    """Listen on the alert channel with reconnect backoff, dispatching to a worker pool."""
    import redis

    backoff = 1.0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="incident") as pool:
        while not stop.is_set():
            try:
                client = redis.Redis.from_url(settings.redis_url)
                pubsub = client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(ALERT_CHANNEL)
                log.info("subscribed to %s", ALERT_CHANNEL)
                backoff = 1.0
                while not stop.is_set():
                    message = pubsub.get_message(timeout=1.0)
                    if message and message.get("type") == "message":
                        pool.submit(handle_alert_message, agent, message["data"])
                pubsub.close()
            except Exception as exc:
                log.warning("redis subscriber error (%s); retrying in %.0fs", exc, backoff)
                stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)


def current_user(request: Request) -> str:
    """The caller's user id from the bearer token (401 otherwise)."""
    return user_id_from_auth_header(request.headers.get("authorization"))


UserId = Annotated[str, Depends(current_user)]


# ── App ───────────────────────────────────────────────────────────────────────


def create_app(
    deps: Deps | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
    start_subscriber: bool = True,
) -> FastAPI:
    """Build the API. Connections are opened in the lifespan, not at import time."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved = deps or build_deps()
        app.state.deps = resolved
        app.state.agent = IncidentAgent(resolved, checkpointer or build_checkpointer())
        try:
            interrupted = app.state.agent.fail_interrupted()
            if interrupted:
                log.warning("marked %d interrupted investigations failed", len(interrupted))
        except Exception:
            log.exception("sweeping interrupted investigations failed")
        stop = threading.Event()
        if start_subscriber:
            threading.Thread(
                target=subscribe_alerts, args=(app.state.agent, stop), daemon=True, name="alerts"
            ).start()
        try:
            yield
        finally:
            stop.set()

    app = FastAPI(title="PulseCheck Incident Agent", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )


    def agent_of(request: Request) -> IncidentAgent:
        return request.app.state.agent

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "agent"}

    @app.get("/api/agent/incidents")
    def list_incidents(request: Request, user_id: UserId) -> list[dict]:
        return agent_of(request).deps.incidents.list(user_id)

    @app.get("/api/agent/incidents/{incident_id}")
    def get_incident(incident_id: str, request: Request, user_id: UserId) -> dict:
        deps = agent_of(request).deps
        incident = deps.incidents.get(incident_id, user_id)
        if incident is None:
            raise HTTPException(404, "Incident not found")
        return {**incident, "audit": deps.audit.list(incident_id)}

    def decide(request: Request, incident_id: str, decision: ApprovalDecision) -> dict:
        try:
            return agent_of(request).resume(incident_id, decision)
        except IncidentNotFound:
            raise HTTPException(404, "Incident not found") from None
        except InvalidIncidentState as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/agent/incidents/{incident_id}/approve")
    def approve(incident_id: str, body: ApproveBody, request: Request, user_id: UserId) -> dict:
        decision = ApprovalDecision(approved=True, actions=body.actions, approver=user_id)
        return decide(request, incident_id, decision)

    @app.post("/api/agent/incidents/{incident_id}/reject")
    def reject(incident_id: str, request: Request, user_id: UserId) -> dict:
        decision = ApprovalDecision(approved=False, actions=[], approver=user_id)
        return decide(request, incident_id, decision)

    @app.post("/api/agent/runbooks")
    def upload_runbook(body: RunbookBody, request: Request, user_id: UserId) -> dict[str, Any]:
        # Every tenant's incidents retrieve from the runbook collection, so uploads are
        # restricted to operators; otherwise one user could plant text for another's agent.
        if user_id not in settings.runbook_admins:
            raise HTTPException(403, "Runbook uploads are restricted to operators")
        try:
            chunks = agent_of(request).deps.kb.index_runbook(body.text, body.source)
        except Exception as exc:
            log.exception("runbook upload failed")
            raise HTTPException(503, f"Knowledge base unavailable: {exc}") from None
        return {"chunks": chunks}

    return app


app = create_app()
