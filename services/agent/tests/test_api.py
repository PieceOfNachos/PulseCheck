"""HTTP API: auth, ownership and the approval flow."""

from __future__ import annotations

import time

import jwt
import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver

from app.config import settings
from app.contracts import AUTO_RECOVERY_APPROVER
from app.graph import INTERRUPTED_ERROR
from app.main import create_app, handle_alert_message
from tests.agent_fakes import OTHER_USER_ID, USER_ID, make_alert, make_harness


def auth(user_id: str = USER_ID) -> dict[str, str]:
    token = jwt.encode(
        {"id": user_id, "email": "owner@example.com", "exp": int(time.time()) + 600},
        settings.jwt_secret,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def harness():
    return make_harness()


@pytest.fixture
def client(harness):
    app = create_app(deps=harness.deps, checkpointer=MemorySaver(), start_subscriber=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def incident(client):
    return client.app.state.agent.start(make_alert())


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/agent/incidents"),
        ("get", "/api/agent/incidents/x"),
        ("post", "/api/agent/incidents/x/approve"),
        ("post", "/api/agent/incidents/x/reject"),
        ("post", "/api/agent/runbooks"),
    ],
)
def test_requires_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401
    bad = {"Authorization": "Bearer not-a-jwt"}
    assert getattr(client, method)(path, headers=bad).status_code == 401


def test_list_and_get_are_scoped_to_owner(client, incident):
    mine = client.get("/api/agent/incidents", headers=auth()).json()
    assert [i["id"] for i in mine] == [incident["id"]]
    assert client.get("/api/agent/incidents", headers=auth(OTHER_USER_ID)).json() == []

    detail = client.get(f"/api/agent/incidents/{incident['id']}", headers=auth()).json()
    assert detail["status"] == "AWAITING_APPROVAL"
    assert any(e["event"] == "tool_call" for e in detail["audit"])

    other = client.get(f"/api/agent/incidents/{incident['id']}", headers=auth(OTHER_USER_ID))
    assert other.status_code == 404


def test_approve_flow(client, harness, incident):
    url = f"/api/agent/incidents/{incident['id']}/approve"

    assert client.post(url, json={"actions": ["escalate"]}, headers=auth(OTHER_USER_ID)).status_code == 404

    res = client.post(url, json={"actions": ["escalate", "delete_monitor"]}, headers=auth())
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "RESOLVED"
    assert [r["action"] for r in body["results"]] == ["escalate"]
    assert body["decision"]["approver"] == USER_ID
    assert [ch for ch, _ in harness.published] == ["agent:escalation"]

    again = client.post(url, json={"actions": ["escalate"]}, headers=auth())
    assert again.status_code == 409


def test_reject_flow(client, harness, incident):
    res = client.post(f"/api/agent/incidents/{incident['id']}/reject", headers=auth())
    assert res.status_code == 200
    assert res.json()["results"] == []
    assert harness.published == []


def test_unknown_incident_is_404(client):
    res = client.post("/api/agent/incidents/nope/approve", json={"actions": []}, headers=auth())
    assert res.status_code == 404


def test_runbook_upload_requires_operator(client):
    body = {"source": "custom.md", "text": "# Fix\nRestart it."}
    assert client.post("/api/agent/runbooks", json=body, headers=auth()).status_code == 403


def test_runbook_upload(client, monkeypatch):
    import dataclasses

    import app.main as main

    monkeypatch.setattr(main, "settings", dataclasses.replace(settings, runbook_admins=frozenset({USER_ID})))
    res = client.post(
        "/api/agent/runbooks", json={"source": "custom.md", "text": "# Fix\nRestart it."}, headers=auth()
    )
    assert res.json() == {"chunks": 2}
    too_big = {"source": "big.md", "text": "x" * 50_001}
    assert client.post("/api/agent/runbooks", json=too_big, headers=auth()).status_code == 422


def test_subscriber_handler_starts_down_alerts_only(client, harness):
    agent = client.app.state.agent
    handle_alert_message(agent, make_alert(type="RECOVERED").model_dump_json())
    handle_alert_message(agent, b"not json")
    assert harness.deps.incidents.list(USER_ID) == []

    handle_alert_message(agent, make_alert().model_dump_json())
    assert len(harness.deps.incidents.list(USER_ID)) == 1


def test_recovered_alert_closes_pending_incident(client, harness):
    agent = client.app.state.agent
    incident = agent.start(make_alert(statusCode=None, errorMessage="ENOTFOUND"))
    assert incident["status"] == "AWAITING_APPROVAL"

    handle_alert_message(agent, make_alert(type="RECOVERED").model_dump_json())

    detail = client.get(f"/api/agent/incidents/{incident['id']}", headers=auth()).json()
    assert detail["status"] == "RESOLVED"
    assert detail["results"] == []
    assert detail["decision"]["approver"] == AUTO_RECOVERY_APPROVER
    assert "auto_closed_on_recovery" in [e["event"] for e in detail["audit"]]
    assert harness.monitors.docs[0]["active"] is True

    url = f"/api/agent/incidents/{incident['id']}/approve"
    assert client.post(url, json={"actions": ["pause_monitor"]}, headers=auth()).status_code == 409
    assert harness.monitors.docs[0]["active"] is True


def test_startup_fails_interrupted_investigations(harness):
    alert = make_alert()
    harness.deps.incidents.upsert(
        {
            "id": alert.alertEventId,
            "userId": USER_ID,
            "monitorId": alert.monitorId,
            "status": "INVESTIGATING",
        }
    )
    app = create_app(deps=harness.deps, checkpointer=MemorySaver(), start_subscriber=False)
    with TestClient(app) as c:
        detail = c.get(f"/api/agent/incidents/{alert.alertEventId}", headers=auth()).json()

    assert detail["status"] == "FAILED"
    assert detail["error"] == INTERRUPTED_ERROR
