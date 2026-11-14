"""End-to-end smoke test against the running docker compose stack (run with AGENT_LLM=fake for a deterministic pass)."""
import json
import subprocess
import sys
import time
import uuid

import httpx

AUTH, MON, AGENT = "http://localhost:3001", "http://localhost:3002", "http://localhost:3004"
REPO = str(__import__("pathlib").Path(__file__).resolve().parents[3])


def step(msg):
    print(f"\n== {msg}", flush=True)


def publish(payload):
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", "PUBLISH", "alert:status-change", json.dumps(payload)],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    print("  subscribers:", out.stdout.strip())


def wait_for(client, iid, statuses, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"{AGENT}/api/agent/incidents/{iid}")
        if r.status_code == 200 and r.json()["status"] in statuses:
            return r.json()
        time.sleep(2)
    sys.exit(f"timeout waiting for {iid} -> {statuses}; last: {r.status_code} {r.text[:300]}")


step("health")
for base in (AUTH, MON, AGENT):
    print(" ", base, httpx.get(f"{base}/health", timeout=10).status_code)

step("register user")
email = f"e2e-{uuid.uuid4().hex[:8]}@example.com"
r = httpx.post(f"{AUTH}/api/auth/register", json={"email": email, "password": "Passw0rd!e2e", "name": "E2E"})
print(" ", r.status_code)
token = r.json().get("token") or httpx.post(f"{AUTH}/api/auth/login", json={"email": email, "password": "Passw0rd!e2e"}).json()["token"]
c = httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=30)
user_id = c.get(f"{AUTH}/api/auth/me").json()
user_id = user_id.get("user", user_id).get("_id") or user_id.get("user", user_id).get("id")
print("  user", user_id)

step("create monitor (unresolvable host)")
r = c.post(f"{MON}/api/monitors", json={"name": "Billing", "url": "https://billing.pulsecheck-e2e.invalid/health", "intervalSeconds": 3600})
print(" ", r.status_code)
mon = r.json().get("monitor", r.json())
monitor_id = mon.get("_id") or mon.get("id")

step("publish DOWN alert via Redis")
iid = uuid.uuid4().hex[:24]
alert = {
    "alertEventId": iid, "monitorId": monitor_id, "userId": user_id, "monitorName": "Billing",
    "monitorUrl": "https://billing.pulsecheck-e2e.invalid/health", "type": "DOWN",
    "statusCode": None, "latencyMs": 12, "errorMessage": "ENOTFOUND",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
publish(alert)
inc = wait_for(c, iid, {"AWAITING_APPROVAL", "RESOLVED", "FAILED"})
print("  status:", inc["status"], "| category:", inc.get("category"))
print("  evidence:", [e["summary"][:90] for e in inc["evidence"]])
print("  retrieved:", [d["source"] for d in inc["retrieved"]])
print("  diagnosis:", (inc.get("diagnosis") or {}).get("root_cause"))
print("  proposed:", [a["action"] for a in inc["proposed_actions"]], "| verification:", inc.get("verification"))
print("  audit events:", len(inc.get("audit", [])))
assert inc["status"] == "AWAITING_APPROVAL", inc.get("error")

step("other user cannot see it")
r2 = httpx.post(f"{AUTH}/api/auth/register", json={"email": f"x{email}", "password": "Passw0rd!e2e", "name": "X"})
other = httpx.Client(headers={"Authorization": f"Bearer {r2.json()['token']}"})
print("  other user GET ->", other.get(f"{AGENT}/api/agent/incidents/{iid}").status_code)

step("approve pause_monitor + escalate")
actions = [a["action"] for a in inc["proposed_actions"]]
r = c.post(f"{AGENT}/api/agent/incidents/{iid}/approve", json={"actions": actions})
print(" ", r.status_code, r.json()["status"], r.json()["results"])
m = c.get(f"{MON}/api/monitors/{monitor_id}").json()
m = m.get("monitor", m)
print("  monitor active after approval:", m.get("active"))
if "pause_monitor" in actions:
    assert m.get("active") is False

step("auto-close on recovery")
iid2 = uuid.uuid4().hex[:24]
publish({**alert, "alertEventId": iid2})
wait_for(c, iid2, {"AWAITING_APPROVAL"})
publish({**alert, "alertEventId": uuid.uuid4().hex[:24], "type": "RECOVERED", "errorMessage": None})
inc2 = wait_for(c, iid2, {"RESOLVED"}, timeout=30)
print("  status:", inc2["status"], "| approver:", (inc2.get("decision") or {}).get("approver"), "| results:", inc2["results"])

print("\nE2E OK")
