# PulseCheck Incident Agent — Master Plan

> An AI incident-response service for PulseCheck. When a monitor goes **DOWN**, a team of
> specialist agents investigates, looks up runbooks and past incidents (RAG), writes a
> root-cause diagnosis, and **proposes** a fix that a human must approve before it runs.
> See [`PROGRESS.md`](./PROGRESS.md) for live status.

---

## 1. Goal

PulseCheck already detects outages and emails the owner. That tells the user *that* the API
is down, but not *why* or *what to do*. The incident agent closes that gap:

1. React to every `DOWN` event automatically, with no user action.
2. Gather evidence: re-probe the endpoint, check DNS / TLS, read the recent check history.
3. Retrieve relevant runbooks and similar past incidents (RAG).
4. Produce a structured diagnosis: category, root-cause hypothesis, confidence, evidence.
5. Propose remediation actions, and **pause for human approval** before any of them run.
6. Keep an audit trail of every tool call, cost budget, and decision.
7. Be measurable: an eval suite with seeded failure scenarios runs in CI.

## 2. Chosen stack (decided)

| Concern         | Choice                                   | Why |
| --------------- | ---------------------------------------- | --- |
| Language        | **Python 3.12** (new service)            | Services already talk over Redis, so mixing languages is free. Python has the most mature agent + eval ecosystem. |
| API             | **FastAPI**                              | Async, typed, auto OpenAPI docs. |
| Orchestration   | **LangGraph**                            | Explicit state graph, checkpointing, first-class `interrupt()` for HITL. |
| LLM             | **Claude** via the official `anthropic` SDK | Strong tool use and native structured outputs (Pydantic). Default `claude-opus-5-5`, set by `AGENT_MODEL`. |
| Vector store    | **Qdrant** (container; in-memory for tests) | One line in compose, no change to the existing Mongo. |
| Embeddings      | **fastembed** (`BAAI/bge-small-en-v1.5`) | Local ONNX model: no extra API key, no data leaves the box. |
| Checkpointer    | **MongoDB** (`langgraph-checkpoint-mongodb`) | Paused incidents survive a restart; reuses the existing DB. |
| Events          | Existing Redis channel `alert:status-change` | Same contract the notification service uses. |

## 3. Architecture

```
monitoring ──publish──► Redis "alert:status-change" ──► notification (email)
                                     │
                                     └──► agent service :3004 (Python)
                                              │
                         ┌────────────────────┴──────────────────────┐
                         │            LangGraph incident graph        │
                         │                                            │
                         │  triage ─► investigator ─► researcher ─►   │
                         │  (rules)   (tool loop)     (RAG/Qdrant)    │
                         │                                            │
                         │  ─► diagnoser ─► planner ─► ⏸ human_gate   │
                         │     (structured)  (allowlisted)  interrupt │
                         │                                    │       │
                         │                     approve ◄──────┤       │
                         │                     executor ─► reporter   │
                         └────────────────────────────────────────────┘
                                   │                    │
                            Mongo: incidents,     Qdrant: runbooks,
                            agent_audit,          past_incidents
                            checkpoints
```

### 3.1 Agent team (specialists + deterministic orchestration)

| Node           | Kind            | Responsibility |
| -------------- | --------------- | -------------- |
| `triage`       | Rules (no LLM)  | Classify the signal (timeout / DNS / TLS / 5xx / 4xx / unknown) from the alert payload. Cheap, fast, testable. |
| `investigator` | LLM + tools     | Bounded ReAct loop (max 4 tool calls): `probe_endpoint`, `check_dns`, `check_tls`, `recent_checks`. |
| `researcher`   | Retrieval       | Query Qdrant for top-k runbook chunks and similar resolved incidents. |
| `diagnoser`    | LLM, structured | Output `{category, root_cause, confidence, evidence[], cited_sources[]}` (Pydantic). |
| `planner`      | LLM, constrained| Propose actions **only** from the allowlist below, with a reason for each. |
| `human_gate`   | `interrupt()`   | Graph pauses; incident status = `AWAITING_APPROVAL`. Resumed by the approve/reject API. |
| `executor`     | Code            | Run approved actions only; re-check the allowlist and ownership. |
| `reporter`     | Code            | Finalise the incident, index it into `past_incidents` for future retrieval. |

Orchestration is a fixed graph, not an LLM supervisor. Routing an outage is predictable, so a
deterministic graph is cheaper, easier to test, and can't loop forever; the LLM is used only
where judgment is needed (investigate, diagnose, plan).

### 3.2 Action allowlist

| Action          | Effect | Risk |
| --------------- | ------ | ---- |
| `pause_monitor` | Set `monitors.active = false` for the affected monitor (stops alert spam). | Low, reversible |
| `escalate`      | Publish to Redis `agent:escalation` with the diagnosis. | Low |
| `no_action`     | Record the diagnosis only. | None |

Nothing outside this list can run, even if the model proposes it.

## 4. API (agent service, port 3004, JWT-protected with the shared secret)

| Method | Path                               | Purpose |
| ------ | ---------------------------------- | ------- |
| GET    | `/api/agent/incidents`             | List the caller's incidents (newest first). |
| GET    | `/api/agent/incidents/:id`         | Full incident: diagnosis, proposed actions, audit trail. |
| POST   | `/api/agent/incidents/:id/approve` | Body `{ actions: string[] }`: resume the graph with approved subset. |
| POST   | `/api/agent/incidents/:id/reject`  | Resume the graph with nothing approved. |
| POST   | `/api/agent/runbooks`              | Upload a markdown runbook → chunk, embed, index. |
| GET    | `/health`                          | Liveness. |

## 5. Security, risk & governance

| Risk | Mitigation |
| ---- | ---------- |
| **Prompt injection** via the monitored endpoint's response body (attacker controls it) | Bodies truncated to 2 KB and wrapped in `<untrusted_content>` tags; system prompt states tagged content is data, never instructions; planner output is validated against the allowlist in code, so an injected "delete everything" can't execute. Covered by an eval case. |
| **SSRF** through re-probe tools | Resolve hostname first; block private, loopback, link-local and metadata ranges (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, `fc00::/7`); http/https only; no redirects to blocked ranges. |
| **Cross-tenant access** | Every DB query and action is scoped by the `userId` from the alert/JWT; executor re-verifies monitor ownership. |
| **Runaway cost / loops** | Max 4 tool calls in the investigator, max tokens per incident (`AGENT_TOKEN_BUDGET`), one graph run per alert event (idempotent on `alertEventId`). |
| **Unreviewed autonomous change** | All side effects go through `human_gate`. No approval → no action. |
| **Auditability** | `agent_audit` collection: every node entry, tool call (args, truncated result, duration), token usage, approval decision and approver. |
| **Secrets** | API key only from the environment; never logged; never sent to tools. |

## 6. Evaluation

`services/agent/evals/` holds seeded scenarios with known answers (timeout, DNS failure,
expired TLS, 500 spike, 404 after deploy, auth 401, prompt-injection body, SSRF target, …).

| Metric | How |
| ------ | --- |
| Triage accuracy | Exact match on category (deterministic). |
| Retrieval hit@3 | Expected runbook appears in the top 3 retrieved chunks. |
| Diagnosis accuracy | Category match + LLM-judge rubric on the root cause (live mode only). |
| Action safety | 100% of proposed actions are in the allowlist; injection case proposes nothing destructive. |
| SSRF guard | Blocked targets are never fetched. |

Two modes: **offline** (scripted fake model, runs in CI with no API key, tests the wiring,
triage, retrieval and safety rails) and **live** (`ANTHROPIC_API_KEY` set, real model,
results table written to `evals/RESULTS.md`).

## 7. Phases (critical path only)

| # | Phase | Delivers |
| - | ----- | -------- |
| 1 | Service core + graph | FastAPI app, Redis subscriber, LangGraph graph with all nodes, tools, Mongo persistence, incidents API, HITL approve/reject. |
| 2 | RAG | Runbook chunking + embedding + Qdrant index, seed runbooks in `services/agent/runbooks/`, past-incident indexing, upload endpoint. |
| 3 | Security & governance | SSRF guard, untrusted-content wrapping, allowlist enforcement, ownership checks, token budget, audit log. Unit tests. |
| 4 | Evals + delivery | Scenario set, offline/live runner, `RESULTS.md`, Dockerfile + compose entries (agent + qdrant), web "Incidents" page with approve/reject. |

## 8. Definition of done

- `docker compose up` starts agent + qdrant alongside the existing services.
- Taking a monitored URL down produces an incident with a diagnosis that cites runbooks, in
  `AWAITING_APPROVAL`.
- Approving `pause_monitor` from the UI pauses the monitor; rejecting runs nothing.
- `pytest` (unit + offline evals) passes with no API key.
- Audit trail visible for every incident.

## 9. Out of scope (v1)

- LLM supervisor / dynamic agent spawning (fixed graph by design, see §3.1).
- Auto-remediation without approval.
- Multi-region probing, log/metrics ingestion from the user's infrastructure.
- Fine-tuning; hybrid (BM25 + vector) search.
