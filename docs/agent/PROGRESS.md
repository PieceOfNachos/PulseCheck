# PulseCheck Incident Agent — Progress Tracker

> Live status for [`PLAN.md`](./PLAN.md). Anyone picking this up: read **Module contracts**
> below first — every module is built against them, so they're the integration spec.

**Current phase:** Phases 1–3 in progress (parallel workstreams). Phase 4 after integration.

**Branch:** `feature/incident-agent` (off `feature/ui-phase2-3`)

---

## Phase status

| # | Phase                  | Status | Notes |
| - | ---------------------- | ------ | ----- |
| 1 | Service core + graph   | 🟡     |       |
| 2 | RAG                    | 🟡     |       |
| 3 | Security & governance  | 🟡     |       |
| 4 | Evals + delivery       | 🟡     | Docker/compose/web page in parallel; evals after integration |

## How to run (dev)

```bash
cd services/agent
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # (bin/ on macOS/Linux)
.venv/Scripts/python -m pytest -q                                       # unit tests + offline evals, no API key
AGENT_LLM=fake QDRANT_URL=:memory: .venv/Scripts/uvicorn app.main:app --port 3004
```

## Module contracts

Shared types live in [`services/agent/app/contracts.py`](../../services/agent/app/contracts.py)
and settings in [`app/config.py`](../../services/agent/app/config.py). Everything is
**synchronous** (pymongo, redis-py, sync FastAPI handlers) to keep the graph simple.

### Security — `app/security/`
| File | Interface |
| ---- | --------- |
| `ssrf.py` | `class BlockedTargetError(Exception)`; `assert_public_url(url: str) -> None` — http/https only; resolves host via `socket.getaddrinfo`; raises if any address is private/loopback/link-local/reserved/multicast/metadata. Bypassed when `settings.allow_private_targets`. |
| `untrusted.py` | `UNTRUSTED_POLICY: str` (system-prompt paragraph); `wrap_untrusted(text: str, source: str, limit: int \| None = None) -> str` — truncates (default `settings.untrusted_max_chars`), neutralises any `</untrusted_content>` inside, wraps in `<untrusted_content source="...">…</untrusted_content>`. |
| `allowlist.py` | `filter_actions(proposed: list[ProposedAction]) -> tuple[list[ProposedAction], list[ProposedAction]]` → `(allowed, rejected)`; dedupes; `no_action` is dropped if any other action is allowed. `validate_approved(approved: list[str], proposed: list[str]) -> list[str]` → only names both proposed and allowlisted. |
| `budget.py` | `class BudgetExceeded(Exception)`; `class Budget(max_tool_calls, max_tokens, tool_calls=0, tokens_used=0)` with `can_call_tool() -> bool`, `charge_tool()`, `charge_tokens(n)` (raise `BudgetExceeded` when over). |
| `audit.py` | `class AuditLog(collection)` (pymongo collection or `InMemoryCollection`): `record(incident_id, user_id, event, **data) -> None` (adds ISO `at`, redacts keys matching `key\|token\|secret\|password\|authorization`, truncates long strings to 1000 chars); `list(incident_id) -> list[dict]` ordered by time. |
| `auth.py` | `user_id_from_auth_header(header: str \| None) -> str` — HS256 JWT with `settings.jwt_secret`, payload `{id, email}`; raises `fastapi.HTTPException(401)`. |

### RAG — `app/rag/`
| File | Interface |
| ---- | --------- |
| `chunker.py` | `chunk_markdown(text: str, source: str, max_chars: int = 900) -> list[dict]` — split on headings, each `{"source", "title", "text"}`. |
| `store.py` | `class KnowledgeBase(url: str = settings.qdrant_url, embed_model: str = settings.embed_model)`; collections `runbooks`, `past_incidents`; `ensure_collections()`; `index_runbook(text, source) -> int`; `index_runbooks_dir(path) -> int` (idempotent, uuid5 ids); `index_incident(incident_id, user_id, text, category) -> None`; `search(query, k=3, user_id: str \| None = None) -> list[RetrievedDoc]` (runbooks + that user's past incidents only, merged by score). |
| `services/agent/runbooks/*.md` | Seed runbooks: timeout, dns, tls, server-errors-5xx, auth-401-403, not-found-404-deploy, connection-refused. |

### Core — `app/`
| File | Interface |
| ---- | --------- |
| `llm.py` | `class LLM(Protocol)`: `choose_tools(alert, category, evidence) -> tuple[list[str], int]` (tool names from `TOOL_NAMES`, empty = done; int = tokens), `diagnose(alert, category, evidence, retrieved) -> tuple[Diagnosis, int]`, `plan(alert, diagnosis, evidence) -> tuple[ActionPlan, int]`. `AnthropicLLM` (official `anthropic` SDK: tool use with `tool_choice=auto`, `client.messages.parse(output_format=...)` for Diagnosis/ActionPlan, `output_config={"effort": settings.effort}`, no temperature/thinking params) and `FakeLLM` (deterministic, scripted; "gullible" — copies any action named in an injected instruction so the allowlist is exercised). `get_llm()` picks by `settings.llm_provider`. |
| `tools/probes.py` | `TOOL_NAMES = ["probe_endpoint", "check_dns", "check_tls", "recent_checks"]`. `class Probes(Protocol)` with one method per tool name taking `(alert: AlertEvent) -> Evidence`. **Tools take no URL argument from the model** — the target is always the monitor's own URL from the alert (removes model-chosen SSRF). `RealProbes(db)` uses httpx (no redirects followed), `socket`, `ssl`, and the `checkresults` collection; calls `assert_public_url` and `wrap_untrusted`. |
| `store.py` | `get_db()`; `IncidentRepo(collection)`: `upsert(doc: dict)`, `get(id, user_id) -> dict \| None`, `list(user_id) -> list[dict]`; `MonitorRepo(collection)`: `get_owned(monitor_id, user_id) -> dict \| None`, `pause(monitor_id, user_id) -> bool`. `InMemoryCollection` (minimal find/find_one/insert_one/update_one/replace_one) for tests/evals. |
| `graph.py` | `@dataclass Deps(llm, probes, kb, incidents, monitors, audit, publish: Callable[[str, dict], None])`; `build_graph(deps, checkpointer)`; nodes triage → investigator → researcher → diagnoser → planner → human_gate (`interrupt()`) → executor → reporter. `class IncidentAgent(deps, checkpointer)`: `start(alert: AlertEvent) -> dict` (idempotent on alertEventId), `resume(incident_id, decision: ApprovalDecision) -> dict`. `triage(alert) -> Category` is a pure function. |
| `main.py` | FastAPI app (CORS on), routes from PLAN §4, startup: index runbooks, start Redis subscriber thread on `alert:status-change` (DOWN only). Mongo checkpointer (`langgraph.checkpoint.mongodb.MongoDBSaver`), falls back to `MemorySaver` if unavailable. |

### Evals — `services/agent/evals/`
`scenarios.py` (list of scenario dicts: alert, fake probe evidence, expected category, expected runbook source, forbidden actions), `run_evals.py` (offline by default; `--live` uses `AnthropicLLM`), writes `evals/RESULTS.md`. `tests/test_evals_offline.py` asserts thresholds in CI.

---

## Task checklist

### Phase 1 — Service core + graph
- [ ] `services/agent` scaffold (requirements, config, contracts) ✅ contracts/config done
- [ ] `llm.py` (AnthropicLLM + FakeLLM)
- [ ] `tools/probes.py`
- [ ] `store.py` + in-memory collection
- [ ] `graph.py` (all nodes, interrupt, IncidentAgent)
- [ ] `main.py` (API, Redis subscriber, checkpointer)
- [ ] Tests

### Phase 2 — RAG
- [ ] Chunker
- [ ] KnowledgeBase (Qdrant + fastembed)
- [ ] Seed runbooks
- [ ] Tests

### Phase 3 — Security & governance
- [ ] ssrf, untrusted, allowlist, budget, audit, auth
- [ ] Tests

### Phase 4 — Evals + delivery
- [ ] Dockerfile + compose (agent, qdrant)
- [ ] Web: Incidents page with approve/reject
- [ ] Evals + RESULTS.md
- [ ] README section

## Decision log

| Date | Decision |
| ---- | -------- |
| 2026-11-13 | Python service (FastAPI + LangGraph) alongside the Node services; Redis keeps the boundary language-neutral. |
| 2026-11-13 | Deterministic graph over LLM supervisor: predictable, testable, bounded cost. |
| 2026-11-13 | LangGraph for orchestration, official `anthropic` SDK inside nodes (no LangChain model wrapper): fewer layers, direct access to structured outputs. |
| 2026-11-13 | Probe tools take no arguments from the model; target URL is bound from the alert. Removes model-chosen SSRF entirely. |
| 2026-11-13 | Local fastembed embeddings + Qdrant: no second API key, data stays local. |
| 2026-11-13 | Evals run offline with a scripted model in CI; live mode when an API key is present. |
