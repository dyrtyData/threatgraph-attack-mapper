# PROGRESS — PF-001 Autonomous Threat-Intel & Attack-Graph Mapper

Running progress log for the `threatgraph` multi-agent pipeline built inside this
`agent-service-toolkit/` build base. Timestamped, phase-boundary entries record what
was decided, built, and still open — plus per-component wall-clock timings, since this
is a **dry run** for a timed live interview (measuring the cost of the full stack so the
live-run cut list can be made from data, not guesswork).

---

## 2026-07-04 16:29 EDT — Phase 0: Setup & tracking scaffold (sprint start)

Sprint kickoff. The toolkit has already been *absorbed* into the public `perficient`
repo (its nested `.git` moved to `~/.pf-001-backups/`), so every file here surfaces as a
normal tracked file in `perficient` and every incremental commit lands in that history —
which is where the "process" the reviewer wants to see lives.

### Stack triage (AC1)

Because this is a **dry run**, the usual "cut for time" triage is *inverted*: we build the
fullest version of every pillar and **measure** cost (see the timing table below) rather
than pre-cutting. The classifications below therefore mark what is a scored **core**
deliverable versus genuine nice-to-have / out-of-scope, not what we intend to skip.

**Core (all six pillars — building the mature version of each):**

| Pillar | Choice | Notes |
| --- | --- | --- |
| Orchestration | LangGraph `StateGraph` — new `threatgraph` sibling agent | `guard_input → retrieve → extractor → graph_architect → defensive_guardrail → END`; registered by one import + one dict entry in `agents.py` (toolkit's only discovery mechanism). |
| Knowledge retrieval / grounding | **Full hybrid RAG** (DQ2) | BM25 + dense (Chroma) fused via `EnsembleRetriever` weighted RRF, then `CrossEncoder` rerank, over the **full ~650+ record** MITRE ATT&CK corpus. Isolated behind one function so a dense-only fallback is a one-line swap for the live run. |
| Memory | **Hosted Mem0 v3** (DQ4) | `MemoryClient.add/.search`, scoped `app_id=perficient-threatgraph`, `user_id=dyrtydata`. Graph memory is automatic on v3 — **no** deprecated `enable_graph`/`version="v2"` flags (documented deviation from AC4's literal wording; see Phase 4). Fail-open no-op when `MEM0_API_KEY` is unset. |
| Safety / guardrails | **Guardrails AI** (output) + existing `Safeguard` (input) (DQ3) | `Guard.for_pydantic(DefenseConfig, on_fail=reask/fix)` validates the defense config; existing prompt-injection classifier gates input. Both fail open. |
| Observability | **Langfuse** (US region) | Tracing rides the existing `RunnableConfig` callback automatically — no per-node instrumentation needed. Keys already in `.env`. |
| Agent evaluation | **Langfuse dataset + experiment** (DQ7) | In-repo SDK evaluators (defense-config faithfulness, extracted-mechanics correctness) **and** UI-configured LLM-as-a-judge scores on captured traces. Results table lands here. |

**UIs (DQ5 — building all three, timed):**

- Streamlit client (fast path / dev + fallback view), Mermaid via `streamlit-mermaid` with a `components.v1.html` CDN fallback (DQ6).
- Vite + React + Tailwind v4 client consuming the FastAPI POST-SSE stream.
- Open WebUI wired to the same FastAPI endpoint (run in place, git-ignored).

**Nice-to-have (do if time):**

- Optional offline DeepEval faithfulness/answer-relevancy spot-check in the venv.
- Executive one-pager (business-value artifact).
- Trace/eval signal surfacing in the React UI.

**Out of scope (this sprint):**

- DeepEval red-teaming / adversarial suite (explicitly out of scope — too heavy).
- RAGFlow, NeMo Guardrails, the local `mem0/` OSS clone (hosted SDK used instead).
- Live threat-feed ingestion, multi-tenant auth, A2A/MCP cross-org protocols.
- Gating progress on the Docker end-to-end path — tests run **locally** (`uv run pytest`).

### Environment bring-up

- `uv venv` + `uv sync --frozen` — resolved cleanly (Python 3.12, `uv` 0.8.22).
- `.gitignore` verified: `.env`, `.env.local`, `.env.*.local`, `coms/`, `.deepeval/`, and
  every reference-only repo (`open-webui/`, `mem0/`, `guardrails/`, `ragflow/`, `deepeval/`,
  `books/`, `skills/`, `alex/`, `cyber/`, `production/`, `Guardrails/`) remain ignored;
  only `agent-service-toolkit/` is intentionally unignored (the build base).
- Baseline `uv run pytest -q`: **green — 126 passed, 2 skipped** after the test-config
  fix recorded below (was 114 passed + 12 auth 401s pre-fix).

### Resolved: baseline test 401s (absorb-model artifact) — Option 4a

- **Root cause.** `core/settings.py` resolves its env file via `find_dotenv()`, which walks
  up from `agent-service-toolkit/src/core/` past the toolkit (no local `.env`) to the
  **repo-root `.env`**, which carries a real `AUTH_SECRET`. That enables FastAPI bearer auth,
  so the 12 service tests that use the real `test_client` without a token returned `401`
  (upstream they return `200` because no parent `.env` exists and `AUTH_SECRET` is `None`).
  The auth-specific tests (`test_auth.py`) were always unaffected — they use the
  `mock_settings` fixture, which replaces `service.service.settings` wholesale.
- **Resolution (small, justified test-config deviation).** Added an **autouse** fixture in
  `tests/service/conftest.py` that neutralizes the ambient secret for service tests only via
  `monkeypatch.setattr("service.service.settings.AUTH_SECRET", None)`. This is test-scoped
  and auto-reverts; **no source and no root `.env`** are touched, so authenticated runs
  still work exactly as before and the auth-specific tests continue to exercise real bearer
  auth through their own `mock_settings`. Also removed a no-op `AUTH_SECRET = ""` line from
  `[tool.pytest_env]` in `pyproject.toml` (a no-op under `env_ignore_empty=True` that would
  have misled readers).

### Per-component wall-clock timing table

Filled in by later phases (dry-run deliverable — informs the live-run cut list).

| Component | Wall-clock | Notes |
| --- | --- | --- |
| ATT&CK corpus fetch (`fetch_attack_corpus.py`) | _tbd_ | Phase 2 — full ~650+ record fetch |
| Chroma index build (`index_attack_corpus.py`) | _tbd_ | Phase 2 — OpenAI embeddings + persist |
| BM25 retriever build | _tbd_ | Phase 2 |
| RRF fusion (`EnsembleRetriever`) | _tbd_ | Phase 2 |
| Cross-encoder rerank | _tbd_ | Phase 2 — model download cost noted separately |
| Guardrails AI validation | _tbd_ | Phase 3 |
| Mem0 recall/write round-trip | _tbd_ | Phase 4 |
| Langfuse experiment run | _tbd_ | Phase 5 |
| Streamlit UI build | ~20 min (Phase 1 skeleton) | Phase 1/3 — custom-message branch + Mermaid renderer w/ CDN fallback |
| Vite + React + Tailwind client build | _tbd_ | Phase 6 |
| Open WebUI wiring | _tbd_ | Phase 7 |

---

## 2026-07-04 17:24 EDT — Phase 1: Walking skeleton (`threatgraph` end-to-end + Mermaid render)

Thinnest vertical slice through the whole stack: a registered `threatgraph` `StateGraph`
that reuses the input safety gate and returns **canned** mechanics / Mermaid / defense
config in a terminal `custom` `ChatMessage`, discovered by the service, reachable via the
FastAPI `/threatgraph/invoke` endpoint, and rendered by Streamlit. This surfaced the two
highest-integration-risk items early — the registry/streaming/`custom_data` contract and
Mermaid-in-Streamlit rendering — before any real logic exists. Wall-clock: **~55 min**.

### Built

- **`src/agents/threatgraph.py`** — `ThreatGraphState(MessagesState, total=False)`; the
  `safeguard_input`/`check_safety`/`block_unsafe_content` idiom lifted verbatim from
  `research_assistant.py`; stub `retrieve → extractor → graph_architect → defensive_guardrail`
  linear pipeline. The terminal node builds an internally-consistent canned payload (the
  Mermaid nodes, extracted mechanics, and defense config all reference the same kill-chain
  technique IDs: T1566.001 → T1204.002 → T1059.001 → T1486) and emits it via the
  `CustomData` helper (`data → ChatMessage(content=[data], role="custom")`).
- **`src/agents/agents.py`** — one import + one `agents["threatgraph"]` dict entry (the
  toolkit's only discovery mechanism).
- **`src/streamlit_app.py`** — `render_mermaid()` (primary `streamlit-mermaid`
  `st_mermaid`, with a `components.html` + `mermaid@11` CDN fallback, explicit height +
  `scrolling=True`) and `draw_threatgraph_output()`; the `case "custom"` arm now branches on
  a `mermaid` key so threatgraph output renders while the bg-task-agent `TaskData` path is
  untouched.
- **`pyproject.toml`** — added `streamlit-mermaid` to the `client` group.
- Tests: `tests/agents/test_threatgraph.py` (benign path populates `mermaid`/`defense_config`
  + terminal `custom` message; unsafe path routes to `block_unsafe_content`),
  `tests/agents/test_agent_loading.py` (+registry/no-op-load asserts),
  `tests/app/test_streamlit_app.py` (+a `custom` mermaid message renders without error).

### Deviation: `streamlit-mermaid` pin (0.2.0, not 0.3.0)

`streamlit-mermaid==0.3.0` pins `setuptools>=75.6,<76`, which conflicts with the toolkit's
`setuptools ~=82.0.1` (unresolvable). Pinned `>=0.2.0,<0.3.0` instead — 0.2.0 depends only
on `streamlit` and renders identically for our use. Recorded here per the dry-run posture;
the `components.html` CDN fallback is the safety net if the package ever misbehaves.

### Verification

- `uv run pytest tests/agents/test_threatgraph.py tests/agents/test_agent_loading.py tests/app -q` → **22 passed**.
- Full suite `uv run pytest -q` → **131 passed, 2 skipped** (was 126/2 at Phase 0; +5 new).
- Registry: `get_all_agent_info()` includes `threatgraph`.
- FastAPI `TestClient`: GET `/info` lists `threatgraph`; POST `/threatgraph/invoke` →
  `200`, `type="custom"`, `custom_data` = `{mechanics, mermaid, defense_config}` (4 defense
  entries). `ruff check` clean on all changed files.
- Manual (service + `streamlit run`) verification: **confirmed** — benign snippet renders the
  kill-chain Mermaid graph (T1566.001 → T1204.002 → T1059.001 → T1486), the 4-row defense-config
  table, and the extracted-mechanics section. `streamlit-mermaid` 0.2.0 was the primary renderer;
  CDN fallback not needed.

### Operational lessons (for future projects branching off this base)

Two friction points hit during the Phase 1 manual run — documented so the next domain project
forking off `main` doesn't rediscover them:

1. **Always launch via `uv run`, never bare `python`.** Running `python src/run_service.py`
   directly used the ambient global interpreter (miniconda) and died with
   `ModuleNotFoundError: No module named 'langfuse'`. The project deps live in the `uv`-managed
   `.venv`, so use `uv run python src/run_service.py` and `uv run streamlit run src/streamlit_app.py`.
2. **Port 8080 collides with the local CTO-brain RAG server.** The toolkit's FastAPI service
   defaults to `:8080`, but this machine already runs the `askCTObrain` server on `:8080`
   (`/health`→200, `/info`→404). Symptom: `[Errno 48] address already in use` on the service,
   and Streamlit shows `404 Not Found ... /info` (the brain answers, not the agent service).
   Fix: run the agent service on a free port and point the client at it —
   `PORT=8081 uv run python src/run_service.py` and
   `AGENT_URL=http://localhost:8081 uv run streamlit run src/streamlit_app.py`.

### Git housekeeping: `main` promoted to the clean shared base

To support running unrelated future projects as parallel worktree branches off a common base,
`main` was **fast-forwarded** from `a502620` to `f138a96` — the merge commit that contains the
full `agent-service-toolkit` + ATT&CK tooling but **no PF-001 domain code**. Net effect:

- `main` = clean shared toolkit base (96 toolkit files tracked, zero threatgraph code).
- All PF-001 work stays exclusively on the `glo-21-…` branch and is **never merged** to `main`.
- New domains start with `git worktree add <path> -b <branch> main`, inheriting the toolkit.

This was a pure pointer fast-forward (no history rewrite; reversible via `git branch -f main a502620`).
The main worktree's pre-existing untracked base copies were tucked into a `git stash -u` safety net
first (git-ignored `.venv`/corpus excluded); the local-only `CLAUDE.md` was preserved out-of-band.
