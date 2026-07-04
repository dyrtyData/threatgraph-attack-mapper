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
| Streamlit UI build | _tbd_ | Phase 1/3 |
| Vite + React + Tailwind client build | _tbd_ | Phase 6 |
| Open WebUI wiring | _tbd_ | Phase 7 |
