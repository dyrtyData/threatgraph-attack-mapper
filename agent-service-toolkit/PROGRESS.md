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
| Memory | **Hosted Mem0 v3** (DQ4) | `MemoryClient.add/.search`, scoped `app_id=perficient-threatgraph`, `user_id=dyrtydata`. **Scoping is asymmetric: `add` takes `user_id`/`app_id` as TOP-LEVEL kwargs; `search` takes them inside `filters=`** (add 400s on filters-only; search rejects top-level — verified live 2026-07-04, see Phase 4). Graph memory is automatic on v3 — **no** deprecated `enable_graph`/`version="v2"` flags. Fail-open no-op when `MEM0_API_KEY` is unset. |
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
| ATT&CK corpus fetch (`fetch_attack_corpus.py`) | **5.5 s** | Phase 2 — full fetch → **697 records** (STIX download + distill; raw bundle then cached) |
| Chroma index build (`index_attack_corpus.py`) | **10.2 s** | Phase 2 — 697 records, OpenAI embeddings + persist to `attack` collection (15.4 s incl. import) |
| BM25 retriever build | **0.03 s** | Phase 2 — `BM25Retriever.from_documents` over 697 docs (in-memory, offline) |
| RRF fusion (`EnsembleRetriever`) | **~1.2 s / query** | Phase 2 — fused query (BM25 top-10 ∪ dense top-10 → 15 candidates); retriever construction ~2.0 s (incl. dense leg open) |
| Cross-encoder rerank | **~84 ms / query** | Phase 2 — `ms-marco-MiniLM-L6-v2`, 15 candidates, model cached. **First-run model download: ~27 s (~90 MB), one-time, opt-in `--run-integration`** |
| Guardrails AI validation | **~10.6 ms / call** | Phase 3 — `Guard.for_pydantic(DefenseConfig).parse(...)`, 3-entry config, local Pydantic structural validation (no Hub inference; `use_remote_inferencing=false`). One-time cold cost: `import guardrails` + `Guard.for_pydantic` build **~1.18 s** |
| Mem0 recall/write round-trip | **~0.0002 ms/pair (disabled fail-open no-op)** | Phase 4 — default path is DISABLED (no key) → `recall`/`remember` short-circuit before any SDK call. Mocked-client path (offline tests) adds only `MagicMock` overhead. **Real hosted v3 round-trip is a live-key manual step** (not exercised by default; keeps `pytest` offline) — measure it during the two-run recall manual verification. |
| Langfuse experiment run | 2m09s (129s) wall-clock | Phase 5 — offline harness + evaluators built & tested (10 tests). Live `run_experiment.py` on 2026-07-05: dataset upsert + 5-item experiment over the real graph (hybrid RAG + cross-encoder reranker + guardrails + LLM extraction). `cross-encoder/ms-marco-MiniLM-L6-v2` (~88MB) was already HF-cached, so no download occurred this run (add ~download time on a cold cache). |
| Streamlit UI build | ~20 min (Phase 1 skeleton) | Phase 1/3 — custom-message branch + Mermaid renderer w/ CDN fallback |
| Vite + React + Tailwind client build | **2.86 s** (`npm run build`, wall-clock) | Phase 6 — `tsc -b && vite build`; Vite 8 + `@tailwindcss/vite` v4 + mermaid 11; node v22.23.1. `npm install` ~30 s (244 pkgs, one-time). `npm run test` (vitest) 5 tests ~1.3 s. |
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
3. **The FastAPI service does NOT auto-reload by default; Streamlit does.** Editing agent
   code (e.g. `threatgraph.py`) has no effect on an already-running service unless it was
   started in dev mode — symptom: the UI keeps showing the *previous* phase's output. Start
   the service with `MODE=dev` so `reload=settings.is_dev()` (`run_service.py`) is `True` and
   uvicorn watches `src/` and restarts on edits:
   `MODE=dev PORT=8081 uv run python src/run_service.py`. Streamlit reruns its own script on
   change automatically, but it talks to the service over HTTP, so a stale service still
   serves stale results. (This bit us verifying Phase 2 — the service kept running the Phase 1
   canned agent until restarted; once restarted in dev mode a non-seed snippet correctly
   extracted `T1003.001` (LSASS), which is absent from the canned chain — proving the real path.)

4. **Langfuse tracing is OFF by default — set `LANGFUSE_TRACING=true`.** `Settings.LANGFUSE_TRACING`
   defaults to `false`, so the FastAPI service does NOT emit traces unless the env var is set —
   even though the keys are in `.env`. Symptom: Streamlit runs work but the Langfuse project stays
   empty (no per-node spans). Fix: add `LANGFUSE_TRACING=true` to `.env` and restart the service;
   each request then produces a trace with the `guard_input → retrieve → extractor → graph_architect
   → defensive_guardrail` span tree (latency + tokens). Note the eval **experiment** (`evals/run_experiment.py`)
   pushes its own traces via the `Langfuse()` client regardless of this flag — this flag only gates
   the *live service* tracing. General lesson for future projects: enabling the tracing SDK ≠ tracing
   on; there's usually an explicit on/off flag separate from the credentials.
   - Also: the Langfuse **REST API** works with the project public/secret keys via HTTP Basic auth
     (`curl -u pk:sk https://us.cloud.langfuse.com/api/public/traces`) — verified. There is **no
     official Langfuse CLI**; project/evaluator setup is UI-only (or org-scoped API). Programmatic
     read/write of traces/scores/datasets is via the REST API or the `langfuse` Python SDK.
5. **Browser client needs CORS + a client-auth strategy that server-side clients hide; and
   `AUTH_SECRET=` does NOT turn auth off.** The React client (Vite `:5173` → service `:8081`)
   first failed with "Failed to fetch" — the service had no CORS, so the cross-origin preflight
   returned 405 with no `Access-Control-Allow-Origin` and the browser blocked it (Streamlit was
   unaffected — it calls server-side). After adding `CORSMiddleware` (configurable
   `CORS_ALLOW_ORIGINS`), it returned **401**: the repo-root `.env` sets `AUTH_SECRET` (bearer auth
   ON) and a browser can't read your `.env` to send the token, whereas Streamlit's Python client
   auto-attaches it. Critical gotcha: `AUTH_SECRET=` (empty) does **not** disable auth —
   `Settings(env_ignore_empty=True)` ignores the empty override and falls back to `.env` (verified:
   `settings.AUTH_SECRET` → STILL ENABLED). Fix chosen: give the browser the token via a
   **git-ignored `frontend/.env`** (`VITE_AGENT_TOKEN=<AUTH_SECRET>`) and keep auth ON; restart Vite
   to load it. Security caveat: `VITE_*` vars are compiled into the browser bundle, so an embedded
   bearer token is a **local-dev shortcut only** — production uses a real user-auth flow, not a
   shared client secret. General lesson: the first browser-origin caller exposes two gaps a
   server-side client hides — **CORS** and **client-side auth**.

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

---

## 2026-07-04 — Phase 2: Grounded Extractor + Graph_Architect over full ATT&CK hybrid retrieval

Replaced the `retrieve`/`extractor`/`graph_architect` stubs with real logic backed by a shared
hybrid-retrieval node over the **full 697-record** MITRE ATT&CK corpus. The retriever is isolated
in one module so a dense-only fallback is a one-line swap for the timed live run.

### Built

- **`scripts/fetch_attack_corpus.py`** (ran) — full fetch → `data/attack/attack_corpus.jsonl`,
  **697 techniques** (≥650 target), 5.5 s.
- **`scripts/index_attack_corpus.py`** (new) — reads the JSONL, shapes `Document`s (name + tactics
  + description + mitigations), embeds with `OpenAIEmbeddings`, persists to a dedicated `attack`
  collection in `agent-service-toolkit/chroma_db`. Reuses the exact doc-shaping + explicit path
  resolution from `retrieval.py` so the dense + BM25 legs index identical text. 697 records, 10.2 s.
- **`src/agents/retrieval.py`** (new) — `build_attack_retriever()` (BM25 + Chroma dense fused via
  `EnsembleRetriever` weighted RRF `[0.5,0.5]`, then `CrossEncoder` rerank) and
  `retrieve_attack_context(query, k)`. **Fails open** to a BM25-only offline path (then to canned
  context) when the dense leg / OpenAI key is unavailable — mirrors the `Safeguard` idiom. Each leg
  is constructable in isolation for testing.
- **`src/schema/schema.py`** (edit) — added shared `Technique` + `ExtractedMechanics` Pydantic types
  (re-exported from `schema/__init__.py`) so the Phase 5 `evals/` harness can import them.
- **`src/agents/threatgraph.py`** (edit) — real `retrieve` node → `attack_context`; `extractor` uses
  `.with_structured_output(ExtractedMechanics)` grounded in `attack_context`, **canonicalizing** to
  the `Txxxx` ids present in the retrieved context (drops hallucinated ids), with a deterministic
  context-derived fallback; `graph_architect` renders a kill-chain Mermaid string from mechanics and
  runs a **structural parse-check** (`is_valid_mermaid` — leading `graph`/`flowchart`, ≥1 declared
  node, edges reference declared nodes) with a canned fallback. Internal LLM calls carry
  `.with_config(tags=["skip_stream"])`.
- **`pyproject.toml`** (edit) — added `rank-bm25`, `langchain-classic` (EnsembleRetriever, moved here
  in LangChain v1), `sentence-transformers`.
- **`.gitignore`** (edit) — ignore `agent-service-toolkit/chroma_db/` (binary index; the distilled
  JSONL corpus stays tracked, raw STIX bundle stays ignored).
- **Tests** — `tests/agents/test_retrieval.py` (offline vs the 14-record **seed** corpus: BM25
  "spearphishing attachment macro" → T1566.001 in top-k; RRF union of two legs; ensemble wiring;
  the CrossEncoder-download rerank test marked opt-in `integration`), `tests/agents/test_threatgraph.py`
  (edited for the new shapes: benign full-graph path with stubbed retrieval + forced fallback;
  structured-extractor canonicalization via a fake structured model; context fallback; Mermaid
  render + structural validity). Added a `--run-integration` marker in `tests/conftest.py` mirroring
  `--run-docker` so default `pytest` stays fast + offline.

### Open-question resolutions (per the outline)

- **Corpus/Chroma paths** — resolved **explicitly** off `retrieval.py`'s location (`_AST_ROOT` /
  `_REPO_ROOT`), not CWD, so BM25 (repo-root `data/attack/…jsonl`) and Chroma
  (`agent-service-toolkit/chroma_db`, collection `attack`) read the same files regardless of launch
  dir. The index script imports the same constants.
- **Shared types** — `ExtractedMechanics`/`Technique` live in `src/schema/schema.py` (importable by
  `evals/`), as the outline specified.
- **Reranker in CI** — the CrossEncoder-download test is opt-in `integration` (skipped by default),
  keeping `uv run pytest` fast + offline.

### Verification

- `uv run python scripts/fetch_attack_corpus.py` → **697** records (`wc -l` ≥ 650 ✅).
- `uv run python scripts/index_attack_corpus.py` → `chroma_db` with the `attack` collection
  (`count() == 697`) ✅.
- `uv run pytest tests/agents/test_retrieval.py tests/agents/test_threatgraph.py -q` → **11 passed,
  1 skipped** (the opt-in reranker) ✅. Full suite `uv run pytest -q` → **140 passed, 3 skipped**
  (was 131/2 at Phase 1). `ruff check` clean on all changed files.
- End-to-end hybrid query (`spearphishing … powershell … ransomware`) fused top ids include
  T1566.001 + T1486; opt-in `--run-integration` rerank promotes T1566.001 to the top.
- Manual Streamlit kill-chain render + per-stage timings: timing table filled above; Streamlit
  visual confirmation pending (human manual-verification step).

---

## 2026-07-04 — Phase 2 tuning pass: fix multi-technique under-extraction

Phase 2 was functionally complete (real hybrid-RAG + structured extraction proven end-to-end),
but the extractor **under-extracted**: on a multi-technique incident snippet it returned only
1–2 techniques instead of the ~4 present.

### Root cause (found by instrumenting each retrieval leg)

Two compounding causes, both on the *retrieval* side (the extractor was correctly grounding
only what it was given):

1. **Single-query retrieval over the whole snippet + narrow `k=5`.** One query for the entire
   incident surfaces mostly the neighbors of the *single most salient* phrase, so the grounding
   set is starved of the other techniques.
2. **The cross-encoder rerank collapses diversity — this was the real killer.** The BM25 + dense
   RRF **fusion** actually produced a *diverse* candidate set (for the test snippet the fused top
   candidates included `T1021.001` RDP and `T1567.002` cloud-exfil alongside the credential-dump
   techniques). But a single-query cross-encoder rerank over the *whole* fused set scores every doc
   against the full incident text, and the densest phrase ("dump credentials from LSASS memory")
   dominates — so the reranked top-k was **entirely** credential-access variants
   (`T1003.*`/`T1110.*`/`T1550.*`), evicting the lateral-movement and exfil techniques.
   Because the extractor grounds only what's retrieved, those techniques were then impossible to
   extract. Raising `k` alone does **not** fix this — the rerank just fills every slot with the
   same cluster.

### Fix (k + enumerate-then-ground + rerank-as-reorder-only)

- **`retrieval.py` — RRF fusion is now the diversity/recall mechanism; the cross-encoder only
  *reorders*.** `build_attack_retriever._retrieve` now takes the RRF-diverse fused **top-k as the
  grounding membership**, then reranks only that window (`rerank_documents(query, fused[:k], k=k)`)
  instead of reranking the whole fused set down to one collapsed cluster. Also broadened the
  per-leg fan-out `CANDIDATE_K` 10 → 20 and added `CONTEXT_K = 15` (the wide grounding window used
  by the graph's `retrieve` node; the library `DEFAULT_K = 5` is unchanged). The BM25-only /
  dense-only fail-open ladder is untouched.
- **`threatgraph.py` — `retrieve` node uses `CONTEXT_K` (15), not the narrow `DEFAULT_K` (5).**
- **`threatgraph.py` — extractor prompt rewritten to *enumerate-then-ground*.** STEP 1: list EVERY
  distinct attacker behavior (incidents span multiple tactics — don't stop at the dominant one);
  STEP 2: ground each enumerated behavior to the single best-matching retrieved ATT&CK id, one
  entry per behavior. Still `.with_structured_output(ExtractedMechanics)`, still canonicalizes to
  the `Txxxx` ids present in context and drops hallucinated ids — but the widened, diversity-
  preserving grounding set means real techniques now survive.

### Before / after (test snippet, real OpenAI key)

Snippet: *"The intruder logged in with stolen VPN credentials, ran Mimikatz to dump credentials
from LSASS memory, then pivoted to other hosts over RDP and exfiltrated archives to a cloud
storage bucket over HTTPS."*

- **Before** (k=5, describe-dominant prompt): `['T1110.004', 'T1003.001']` — 2 techniques, both
  Credential Access (the collapsed cluster); no lateral movement, no exfil.
- **After** (k=15, RRF-diverse membership + enumerate-then-ground): `['T1003.001', 'T1021.001',
  'T1567.002']` — 3 techniques spanning **Credential Access → Lateral Movement → Exfiltration**
  (LSASS Memory, Remote Desktop Protocol, Exfiltration to Cloud Storage), correctly grounded, no
  hallucinations. Confirmed via both the `extractor` node directly and full `threatgraph.ainvoke`.
- The 4th expected technique (`T1078` Valid Accounts, for the VPN login) does **not** surface: the
  correct base id is under-retrieved (only `T1078.004` "Cloud Accounts" appears at k≥18, which the
  model correctly declines as a poor match for a VPN login). Genuine single-query-retrieval recall
  limit for weakly-lexical initial-access techniques — see lesson below. 3-of-4 with a clean
  kill-chain spread and zero hallucination is the accepted result for this pass.

### General lesson (for future runs)

**Single-query retrieval + a single-query cross-encoder rerank + ground-only-what's-retrieved is a
recipe for multi-technique under-extraction.** A cross-encoder rerank optimizes precision for a
*single-intent* query; feeding it a whole multi-technique incident makes it collapse to the one
densest phrase and evict every other technique. For multi-intent grounding: (1) let RRF **fusion**
own diversity/recall and use the cross-encoder only to *reorder* a diverse window (not to filter
the fused set down); (2) widen `k` (~15); (3) prompt the extractor to **enumerate all behaviors
first, then ground each** rather than describe the dominant one. The remaining recall gap for
weakly-lexical techniques (e.g. `T1078` from "VPN login") is the next lever if needed:
**multi-query / per-behavior retrieval** (decompose the snippet, retrieve per behavior, union) —
deferred as it wasn't required to clear this pass.

### Verification

- `uv run pytest -q` → **140 passed, 3 skipped** (unchanged; extraction *shape* unchanged, so no
  test edits were needed — the offline benign/fallback and fake-structured-model tests still pass).
  `ruff check` clean on both changed files.
- Real-key in-process runs (both the `extractor` node and full `threatgraph.ainvoke`) produce the
  after ids above; Mermaid renders `graph TD` and passes the structural check.
- **Chroma index NOT rebuilt** — only retrieval *ranking* logic changed (k values + rerank-as-
  reorder); the corpus, document shaping, and embeddings are identical, and the dense leg simply
  requests more results from the existing 697-record `attack` collection. Timing table unchanged.

### Files changed

- `src/agents/retrieval.py` — `CANDIDATE_K` 10→20, new `CONTEXT_K=15`, `_retrieve` reranks the
  RRF-diverse top-k (reorder) instead of collapsing the whole fused set.
- `src/agents/threatgraph.py` — `retrieve` node uses `CONTEXT_K`; extractor prompt enumerate-then-ground.

## 2026-07-04 — Streamlit UX: progress indicator

**Root cause.** The `threatgraph` agent tags its internal LLM/retrieval calls with `skip_stream`,
so no tokens stream to the client — nothing renders in Streamlit until the terminal `custom`
message (Mermaid attack graph + defense config) arrives several seconds later. With no progress
indicator, the app looked frozen/broken for the entire wait.

**Fix (`src/streamlit_app.py`, Streamlit-only).** Added a visible "running" indicator around the
response consume, covering both toggle paths:
- **Streaming (`astream`) path:** `draw_messages` now shows an `st.status(..., state="running")`
  in an `st.empty()` placeholder (only when `is_new`) before awaiting the first chunk, and clears
  it the instant the first token/message renders. For `threatgraph` (skip_stream) it stays up
  during the wait, then clears when the terminal `custom` message lands. For token-streaming
  agents (research-assistant, etc.) it disappears the moment tokens start — so they are unaffected.
- **Non-streaming (`ainvoke`) path:** wrapped the `await agent_client.ainvoke(...)` in
  `with st.spinner("Analyzing threat intel & building attack graph…")`, which clears before the
  response renders.

No agent/service code touched. `uv run pytest tests/app -q` → **11 passed** (no test edits needed;
the indicator lives at the top level, not inside the chat-message containers the tests assert on).

**General lesson (for future projects).** Any agent that does non-streamed internal work — anything
tagged `skip_stream`, long tool/retrieval chains, or an `ainvoke` that only returns a terminal
message — produces a dead-looking UI with no feedback. Always pair such work with an explicit
progress indicator (spinner / `st.status`) that is shown while awaiting and cleared on first render,
so a slow-but-working agent is never mistaken for a frozen one.

## 2026-07-04 — Phase 3: Defensive_Guardrail with Guardrails AI Pydantic validation

Turned the canned defense stub into a real node: the `defensive_guardrail` now **synthesizes** a
`DefenseConfig` grounded in the retrieved `attack_context` mitigations and validates it through
Guardrails AI, then attaches the validated config to the terminal `custom` message. Fail-open
end-to-end, matching the `Safeguard`/retrieval philosophy — the graph never hard-crashes on the
guardrail step.

### Built

- **`src/schema/schema.py`** — added shared Pydantic types `Defense` (`technique_id`,
  `mitigation_id`, `action`, `rationale`) and `DefenseConfig` (`defenses: list[Defense]`),
  mirroring how `Technique`/`ExtractedMechanics` were added in Phase 2. Both exported from
  `src/schema/__init__.py` so the Phase 5 `evals/` harness can import them.
- **`src/agents/guardrails.py`** (new) — `validate_defense_config(raw)` wraps
  `Guard.for_pydantic(DefenseConfig)` + `guard.parse(...)`. **Fail-open like `Safeguard`:** on any
  failure (guardrails import error, Guard build error, validation not passing) it falls back to a
  best-effort local parse (`_best_effort_parse`) that coerces the payload into a valid
  `DefenseConfig`, keeping every entry with the grounded core (`technique_id` + `mitigation_id`)
  and backfilling missing `action`/`rationale`. Accepts `str | dict | list | DefenseConfig`.
- **`src/agents/threatgraph.py`** — `defensive_guardrail` rewrite. `_grounded_pairs` walks the
  extracted `mechanics` in kill-chain order and joins each technique's mitigations **from
  `attack_context`** (never invented); `_synthesize_defense` writes the action/rationale prose via
  a structured LLM call tagged `skip_stream`, then **hard-filters** the result back to the allowed
  `(technique_id, mitigation_id)` pairs, failing open to a deterministic grounded synthesis
  (`_deterministic_defense`) when the model is unavailable. The synthesized config runs through
  `validate_defense_config` before being attached to `custom_data`. `CANNED_DEFENSE_CONFIG` is
  retained only as the last-resort fallback when no grounded pairs exist at all.
- **`pyproject.toml`** — added `guardrails-ai>=0.6` (resolved to **0.10.2**).
- **`tests/agents/test_defense_guardrail.py`** (new, 9 tests) — valid config passes; malformed
  output exercises the fix/fail-open path (missing fields backfilled, ungrounded entries dropped);
  garbage string fails open to an empty-but-valid config; bare-list/model inputs round-trip;
  `_grounded_pairs` only emits context-grounded pairs and ignores ungrounded techniques; the node
  synthesizes a validated, context-grounded config offline.
- **`tests/agents/test_threatgraph.py`** — extended the benign end-to-end assertion for the
  now-real defense_config shape (technique/mitigation/action/rationale) with mitigation ids
  grounded in the retrieved `attack_context`.

### Guardrails AI: local validation, no Hub needed

- The token / config already live in `~/.guardrailsrc` (`use_remote_inferencing=false`), so
  **validation runs entirely locally** — `Guard.for_pydantic(DefenseConfig)` enforces the Pydantic
  JSON structure in-process; there is **no Hub/network call** on the default path. This was
  confirmed at runtime (guardrails logs "Falling back to synchronous validation").
- **No `guardrails hub install` step was required** for this phase: `DefenseConfig` uses plain typed
  fields (no `guardrails.hub` validators like `DetectPII`/`ToxicLanguage`), so nothing needs to be
  fetched from the Hub. **If a future phase adds a Hub validator**, run (out-of-band, not committed):
  `guardrails hub install hub://guardrails/<validator>` — the token in `~/.guardrailsrc` authorizes
  it. The `~/.guardrailsrc` file is git-ignored and never enters history.
- **On `on_fail`:** `Guard.for_pydantic` takes no `on_fail` kwarg (that is a per-*validator*
  action). The outline's `on_fail=reask/fix` intent is realized as: structural validation via the
  Pydantic schema itself, `fix` semantics applied as the local best-effort coercion, and `reask`
  deliberately **not** wired to an `llm_api` (a network call) so the default node path stays
  offline/fast and fail-open.

### API note (deviation surfaced at implementation time)

The outline's signature sketch `Guard.for_pydantic(DefenseConfig, on_fail=reask/fix)` does not match
the installed guardrails-ai 0.10.2 API (`for_pydantic` has no `on_fail` param). Resolved as above —
the structure outline's *intent* (Guardrails-AI Pydantic validation, fail-open) is fully satisfied;
only the literal kwarg placement differs.

### Verification

- `uv run pytest tests/agents/test_defense_guardrail.py -q` → **9 passed**;
  `tests/agents/test_defense_guardrail.py tests/agents/test_threatgraph.py` → **15 passed**.
- Full suite `uv run pytest -q` → **148 passed, 3 skipped** (was 148/3 baseline entering the phase;
  the 3 skips are the opt-in `--run-integration` reranker-download test + 2 docker tests).
  `ruff check` clean on all changed files.
- **End-to-end (offline graph run):** the compiled `threatgraph` emits a terminal `custom` message
  whose `custom_data.defense_config` is a 3-entry, schema-valid `DefenseConfig`
  (`T1566.001→M1017`, `T1059.001→M1042`, `T1486→M1053`) with **every mitigation id grounded in the
  retrieved `attack_context`** — verified programmatically.
- Per-component timing (Guardrails validation ~10.6 ms/call warm; ~1.18 s cold import+build)
  recorded in the timing table above.

### Manual verification still pending (for the human)

- Streamlit: submit a real threat-intel snippet and confirm the defense-config table shows `Mxxxx`
  mitigations tied to the extracted `Txxxx` techniques (run the service with `MODE=dev` so it
  picks up the new node code; use `PORT=8081`/`AGENT_URL` per the Phase 1 note to avoid the `:8080`
  conflict).

---

## 2026-07-04 — DQ6 fix: CDN `components.html` + `mermaid@11` is now the PRIMARY Mermaid renderer

**Bug (confirmed in browser):** the attack graph failed to render with *"Your app is having
trouble loading the streamlit_mermaid.streamlit_mermaid component."* The prior `render_mermaid()`
used `streamlit-mermaid` (`st_mermaid`) as the **primary** renderer and only fell back to the
CDN `components.html` path on a **Python** exception. But `streamlit-mermaid` fails
**asynchronously in the browser** (its component frontend assets don't load), which raises **no
Python exception** — so the exception-based fallback never fired and the user saw a broken
component box.

**Fix (`src/streamlit_app.py`):**
- `render_mermaid()` now renders **only** via `st.components.v1.html(...)` — a self-contained
  inline HTML doc that imports `mermaid@11` (ESM) from jsdelivr, calls
  `mermaid.initialize({startOnLoad:false})`, then `mermaid.run({nodes})`.
- Diagram source is embedded in a `<pre class="mermaid">` block, **HTML-escaped** (`html.escape`),
  so backticks/quotes/newlines can't break the render (avoids JS string-escaping pitfalls).
- Unique **CSS-safe** container id per render (`"mermaid-" + uuid4().hex`, **no colons**) prevents
  collisions across Streamlit reruns.
- Explicit `height=500` + `scrolling=True` (the sandboxed iframe does not auto-resize).
- Dropped the `streamlit_mermaid` import/usage from the renderer. **The `streamlit-mermaid`
  dependency stays in `pyproject.toml`** (still installed) — it is simply no longer relied upon.

**Verify:** `uv run pytest tests/app -q` → **11 passed**; `ruff check src/streamlit_app.py` clean.
Generated HTML sanity-checked well-formed (parses; id has no colon; a `graph TD\n A-->B` source
embeds correctly in the `<pre>`).

**General lesson (future projects):** for Streamlit custom-component rendering, prefer a
self-contained CDN / `components.html` approach over third-party components whose frontend assets
can silently fail — and **never rely on Python `try/except` to catch browser-side component
failures**, because they raise no Python exception on the server.

---

## 2026-07-04 — Phase 4: Mem0 hosted memory (v3) recall + write

Wired hosted **Mem0 (v3)** into the graph: the Extractor **recalls** prior analyses and
**prepends** them to its grounding before structured extraction; the Defensive_Guardrail
**writes** the analysis turn after synthesis. All behind a small fail-open module that no-ops
when `MEM0_API_KEY` is unset — same philosophy as `Safeguard` / retrieval / guardrails, so the
graph never breaks on the memory step.

### Built

- **`src/memory/mem0_client.py`** (new) — lazy, fail-open wrapper: `get_mem0()`
  (`@lru_cache`d hosted `MemoryClient`, `None` when the key is unset or the SDK can't
  import/construct), `recall(query) -> list[dict]` (`[]` when disabled / on any error;
  normalizes the v3 `{"results": [...]}` shape), `remember(messages) -> None` (no-op when
  disabled / on any error). Scope constants `APP_ID="perficient-threatgraph"`,
  `USER_ID="dyrtydata"`.
- **`src/core/settings.py`** — declared `MEM0_API_KEY: SecretStr | None = None` (validation /
  gating only; the SDK reads the env var itself).
- **`src/agents/threatgraph.py`** — `extractor` calls `recall(raw_text)` and, when non-empty,
  **prepends** a "recalled from prior analyses" block *before* the ATT&CK grounding
  instructions (prompt byte-for-byte unchanged when recall is empty). `defensive_guardrail`
  builds an `_analysis_turn` (user snippet + an assistant summary of extracted techniques +
  recommended mitigations) and calls `remember(...)` after synthesis. Internal LLM calls keep
  their `skip_stream` tags; recall/remember are plain sync calls (like the `retrieve` node).
- **`pyproject.toml`** — added `mem0ai>=0.1.0` (resolved to **2.0.11**).
- **`.env.example`** (root) — `MEM0_API_KEY` placeholder already present (verified; unchanged).
- **`tests/conftest.py`** — added a global **autouse** `_mem0_offline_by_default` fixture that
  neutralizes the ambient real `MEM0_API_KEY` (repo-root `.env`, picked up by `find_dotenv`)
  and clears the client cache, so the default suite stays **offline**. Mirrors the Phase-0
  `AUTH_SECRET` neutralization; enabled-path tests re-set the key via their own `monkeypatch`
  (runs after, wins) and inject a fake `mem0` module — no real network call ever fires.
- **`tests/agents/test_mem0.py`** (new, 11 tests) — disabled fail-open no-ops (`recall`→`[]`,
  `remember`→no-op, `get_mem0`→`None`); the full graph runs to completion with Mem0 disabled;
  the enabled (mocked-client) path asserts `search`/`add` are called with the `user_id`/`app_id`
  scope **inside `filters`** and with **no** `version`/`enable_graph`/`output_format` flags;
  recall normalizes both `{"results":[...]}` and bare-list shapes; recall/remember fail open on
  client errors; the extractor **prepends** recalled facts (and leaves the prompt intact when
  recall is empty); the defensive_guardrail writes the analysis turn.

### DQ4 deviation — v3 auto-graph, no `enable_graph` / `version="v2"` (intentional, documented)

Per **DQ4** this is a deliberate, documented **deviation from AC4's literal wording**: the
hosted platform migrated v2→v3, so **Graph Memory is automatic**. We call `add`/`search`
**plainly** with **no** deprecated `enable_graph` / `version="v2"` / `output_format` flags
(they are ignored/removed on the current SDK; graph signal is folded into each result's unified
score). AC4's *intent* — graph+vector fusion, auto fact-extraction, correct `app_id`/`user_id`
scoping — is fully satisfied.

### API-shape note (CORRECTED 2026-07-04 — the earlier "filters for both" note was WRONG)

> **Supersedes the prior note.** An earlier revision claimed entity ids go **inside `filters`
> for BOTH `add` and `search`**. That was **wrong for `add`** and is the direct cause of the
> "0 stored memories" bug below. The two calls scope entities **asymmetrically**:
>
> * **`add` requires TOP-LEVEL entity kwargs** — `client.add(messages, user_id=..., app_id=...)`.
>   Passing them inside `filters=` makes `POST /v3/memories/add/` reject the write with
>   **HTTP 400 `ValidationError`: "At least one entity ID is required (user_id, agent_id,
>   app_id, or run_id)."** The add endpoint does **not** read entity ids from `filters`. (The
>   docstring lists `user_id`/`app_id` as valid top-level kwargs; `add` does **not** guard
>   against them — only `search`/`get_all` do.)
> * **`search`/`get_all` require the scope INSIDE `filters=`** and actively **raise
>   `ValueError`** on top-level entity params (`ENTITY_PARAMS = {user_id, agent_id, app_id,
>   run_id}`). No `version="v2"` kwarg is needed — v3 filters work plainly.
>
> Verified against the installed **`mem0ai` 2.0.11** SDK **and the live hosted API**.

**Root cause of the "add logged as a request but 0 memories stored" bug:** `remember()` called
`client.add(messages, filters={user_id, app_id})`. Server returned **400** ("At least one
entity ID is required…"); `remember`'s broad fail-open `except` swallowed it as a warning, so
every write silently no-op'd. The `add` still hit the API (hence "requests logged"), but stored
nothing → `search` always returned `[]` → UI showed "No prior memories recalled".

**Fix (`src/memory/mem0_client.py`):**
- `remember` → `client.add(messages, **_SCOPE)` — entity ids **top-level** (`_SCOPE = {"user_id":
  USER_ID, "app_id": APP_ID}`), file:`src/memory/mem0_client.py:remember`.
- `recall` → `client.search(query, filters=dict(_SCOPE), top_k=...)` — **unchanged**, scope in
  `filters` (correct for search).

**Live round-trip proof (real key, throwaway script, since cleaned up):**
```
remember([{user: "…Cobalt Strike beacon via T1055 process injection into explorer.exe"},
          {assistant: "…Extracted techniques: T1055; mitigations: M1040 counters T1055"}])
# wait ~20s for async v3 extraction
recall("Cobalt Strike process injection explorer.exe T1055") -> 4 memories (NON-EMPTY):
  - "…threat actor deployed a Cobalt Strike beacon by using ATT&CK technique T1055
     (Process Injection) to inject code into explorer.exe." | score 0.40
  - "…recommended mitigation M1040 to counter ATT&CK technique T1055…" | score 0.27
  (+ 2 prior probe memories, since deleted)
```
Confirmed the same `add(filters=…)` path returns **400** while `add(user_id=…, app_id=…)`
returns `{status: PENDING}` and the facts appear under the scope via both `get_all` and
`search`. All probe/round-trip test memories were deleted afterward; the throwaway scripts
were removed.

### Verification

- `uv run pytest tests/agents/test_mem0.py -q` → **11 passed**;
  `tests/agents/test_mem0.py tests/agents/test_threatgraph.py` → **18 passed**.
- Full suite `uv run pytest -q` → **159 passed, 3 skipped** (was 148/3 entering the phase; +11
  new Mem0 tests; the 3 skips remain the opt-in `--run-integration` reranker + 2 docker tests).
  `ruff check` clean on all changed files.
- **Fail-open confirmed:** with `MEM0_API_KEY` unset the compiled graph runs end-to-end and
  emits mechanics + Mermaid + defense_config; `recall`→`[]`, `remember`→no-op, `get_mem0`→`None`.
- **Real Mem0 was NOT exercised** — it was **mocked** (fake `mem0` module + `MagicMock`
  `MemoryClient`) to keep the default suite offline. Timing row records the disabled fail-open
  no-op (~0.0002 ms/pair); the real hosted v3 round-trip is the live-key manual step below.

### Live round-trip — DONE (2026-07-04, real key)

The hosted v3 write→recall round-trip is now **verified live** (see the API-shape section above):
`remember()` stored an analysis turn, and after ~20s of async extraction `recall()` returned the
extracted facts (NON-EMPTY, scoped to `app_id=perficient-threatgraph`/`user_id=dyrtydata`). This
was previously broken (0 stored) purely because of the `add(filters=…)` scoping bug now fixed.
Remaining optional manual step: run the full service twice on the same actor/technique to see the
"recalled from prior analyses" block appear in the Extractor grounding + the "🧠 Recalled…"
expander in the UI (`MODE=dev`, `PORT=8081`/`AGENT_URL` per the Phase-1 operational note).

### General lesson (future projects)

Memory recall/write must be **fail-open and off the critical path**: gate on the key, wrap every
SDK call in a broad `except` that no-ops, and keep the default test suite offline by neutralizing
any ambient key in `conftest.py` + injecting a fake SDK module. Also **verify the installed SDK's
actual signatures against the LIVE API** before wiring — the hosted Mem0 client scopes entities
**asymmetrically** (`add` = top-level `user_id`/`app_id`; `search`/`get_all` = inside `filters=`,
which *reject* top-level ids). **Watch out: a broad fail-open `except` will happily swallow a real
HTTP 400 as a "warning" and look like success** — the write "logged a request" yet stored nothing.
When a fail-open path is meant to *do* something, prove it with a live round-trip (write → wait for
async extraction → read it back), not just a mocked unit test asserting the call shape. A mock that
encodes the *wrong* signature passes green while production silently no-ops.

### Enhancement — surface recalled memories in the UI (recall was invisible)

As first built, Phase-4 recall was **invisible**: `extractor` called `recall(raw_text)` and fed
the result **only** into its internal grounding prompt (`_format_memories(...)` → prepended
block). The recalled facts never reached `custom_data`, so the Streamlit UI couldn't show *what*
memory influenced a run — the behavior was real but un-demonstrable and hard to debug.

Fix — surface `recalled_memories` end-to-end:

- **`src/agents/threatgraph.py`** — added `recalled_memories: list[dict]` to `ThreatGraphState`
  (`total=False`). `extractor` now captures the raw `recall(raw_text)` list (still renders it into
  the grounding block exactly as before) and returns it on state from **both** its structured-path
  and fail-open return points. `defensive_guardrail` adds `custom_data["recalled_memories"] =
  state.get("recalled_memories", [])` to the terminal payload — mechanics / mermaid / defense_config
  unchanged. Fail-open preserved: empty list when Mem0 is disabled / no hits.
- **`src/streamlit_app.py`** — new `draw_recalled_memories(...)` renders a
  "🧠 Recalled from prior analyses (N)" expander above the attack graph, listing each memory
  defensively (`m.get("memory") or m.get("text")`, optional `score`). When empty it shows a subtle
  "No prior memories recalled (first run or memory disabled)" caption.
- **Tests** — `test_threatgraph.py` benign end-to-end now asserts the `recalled_memories` key is
  present in `custom_data` and is `[]` on the default offline path; `test_streamlit_app.py`'s
  custom-message test now includes a non-empty `recalled_memories` entry so the panel's populated
  branch is exercised. Full suite: **159 passed, 3 skipped**; `ruff check` clean on changed files.

**General lesson (future projects):** when a memory/RAG layer silently influences an agent's
output, **surface *what* was recalled in the UI** — expose the retrieved items through the same
output payload the UI already consumes. Otherwise the behavior is untraceable: you can't tell a
"recall did nothing" run from a "recall fed in the wrong facts" run. Make the influence visible so
it is demonstrable and debuggable, not just internal.

### Streamlit default agent → `threatgraph` (2026-07-04)

The sidebar "Agent to use" selectbox previously defaulted to the **service** `default_agent`
(`research-assistant`), so anyone opening the UI landed on a stock agent instead of the one this
project actually builds. Fixed in **`src/streamlit_app.py`**: compute the selectbox `index=` from
the position of `"threatgraph"` when it is present in the agent list, else fall back to
`agent_client.info.default_agent`:

```python
preferred_agent = "threatgraph"
if preferred_agent in agent_list:
    agent_idx = agent_list.index(preferred_agent)
else:
    agent_idx = agent_list.index(agent_client.info.default_agent)
```

The guard keeps forks safe — if `threatgraph` isn't registered, the UI still opens on the service
default and never raises `ValueError` from a missing `.index(...)`.

**General lesson:** default the UI to the agent the project builds, not the upstream template's
default. A demo/tool should open on its own primary experience — but guard the lookup (`if in
list` + graceful fallback) so removing or renaming that agent in a fork degrades gracefully
instead of crashing the sidebar.

---

## 2026-07-04 — Phase 5: Langfuse dataset + experiment eval (SDK evaluators + UI LLM-as-a-judge)

Score the agent's own output (AC8) with a Langfuse **dataset + experiment**, plus notes for the
UI-configured LLM-as-a-judge half of DQ7. Tracing already rides the run config (AC7, Phase 0/1),
so this is a standalone `evals/` harness — no service/graph changes.

### Built

- **`evals/dataset.py`** — 5 threat-intel cases with *known* expected ATT&CK ids: the seed
  ransomware-phishing kill chain (`T1566.001→T1204.002→T1059.001→T1486`) plus four distinct
  multi-tactic incidents (the **APT29 / Mimikatz-LSASS / RDP / cloud-exfil** case
  `T1003.001→T1021.001→T1567.002`, a web-exploit→web-shell→create-account chain, a brute-force→RDP→
  disable-tools chain, and a spearphishing-link→valid-accounts→collect chain). Every id is a real
  ATT&CK id so the expectations are checkable. Pure data (no Langfuse at import).
- **`evals/evaluators.py`** — two deterministic SDK evaluators returning `langfuse.Evaluation`:
  - `mechanics_correctness(*, input, output, expected)` — technique-id overlap; **F1** headline
    value (perfect→1.0, disjoint→0.0), precision/recall/Jaccard in `metadata`/`comment`.
  - `defense_faithfulness(*, input, output, expected)` — fraction of the defense config's
    mitigation ids that are **grounded** (present in the retrieved `attack_context` ∪ the expected
    set) vs. invented; empty config is vacuously faithful (1.0).
  - Output is normalized through the shared `ExtractedMechanics` / `DefenseConfig` Pydantic types
    (imported from `schema.schema`). Both the outline's `expected=` and the framework's
    `expected_output=` kwargs are accepted (`**kwargs` absorbs the rest).
- **`evals/run_experiment.py`** — `run_threatgraph(*, item)` task fn runs the compiled graph and
  returns `{mechanics, mermaid, defense_config, attack_context}`; `build_dataset` +
  `dataset.run_experiment(name=, task=, evaluators=[...])` on the **Langfuse v4** API. Import-safe
  (no `Langfuse()` at import; client built only inside `main()`), runnable as a script.
- **`evals/README.md`** — run instructions (offline tests + live experiment) and the step-by-step
  **UI LLM-as-a-judge** configuration (DQ7 second half — console config, not code).
- **`tests/evals/test_evaluators.py`** — 10 offline tests: evaluator scoring (perfect/disjoint/
  partial for both), `expected_output` kwarg compat, harness importability, and the task fn driving
  the real graph offline (`FakeToolModel` + seed retrieval). `pyproject.toml`: `pythonpath` gains
  `evals` so the sibling-import harness is importable under pytest (matches script layout).

### Langfuse v4 API confirmed (research §9.3)

Verified against the installed **langfuse 4.12.0**: `Langfuse.create_dataset(name=...)`,
`create_dataset_item(dataset_name=, input=, expected_output=)`, `get_dataset(name).run_experiment(
name=, task=, evaluators=[...])`, evaluators invoked with `input/output/expected_output/metadata`
kwargs and returning `langfuse.Evaluation(name=, value=, comment=, metadata=)`. This is the v4
surface that replaced v3 `item.run()` — no API mismatch, no deviation needed.

### Experiment results (SDK evaluators)

Offline harness is green; the **live experiment is a keyed manual step** — run
`uv run python evals/run_experiment.py` with `LANGFUSE_*` (US) keys to populate the numbers below.

| Case | mechanics_correctness (F1) | defense_faithfulness | Notes |
| --- | --- | --- | --- |
| ransomware-phishing | 0.571 | 1.000 | seed kill chain |
| apt29-mimikatz-rdp-exfil | 0.800 | 1.000 | cred-access→lateral→exfil |
| exploit-webshell-persistence | 1.000 | 1.000 | initial-access→persistence |
| brute-force-rdp-defense-evasion | 0.400 | 1.000 | cred-access→lateral→defense-evasion |
| spearphishing-link-valid-accounts | 0.800 | 1.000 | initial-access→collection |
| **mean** | **0.714** | **1.000** | + UI LLM-as-a-judge column once attached |

Live run recorded 2026-07-05 (US region, project "My Project" / org "Dyrty's Organization"). Dataset
`threatgraph-mvp` (5 items); experiment run name `threatgraph-sdk-eval - 2026-07-05T01:08:14.300410Z`.
Note: `MEM0_API_KEY` IS present in the workspace `.env`, so the experiment ran with Mem0 active
(the graph recalled/wrote memories per item). Memory provides extra grounding context but does not
change how the two SDK evaluators score the output (they judge extracted techniques vs expected and
mitigation-grounding vs `attack_context`), so the scores reflect the graph's extraction/defense
quality regardless of Mem0.

(The **UI LLM-as-a-judge** scores are added as extra columns after attaching a managed evaluator
to the captured traces / experiment run — see `evals/README.md`. Record the Langfuse experiment-run
wall-clock in the timing table above.)

### Verification

- `uv run pytest tests/evals -q` → **10 passed** (offline; no live Langfuse).
- Full suite: **169 passed, 3 skipped** (was 159+3 in Phase 4; +10 new).
- Live `run_experiment.py` + Langfuse-UI checks (dataset, experiment run, per-item SDK scores,
  managed LLM-as-a-judge) remain a keyed manual step for the human.

### General lesson

Keep the eval harness **import-safe and offline by default**: no network client at import, task
fn drives the real graph but the graph's LLM + retrieval are the monkeypatch seams (already there
from Phase 2). The one packaging wrinkle — a standalone `evals/` dir that must import both `src/`
(for the graph) and its own siblings, and run *both* as a script and under pytest — is solved by a
tiny `sys.path` bootstrap in the script + `pythonpath = ["src", "evals"]` for pytest.

---

## 2026-07-04 — Phase 6: Vite + React + Tailwind client on FastAPI POST-SSE

The polished presentation layer over the **same** FastAPI backend (Streamlit stays as the
dev/fast path). A minimal Vite + React + TS + Tailwind v4 client at repo-root `frontend/`
(sibling to `agent-service-toolkit/`) consumes `POST /threatgraph/stream` and renders the
Mermaid attack graph + validated defense config.

### Built

- **`frontend/`** — Vite 8 + React 19 + TypeScript 5.9 scaffold. Tailwind v4 via the
  `@tailwindcss/vite` plugin + a single `@import "tailwindcss";` in `src/index.css`
  (**no** `tailwind.config.js` / postcss / `@tailwind` triad).
- **`src/api/stream.ts`** — the load-bearing piece: a POST-SSE reader. Native `EventSource`
  is GET-only, so it uses `fetch` + `response.body.getReader()` + `TextDecoder`, buffers the
  byte stream and frame-splits on `"\n\n"`, **keeps the incomplete tail**, parses `data:` lines
  into the toolkit's `{type: token|message|error}` line protocol, stops on `[DONE]`, and cancels
  via `AbortController`. The terminal `custom` ChatMessage is detected by a `mermaid` key in
  `custom_data` and unpacked to `{mechanics, mermaid, defense_config, recalled_memories}` —
  exactly mirroring the Python `AgentClient._parse_stream_line` + Streamlit `draw_threatgraph_output`.
- **`src/components/AttackGraph.tsx`** — `mermaid` npm v11. `mermaid.initialize({startOnLoad:false})`
  **once** at module load; in `useEffect`, `await mermaid.parse(chart)` then `mermaid.render(id, chart)`
  with a `useId()`-derived, colon-stripped **CSS-safe id** and a `cancelled` cleanup flag; sets
  `innerHTML` from the returned svg. Falls back to a readable error panel on parse/render failure
  (mirrors the reliability intent of the Streamlit CDN fix).
- **`src/components/DefenseConfig.tsx`** — tables of the validated defense config + extracted
  mechanics, plus a recalled-memories list (Mem0, Phase 4) when present.
- **`src/App.tsx`** — textarea (prefilled sample) → Analyze button → spinner/Cancel while awaiting
  → AttackGraph + DefenseConfig. Clean minimal Tailwind styling.
- Backend base URL is configurable via **`VITE_AGENT_URL`** (default `http://localhost:8081`);
  optional **`VITE_AGENT_TOKEN`** bearer for when the service sets `AUTH_SECRET`. `.env.example` provided.
- Tests (Vitest + jsdom + Testing Library): `stream.test.ts` exercises token/tail-buffering/
  terminal-custom/error/HTTP-error via a mocked `fetch` streaming a `ReadableStream`;
  `AttackGraph.test.tsx` is a mount-and-settle smoke test (jsdom can't fully lay out SVG, so it
  tolerates the error branch — a shallow render check, per the outline's note).

### Verification

- `npm install` → 244 packages, 0 vulnerabilities (~30 s, one-time; `package-lock.json` committed).
- `npm run build` (`tsc -b && vite build`) ✓ — **2.86 s wall-clock**.
- `npm run test` → **5 passed** (~1.3 s).
- Hygiene: `frontend/node_modules/` and `frontend/dist/` git-ignored (own `frontend/.gitignore`);
  `git add -n frontend/` stages **0** node_modules paths — only source + `package-lock.json`.

### Deviations / notes

- Versions pinned to current-latest that satisfy peer deps: `@vitejs/plugin-react` v6 requires
  Vite **8**, so the scaffold is Vite 8 (not the "7" in older docs) with Vitest 4. Node v22.23.1.
- `stream_tokens:false` from the client — the `threatgraph` payload arrives as one terminal
  `custom` message, so token streaming isn't needed for this UI (the reader still handles tokens
  for completeness / future agents).

### Remaining (manual, human)

- `npm run dev`, submit a snippet, compare the rendered Mermaid graph + defense config to the
  Streamlit output (backend on `PORT=8081`).

## 2026-07-05 — Phase 6 fix: browser "Failed to fetch" → server CORS + auth-for-browser

**Symptom.** The new React client (Vite dev server, `http://localhost:5173`) showed
"Failed to fetch" on Analyze, which POSTs to `http://localhost:8081/threatgraph/stream`.
Streamlit against the *same* backend worked fine.

**Root cause (confirmed empirically).**
1. **No CORS on the FastAPI service.** A browser cross-origin POST from `:5173` to
   `:8081` first issues an `OPTIONS` preflight. Before the fix that returned
   `405 Method Not Allowed` with **no** `Access-Control-Allow-Origin`, so the browser
   blocked the request — surfacing as the generic `TypeError: Failed to fetch`.
   Streamlit is unaffected because it calls the backend **server-side** (httpx, no
   browser, no same-origin policy).
2. **Auth was also on.** The repo-root `.env` sets `AUTH_SECRET`, which `settings`
   loads via `find_dotenv`, so `verify_bearer` was active; an unauthenticated POST
   returned `401`. (Secondary to the CORS block, but would bite next.)

**Fix.**
- Added `fastapi.middleware.cors.CORSMiddleware` to the **app** (not the router) in
  `src/service/service.py`, so the preflight is answered before the bearer dependency.
- Added `CORS_ALLOW_ORIGINS` to `src/core/settings.py` (JSON-array **or**
  comma-separated string via a `BeforeValidator`), defaulting to the Vite dev origins
  `http://localhost:5173` and `http://127.0.0.1:5173`. `allow_methods=["*"]`,
  `allow_headers=["*"]`, `allow_credentials=True`.
- Auth-for-browser: `frontend/src/api/stream.ts` already sends
  `Authorization: Bearer <VITE_AGENT_TOKEN>` when set (verified, no change needed).
  Documented both paths in `frontend/.env.example` + README, recommending the smoothest
  default for local dev: start the service with `AUTH_SECRET=` (auth off) — or set
  `VITE_AGENT_TOKEN` to match the service's `AUTH_SECRET`.

**Verification (curl, before → after).**
- `OPTIONS /threatgraph/stream` (Origin `:5173`): `405`, no CORS header → **`200`** with
  `access-control-allow-origin: http://localhost:5173`.
- `POST` unauthenticated: `401` (no CORS) → `401` **with** CORS headers (browser now sees
  the real response instead of a network error).
- `POST` with valid bearer: passes auth (`422` model-validation only, i.e. auth OK) with
  CORS headers present.
- `uv run pytest -q`: **170 passed, 3 skipped** (added a CORS-preflight test in
  `tests/service/test_auth.py`).

**General lesson (future projects).** A browser client needs two things a server-side
client (Streamlit, Python `AgentClient`) never does: (1) **server CORS** — the backend
must return `Access-Control-Allow-Origin` (and answer the `OPTIONS` preflight *before*
any auth dependency), or every call dies as "Failed to fetch"; (2) a **token strategy
that works from the browser** — a server-side client can hold the secret quietly, but a
browser must either talk to an auth-disabled dev service or be given the bearer token via
build-time env (`VITE_*`). Wire both when adding any browser frontend to an authed API.
