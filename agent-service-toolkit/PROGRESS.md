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
| ATT&CK corpus fetch (`fetch_attack_corpus.py`) | **5.5 s** | Phase 2 — full fetch → **697 records** (STIX download + distill; raw bundle then cached) |
| Chroma index build (`index_attack_corpus.py`) | **10.2 s** | Phase 2 — 697 records, OpenAI embeddings + persist to `attack` collection (15.4 s incl. import) |
| BM25 retriever build | **0.03 s** | Phase 2 — `BM25Retriever.from_documents` over 697 docs (in-memory, offline) |
| RRF fusion (`EnsembleRetriever`) | **~1.2 s / query** | Phase 2 — fused query (BM25 top-10 ∪ dense top-10 → 15 candidates); retriever construction ~2.0 s (incl. dense leg open) |
| Cross-encoder rerank | **~84 ms / query** | Phase 2 — `ms-marco-MiniLM-L6-v2`, 15 candidates, model cached. **First-run model download: ~27 s (~90 MB), one-time, opt-in `--run-integration`** |
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
