# Tooling & Environment Reference — PF-001

Reference for the CLIs, MCP servers, API keys, and git hooks backing this project.
**No secret values live in this file** — only names and where each secret is stored.

Status legend: ✅ validated this machine · ⏳ configured, pending a restart/OAuth to verify · ➖ optional/not required

---

## 1. API keys (values only in git-ignored `.env`; template in `.env.example`)

| Key | Used by | Where the real value lives | Status |
|---|---|---|---|
| `OPENAI_API_KEY` | LLM calls | `.env`, `~/.zshrc` | ✅ |
| `ANTHROPIC_API_KEY` | LLM calls (optional) | `.env`, `~/.zshrc` | ✅ |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Observability + agent eval | `.env`, `~/.zshrc` | ✅ |
| `LANGFUSE_HOST` (`https://us.cloud.langfuse.com`) | Langfuse region | `.env`, `~/.zshrc` | ✅ |
| `MEM0_API_KEY` | Hosted Mem0 memory | `.env`, `~/.zshrc`, `~/.claude.json` (MCP) | ✅ key present |
| `CONFIDENT_API_KEY` | DeepEval / Confident AI | `.env`, `~/.zshrc` | ✅ (name corrected from `CONFIDENTAI_*`) |
| `AUTH_SECRET` | agent-service-toolkit FastAPI auth | `.env` | ✅ dummy ok for local |
| Guardrails AI Hub token | Guardrails validators | `~/.guardrailsrc` (NOT an env var) | ✅ configured |
| `COHERE_API_KEY` | Optional — Cohere embeddings/rerank for hybrid RAG | `.env` (commented) | ➖ optional (OpenAI embed + local cross-encoder needs no key) |

> `.env`, `.env.local`, `.deepeval/`, `coms/`, and `.claude/settings.local.json` are git-ignored. Never commit real keys.

## 2. MCP servers (Claude Code / HumanLayer, in `~/.claude.json`)

| Server | Purpose | Auth | Status |
|---|---|---|---|
| `context7` | Live library/framework docs | none | ✅ |
| `langfuse` | Query traces / prompts / token usage | Basic auth header (from Langfuse keys) | ⏳ verify after restart |
| `mem0-mcp` (`mcp.mem0.ai`) | Agent long-term memory across sessions | Bearer `MEM0_API_KEY` | ⏳ tools not yet surfacing — verify after restart |
| `ruflo`, `postgres-ruflo` | Other projects (not needed here) | — | ➖ |
| Linear | Issues (via official Claude Code Linear **plugin** + OAuth) | OAuth | ⏳ authed in interactive Terminal `claude`; not usable from a non-interactive HumanLayer session |

> Note: the hosted Mem0 client used **inside the app code** (via `MEM0_API_KEY`) is independent of the `mem0-mcp` server and works regardless.

## 3. CLIs

| CLI | Purpose | Status |
|---|---|---|
| `gh` | GitHub (branch/push/PR) — logged in as `dyrtyData` | ✅ |
| `uv` / `uvx` | Python env + deps for the toolkit | ✅ |
| `node` / `npm` / `npx` | JS tooling (Mermaid, optional React frontend) | ✅ |
| `docker` | Optional; RAGFlow / Open WebUI / toolkit compose | ✅ present |
| `langgraph` | LangGraph CLI | ✅ present |
| `graphify` | Code knowledge graph (see §5) | ✅ |
| `gitleaks` | Secret scanning (see §5) | ✅ 8.30.1 |
| `guardrails` | Guardrails AI (Hub token in `~/.guardrailsrc`) | ✅ authed* |
| `deepeval` | Offline eval harness | ⚠️ global (miniconda) build crashes on `--help`; **run from the project venv** |

\* The global `guardrails`/`deepeval` CLIs error under miniconda; install both into the toolkit's `uv` venv for the sprint.

## 4. Local research corpus

- **`/askCTObrain`** (skill + command) — local vector RAG over CTO/architecture textbooks at `localhost:8080`. `--quick` (fast single hit), default (smart), `--deep` (multi-angle). Corpus overlaps `books/`. Health-check `localhost:8080` first; if down, read `books/` directly.

## 5. Git hooks (global via `core.hooksPath = ~/.config/git/hooks`)

| Hook | Does | Status |
|---|---|---|
| `pre-commit` | Runs `gitleaks protect --staged`; **blocks commits containing staged secrets** (warns-and-allows if gitleaks missing) | ✅ covers this repo |
| `post-commit` | Rebuilds the **graphify** code graph in the background after each commit | ✅ |
| `post-checkout` | graphify bookkeeping on checkout | ✅ |

Graphify artifacts (`graphify-out/`, `.graphify/`) are git-ignored. The graph is empty until first-party code lands, then auto-maintained.

## 6. How to verify each (quick commands)

```bash
# keys loaded in an interactive shell
zsh -ic 'echo ${OPENAI_API_KEY:+openai_ok} ${LANGFUSE_HOST} ${MEM0_API_KEY:+mem0_ok} ${CONFIDENT_API_KEY:+confident_ok}'

# GitHub auth
gh auth status

# secret gate present + tool installed
git config core.hooksPath && gitleaks version

# guardrails hub configured
test -f ~/.guardrailsrc && echo "guardrails configured"

# CTO brain up
curl -s localhost:8080/health || echo "askCTObrain server down"

# Langfuse + Mem0 (after Claude Code restart): run /mcp and confirm the tools list;
# Mem0 writes are visible at app.mem0.ai (filter user_id=dyrtydata, app_id=perficient-threatgraph)
```

## 7. Known pending validations
- `mem0-mcp` tools not yet exposed to the agent harness — verify with `/mcp` after a restart; the in-app SDK path is unaffected.
- `langfuse` MCP — added; verify tools list after restart.
- Linear — usable only from an interactive session with the authed plugin, not from non-interactive HumanLayer runs.
