# ThreatGraph — Autonomous Threat-Intel Attack Graph Mapper

ThreatGraph ingests unstructured threat-intelligence text (an incident writeup, a threat
report, a raw paste) and autonomously produces:

1. A **Mermaid.js attack graph** of the attacker's kill-chain, mapped to canonical
   [MITRE ATT&CK](https://attack.mitre.org/) technique IDs.
2. A **structurally validated defensive configuration** — mitigations grounded in the same
   retrieved ATT&CK context, so the output can never cite a technique or mitigation that
   wasn't actually retrieved.

It's a multi-agent [LangGraph](https://langchain-ai.github.io/langgraph/) pipeline built to
demonstrate what a *production-shaped* agentic system looks like end to end: explicit
orchestration, grounded retrieval, persistent memory, output guardrails, tracing, and
evaluation — not just a single prompt wrapped in a chat loop.

## Pipeline

```
guard_input --check_safety--> retrieve --> extractor --> graph_architect --> defensive_guardrail --> END
     |
     +--unsafe--> block_unsafe_content --> END
```

| Stage | What it does |
| --- | --- |
| `guard_input` | Prompt-injection / unsafe-input classifier gate. Fail-open by design. |
| `retrieve` | Hybrid RAG over the full MITRE ATT&CK corpus (~700 records): BM25 + dense (Chroma) retrieval fused via Reciprocal Rank Fusion, then cross-encoder reranked. |
| `extractor` | Structured-output LLM extraction of attacker techniques, canonicalized to only the `Txxxx` ids present in the retrieved context (no hallucinated techniques). Recalls prior related analyses from long-term memory. |
| `graph_architect` | Renders the extracted kill-chain as a Mermaid attack graph. |
| `defensive_guardrail` | Synthesizes mitigations, validates the output against a Pydantic schema (Guardrails AI), and hard-filters to only mitigation ids grounded in the retrieved context. Writes the analysis to long-term memory. |

## Capabilities

- **Grounded retrieval** — hybrid BM25 + dense RAG with RRF fusion and cross-encoder
  reranking over a full MITRE ATT&CK corpus; a dense-only fallback is a one-line swap.
- **Long-term memory** — hosted [Mem0](https://mem0.ai/) recall/write so repeated analyses
  of the same actor or technique get sharper over time; fails open with no key configured.
- **Guardrails** — an input-side prompt-injection classifier and an output-side
  [Guardrails AI](https://www.guardrailsai.com/) schema validator, plus retrieval-grounding
  as an anti-hallucination guardrail on both the extracted mechanics and the defense config.
- **Observability** — full [Langfuse](https://langfuse.com/) tracing of every node, with a
  dataset + experiment harness (technique-id F1, mitigation faithfulness) and LLM-as-a-judge
  scoring configured against captured traces.
- **Three interchangeable UIs** — a Streamlit dev client, a Vite + React + Tailwind client
  over a FastAPI POST-SSE stream, and an [Open WebUI](https://github.com/open-webui/open-webui)
  pipe — all rendering the same graph + defense config from one backend.

See [`docs/ARCHITECTURE_PILLARS.md`](docs/ARCHITECTURE_PILLARS.md) for a detailed,
honesty-first mapping of the implementation against a production multi-agent architecture
framework (including partials and known gaps), and [`docs/PROGRESS.md`](docs/PROGRESS.md)
for the full build log with per-component wall-clock timings.

## Roadmap

The pipeline covers the core multi-agent shape end to end. A number of concrete extensions
were scoped during design and prioritized for later:

- **Retrieval** — decompose a multi-tactic snippet into per-behavior sub-queries so
  weakly-lexical techniques aren't under-retrieved; rank/cap mitigations to the most
  relevant few per technique instead of listing every grounded match; a semantic cache in
  front of the vector store for latency at scale.
- **Memory** — a true multi-turn "analyst conversation" mode on top of the existing
  LangGraph checkpointer, instead of single-shot analysis; visualizing Mem0's graph-memory
  entities/relations in the UI; checkpoint time-travel (rollback/replay of a run's state).
- **Engine / routing** — a real LLM gateway (LiteLLM-style) in place of the current static
  per-node model dispatch table, with complexity-based dynamic routing instead of static
  per-node model pinning.
- **Guardrails** — wiring Guardrails AI's `reask`/`fix` loop to a live validator LLM
  (currently local structural validation + best-effort coercion, kept off the network for
  speed).
- **Evaluation** — a larger, more adversarial Langfuse eval set with trajectory-level
  assertions; an offline DeepEval faithfulness/answer-relevancy pass as a second signal;
  version-controlled LLM-as-a-judge definitions in code (currently console-configured); a
  dedicated adversarial/red-teaming suite against the pipeline.
- **UI** — surfacing per-node latency, token usage, and eval scores inline in the React
  client (currently only visible in the Langfuse console).
- **Production readiness** — live threat-feed ingestion in place of pasted/static text;
  real per-user authentication in place of the shared local dev bearer token;
  cross-organization agent protocols (A2A/MCP) for distributed, multi-org threat-intel
  sharing.
- **Business** — a non-technical, executive-facing one-pager (problem → resolution → ROI).

## Tech stack

LangGraph · FastAPI · Chroma · BM25 (`rank-bm25`) · Sentence-Transformers cross-encoder ·
Mem0 · Guardrails AI · Langfuse · Streamlit · React · Vite · Tailwind CSS · Open WebUI

Built on top of the open-source
[`agent-service-toolkit`](https://github.com/JoshuaC215/agent-service-toolkit) (LangGraph +
FastAPI + Streamlit scaffold), vendored in `agent-service-toolkit/`.

## Quickstart

```bash
cd agent-service-toolkit
uv sync --frozen
cp ../.env.example ../.env   # fill in API keys

# Service
MODE=dev PORT=8081 uv run python src/run_service.py

# Streamlit UI (in another shell)
AGENT_URL=http://localhost:8081 uv run streamlit run src/streamlit_app.py
```

Or the React client:

```bash
cd frontend
npm ci
npm run dev   # http://localhost:5173
```

Or Open WebUI — see [`docs/OpenWebUI.md`](docs/OpenWebUI.md).

Run the eval harness:

```bash
cd agent-service-toolkit
uv run --env-file ../.env python evals/run_experiment.py
```

## Layout

```
agent-service-toolkit/   LangGraph agent, FastAPI service, Streamlit UI, eval harness
  src/agents/threatgraph.py   the graph definition + nodes
  src/agents/retrieval.py     hybrid RAG (BM25 + dense + rerank)
  src/memory/mem0_client.py   long-term memory
  src/agents/guardrails.py    output validation
  evals/                      Langfuse dataset + experiment evaluators
frontend/                React + Tailwind client
data/attack/              MITRE ATT&CK corpus (fetched + distilled)
scripts/                  corpus fetch script
docs/                     architecture mapping + build log
```
