# ThreatGraph evals (PF-001 Phase 5)

Scores the `threatgraph` agent's own output (AC8) with a Langfuse **dataset + experiment**:

- **`dataset.py`** — ~5 threat-intel snippets with *known* expected ATT&CK technique + mitigation
  ids (the seed ransomware-phishing kill chain + distinct multi-tactic incidents, e.g. the
  APT29 / Mimikatz / RDP / cloud-exfil case).
- **`evaluators.py`** — two in-repo SDK evaluators returning `langfuse.Evaluation(...)`:
  - `mechanics_correctness` — technique-id overlap (F1 headline; precision / recall / Jaccard in
    metadata) between the extracted mechanics and the expected techniques.
  - `defense_faithfulness` — fraction of the defense config's mitigation ids that are *grounded*
    (present in the retrieved `attack_context` or the expected set) vs. invented.
- **`run_experiment.py`** — builds the Langfuse dataset and runs the graph as the experiment task
  via the v4 API (`dataset.run_experiment(task=..., evaluators=[...])`).

## Run the offline tests (no network / keys)

```bash
cd agent-service-toolkit
uv run pytest tests/evals -q
```

The task fn drives the real graph with the LLM stubbed to `FakeToolModel` and retrieval stubbed
to a seed context, so no Langfuse / OpenAI / model download happens.

## Run the live experiment (requires keys)

Set the US-region Langfuse keys in the repo-root `.env` (already present in this workspace):

```
LANGFUSE_TRACING=true
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=https://us.cloud.langfuse.com
```

Then:

```bash
cd agent-service-toolkit
uv run python evals/run_experiment.py
```

This creates (idempotently) the `threatgraph-mvp` dataset, upserts one item per case, runs the
`threatgraph-sdk-eval` experiment over the graph, and attaches the two SDK evaluator scores to
each item. It prints a formatted summary and the run appears in the Langfuse UI.

> Running the live experiment calls the real OpenAI extractor/defense models and the hybrid
> retriever (first reranker call downloads the cross-encoder). It is intentionally kept out of
> the default `pytest` path.

## LLM-as-a-judge — configure in the Langfuse UI (DQ7, second half)

The second half of DQ7 ("do both") is a **managed LLM-as-a-judge evaluator configured in the
Langfuse UI** on the captured traces — this is console configuration, not code, so it lives here
as documentation. Steps (Langfuse v4, US region):

1. **Traces exist already.** Every `threatgraph` run is traced automatically (AC7 — the no-arg
   `CallbackHandler()` rides the `RunnableConfig`), and each experiment item run is traced too.
   No extra instrumentation is needed.
2. **Settings → Evaluators → LLM-as-a-judge → New evaluator.** Pick a managed template
   (e.g. **Correctness**, **Hallucination**, **Relevance**, or **Helpfulness**) or start from a
   custom prompt. Choose the judge model (an OpenAI/Anthropic key configured under
   **Settings → LLM connections**).
3. **Map variables** to the trace/observation fields — typically `{{input}}` → the trace input
   (the threat-intel snippet) and `{{output}}` / `{{generation}}` → the trace output (the graph's
   mechanics + defense config, or a specific observation). For a grounded-faithfulness judge, also
   map a context variable to the `retrieve` node's `attack_context`.
4. **Scope / target.** Point the evaluator at the `threatgraph` traces (filter by name/tag) and/or
   at the `threatgraph-sdk-eval` **experiment runs** so the LLM-judge scores land next to the SDK
   scores on the same items. Set a sampling rate (e.g. 100% for the dataset run, lower for live
   traffic).
5. **Run + review.** New scores appear on the traces and in the experiment comparison view
   alongside `mechanics_correctness` / `defense_faithfulness`. Capture the numbers in
   `PROGRESS.md`.

Docs: [Experiments via SDK](https://langfuse.com/docs/evaluation/experiments/experiments-via-sdk) ·
[LLM-as-a-judge](https://langfuse.com/docs/evaluation/evaluation-methods/llm-as-a-judge) ·
[Data Regions](https://langfuse.com/security/data-regions).
