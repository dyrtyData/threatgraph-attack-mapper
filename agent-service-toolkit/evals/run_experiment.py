"""Langfuse dataset + experiment harness for ``threatgraph`` (PF-001 Phase 5, AC8 + DQ7).

Runs the compiled ``threatgraph`` graph as the experiment *task* over a small dataset of
threat-intel snippets (:mod:`dataset`) and scores each item with the in-repo SDK evaluators
(:mod:`evaluators`). Uses the Langfuse v4 experiment API (which replaced v3 ``item.run()``):

    langfuse.create_dataset(name=...)                       # idempotent upsert
    langfuse.create_dataset_item(dataset_name=..., input=..., expected_output=...)
    dataset = langfuse.get_dataset(name)
    dataset.run_experiment(name=..., task=run_threatgraph, evaluators=[...])

**Import-safe without network.** No ``Langfuse()`` client is constructed at import time — the
task fn and evaluators are importable and unit-testable offline (the graph's LLM + retrieval
are monkeypatched to ``FakeToolModel`` / a seed context in the tests). The live experiment runs
only when this module is executed as a script (``uv run python evals/run_experiment.py``) with
``LANGFUSE_*`` keys present.

The UI-configured LLM-as-a-judge half of DQ7 is documentation-only (not code) — see
``evals/README.md`` for how to attach a managed evaluator to the captured traces.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

# --- Standalone-script bootstrap -------------------------------------------------------
# When run as `python evals/run_experiment.py`, sys.path[0] is evals/ (so the sibling
# `dataset` / `evaluators` modules import cleanly) but src/ is NOT on the path. Add it so
# `from agents.threatgraph import threatgraph` resolves. Under pytest, pyproject's
# `pythonpath = ["src", "evals"]` already covers both, and these inserts are no-ops.
_EVALS_DIR = Path(__file__).resolve().parent
_SRC_DIR = _EVALS_DIR.parent / "src"
for _p in (str(_SRC_DIR), str(_EVALS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dataset import DATASET_NAME, THREAT_INTEL_CASES, expected_output  # noqa: E402
from evaluators import defense_faithfulness, mechanics_correctness  # noqa: E402
from langchain_core.messages import HumanMessage  # noqa: E402

from agents.threatgraph import threatgraph  # noqa: E402

logger = logging.getLogger(__name__)

EXPERIMENT_NAME = "threatgraph-sdk-eval"


def _item_input(item: Any) -> str:
    """Extract the raw threat-intel text from a Langfuse ``DatasetItem`` or a plain dict."""
    raw = getattr(item, "input", None)
    if raw is None and isinstance(item, dict):
        raw = item.get("input")
    if isinstance(raw, dict):
        raw = raw.get("text") or raw.get("input") or ""
    return raw if isinstance(raw, str) else str(raw or "")


async def run_threatgraph(*, item: Any, **kwargs: Any) -> dict[str, Any]:
    """Experiment task: run the graph on one dataset item and return its scored output.

    Returns the subset of graph state the evaluators need — the extracted ``mechanics``, the
    rendered ``mermaid`` string, the validated ``defense_config``, and the retrieved
    ``attack_context`` (defense-faithfulness grounds against it).
    """
    text = _item_input(item)
    result = await threatgraph.ainvoke({"messages": [HumanMessage(content=text)]})
    return {
        "mechanics": result.get("mechanics", []),
        "mermaid": result.get("mermaid", ""),
        "defense_config": result.get("defense_config", []),
        "attack_context": result.get("attack_context", []),
    }


def build_dataset(langfuse: Any) -> None:
    """Create (idempotent) the Langfuse dataset and upsert one item per threat-intel case."""
    langfuse.create_dataset(
        name=DATASET_NAME,
        description="Threat-intel snippets with expected ATT&CK technique + mitigation ids.",
        metadata={"project": "PF-001", "source": "evals/dataset.py"},
    )
    for case in THREAT_INTEL_CASES:
        langfuse.create_dataset_item(
            dataset_name=DATASET_NAME,
            input=case["input"],
            expected_output=expected_output(case),
            metadata={"name": case["name"], **case.get("metadata", {})},
        )


def main() -> None:
    """Run the live experiment (requires ``LANGFUSE_*`` keys). Not exercised by default tests."""
    logging.basicConfig(level=logging.INFO)
    from langfuse import Langfuse  # local import: keeps the module import-safe / offline

    langfuse = Langfuse()
    if not langfuse.auth_check():
        raise SystemExit(
            "Langfuse auth_check failed — set LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY / "
            "LANGFUSE_HOST (US region) in .env before running the live experiment."
        )

    logger.info("Building dataset %r ...", DATASET_NAME)
    build_dataset(langfuse)

    dataset = langfuse.get_dataset(DATASET_NAME)
    logger.info("Running experiment %r over %d items ...", EXPERIMENT_NAME, len(dataset.items))
    result = dataset.run_experiment(
        name=EXPERIMENT_NAME,
        description="threatgraph graph output scored by in-repo SDK evaluators (Phase 5).",
        task=run_threatgraph,
        evaluators=[mechanics_correctness, defense_faithfulness],
    )

    langfuse.flush()
    # v4 ExperimentResult exposes a human-readable summary via format().
    try:
        print(result.format())  # noqa: T201
    except Exception:
        print(f"Experiment {EXPERIMENT_NAME!r} complete: {len(getattr(result, 'item_results', []))} items.")  # noqa: T201


if __name__ == "__main__":
    main()
