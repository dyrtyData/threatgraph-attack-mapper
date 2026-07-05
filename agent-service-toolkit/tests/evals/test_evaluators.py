"""Phase-5 eval-harness tests — fully offline (no live Langfuse).

Two halves:

* **Evaluator scoring** — ``mechanics_correctness`` / ``defense_faithfulness`` on canned
  input/output/expected: a perfect match scores high, a disjoint one scores low, partials land
  in between, and both the outline's ``expected=`` param and the framework's ``expected_output=``
  param are accepted.
* **Harness importability + offline task run** — the experiment module imports without touching
  the network, and its task fn drives the real ``threatgraph`` graph with the LLM stubbed to
  ``FakeToolModel`` and retrieval stubbed to a seed context (mirroring
  ``tests/agents/test_threatgraph.py``), so no Langfuse / OpenAI / model-download happens.
"""

import pytest
from evaluators import defense_faithfulness, mechanics_correctness
from langfuse import Evaluation

# --- Canned fixtures -------------------------------------------------------------------

SEED_CONTEXT = [
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "A macro-enabled document delivered by email.",
        "mitigations": [{"id": "M1017", "name": "User Training"}],
    },
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactics": ["Execution"],
        "description": "An encoded PowerShell downloader was spawned.",
        "mitigations": [{"id": "M1042", "name": "Disable or Remove Feature or Program"}],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "description": "Files were encrypted and a ransom note dropped.",
        "mitigations": [{"id": "M1053", "name": "Data Backup"}],
    },
]

EXPECTED = {
    "technique_ids": ["T1566.001", "T1059.001", "T1486"],
    "mitigation_ids": ["M1017", "M1042", "M1053"],
}


def _output(technique_ids, defense_pairs):
    """Build a task-output dict with the given techniques + (technique, mitigation) defenses."""
    return {
        "mechanics": [
            {"tactic": "X", "technique_id": t, "name": t, "evidence": "e"} for t in technique_ids
        ],
        "mermaid": "graph TD\n    A[\"a\"]\n",
        "defense_config": [
            {"technique_id": t, "mitigation_id": m, "action": "a", "rationale": "r"}
            for t, m in defense_pairs
        ],
        "attack_context": SEED_CONTEXT,
    }


# --- mechanics_correctness -------------------------------------------------------------


def test_mechanics_correctness_perfect_match_scores_high():
    out = _output(["T1566.001", "T1059.001", "T1486"], [])
    ev = mechanics_correctness(input="x", output=out, expected=EXPECTED)
    assert isinstance(ev, Evaluation)
    assert ev.name == "mechanics_correctness"
    assert ev.value == pytest.approx(1.0)


def test_mechanics_correctness_disjoint_scores_zero():
    out = _output(["T9999", "T8888"], [])
    ev = mechanics_correctness(input="x", output=out, expected=EXPECTED)
    assert ev.value == pytest.approx(0.0)


def test_mechanics_correctness_partial_between():
    # 2 of 3 gold matched, no spurious → precision 1.0, recall 2/3, F1 = 0.8
    out = _output(["T1566.001", "T1059.001"], [])
    ev = mechanics_correctness(input="x", output=out, expected=EXPECTED)
    assert 0.0 < ev.value < 1.0
    assert ev.metadata["recall"] == pytest.approx(2 / 3, abs=1e-3)


def test_mechanics_correctness_accepts_expected_output_kwarg():
    """The Langfuse framework passes ``expected_output`` (not ``expected``)."""
    out = _output(["T1566.001", "T1059.001", "T1486"], [])
    ev = mechanics_correctness(input="x", output=out, expected_output=EXPECTED, metadata=None)
    assert ev.value == pytest.approx(1.0)


# --- defense_faithfulness --------------------------------------------------------------


def test_defense_faithfulness_all_grounded_scores_high():
    # Every mitigation appears in SEED_CONTEXT / EXPECTED → fully faithful.
    out = _output(
        ["T1566.001", "T1059.001", "T1486"],
        [("T1566.001", "M1017"), ("T1059.001", "M1042"), ("T1486", "M1053")],
    )
    ev = defense_faithfulness(input="x", output=out, expected=EXPECTED)
    assert isinstance(ev, Evaluation)
    assert ev.name == "defense_faithfulness"
    assert ev.value == pytest.approx(1.0)


def test_defense_faithfulness_ungrounded_scores_low():
    # Invented mitigation ids present in neither the context nor the expected set → 0.0.
    out = _output(
        ["T1566.001", "T1059.001"],
        [("T1566.001", "M9999"), ("T1059.001", "M8888")],
    )
    ev = defense_faithfulness(input="x", output=out, expected=EXPECTED)
    assert ev.value == pytest.approx(0.0)
    assert set(ev.metadata["ungrounded"]) == {"M9999", "M8888"}


def test_defense_faithfulness_partial_between():
    out = _output(
        ["T1566.001", "T1059.001"],
        [("T1566.001", "M1017"), ("T1059.001", "M8888")],  # one grounded, one invented
    )
    ev = defense_faithfulness(input="x", output=out, expected=EXPECTED)
    assert ev.value == pytest.approx(0.5)


def test_defense_faithfulness_empty_is_vacuously_faithful():
    out = _output(["T1566.001"], [])
    ev = defense_faithfulness(input="x", output=out, expected=EXPECTED)
    assert ev.value == pytest.approx(1.0)


# --- harness importability + offline task run ------------------------------------------


def test_run_experiment_module_is_importable():
    """Importing the harness must not touch the network (no Langfuse client at import)."""
    import run_experiment

    assert callable(run_experiment.run_threatgraph)
    assert callable(run_experiment.build_dataset)
    assert callable(run_experiment.main)
    assert run_experiment.DATASET_NAME
    assert run_experiment.mechanics_correctness is mechanics_correctness
    assert run_experiment.defense_faithfulness is defense_faithfulness


@pytest.mark.asyncio
async def test_task_runs_graph_offline_with_fake_model(monkeypatch):
    """The task fn runs the real graph offline (FakeToolModel + seed retrieval) and scores well."""
    from core.llm import FakeToolModel

    # Stub retrieval to the seed context and the LLM to a FakeToolModel so no network / model
    # download / OpenAI call happens (mirrors tests/agents/test_threatgraph.py).
    monkeypatch.setattr(
        "agents.threatgraph.retrieve_attack_context", lambda query, k=5: SEED_CONTEXT
    )
    monkeypatch.setattr(
        "agents.threatgraph.get_model",
        lambda *a, **k: FakeToolModel(responses=["{}"]),
    )

    import run_experiment

    item = {
        "input": (
            "A user opened a macro-enabled email attachment which launched PowerShell and "
            "ultimately encrypted files for ransom."
        )
    }
    output = await run_experiment.run_threatgraph(item=item)

    assert output["mechanics"], "task output should carry extracted mechanics"
    assert output["mermaid"].lower().startswith("graph"), "task output should carry Mermaid"
    assert output["defense_config"], "task output should carry a defense config"
    assert output["attack_context"] == SEED_CONTEXT

    # The evaluators score the real graph output against the expected ids.
    mech = mechanics_correctness(input=item["input"], output=output, expected=EXPECTED)
    faith = defense_faithfulness(input=item["input"], output=output, expected=EXPECTED)
    assert mech.value == pytest.approx(1.0)  # fallback extraction surfaces exactly the seed ids
    assert faith.value == pytest.approx(1.0)  # all mitigations grounded in the seed context
