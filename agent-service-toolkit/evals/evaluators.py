"""In-repo SDK evaluators for the ``threatgraph`` experiment (PF-001 Phase 5, AC8).

Two deterministic, offline evaluators scoring the graph's own output:

* :func:`mechanics_correctness` — technique-id overlap between the extracted mechanics and the
  dataset's expected technique ids (precision / recall / F1 + Jaccard).
* :func:`defense_faithfulness` — the fraction of the synthesized defense config's mitigation ids
  that are *grounded* — present in the retrieved ``attack_context`` or the expected mitigation
  set — rather than invented.

Both return a Langfuse :class:`~langfuse.Evaluation` (``name`` / ``value`` / ``comment`` /
``metadata``) so they plug directly into ``dataset.run_experiment(evaluators=[...])``.

The parameter names ``input`` / ``output`` / ``expected`` follow the structure outline. The
Langfuse experiment harness invokes evaluators with ``input`` / ``output`` / ``expected_output``
/ ``metadata`` keyword args, so both ``expected`` and ``expected_output`` are accepted and
unified (``**kwargs`` absorbs anything else the framework passes). The output is normalized
through the shared :class:`~schema.schema.ExtractedMechanics` / :class:`~schema.schema.DefenseConfig`
Pydantic types so the same evaluator works whether the task returns raw dicts or model objects.
"""

from __future__ import annotations

from typing import Any

from langfuse import Evaluation

from schema.schema import DefenseConfig, ExtractedMechanics


def _coerce_expected(expected: Any, expected_output: Any) -> dict[str, Any]:
    """Unify the outline's ``expected`` and the framework's ``expected_output`` into a dict."""
    exp = expected if expected is not None else expected_output
    return exp if isinstance(exp, dict) else {}


def _output_dict(output: Any) -> dict[str, Any]:
    """The task returns a dict of {mechanics, mermaid, defense_config, attack_context}."""
    return output if isinstance(output, dict) else {}


def _extracted_technique_ids(output: Any) -> set[str]:
    """Technique ids the extractor surfaced, validated through ``ExtractedMechanics``."""
    raw = _output_dict(output).get("mechanics") or []
    try:
        mechanics = ExtractedMechanics(techniques=raw)
    except Exception:
        # Best-effort: pull ids straight from the raw dicts if strict validation fails.
        return {t.get("technique_id", "") for t in raw if isinstance(t, dict)} - {""}
    return {t.technique_id for t in mechanics.techniques if t.technique_id}


def _defense_mitigation_ids(output: Any) -> list[str]:
    """Ordered mitigation ids the defense config proposes (validated through ``DefenseConfig``)."""
    raw = _output_dict(output).get("defense_config") or []
    try:
        config = DefenseConfig(defenses=raw)
    except Exception:
        return [d.get("mitigation_id", "") for d in raw if isinstance(d, dict) and d.get("mitigation_id")]
    return [d.mitigation_id for d in config.defenses if d.mitigation_id]


def _grounded_mitigation_ids(output: Any, expected: dict[str, Any]) -> set[str]:
    """Mitigation ids considered grounded: those in the retrieved context ∪ expected set.

    A defense is faithful when the mitigation it cites was actually surfaced by the ``retrieve``
    node for one of the techniques (``attack_context[*].mitigations[*].id``) or is a known
    ground-truth mitigation for the incident.
    """
    grounded: set[str] = set(expected.get("mitigation_ids") or [])
    for record in _output_dict(output).get("attack_context") or []:
        if not isinstance(record, dict):
            continue
        for mit in record.get("mitigations") or []:
            mid = mit.get("id") if isinstance(mit, dict) else None
            if mid:
                grounded.add(mid)
    return grounded


def mechanics_correctness(
    *,
    input: Any = None,
    output: Any = None,
    expected: Any = None,
    expected_output: Any = None,
    metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Evaluation:
    """Score technique-id overlap between extracted mechanics and the expected techniques.

    Headline ``value`` is F1 (perfect match → 1.0, disjoint → 0.0); precision, recall and
    Jaccard are recorded in ``metadata`` and summarized in ``comment``.
    """
    exp = _coerce_expected(expected, expected_output)
    gold = set(exp.get("technique_ids") or [])
    predicted = _extracted_technique_ids(output)

    if not gold:
        return Evaluation(
            name="mechanics_correctness",
            value=0.0,
            comment="No expected technique ids on the dataset item; cannot score.",
            metadata={"predicted": sorted(predicted)},
        )

    tp = predicted & gold
    precision = len(tp) / len(predicted) if predicted else 0.0
    recall = len(tp) / len(gold)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    union = predicted | gold
    jaccard = len(tp) / len(union) if union else 0.0

    return Evaluation(
        name="mechanics_correctness",
        value=round(f1, 4),
        comment=(
            f"F1={f1:.2f} (precision={precision:.2f}, recall={recall:.2f}, "
            f"jaccard={jaccard:.2f}); matched {sorted(tp)} of expected {sorted(gold)}."
        ),
        metadata={
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "jaccard": round(jaccard, 4),
            "predicted": sorted(predicted),
            "expected": sorted(gold),
            "matched": sorted(tp),
        },
    )


def defense_faithfulness(
    *,
    input: Any = None,
    output: Any = None,
    expected: Any = None,
    expected_output: Any = None,
    metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Evaluation:
    """Score the fraction of defense mitigation ids that are grounded (not invented).

    ``value`` = grounded_mitigations / proposed_mitigations. An empty defense config is
    vacuously faithful (1.0 — nothing ungrounded was emitted); a config whose mitigations are
    all absent from both the retrieved context and the expected set scores 0.0.
    """
    exp = _coerce_expected(expected, expected_output)
    proposed = _defense_mitigation_ids(output)
    grounded_set = _grounded_mitigation_ids(output, exp)

    if not proposed:
        return Evaluation(
            name="defense_faithfulness",
            value=1.0,
            comment="No defenses emitted; vacuously faithful (nothing ungrounded).",
            metadata={"proposed": [], "grounded_set": sorted(grounded_set)},
        )

    grounded_hits = [m for m in proposed if m in grounded_set]
    ungrounded = [m for m in proposed if m not in grounded_set]
    fraction = len(grounded_hits) / len(proposed)

    return Evaluation(
        name="defense_faithfulness",
        value=round(fraction, 4),
        comment=(
            f"{len(grounded_hits)}/{len(proposed)} proposed mitigations grounded in the "
            f"retrieved context / expected set."
            + (f" Ungrounded: {sorted(set(ungrounded))}." if ungrounded else "")
        ),
        metadata={
            "proposed": proposed,
            "grounded": grounded_hits,
            "ungrounded": sorted(set(ungrounded)),
            "grounded_set": sorted(grounded_set),
        },
    )
