"""Guardrails AI structured-output validation of the defense config (Phase 3, PF-001).

Thin wrapper around ``Guard.for_pydantic(DefenseConfig)`` that validates a synthesized
defense configuration against its Pydantic schema. The ``threatgraph`` ``defensive_guardrail``
node calls :func:`validate_defense_config` on the config it synthesizes from the retrieved
ATT&CK mitigations before attaching it to the terminal ``custom`` message.

**Fail-open, like ``Safeguard``.** Guardrails AI, the Hub, or the ``~/.guardrailsrc`` token
may be unavailable at runtime (offline dev, CI, a fresh checkout without
``guardrails hub install`` run). If the ``guardrails`` import fails, the Guard raises, or
structural validation does not pass, we fall back to a **best-effort local parse** that
coerces the raw payload into a :class:`DefenseConfig`, dropping only entries that lack the
grounded core (``technique_id`` + ``mitigation_id``). The graph therefore never hard-crashes
on the guardrail step — the toolkit's fail-open philosophy end-to-end.

On the API surface: ``Guard.for_pydantic`` does not accept an ``on_fail`` kwarg (that is a
per-*validator* action). We enforce the Pydantic structure itself and realize ``reask``/``fix``
semantics locally: a full reask would require an ``llm_api`` (a network call) which we
deliberately avoid so the default path stays offline/fast, and ``fix`` is applied as the
local best-effort coercion below.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from schema.schema import Defense, DefenseConfig

logger = logging.getLogger(__name__)


def _coerce_items(raw: Any) -> list[dict[str, Any]]:
    """Normalize an arbitrary raw payload into a list of candidate defense dicts."""
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            return _coerce_items(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            logger.debug("Defense payload was a non-JSON string; nothing to parse.")
            return []
    if isinstance(raw, DefenseConfig):
        return [d.model_dump() for d in raw.defenses]
    if isinstance(raw, dict):
        if "defenses" in raw and isinstance(raw["defenses"], list):
            return [d for d in raw["defenses"] if isinstance(d, dict)]
        # A bare single-entry dict.
        if {"technique_id", "mitigation_id"} & set(raw):
            return [raw]
        return []
    if isinstance(raw, list):
        return [d for d in raw if isinstance(d, dict)]
    return []


def _best_effort_parse(raw: Any) -> DefenseConfig:
    """Fail-open, offline coercion of ``raw`` into a valid :class:`DefenseConfig`.

    Realizes ``on_fail="fix"`` locally: keep every entry that carries the grounded core
    (``technique_id`` + ``mitigation_id``), backfilling missing ``action``/``rationale`` with
    a neutral placeholder rather than dropping an otherwise-grounded mitigation.
    """
    defenses: list[Defense] = []
    for item in _coerce_items(raw):
        technique_id = str(item.get("technique_id") or "").strip()
        mitigation_id = str(item.get("mitigation_id") or "").strip()
        if not technique_id or not mitigation_id:
            continue
        defenses.append(
            Defense(
                technique_id=technique_id,
                mitigation_id=mitigation_id,
                action=str(item.get("action") or f"Apply mitigation {mitigation_id}."),
                rationale=str(
                    item.get("rationale")
                    or f"{mitigation_id} is the ATT&CK mitigation mapped to {technique_id}."
                ),
            )
        )
    return DefenseConfig(defenses=defenses)


def validate_defense_config(raw: str | dict | list | DefenseConfig) -> DefenseConfig:
    """Validate a synthesized defense config with Guardrails AI, failing open.

    Tries ``Guard.for_pydantic(DefenseConfig).parse(...)`` for real structural validation; on
    any failure (import error, Guard construction error, validation not passing) it falls back
    to :func:`_best_effort_parse` so the graph never crashes on the guardrail step.
    """
    # Normalize to the JSON string that Guardrails' `parse` expects.
    if isinstance(raw, DefenseConfig):
        payload = raw.model_dump()
    elif isinstance(raw, (dict, list)):
        payload = raw
    else:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            payload = raw  # leave as-is; guardrails / best-effort will handle it
    # Guardrails expects `{"defenses": [...]}`; wrap a bare list.
    if isinstance(payload, list):
        payload = {"defenses": payload}

    try:
        from guardrails import Guard

        guard = Guard.for_pydantic(DefenseConfig)
        outcome = guard.parse(json.dumps(payload))
        if getattr(outcome, "validation_passed", False) and outcome.validated_output:
            validated = outcome.validated_output
            if isinstance(validated, DefenseConfig):
                return validated
            if isinstance(validated, dict):
                return DefenseConfig(**validated)
        logger.warning(
            "Guardrails validation did not pass; falling back to best-effort defense parse."
        )
    except Exception as exc:  # noqa: BLE001 — fail open (import/Hub/token/validation issues)
        logger.warning(
            "Guardrails AI unavailable (%s); using best-effort local defense-config parse.", exc
        )

    return _best_effort_parse(payload)
