"""Hosted Mem0 (v3) recall + write for the ``threatgraph`` pipeline (Phase 4, PF-001).

Lazy, FAIL-OPEN wrapper around the hosted ``mem0`` ``MemoryClient``. The Extractor recalls
prior analyses (:func:`recall`) to prepend to its grounding; the Defensive_Guardrail writes
the analysis turn (:func:`remember`) after synthesis. Both are scoped to
``app_id="perficient-threatgraph"`` / ``user_id="dyrtydata"``.

**DQ4 — v3 graph memory is automatic (documented, intentional deviation from AC4's literal
wording).** The platform migrated v2 -> v3, so Graph Memory is automatic and the deprecated
``enable_graph`` / ``version="v2"`` / ``output_format`` flags are gone. We call ``add`` /
``search`` plainly, with the entity scope (``user_id`` / ``app_id``) passed **inside the
``filters`` dict** — the installed ``mem0ai`` (2.0.x) v3 SDK requires identity fields there
(``search`` actively rejects top-level entity params; ``AddMemoryOptions`` documents the same
for ``add``). This is a small API-shape deviation from the outline's ``add(messages,
user_id=..., app_id=...)`` sketch, resolved as the outline instructed ("confirm current API at
implementation time"); the scoping intent is unchanged.

**Fail-open, like ``Safeguard`` / the retrieval + guardrail nodes.** If ``MEM0_API_KEY`` is
unset, the ``mem0`` SDK cannot be imported / constructed, or any call raises, every function
no-ops (``recall`` -> ``[]``, ``remember`` -> ``None``) so the graph never breaks.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from core import settings

logger = logging.getLogger(__name__)

# Entity scope for every recall/write (DQ4 — passed inside the `filters` dict on the v3 SDK).
APP_ID = "perficient-threatgraph"
USER_ID = "dyrtydata"
# How many prior memories to surface into the Extractor's grounding.
RECALL_TOP_K = 5

# The v3 SDK wants entity ids inside `filters`; keep one canonical scope dict.
_SCOPE: dict[str, str] = {"user_id": USER_ID, "app_id": APP_ID}


@lru_cache(maxsize=1)
def get_mem0() -> Any | None:
    """Return a cached hosted ``MemoryClient``, or ``None`` when Mem0 is disabled.

    Disabled (returns ``None``, fail-open) when ``MEM0_API_KEY`` is unset or the ``mem0`` SDK
    cannot be imported / constructed. The SDK reads ``MEM0_API_KEY`` from the environment
    itself; the ``Settings`` field only declares/validates/gates it. Cached so the client is
    built once; call ``get_mem0.cache_clear()`` to force re-resolution (used in tests).
    """
    if settings.MEM0_API_KEY is None:
        logger.info("MEM0_API_KEY unset; Mem0 memory disabled (fail-open no-op).")
        return None
    try:
        from mem0 import MemoryClient

        return MemoryClient()
    except Exception as exc:  # noqa: BLE001 — fail open on import / auth / construction errors
        logger.warning("Mem0 unavailable (%s); memory disabled (fail-open no-op).", exc)
        return None


def recall(query: str) -> list[dict]:
    """Recall prior analyses relevant to ``query`` — ``[]`` when disabled / on any error.

    Calls ``client.search(query, filters={user_id, app_id}, top_k=...)`` — no deprecated
    ``version`` / ``enable_graph`` / ``output_format`` flags (v3 graph memory is automatic).
    """
    client = get_mem0()
    if client is None or not query:
        return []
    try:
        results = client.search(query, filters=dict(_SCOPE), top_k=RECALL_TOP_K)
    except Exception as exc:  # noqa: BLE001 — fail open
        logger.warning("Mem0 recall failed (%s); returning no memories.", exc)
        return []
    # v3 search returns {"results": [...]}; older shapes may return a bare list. Normalize.
    if isinstance(results, dict):
        results = results.get("results", [])
    return results if isinstance(results, list) else []


def remember(messages: list[dict]) -> None:
    """Write the analysis turn to Mem0 — no-op when disabled / on any error.

    Calls ``client.add(messages, filters={user_id, app_id})`` plainly — v3 auto-extracts
    salient facts and folds graph signal in with no extra flags (DQ4).
    """
    client = get_mem0()
    if client is None or not messages:
        return
    try:
        client.add(messages, filters=dict(_SCOPE))
    except Exception as exc:  # noqa: BLE001 — fail open
        logger.warning("Mem0 remember failed (%s); analysis not persisted.", exc)
