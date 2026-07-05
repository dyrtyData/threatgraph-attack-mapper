"""Tests for hosted Mem0 (v3) recall + write wiring (Phase 4, PF-001).

Default pytest stays OFFLINE — no real Mem0 network calls. The hosted ``MemoryClient`` is
always mocked (injected as a fake ``mem0`` module), and the global autouse fixture in
``tests/conftest.py`` disables Mem0 unless a test explicitly re-enables it. Two behaviours
are covered:

* DISABLED (no ``MEM0_API_KEY``): ``get_mem0()`` -> ``None``, ``recall`` -> ``[]``,
  ``remember`` -> no-op, and the full graph still runs to completion (fail-open).
* ENABLED (key set, client mocked): ``recall`` / ``remember`` call ``search`` / ``add`` with
  the correct ``app_id`` / ``user_id`` scope inside ``filters`` and NO deprecated v3 flags
  (``version`` / ``enable_graph`` / ``output_format``) — the DQ4 auto-graph contract.
"""

import sys
import types
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import HumanMessage
from pydantic import SecretStr

from core.settings import settings
from memory.mem0_client import APP_ID, USER_ID, get_mem0, recall, remember

# Offline seed context reused by the graph-level test (mirrors test_threatgraph.py).
SEED_CONTEXT = [
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "A macro-enabled document was delivered by email.",
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


def _enable_mem0(monkeypatch) -> MagicMock:
    """Enable Mem0 with a fake key + a mocked ``MemoryClient`` (no real network)."""
    monkeypatch.setattr(settings, "MEM0_API_KEY", SecretStr("m0-test-key"), raising=False)
    fake_client = MagicMock(name="MemoryClient-instance")
    fake_module = types.ModuleType("mem0")
    fake_module.MemoryClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "mem0", fake_module)
    get_mem0.cache_clear()
    return fake_client


# --- DISABLED (no key) -> fail-open no-op --------------------------------------------------


def test_get_mem0_returns_none_without_key(monkeypatch):
    monkeypatch.setattr(settings, "MEM0_API_KEY", None, raising=False)
    get_mem0.cache_clear()
    assert get_mem0() is None


def test_recall_and_remember_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "MEM0_API_KEY", None, raising=False)
    get_mem0.cache_clear()
    assert recall("mimikatz lsass credential dump") == []
    assert remember([{"role": "user", "content": "incident"}]) is None


@pytest.mark.asyncio
async def test_graph_runs_with_mem0_disabled(monkeypatch):
    """The full graph runs to completion with Mem0 unset (fail-open no-op)."""
    monkeypatch.setattr(settings, "MEM0_API_KEY", None, raising=False)
    get_mem0.cache_clear()
    # Offline: stub retrieval and force the extractor/defense deterministic fallback.
    monkeypatch.setattr(
        "agents.threatgraph.retrieve_attack_context", lambda query, k=5: SEED_CONTEXT
    )
    monkeypatch.setattr(
        "agents.threatgraph.get_model",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    from agents.threatgraph import threatgraph

    result = await threatgraph.ainvoke(
        {
            "messages": [
                HumanMessage(
                    content=(
                        "A user opened a macro-enabled attachment which launched PowerShell "
                        "and ultimately encrypted files for ransom."
                    )
                )
            ]
        }
    )
    assert result["mechanics"], "graph populates mechanics even with Mem0 disabled"
    assert result["defense_config"], "graph populates defense_config with Mem0 disabled"
    assert result["mermaid"].lower().startswith("graph")


# --- ENABLED (mocked client) -> correct scope, no deprecated flags -------------------------


def test_recall_calls_search_with_scope(monkeypatch):
    fake_client = _enable_mem0(monkeypatch)
    fake_client.search.return_value = {"results": [{"memory": "prior: T1003.001 seen"}]}

    out = recall("mimikatz dumped LSASS credentials")

    assert out == [{"memory": "prior: T1003.001 seen"}]
    fake_client.search.assert_called_once()
    args, kwargs = fake_client.search.call_args
    assert args[0] == "mimikatz dumped LSASS credentials"
    # Entity scope lives inside `filters` on the v3 SDK.
    filters = kwargs["filters"]
    assert filters.get("user_id") == USER_ID
    assert filters.get("app_id") == APP_ID
    # DQ4: no deprecated v3 flags anywhere in the call.
    for banned in ("version", "enable_graph", "output_format"):
        assert banned not in kwargs
        assert banned not in filters


def test_recall_normalizes_bare_list(monkeypatch):
    """A bare-list search response (older shape) is normalized to a list too."""
    fake_client = _enable_mem0(monkeypatch)
    fake_client.search.return_value = [{"memory": "a"}, {"memory": "b"}]
    assert recall("q") == [{"memory": "a"}, {"memory": "b"}]


def test_remember_calls_add_with_scope(monkeypatch):
    fake_client = _enable_mem0(monkeypatch)

    msgs = [
        {"role": "user", "content": "incident text"},
        {"role": "assistant", "content": "analysis summary"},
    ]
    remember(msgs)

    fake_client.add.assert_called_once()
    args, kwargs = fake_client.add.call_args
    assert args[0] == msgs
    filters = kwargs["filters"]
    assert filters.get("user_id") == USER_ID
    assert filters.get("app_id") == APP_ID
    for banned in ("version", "enable_graph", "output_format"):
        assert banned not in kwargs
        assert banned not in filters


def test_recall_fails_open_on_client_error(monkeypatch):
    fake_client = _enable_mem0(monkeypatch)
    fake_client.search.side_effect = RuntimeError("network down")
    assert recall("q") == []


def test_remember_fails_open_on_client_error(monkeypatch):
    fake_client = _enable_mem0(monkeypatch)
    fake_client.add.side_effect = RuntimeError("network down")
    assert remember([{"role": "user", "content": "x"}]) is None


# --- Node-level wiring: extractor prepends recall; defensive_guardrail writes ---------------


@pytest.mark.asyncio
async def test_extractor_prepends_recalled_facts(monkeypatch):
    """The extractor prepends recalled Mem0 facts into its system grounding."""
    monkeypatch.setattr(
        "agents.threatgraph.recall", lambda q: [{"memory": "PRIOR-FACT-XYZ actor uses T1003.001"}]
    )

    captured: dict[str, str] = {}

    class _Struct:
        def with_config(self, *a, **k):
            return self

        async def ainvoke(self, messages, config=None):
            captured["system"] = messages[0].content
            from schema.schema import ExtractedMechanics

            return ExtractedMechanics(techniques=[])

    class _Model:
        def with_structured_output(self, schema):
            return _Struct()

    monkeypatch.setattr("agents.threatgraph.get_model", lambda *a, **k: _Model())

    from agents.threatgraph import extractor

    await extractor(
        {"attack_context": SEED_CONTEXT, "raw_text": "dump lsass"}, {"configurable": {}}
    )
    assert "PRIOR-FACT-XYZ" in captured["system"]
    # The recalled block is PREPENDED (before the main enumerate-then-ground instructions).
    assert captured["system"].index("PRIOR-FACT-XYZ") < captured["system"].index("STEP 1")


@pytest.mark.asyncio
async def test_extractor_prompt_unchanged_when_recall_empty(monkeypatch):
    """When recall returns nothing, no memory block is added (fail-open, prompt intact)."""
    monkeypatch.setattr("agents.threatgraph.recall", lambda q: [])

    captured: dict[str, str] = {}

    class _Struct:
        def with_config(self, *a, **k):
            return self

        async def ainvoke(self, messages, config=None):
            captured["system"] = messages[0].content
            from schema.schema import ExtractedMechanics

            return ExtractedMechanics(techniques=[])

    class _Model:
        def with_structured_output(self, schema):
            return _Struct()

    monkeypatch.setattr("agents.threatgraph.get_model", lambda *a, **k: _Model())

    from agents.threatgraph import EXTRACTOR_INSTRUCTIONS, extractor

    await extractor(
        {"attack_context": SEED_CONTEXT, "raw_text": "dump lsass"}, {"configurable": {}}
    )
    assert "recalled from prior" not in captured["system"]
    assert captured["system"].startswith(EXTRACTOR_INSTRUCTIONS.split("{context}")[0][:40])


@pytest.mark.asyncio
async def test_defensive_guardrail_writes_analysis_turn(monkeypatch):
    """After synthesis, the defensive_guardrail writes the analysis turn to Mem0."""
    calls: list[list[dict]] = []
    monkeypatch.setattr("agents.threatgraph.remember", lambda messages: calls.append(messages))
    monkeypatch.setattr(
        "agents.threatgraph.get_model",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    from agents.threatgraph import defensive_guardrail

    mechanics = [
        {
            "tactic": "Initial Access",
            "technique_id": "T1566.001",
            "name": "Spearphishing Attachment",
            "evidence": "macro attachment",
        }
    ]
    state = {
        "mechanics": mechanics,
        "attack_context": SEED_CONTEXT,
        "raw_text": "user opened a macro attachment",
        "mermaid": 'graph TD\n    T1566_001["x"]\n',
    }
    await defensive_guardrail(state, {"configurable": {}})

    assert calls, "remember should be called with the analysis turn"
    turn = calls[0]
    assert turn[0]["role"] == "user"
    assert turn[0]["content"] == "user opened a macro attachment"
    assert turn[1]["role"] == "assistant"
    # The written summary carries the salient extracted technique.
    assert "T1566.001" in turn[1]["content"]
