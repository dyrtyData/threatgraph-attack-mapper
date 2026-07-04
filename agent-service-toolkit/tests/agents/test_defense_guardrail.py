"""Tests for the Phase 3 Defensive_Guardrail (Guardrails AI defense-config validation).

The suite stays fast/offline: :func:`validate_defense_config` runs Guardrails' local Pydantic
structural validation (no Hub inference — ``use_remote_inferencing=false`` in
``~/.guardrailsrc``), and every path is designed to *fail open* if Guardrails AI is absent.
The ``defensive_guardrail`` node is exercised with the extractor's deterministic offline path
(``get_model`` forced to raise) so no network/model download happens, and we assert the
synthesized mitigation ids are grounded in the provided ``attack_context``.
"""

import pytest
from langchain_core.messages import ChatMessage as LangchainChatMessage

from agents.guardrails import validate_defense_config
from agents.threatgraph import _grounded_pairs, defensive_guardrail
from schema.schema import DefenseConfig

# Retrieved ATT&CK context with mitigations (the grounding source of truth).
CONTEXT = [
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "A macro-enabled document was delivered by email.",
        "mitigations": [
            {"id": "M1017", "name": "User Training"},
            {"id": "M1049", "name": "Antivirus/Antimalware"},
        ],
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

MECHANICS = [
    {"tactic": "Initial Access", "technique_id": "T1566.001", "name": "Spearphishing", "evidence": "x"},
    {"tactic": "Execution", "technique_id": "T1059.001", "name": "PowerShell", "evidence": "y"},
    {"tactic": "Impact", "technique_id": "T1486", "name": "Data Encrypted for Impact", "evidence": "z"},
]

_CONTEXT_MITIGATION_IDS = {"M1017", "M1049", "M1042", "M1053"}
_DEFENSE_KEYS = {"technique_id", "mitigation_id", "action", "rationale"}


# --- validate_defense_config -----------------------------------------------------------


def test_valid_config_passes_validation():
    """A well-formed config validates (Guardrails locally, or fail-open) into a DefenseConfig."""
    raw = {
        "defenses": [
            {
                "technique_id": "T1566.001",
                "mitigation_id": "M1017",
                "action": "Deliver phishing-awareness training.",
                "rationale": "User Training reduces the chance a spearphishing attachment is opened.",
            }
        ]
    }
    result = validate_defense_config(raw)
    assert isinstance(result, DefenseConfig)
    assert len(result.defenses) == 1
    d = result.defenses[0]
    assert d.technique_id == "T1566.001"
    assert d.mitigation_id == "M1017"


def test_malformed_output_exercises_fix_failopen_path():
    """Malformed model output must not crash — fix/fail-open coerces to a valid DefenseConfig."""
    # Entries missing action/rationale are backfilled (grounded core kept); entries missing the
    # grounded core (no mitigation_id) are dropped.
    malformed = {
        "defenses": [
            {"technique_id": "T1059.001", "mitigation_id": "M1042"},  # missing action/rationale
            {"technique_id": "T1486"},  # missing mitigation_id -> dropped
        ]
    }
    result = validate_defense_config(malformed)
    assert isinstance(result, DefenseConfig)
    ids = [(d.technique_id, d.mitigation_id) for d in result.defenses]
    assert ids == [("T1059.001", "M1042")]
    # Backfilled action/rationale are non-empty strings.
    assert result.defenses[0].action
    assert result.defenses[0].rationale


def test_garbage_string_fails_open_to_empty_config():
    """A non-JSON string cannot validate; we fail open to an empty (but valid) DefenseConfig."""
    result = validate_defense_config("this is not json at all")
    assert isinstance(result, DefenseConfig)
    assert result.defenses == []


def test_validate_accepts_bare_list_and_model():
    """A bare list of entries and an already-built DefenseConfig both round-trip cleanly."""
    bare = [
        {
            "technique_id": "T1486",
            "mitigation_id": "M1053",
            "action": "Maintain offline backups.",
            "rationale": "Data Backup enables recovery without paying ransom.",
        }
    ]
    from_list = validate_defense_config(bare)
    assert [d.mitigation_id for d in from_list.defenses] == ["M1053"]

    from_model = validate_defense_config(from_list)
    assert [d.mitigation_id for d in from_model.defenses] == ["M1053"]


# --- grounding in attack_context -------------------------------------------------------


def test_grounded_pairs_only_from_context():
    """Every synthesized (technique, mitigation) pair comes from attack_context mitigations."""
    pairs = _grounded_pairs(MECHANICS, CONTEXT)
    assert pairs, "expected grounded pairs for techniques present in context"
    for p in pairs:
        assert p["mitigation_id"] in _CONTEXT_MITIGATION_IDS


def test_grounded_pairs_ignore_ungrounded_technique():
    """A mechanic whose technique is absent from context contributes no pairs (nothing invented)."""
    mechanics = MECHANICS + [
        {"tactic": "Discovery", "technique_id": "T9999", "name": "Bogus", "evidence": "q"}
    ]
    pairs = _grounded_pairs(mechanics, CONTEXT)
    assert all(p["technique_id"] != "T9999" for p in pairs)


@pytest.mark.asyncio
async def test_node_synthesizes_grounded_defense_offline(monkeypatch):
    """The node (offline LLM) synthesizes a validated config with context-grounded mitigations."""
    # Force the deterministic (fail-open) synthesis path — no network/model.
    monkeypatch.setattr(
        "agents.threatgraph.get_model",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    result = await defensive_guardrail(
        {"mechanics": MECHANICS, "attack_context": CONTEXT, "mermaid": "graph TD\n    A[\"a\"]\n"},
        {"configurable": {}},
    )

    defense_config = result["defense_config"]
    assert defense_config, "node should synthesize a non-empty defense config"
    for entry in defense_config:
        assert _DEFENSE_KEYS <= set(entry)
        assert entry["mitigation_id"] in _CONTEXT_MITIGATION_IDS  # grounded, not invented
        assert entry["technique_id"] in {"T1566.001", "T1059.001", "T1486"}

    # Terminal message is a `custom` LangChain ChatMessage carrying the validated config.
    last = result["messages"][-1]
    assert isinstance(last, LangchainChatMessage)
    assert last.role == "custom"
    assert last.content[0]["defense_config"] == defense_config


@pytest.mark.asyncio
async def test_node_config_validates_against_schema(monkeypatch):
    """The config the node emits is itself schema-valid under DefenseConfig."""
    monkeypatch.setattr(
        "agents.threatgraph.get_model",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    result = await defensive_guardrail(
        {"mechanics": MECHANICS, "attack_context": CONTEXT},
        {"configurable": {}},
    )
    # Re-validate the emitted config: it must round-trip through the schema unchanged in shape.
    revalidated = validate_defense_config(result["defense_config"])
    assert isinstance(revalidated, DefenseConfig)
    assert len(revalidated.defenses) == len(result["defense_config"])
