"""ThreatGraph multi-agent pipeline (PF-001).

A registered ``threatgraph`` ``StateGraph`` that reuses the existing input safety gate
(``Safeguard``) and, on the benign path, runs a deterministic linear pipeline. Output is
delivered as a terminal ``custom`` ``ChatMessage`` carrying the payload in ``custom_data``
(via the ``CustomData`` helper), consistent with the toolkit's streaming contract.

Topology (matches the ``research_assistant`` safety-first idiom):

    guard_input --check_safety--> {unsafe: block_unsafe_content, safe: retrieve}
    retrieve -> extractor -> graph_architect -> defensive_guardrail -> END

Node status:
  * ``retrieve``            -> hybrid BM25 + dense RRF + cross-encoder rerank (Phase 2) ✅
  * ``extractor``           -> structured ``ExtractedMechanics`` grounded in ATT&CK (Phase 2) ✅
  * ``graph_architect``     -> Mermaid rendered from mechanics + parse-check (Phase 2) ✅
  * ``defensive_guardrail`` -> Guardrails-AI-validated ``DefenseConfig``, mitigations grounded
                               in the retrieved ``attack_context`` (Phase 3) ✅

The canned constants below are retained as fail-open fallbacks (no retrieval hit, empty
extraction, or a Mermaid parse-check failure degrade gracefully to them).
"""

import logging
import re
from typing import Any, Literal

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.managed import RemainingSteps

from agents.guardrails import validate_defense_config
from agents.retrieval import CONTEXT_K, retrieve_attack_context
from agents.safeguard import Safeguard, SafeguardOutput, SafetyAssessment
from agents.utils import CustomData
from core import get_model, settings
from schema.schema import DefenseConfig, ExtractedMechanics

logger = logging.getLogger(__name__)

# Kill-chain tactic ordering used to order techniques for the Mermaid graph and the
# deterministic fallback extractor (ATT&CK enterprise tactic sequence).
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class ThreatGraphState(MessagesState, total=False):
    """State for the threat-intel attack-graph pipeline.

    ``total=False`` (PEP 589) so every field is optional and populated as the pipeline
    progresses. ``mechanics`` / ``defense_config`` are plain ``dict``/``list`` in Phase 1
    and become the shared Pydantic ``ExtractedMechanics`` / ``DefenseConfig`` types in
    Phases 2-3.
    """

    raw_text: str  # unstructured threat-intel input
    safety: SafeguardOutput  # reuse existing input gate
    attack_context: list[dict]  # retrieved ATT&CK techniques + mitigations
    mechanics: list[dict]  # ordered techniques w/ tactic, id, evidence
    mermaid: str  # Mermaid attack-graph string
    defense_config: list[dict]  # synthesized, (Phase 3) guardrail-validated defense config
    remaining_steps: RemainingSteps


# ---------------------------------------------------------------------------
# Canned Phase-1 payloads (replaced with grounded logic in Phases 2-3).
# The three payloads are internally consistent — the Mermaid nodes, the extracted
# mechanics, and the defense config all reference the same kill-chain technique IDs —
# so the walking skeleton renders a coherent end-to-end example in every UI.
# ---------------------------------------------------------------------------

CANNED_ATTACK_CONTEXT: list[dict] = [
    {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "mitigations": [
            {"id": "M1049", "name": "Antivirus/Antimalware"},
            {"id": "M1017", "name": "User Training"},
        ],
    },
    {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactics": ["Execution"],
        "mitigations": [{"id": "M1038", "name": "Execution Prevention"}],
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ["Execution"],
        "mitigations": [{"id": "M1042", "name": "Disable or Remove Feature or Program"}],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "mitigations": [{"id": "M1053", "name": "Data Backup"}],
    },
]

CANNED_MECHANICS: list[dict] = [
    {
        "tactic": "Initial Access",
        "technique_id": "T1566.001",
        "name": "Spearphishing Attachment",
        "evidence": "A macro-enabled document was delivered by email to the victim.",
    },
    {
        "tactic": "Execution",
        "technique_id": "T1204.002",
        "name": "User Execution: Malicious File",
        "evidence": "The user opened the attachment and enabled content.",
    },
    {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "evidence": "The macro spawned an encoded PowerShell downloader.",
    },
    {
        "tactic": "Impact",
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "evidence": "Files were encrypted and a ransom note was dropped.",
    },
]

CANNED_MERMAID: str = (
    "graph TD\n"
    '    T1566_001["T1566.001 · Spearphishing Attachment<br/>(Initial Access)"]\n'
    '    T1204_002["T1204.002 · User Execution: Malicious File<br/>(Execution)"]\n'
    '    T1059_001["T1059.001 · PowerShell<br/>(Execution)"]\n'
    '    T1486["T1486 · Data Encrypted for Impact<br/>(Impact)"]\n'
    "    T1566_001 --> T1204_002\n"
    "    T1204_002 --> T1059_001\n"
    "    T1059_001 --> T1486\n"
)

CANNED_DEFENSE_CONFIG: list[dict] = [
    {
        "technique_id": "T1566.001",
        "mitigation_id": "M1017",
        "action": "Deliver phishing-awareness training and simulated-phishing exercises.",
        "rationale": "User Training reduces the likelihood that a spearphishing attachment is opened.",
    },
    {
        "technique_id": "T1204.002",
        "mitigation_id": "M1038",
        "action": "Enforce macro-execution prevention and application allow-listing.",
        "rationale": "Execution Prevention blocks malicious macros from launching payloads.",
    },
    {
        "technique_id": "T1059.001",
        "mitigation_id": "M1042",
        "action": "Constrain PowerShell (Constrained Language Mode, script-block logging).",
        "rationale": "Removing/limiting PowerShell disrupts the encoded downloader stage.",
    },
    {
        "technique_id": "T1486",
        "mitigation_id": "M1053",
        "action": "Maintain tested, offline, immutable backups of critical data.",
        "rationale": "Data Backup enables recovery without paying ransom after encryption.",
    },
]


def _latest_user_text(messages: list[AnyMessage]) -> str:
    """Return the most recent human message content as a string."""
    for message in reversed(messages):
        if getattr(message, "type", None) == "human":
            content = message.content
            return content if isinstance(content, str) else str(content)
    return ""


def format_safety_message(safety: SafeguardOutput) -> AIMessage:
    content = (
        f"This threat-intel submission was flagged for unsafe content: "
        f"{', '.join(safety.unsafe_categories)}"
    )
    return AIMessage(content=content)


async def safeguard_input(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Input safety gate — reuses the existing prompt-injection classifier (fail-open)."""
    safeguard = Safeguard()
    safety_output = await safeguard.ainvoke(state["messages"])
    return {
        "safety": safety_output,
        "raw_text": _latest_user_text(state["messages"]),
        "messages": [],
    }


def check_safety(state: ThreatGraphState) -> Literal["unsafe", "safe"]:
    safety: SafeguardOutput = state["safety"]
    match safety.safety_assessment:
        case SafetyAssessment.UNSAFE:
            return "unsafe"
        case _:
            return "safe"


async def block_unsafe_content(
    state: ThreatGraphState, config: RunnableConfig
) -> ThreatGraphState:
    safety: SafeguardOutput = state["safety"]
    return {"messages": [format_safety_message(safety)]}


async def retrieve(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Shared hybrid-retrieval node (Phase 2).

    Grounds both the ``extractor`` and (later) the ``defensive_guardrail`` in one retrieval
    over the full ATT&CK corpus: BM25 + dense RRF fusion + cross-encoder rerank, isolated in
    :mod:`agents.retrieval`. Fails open (BM25-only, then canned) so the graph never crashes.

    Uses a wide ``CONTEXT_K`` (not the narrow library ``DEFAULT_K``): a single query over the
    whole snippet only surfaces the neighbors of the *most salient* technique, so a small k
    starves the extractor's grounding set and multi-technique incidents get under-extracted.
    """
    query = state.get("raw_text") or _latest_user_text(state["messages"])
    context = retrieve_attack_context(query, k=CONTEXT_K)
    if not context:
        logger.warning("ATT&CK retrieval returned nothing; using canned context.")
        context = CANNED_ATTACK_CONTEXT
    return {"attack_context": context}


EXTRACTOR_INSTRUCTIONS = """You are a threat-intelligence analyst. Read the incident text \
and extract the attacker's execution mechanics as an ordered kill chain.

Work in two explicit steps:

STEP 1 — ENUMERATE. First re-read the text and list EVERY distinct attacker behavior it \
describes. Incident reports almost always describe MULTIPLE techniques spanning several \
tactics (e.g. initial access, execution, credential access, lateral movement, collection, \
command-and-control, exfiltration, impact). Do NOT stop at the single most obvious or \
dominant behavior — account for each separate action the attacker took (a login, a \
credential dump, a pivot to another host, an exfil, etc. are all separate behaviors).

STEP 2 — GROUND. For each behavior you enumerated, map it to the SINGLE best-matching MITRE \
ATT&CK technique from the retrieved context below, and emit one entry with that technique's \
canonical id, name, tactic, and the exact span of source text that is the evidence.

Rules:
- Emit ONE technique entry per distinct behavior from STEP 1 — aim for completeness, not \
just the most salient one. A typical incident yields several entries.
- ONLY use technique ids that appear in the retrieved ATT&CK context below. If an \
enumerated behavior has no good match in the context, omit that entry rather than inventing \
an id — but do include every behavior that DOES have a match.
- Order the emitted techniques along the kill chain (Initial Access first, Impact last).

Retrieved ATT&CK context:
{context}
"""


def _format_context(attack_context: list[dict[str, Any]]) -> str:
    lines = []
    for c in attack_context:
        tactics = ", ".join(c.get("tactics") or [])
        lines.append(f"- {c.get('id')} {c.get('name')} [{tactics}]: {c.get('description', '')}")
    return "\n".join(lines)


def _mechanics_from_context(attack_context: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic fallback: derive ordered mechanics straight from retrieved context.

    Used when the structured LLM call is unavailable (no key / offline / parse failure), so
    the pipeline still emits grounded, kill-chain-ordered mechanics.
    """

    def sort_key(c: dict[str, Any]) -> int:
        tactics = c.get("tactics") or []
        first = tactics[0] if tactics else ""
        return TACTIC_ORDER.index(first) if first in TACTIC_ORDER else len(TACTIC_ORDER)

    mechanics: list[dict[str, Any]] = []
    for c in sorted(attack_context, key=sort_key):
        tactics = c.get("tactics") or []
        description = (c.get("description") or "").strip()
        mechanics.append(
            {
                "tactic": tactics[0] if tactics else "Unknown",
                "technique_id": c.get("id", ""),
                "name": c.get("name", ""),
                "evidence": description[:200] or "Present in the retrieved ATT&CK context.",
            }
        )
    return mechanics


async def extractor(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Extract structured, ATT&CK-grounded mechanics from the raw threat-intel text.

    Uses ``.with_structured_output(ExtractedMechanics)`` grounded in ``attack_context``,
    canonicalizing technique ids to the ``Txxxx`` ids present in the retrieved context. The
    internal LLM call is tagged ``skip_stream`` so its tokens never reach the user. Fails
    open to a deterministic context-derived extraction (mirrors ``Safeguard``).
    """
    attack_context = state.get("attack_context") or CANNED_ATTACK_CONTEXT
    raw_text = state.get("raw_text") or _latest_user_text(state["messages"])
    canonical = {c.get("id") for c in attack_context if c.get("id")}

    try:
        model = get_model(config["configurable"].get("model", settings.DEFAULT_MODEL))
        structured = model.with_structured_output(ExtractedMechanics).with_config(
            tags=["skip_stream"]
        )
        system = SystemMessage(
            content=EXTRACTOR_INSTRUCTIONS.format(context=_format_context(attack_context))
        )
        result = await structured.ainvoke([system, HumanMessage(content=raw_text)], config)
        techniques = result.techniques if isinstance(result, ExtractedMechanics) else []
        # Canonicalize: keep only techniques grounded in the retrieved context.
        grounded = [t for t in techniques if t.technique_id in canonical]
        mechanics = [t.model_dump() for t in (grounded or techniques)]
        if mechanics:
            return {"mechanics": mechanics}
        logger.warning("Structured extraction returned no grounded techniques; using fallback.")
    except Exception as exc:  # noqa: BLE001 — fail open to deterministic extraction
        logger.warning("Structured extraction failed (%s); using context-derived fallback.", exc)

    return {"mechanics": _mechanics_from_context(attack_context)}


def _sanitize_node_id(technique_id: str) -> str:
    """Mermaid node ids must be identifier-safe (dots/spaces break the parser)."""
    return re.sub(r"[^A-Za-z0-9_]", "_", technique_id) or "node"


def render_mermaid(mechanics: list[dict[str, Any]]) -> str:
    """Render an ordered kill-chain ``graph TD`` Mermaid string from mechanics."""
    lines = ["graph TD"]
    node_ids: list[str] = []
    for m in mechanics:
        technique_id = m.get("technique_id", "")
        node_id = _sanitize_node_id(technique_id)
        name = (m.get("name", "") or "").replace('"', "'")
        tactic = m.get("tactic", "")
        lines.append(f'    {node_id}["{technique_id} · {name}<br/>({tactic})"]')
        node_ids.append(node_id)
    for src, dst in zip(node_ids, node_ids[1:]):
        lines.append(f"    {src} --> {dst}")
    return "\n".join(lines) + "\n"


def is_valid_mermaid(code: str) -> bool:
    """Lightweight structural parse-check (no browser needed server-side).

    Confirms: a leading ``graph``/``flowchart`` directive, at least one declared node, and
    that every edge references a declared node id.
    """
    lines = [ln.strip() for ln in code.splitlines() if ln.strip()]
    if not lines or not re.match(r"^(graph|flowchart)\b", lines[0]):
        return False
    node_ids: set[str] = set()
    edges: list[tuple[str, str]] = []
    for line in lines[1:]:
        node_match = re.match(r"^([A-Za-z0-9_]+)\s*[\[({]", line)
        if node_match:
            node_ids.add(node_match.group(1))
            continue
        edge_match = re.match(r"^([A-Za-z0-9_]+)\s*-->\s*([A-Za-z0-9_]+)", line)
        if edge_match:
            edges.append((edge_match.group(1), edge_match.group(2)))
    if not node_ids:
        return False
    return all(a in node_ids and b in node_ids for a, b in edges)


async def graph_architect(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Render the Mermaid kill-chain from ``mechanics`` with a structural parse-check.

    Falls open to the canned diagram if the rendered string fails the structural check.
    """
    mechanics = state.get("mechanics") or CANNED_MECHANICS
    mermaid = render_mermaid(mechanics)
    if not is_valid_mermaid(mermaid):
        logger.warning("Rendered Mermaid failed structural parse-check; using canned diagram.")
        mermaid = CANNED_MERMAID
    return {"mermaid": mermaid}


DEFENSE_INSTRUCTIONS = """You are a defensive security engineer. For each (technique, \
mitigation) pair below, write a concrete defensive ACTION and a one-sentence RATIONALE for \
why that MITRE ATT&CK mitigation counters the technique.

HARD CONSTRAINTS:
- Emit ONE entry per provided pair, reusing its EXACT technique_id and mitigation_id verbatim.
- Do NOT invent, alter, or add any technique_id or mitigation_id — use only the pairs given.
- Keep the action operational and specific; keep the rationale to one sentence.

Grounded (technique, mitigation) pairs:
{pairs}
"""


def _mitigations_by_technique(
    attack_context: list[dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    """Map technique_id -> its ATT&CK mitigations ({id, name}) from the retrieved context."""
    out: dict[str, list[dict[str, str]]] = {}
    for record in attack_context:
        tid = record.get("id")
        if not tid:
            continue
        mitigations = [
            {"id": m.get("id", ""), "name": m.get("name", "")}
            for m in (record.get("mitigations") or [])
            if m.get("id")
        ]
        if mitigations:
            out.setdefault(tid, []).extend(mitigations)
    return out


def _grounded_pairs(
    mechanics: list[dict[str, Any]], attack_context: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Ordered (technique, mitigation) pairs grounded in the retrieved context.

    Walks the extracted ``mechanics`` in kill-chain order and, for each technique, joins in
    every mitigation the ``retrieve`` node surfaced for it. Mitigation ids therefore always
    come from ``attack_context`` — never invented downstream.
    """
    mit_map = _mitigations_by_technique(attack_context)
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in mechanics:
        tid = m.get("technique_id", "")
        tname = m.get("name", "")
        for mit in mit_map.get(tid, []):
            key = (tid, mit["id"])
            if key in seen:
                continue
            seen.add(key)
            pairs.append(
                {
                    "technique_id": tid,
                    "technique_name": tname,
                    "mitigation_id": mit["id"],
                    "mitigation_name": mit["name"],
                }
            )
    return pairs


def _deterministic_defense(pairs: list[dict[str, str]]) -> list[dict[str, str]]:
    """Offline fail-open synthesis — grounded templated action/rationale per pair."""
    defenses: list[dict[str, str]] = []
    for p in pairs:
        mit_name = p.get("mitigation_name") or p["mitigation_id"]
        tech_name = p.get("technique_name") or p["technique_id"]
        defenses.append(
            {
                "technique_id": p["technique_id"],
                "mitigation_id": p["mitigation_id"],
                "action": f"Implement {mit_name} to counter {tech_name} ({p['technique_id']}).",
                "rationale": (
                    f"{mit_name} ({p['mitigation_id']}) is the MITRE ATT&CK mitigation mapped "
                    f"to {p['technique_id']}."
                ),
            }
        )
    return defenses


def _format_pairs(pairs: list[dict[str, str]]) -> str:
    return "\n".join(
        f"- {p['technique_id']} ({p['technique_name']}) -> "
        f"{p['mitigation_id']} ({p['mitigation_name']})"
        for p in pairs
    )


async def _synthesize_defense(
    pairs: list[dict[str, str]], config: RunnableConfig
) -> list[dict[str, str]]:
    """Synthesize defense entries for the grounded pairs; fail open to deterministic text.

    Uses a structured LLM call (tagged ``skip_stream`` so its tokens never reach the user) to
    write the action/rationale prose, then hard-filters the result back to the allowed
    (technique_id, mitigation_id) pairs so no mitigation id can be invented. Falls open to a
    deterministic, grounded synthesis when the model is unavailable.
    """
    if not pairs:
        return []
    allowed = {(p["technique_id"], p["mitigation_id"]) for p in pairs}
    try:
        model = get_model(config["configurable"].get("model", settings.DEFAULT_MODEL))
        structured = model.with_structured_output(DefenseConfig).with_config(
            tags=["skip_stream"]
        )
        system = SystemMessage(content=DEFENSE_INSTRUCTIONS.format(pairs=_format_pairs(pairs)))
        result = await structured.ainvoke([system], config)
        defenses = result.defenses if isinstance(result, DefenseConfig) else []
        grounded = [
            d.model_dump()
            for d in defenses
            if (d.technique_id, d.mitigation_id) in allowed
        ]
        if grounded:
            return grounded
        logger.warning("LLM defense synthesis produced no grounded entries; using fallback.")
    except Exception as exc:  # noqa: BLE001 — fail open to deterministic grounded synthesis
        logger.warning("Defense synthesis LLM call failed (%s); using deterministic.", exc)
    return _deterministic_defense(pairs)


async def defensive_guardrail(
    state: ThreatGraphState, config: RunnableConfig
) -> ThreatGraphState:
    """Terminal node — synthesize a grounded defense config, Guardrails-validate it, emit output.

    Synthesizes a ``DefenseConfig`` whose mitigation ids are grounded in the retrieved
    ``attack_context`` (never invented), runs it through Guardrails AI
    (:func:`agents.guardrails.validate_defense_config`, fail-open), and attaches the validated
    config to the terminal ``custom`` ``ChatMessage`` payload. Fails open to the canned config
    only if no grounded pairs are available at all.
    """
    mechanics = state.get("mechanics") or CANNED_MECHANICS
    attack_context = state.get("attack_context") or CANNED_ATTACK_CONTEXT

    pairs = _grounded_pairs(mechanics, attack_context)
    synthesized = await _synthesize_defense(pairs, config)
    if not synthesized:
        logger.warning("No grounded defense pairs available; using canned defense config.")
        synthesized = CANNED_DEFENSE_CONFIG

    # Guardrails AI structural validation (fail-open) of the synthesized config.
    validated = validate_defense_config(synthesized)
    defense_config = [d.model_dump() for d in validated.defenses] or synthesized

    payload = {
        "mechanics": mechanics,
        "mermaid": state.get("mermaid", CANNED_MERMAID),
        "defense_config": defense_config,
    }
    custom_message = CustomData(data=payload).to_langchain()
    return {"defense_config": defense_config, "messages": [custom_message]}


# Define the graph — safety-first gate + deterministic linear pipeline.
g = StateGraph(ThreatGraphState)
g.add_node("guard_input", safeguard_input)
g.add_node("block_unsafe_content", block_unsafe_content)
g.add_node("retrieve", retrieve)
g.add_node("extractor", extractor)
g.add_node("graph_architect", graph_architect)
g.add_node("defensive_guardrail", defensive_guardrail)

g.set_entry_point("guard_input")
g.add_conditional_edges(
    "guard_input", check_safety, {"unsafe": "block_unsafe_content", "safe": "retrieve"}
)
g.add_edge("block_unsafe_content", END)
g.add_edge("retrieve", "extractor")
g.add_edge("extractor", "graph_architect")
g.add_edge("graph_architect", "defensive_guardrail")
g.add_edge("defensive_guardrail", END)

# checkpointer/store are attached at startup by the service lifespan, not here.
threatgraph = g.compile()
