"""ThreatGraph multi-agent pipeline (PF-001).

Phase 1 — walking skeleton. A registered ``threatgraph`` ``StateGraph`` that reuses the
existing input safety gate (``Safeguard``) and, on the benign path, runs a deterministic
linear pipeline of three stub nodes that emit **canned** mechanics / Mermaid attack graph /
defense config. Output is delivered as a terminal ``custom`` ``ChatMessage`` carrying the
payload in ``custom_data`` (via the ``CustomData`` helper), consistent with the toolkit's
existing streaming contract.

Topology (matches the ``research_assistant`` safety-first idiom):

    guard_input --check_safety--> {unsafe: block_unsafe_content, safe: retrieve}
    retrieve -> extractor -> graph_architect -> defensive_guardrail -> END

Later phases replace the stubs with real logic:
  * ``retrieve``            -> hybrid BM25 + dense RRF + cross-encoder rerank (Phase 2)
  * ``extractor``           -> structured ``ExtractedMechanics`` grounded in ATT&CK (Phase 2)
  * ``graph_architect``     -> Mermaid rendered from mechanics + parse-check (Phase 2)
  * ``defensive_guardrail`` -> Guardrails-AI-validated ``DefenseConfig`` (Phase 3)
"""

from typing import Literal

from langchain_core.messages import AIMessage, AnyMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.managed import RemainingSteps

from agents.safeguard import Safeguard, SafeguardOutput, SafetyAssessment
from agents.utils import CustomData


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
    """Phase 1 stub — canned ATT&CK context.

    Phase 2 replaces this with a shared hybrid-retrieval node (BM25 + dense RRF fusion +
    cross-encoder rerank) over the full ATT&CK corpus.
    """
    return {"attack_context": CANNED_ATTACK_CONTEXT}


async def extractor(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Phase 1 stub — canned extracted mechanics.

    Phase 2 grounds this in ``attack_context`` via ``.with_structured_output(ExtractedMechanics)``.
    """
    return {"mechanics": CANNED_MECHANICS}


async def graph_architect(state: ThreatGraphState, config: RunnableConfig) -> ThreatGraphState:
    """Phase 1 stub — canned Mermaid kill-chain string.

    Phase 2 renders this from ``mechanics`` and adds a structural parse-check.
    """
    return {"mermaid": CANNED_MERMAID}


async def defensive_guardrail(
    state: ThreatGraphState, config: RunnableConfig
) -> ThreatGraphState:
    """Terminal node — synthesize the defense config and emit the ``custom`` output message.

    Phase 3 replaces the canned config with a Guardrails-AI-validated ``DefenseConfig``
    grounded in the retrieved ATT&CK mitigations.
    """
    defense_config = CANNED_DEFENSE_CONFIG
    payload = {
        "mechanics": state.get("mechanics", CANNED_MECHANICS),
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
