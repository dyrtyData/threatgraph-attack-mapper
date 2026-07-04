from typing import Any, Literal, NotRequired

from pydantic import BaseModel, Field, SerializeAsAny
from typing_extensions import TypedDict

from schema.models import AllModelEnum, AnthropicModelName, OpenAIModelName


class AgentInfo(BaseModel):
    """Info about an available agent."""

    key: str = Field(
        description="Agent key.",
        examples=["research-assistant"],
    )
    description: str = Field(
        description="Description of the agent.",
        examples=["A research assistant for generating research papers."],
    )


class ServiceMetadata(BaseModel):
    """Metadata about the service including available agents and models."""

    agents: list[AgentInfo] = Field(
        description="List of available agents.",
    )
    models: list[AllModelEnum] = Field(
        description="List of available LLMs.",
    )
    default_agent: str = Field(
        description="Default agent used when none is specified.",
        examples=["research-assistant"],
    )
    default_model: AllModelEnum = Field(
        description="Default model used when none is specified.",
    )


class UserInput(BaseModel):
    """Basic user input for the agent."""

    message: str = Field(
        description="User input to the agent.",
        examples=["What is the weather in Tokyo?"],
    )
    model: SerializeAsAny[AllModelEnum] | None = Field(
        title="Model",
        description="LLM Model to use for the agent. Defaults to the default model set in the settings of the service.",
        default=None,
        examples=[OpenAIModelName.GPT_5_NANO, AnthropicModelName.HAIKU_45],
    )
    thread_id: str | None = Field(
        description="Thread ID to persist and continue a multi-turn conversation.",
        default=None,
        examples=["847c6285-8fc9-4560-a83f-4e6285809254"],
    )
    user_id: str | None = Field(
        description="User ID to persist and continue a conversation across multiple threads.",
        default=None,
        examples=["847c6285-8fc9-4560-a83f-4e6285809254"],
    )
    agent_config: dict[str, Any] = Field(
        description="Additional configuration to pass through to the agent",
        default={},
        examples=[{"spicy_level": 0.8}],
    )


class StreamInput(UserInput):
    """User input for streaming the agent's response."""

    stream_tokens: bool = Field(
        description="Whether to stream LLM tokens to the client.",
        default=True,
    )


class ToolCall(TypedDict):
    """Represents a request to call a tool."""

    name: str
    """The name of the tool to be called."""
    args: dict[str, Any]
    """The arguments to the tool call."""
    id: str | None
    """An identifier associated with the tool call."""
    type: NotRequired[Literal["tool_call"]]


class Technique(BaseModel):
    """A single attacker technique extracted from threat-intel text.

    Canonicalized to a MITRE ATT&CK ``Txxxx[.yyy]`` id grounded in the retrieved
    ``attack_context`` (Phase 2, shared by ``threatgraph`` and the ``evals/`` harness).
    """

    tactic: str = Field(
        description="ATT&CK tactic (kill-chain phase) this technique serves.",
        examples=["Initial Access", "Execution", "Impact"],
    )
    technique_id: str = Field(
        description="Canonical MITRE ATT&CK technique id.",
        examples=["T1566.001", "T1059.001", "T1486"],
    )
    name: str = Field(
        description="Human-readable technique name.",
        examples=["Spearphishing Attachment", "PowerShell"],
    )
    evidence: str = Field(
        description="Span of the source text that supports this technique.",
        examples=["A macro-enabled document was delivered by email to the victim."],
    )


class ExtractedMechanics(BaseModel):
    """Ordered attacker execution mechanics extracted by the ``Extractor`` node.

    Shared Pydantic type (lives here, not in ``threatgraph.py``) so the ``evals/`` harness
    can import it in Phase 5. Techniques are ordered along the kill chain.
    """

    techniques: list[Technique] = Field(
        default_factory=list,
        description="Ordered list of attacker techniques along the kill chain.",
    )


class Defense(BaseModel):
    """A single defensive measure tied to one extracted technique.

    Grounded in the retrieved ``attack_context``: the ``mitigation_id`` is a canonical
    MITRE ATT&CK mitigation id that the ``retrieve`` node surfaced for the technique — it is
    never invented by the model (Phase 3).
    """

    technique_id: str = Field(
        description="Canonical MITRE ATT&CK technique id this defense addresses.",
        examples=["T1566.001", "T1059.001", "T1486"],
    )
    mitigation_id: str = Field(
        description="Canonical MITRE ATT&CK mitigation id (grounded in attack_context).",
        examples=["M1017", "M1042", "M1053"],
    )
    action: str = Field(
        description="Concrete defensive action to take.",
        examples=["Deliver phishing-awareness training and simulated-phishing exercises."],
    )
    rationale: str = Field(
        description="Why this mitigation counters the technique.",
        examples=["User Training reduces the likelihood a spearphishing attachment is opened."],
    )


class DefenseConfig(BaseModel):
    """Synthesized, Guardrails-AI-validated defense configuration (Phase 3).

    Shared Pydantic type (lives here, not in ``threatgraph.py``) so the ``evals/`` harness
    can import it in Phase 5. Each entry maps an extracted technique to a mitigation grounded
    in the retrieved ATT&CK context, validated via ``Guard.for_pydantic(DefenseConfig)``.
    """

    defenses: list[Defense] = Field(
        default_factory=list,
        description="Defensive measures, one per (technique, grounded mitigation) pairing.",
    )


class ChatMessage(BaseModel):
    """Message in a chat."""

    type: Literal["human", "ai", "tool", "custom"] = Field(
        description="Role of the message.",
        examples=["human", "ai", "tool", "custom"],
    )
    content: str = Field(
        description="Content of the message.",
        examples=["Hello, world!"],
    )
    tool_calls: list[ToolCall] = Field(
        description="Tool calls in the message.",
        default=[],
    )
    tool_call_id: str | None = Field(
        description="Tool call that this message is responding to.",
        default=None,
        examples=["call_Jja7J89XsjrOLA5r!MEOW!SL"],
    )
    run_id: str | None = Field(
        description="Run ID of the message.",
        default=None,
        examples=["847c6285-8fc9-4560-a83f-4e6285809254"],
    )
    response_metadata: dict[str, Any] = Field(
        description="Response metadata. For example: response headers, logprobs, token counts.",
        default={},
    )
    custom_data: dict[str, Any] = Field(
        description="Custom message data.",
        default={},
    )

    def pretty_repr(self) -> str:
        """Get a pretty representation of the message."""
        base_title = self.type.title() + " Message"
        padded = " " + base_title + " "
        sep_len = (80 - len(padded)) // 2
        sep = "=" * sep_len
        second_sep = sep + "=" if len(padded) % 2 else sep
        title = f"{sep}{padded}{second_sep}"
        return f"{title}\n\n{self.content}"

    def pretty_print(self) -> None:
        print(self.pretty_repr())  # noqa: T201


class Feedback(BaseModel):  # type: ignore[no-redef]
    """Feedback for a run, to record to LangSmith."""

    run_id: str = Field(
        description="Run ID to record feedback for.",
        examples=["847c6285-8fc9-4560-a83f-4e6285809254"],
    )
    key: str = Field(
        description="Feedback key.",
        examples=["human-feedback-stars"],
    )
    score: float = Field(
        description="Feedback score.",
        examples=[0.8],
    )
    kwargs: dict[str, Any] = Field(
        description="Additional feedback kwargs, passed to LangSmith.",
        default={},
        examples=[{"comment": "In-line human feedback"}],
    )


class FeedbackResponse(BaseModel):
    status: Literal["success"] = "success"


class ChatHistoryInput(BaseModel):
    """Input for retrieving chat history."""

    thread_id: str = Field(
        description="Thread ID to persist and continue a multi-turn conversation.",
        examples=["847c6285-8fc9-4560-a83f-4e6285809254"],
    )


class ChatHistory(BaseModel):
    messages: list[ChatMessage]
