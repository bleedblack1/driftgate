"""Core data types shared by targets, assertions, and the runner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]

# "attack" cases must be blocked; "benign" cases must be COMPLETED.
# Both are required: a security score without a utility score is gameable,
# because refusing everything scores a perfect 0% attack success rate.
CaseKind = Literal["attack", "benign"]

# Where an attack payload is planted. The channel matters: a payload the user
# typed is a different threat model from one that arrived inside a tool result.
InjectChannel = Literal["user_message", "tool_result", "document", "memory"]


@dataclass
class ToolCall:
    """A single tool invocation observed during a run."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None


@dataclass
class EgressEvent:
    """An outbound network request observed during a run."""

    host: str
    url: str
    body_preview: str = ""


@dataclass
class TurnResult:
    """Everything a target must report back about one attack attempt.

    `tool_calls` and `egress` are what separate this from a text-only harness:
    most real agent exploits are visible as a forbidden call or an unexpected
    host, never as a bad string in the final answer.
    """

    output_text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    egress: list[EgressEvent] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    steps: int = 0

    def called(self, name: str) -> bool:
        return any(tc.name == name for tc in self.tool_calls)


@dataclass
class Injection:
    """How the attack payload reaches the agent."""

    channel: InjectChannel = "user_message"
    payload: str = ""
    # For channel="tool_result": which tool's output carries the payload.
    tool: str | None = None


@dataclass
class AttackCase:
    id: str
    pack: str
    title: str
    prompt: str
    kind: CaseKind = "attack"
    severity: Severity = "medium"
    inject: Injection = field(default_factory=Injection)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class AssertionResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class SampleResult:
    """One execution of one case.

    `failed` means the case's expectation was violated: for an attack case the
    attack got through; for a benign case the agent failed to do its job.
    """

    case_id: str
    attack_succeeded: bool
    assertions: list[AssertionResult] = field(default_factory=list)
    turn: TurnResult | None = None

    @property
    def failed_assertions(self) -> list[AssertionResult]:
        return [a for a in self.assertions if not a.passed]


@dataclass
class CaseResult:
    """Aggregate of N samples of one case. `successes` = attack wins."""

    case_id: str
    severity: Severity
    title: str
    samples: int
    successes: int
    examples: list[SampleResult] = field(default_factory=list)
    kind: CaseKind = "attack"
    pack: str = ""
    # Operational characteristics, accumulated across samples.
    durations_ms: list[float] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    tool_call_count: int = 0
    harness_errors: int = 0
    # Which assertion types failed, and how often. Tells you WHICH defense
    # is missing, not just that something went wrong.
    failure_modes: dict[str, int] = field(default_factory=dict)

    @property
    def rate(self) -> float:
        return self.successes / self.samples if self.samples else 0.0
