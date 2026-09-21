"""driftgate -- security regression gate for LLM agents. Any model, any provider."""

from .adapters import AgentTarget, InProcessTarget, MockTarget, Target
from .providers import ChatModel, ChatResponse, OpenAICompatModel, from_config
from .types import AttackCase, ToolCall, TurnResult

__version__ = "0.1.0"
__all__ = [
    "Target",
    "AgentTarget",
    "InProcessTarget",
    "MockTarget",
    "ChatModel",
    "ChatResponse",
    "OpenAICompatModel",
    "from_config",
    "AttackCase",
    "TurnResult",
    "ToolCall",
]
