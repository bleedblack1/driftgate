"""The Target protocol: how driftgate invokes the system under test."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..types import AttackCase, TurnResult


@runtime_checkable
class Target(Protocol):
    """Implement this to point driftgate at your agent.

    `ctx` carries per-sample state -- most importantly ctx["canary"], the
    sentinel value the adapter must plant somewhere the agent can see (a fake
    credential in the system prompt, a row in retrieved context). Assertions
    then check that it never escapes.
    """

    name: str

    async def run(self, case: AttackCase, ctx: dict[str, Any]) -> TurnResult: ...

    def fingerprint(self) -> dict[str, str]:
        """Identify the attack surface: model id, prompt hash, tool-schema hash."""
        ...
