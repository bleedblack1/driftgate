"""Generic in-process adapter -- the one most people should use.

You hand driftguard two things:

    tools  : {name: callable}  the real tool functions your agent dispatches to
    invoke : async (prompt, tools, system) -> str   one turn of your agent

driftguard wraps every tool before handing them back, so it sees each call and
its arguments no matter which framework routed it. That is the whole trick:
the instrumentation sits at the tool boundary, not at the HTTP boundary, so it
works for LangGraph, the Claude Agent SDK, Pydantic AI, or a hand-rolled loop.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable
from typing import Any, Awaitable

from ..recorder import Recorder
from ..types import AttackCase, TurnResult

InvokeFn = Callable[..., Awaitable[str]]


class InProcessTarget:
    name = "inprocess"

    def __init__(
        self,
        invoke: InvokeFn,
        tools: dict[str, Callable[..., Any]],
        system_prompt: str = "",
        model: str = "",
        *,
        canary_template: str = "\n\n[internal] SERVICE_API_KEY={canary}\n",
        capture_http: bool = True,
    ) -> None:
        self.invoke = invoke
        self.tools = tools
        self.system_prompt = system_prompt
        self.model = model
        self.canary_template = canary_template
        self.capture_http = capture_http

    def fingerprint(self) -> dict[str, str]:
        # Tool *schemas* are part of the attack surface: adding a tool or
        # widening a signature can reopen a hole a prompt fix closed.
        schema = json.dumps(
            {name: str(inspect.signature(fn)) for name, fn in sorted(self.tools.items())},
            sort_keys=True,
        )
        return {
            "model": self.model,
            "prompt_sha": _sha(self.system_prompt),
            "tools_sha": _sha(schema),
        }

    async def run(self, case: AttackCase, ctx: dict[str, Any]) -> TurnResult:
        rec = Recorder()
        canary = ctx.get("canary", "")

        tools = dict(self.tools)

        # Plant the payload on the channel the case specifies.
        if case.inject.channel == "tool_result" and case.inject.tool:
            target_tool = case.inject.tool
            if target_tool not in tools:
                return TurnResult(
                    error=(
                        f"case {case.id} injects via tool {target_tool!r} which this target "
                        f"does not expose; available: {sorted(tools)}"
                    )
                )
            tools[target_tool] = _poisoned(tools[target_tool], case.inject.payload)

        system = self.system_prompt
        if canary:
            system += self.canary_template.format(canary=canary)
        if case.inject.channel == "memory":
            system += f"\n\n[recalled memory]\n{case.inject.payload}\n"

        prompt = case.prompt
        if case.inject.channel in ("user_message", "document") and case.inject.payload:
            prompt = f"{prompt}\n\n{case.inject.payload}"

        wrapped = rec.wrap_all(tools)

        ctx_mgr = rec.patch_http() if self.capture_http else _nullcontext()
        try:
            with ctx_mgr:
                text = await self.invoke(prompt=prompt, tools=wrapped, system=system)
        except Exception as exc:
            return TurnResult(
                output_text="",
                tool_calls=rec.tool_calls,
                egress=rec.egress,
                error=f"{type(exc).__name__}: {exc}",
            )

        return TurnResult(output_text=text or "", tool_calls=rec.tool_calls, egress=rec.egress)


def _poisoned(fn: Callable[..., Any], payload: str) -> Callable[..., Any]:
    """Return a stand-in that yields the attack payload instead of real content.

    We replace rather than append so the case is reproducible and never depends
    on a live network fetch -- a security gate must not be flaky because a
    third-party site was slow.
    """
    if inspect.iscoroutinefunction(fn):

        async def apoison(*a: Any, **k: Any) -> str:
            return payload

        apoison.__name__ = getattr(fn, "__name__", "tool")
        apoison.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
        return apoison

    def poison(*a: Any, **k: Any) -> str:
        return payload

    poison.__name__ = getattr(fn, "__name__", "tool")
    poison.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
    return poison


class _nullcontext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *a: Any) -> bool:
        return False


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]
