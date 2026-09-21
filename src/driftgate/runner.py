"""Execute the corpus against a target, N samples per case."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from typing import Any

from .adapters.base import Target
from .assertions import run_assertions
from .types import AssertionResult, AttackCase, CaseResult, SampleResult


def make_canary() -> str:
    """A random sentinel, for callers with no cache and no need to replay."""
    return f"dgt-{secrets.token_hex(12)}"


def derive_canary(salt: str, case_id: str, sample_index: int) -> str:
    """A sentinel that is unique per sample but identical across runs.

    Both properties are required. Unique per sample, or the N samples of a
    case would send byte-identical requests, collapse onto one cache entry
    and destroy the rate this tool measures. Identical across runs, or the
    cache could never hit and would be pointless.

    Derived from a per-project salt rather than a fixed pattern: a predictable
    sentinel could be learned and specifically avoided, which would quietly
    defeat every exfiltration check.
    """
    digest = hmac.new(salt.encode(), f"{case_id}:{sample_index}".encode(), hashlib.sha256)
    return f"dgt-{digest.hexdigest()[:24]}"


async def run_case(
    target: Target,
    case: AttackCase,
    samples: int,
    *,
    judge: Callable | None = None,
    keep_examples: int = 2,
    canary_salt: str | None = None,
) -> CaseResult:
    """Run one case N times and aggregate.

    "Success" is expectation-relative: for an attack case it means the attack
    got through; for a benign case it means the agent failed to do the job.
    Both are counted the same way so the gate can fail on either -- an agent
    that got "safer" by refusing legitimate work has regressed too.
    """
    reason = getattr(target, "skip_reason", lambda _c: "")(case)
    if reason:
        # Zero samples, so it contributes to no rate. Reported loudly instead.
        return CaseResult(
            case_id=case.id,
            severity=case.severity,
            title=case.title,
            samples=0,
            successes=0,
            kind=case.kind,
            pack=case.pack,
            skipped=True,
            skip_reason=reason,
        )

    successes = 0
    examples: list[SampleResult] = []
    durations: list[float] = []
    tok_in = tok_out = tool_calls = harness_errors = 0
    failure_modes: dict[str, int] = {}

    for i in range(samples):
        canary = (
            derive_canary(canary_salt, case.id, i) if canary_salt else make_canary()
        )
        ctx: dict[str, Any] = {"canary": canary, "kind": case.kind, "sample_index": i}
        if judge is not None:
            ctx["judge"] = judge

        t0 = time.perf_counter()
        turn = await target.run(case, ctx)
        elapsed = (time.perf_counter() - t0) * 1000
        durations.append(turn.duration_ms or elapsed)
        tok_in += turn.input_tokens
        tok_out += turn.output_tokens
        tool_calls += len(turn.tool_calls)

        if turn.error:
            # A harness error is not a result. Scoring it as a pass would let a
            # broken adapter or a dead endpoint turn the whole gate green.
            harness_errors += 1
            examples.append(
                SampleResult(
                    case.id, False, [AssertionResult("harness_error", True, turn.error)], turn
                )
            )
            continue

        results = run_assertions(case.assertions, turn, ctx)
        violated = any(not r.passed for r in results)
        successes += int(violated)
        if violated:
            for r in results:
                if not r.passed:
                    failure_modes[r.name] = failure_modes.get(r.name, 0) + 1
            if len(examples) < keep_examples:
                examples.append(SampleResult(case.id, True, results, turn))

    return CaseResult(
        case_id=case.id,
        severity=case.severity,
        title=case.title,
        samples=samples,
        successes=successes,
        examples=examples,
        kind=case.kind,
        pack=case.pack,
        durations_ms=durations,
        input_tokens=tok_in,
        output_tokens=tok_out,
        tool_call_count=tool_calls,
        harness_errors=harness_errors,
        failure_modes=failure_modes,
    )


async def run_corpus(
    target: Target,
    cases: list[AttackCase],
    samples: int = 20,
    *,
    concurrency: int = 4,
    judge: Callable | None = None,
    on_case_done: Callable[[CaseResult], None] | None = None,
    canary_salt: str | None = None,
) -> list[CaseResult]:
    sem = asyncio.Semaphore(concurrency)

    async def one(case: AttackCase) -> CaseResult:
        async with sem:
            r = await run_case(target, case, samples, judge=judge, canary_salt=canary_salt)
            if on_case_done:
                on_case_done(r)
            return r

    return list(await asyncio.gather(*(one(c) for c in cases)))
