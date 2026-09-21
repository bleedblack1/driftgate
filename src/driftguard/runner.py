"""Execute the corpus against a target, N samples per case."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from typing import Any

from .adapters.base import Target
from .assertions import run_assertions
from .types import AssertionResult, AttackCase, CaseResult, SampleResult


def make_canary() -> str:
    """A high-entropy sentinel. Distinctive enough that a substring match on it
    cannot plausibly be a coincidence, short enough not to blow the context."""
    return f"dgk-{secrets.token_hex(12)}"


async def run_case(
    target: Target,
    case: AttackCase,
    samples: int,
    *,
    judge: Callable | None = None,
    keep_examples: int = 2,
) -> CaseResult:
    successes = 0
    examples: list[SampleResult] = []

    for _ in range(samples):
        ctx: dict[str, Any] = {"canary": make_canary()}
        if judge is not None:
            ctx["judge"] = judge

        turn = await target.run(case, ctx)

        if turn.error:
            # A harness error is not an attack success -- silently scoring it as
            # a pass would let a broken adapter turn the whole gate green.
            examples.append(
                SampleResult(
                    case.id,
                    False,
                    [AssertionResult("harness_error", True, turn.error)],
                    turn,
                )
            )
            continue

        results = run_assertions(case.assertions, turn, ctx)
        attack_won = any(not r.passed for r in results)
        successes += int(attack_won)
        if attack_won and len(examples) < keep_examples:
            examples.append(SampleResult(case.id, True, results, turn))

    return CaseResult(
        case_id=case.id,
        severity=case.severity,
        title=case.title,
        samples=samples,
        successes=successes,
        examples=examples,
    )


async def run_corpus(
    target: Target,
    cases: list[AttackCase],
    samples: int = 20,
    *,
    concurrency: int = 4,
    judge: Callable | None = None,
    on_case_done: Callable[[CaseResult], None] | None = None,
) -> list[CaseResult]:
    sem = asyncio.Semaphore(concurrency)

    async def one(case: AttackCase) -> CaseResult:
        async with sem:
            r = await run_case(target, case, samples, judge=judge)
            if on_case_done:
                on_case_done(r)
            return r

    return list(await asyncio.gather(*(one(c) for c in cases)))
