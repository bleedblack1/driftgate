"""Small, dependency-free statistics for comparing two attack-success rates.

Why this exists: LLMs are non-deterministic, so a single-shot pass/fail gate is
flaky, and a flaky gate gets disabled within a week. We compare *rates* over N
samples and only fail the build when the change is unlikely to be sampling noise.

Implemented by hand (math.comb only) rather than pulling in scipy -- a security
tool should be cheap to install and small to audit.
"""

from __future__ import annotations

from math import comb, sqrt


def fisher_exact_greater(a: int, n1: int, c: int, n2: int) -> float:
    """One-sided Fisher exact p-value for "the new run has a higher rate".

    a/n1 = baseline successes/samples, c/n2 = new successes/samples.
    Returns P(observing >= c successes in the new row | fixed margins, H0: equal rates).
    """
    if n1 <= 0 or n2 <= 0:
        return 1.0
    b, d = n1 - a, n2 - c
    if min(a, b, c, d) < 0:
        raise ValueError("successes cannot exceed samples")

    total = n1 + n2
    successes = a + c  # K
    failures = b + d  # N - K

    denom = comb(total, n2)
    if denom == 0:
        return 1.0

    hi = min(successes, n2)
    p = 0.0
    for x in range(c, hi + 1):
        # need n2 - x failures available
        if n2 - x > failures:
            continue
        p += comb(successes, x) * comb(failures, n2 - x) / denom
    return min(1.0, max(0.0, p))


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval -- behaves sanely at k=0 and k=n, unlike normal approx."""
    if n == 0:
        return (0.0, 1.0)
    phat = k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def required_samples(baseline_rate: float, detectable_delta: float, z: float = 1.96) -> int:
    """Rough sample size to detect `detectable_delta` at ~80% power.

    Used by `driftgate baseline --advise` to stop people from baselining at
    n=3 and then wondering why the gate is noisy.
    """
    p1 = min(max(baseline_rate, 0.0), 1.0)
    p2 = min(max(p1 + detectable_delta, 0.0), 1.0)
    pbar = (p1 + p2) / 2
    if p2 == p1:
        return 0
    z_power = 0.84  # ~80% power
    num = (z * sqrt(2 * pbar * (1 - pbar)) + z_power * sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2
    return max(1, int(num / ((p2 - p1) ** 2) + 0.5))


def benjamini_hochberg(pvalues: list[float]) -> list[float]:
    """Benjamini-Hochberg adjusted p-values (q-values), returned in input order.

    Why this is not optional: a suite of M cases each tested at alpha=0.05
    produces ~0.05*M false alarms per run by construction. Measured on a
    12-case suite with an unchanged target, 25% of runs reported a spurious
    regression; at 100 cases essentially every run would. A gate that cries
    wolf gets switched off, so it must control the error rate across the whole
    suite, not per case.

    BH controls the false discovery rate -- the expected share of reported
    regressions that are spurious -- rather than the family-wise error rate.
    That is the right trade here: missing a real regression is worse than
    occasionally over-reporting one, so we prefer BH to the harsher Bonferroni.
    """
    m = len(pvalues)
    if m == 0:
        return []

    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [1.0] * m
    prev = 1.0
    # Walk from the largest p down, enforcing monotonicity.
    for rank in range(m, 0, -1):
        i = order[rank - 1]
        q = min(prev, pvalues[i] * m / rank)
        adjusted[i] = min(1.0, q)
        prev = adjusted[i]
    return adjusted
