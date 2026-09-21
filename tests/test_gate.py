"""The gate's own tests. A security gate you cannot test is decoration.

The false-positive tests matter more than the true-positive ones: a gate that
cries wolf gets disabled, and then it protects nothing.
"""

import asyncio

import pytest

from driftgate import corpus
from driftgate.adapters.mock import MockTarget
from driftgate.baseline import Baseline, Fingerprint
from driftgate.diff import GatePolicy, compare
from driftgate.runner import run_corpus
from driftgate.stats import fisher_exact_greater, required_samples, wilson_interval


def _run(target, cases, n):
    return asyncio.run(run_corpus(target, cases, n, concurrency=8))


@pytest.fixture(scope="module")
def cases():
    return corpus.load()


def _baseline(results, n, model="m"):
    return Baseline.from_results(results, Fingerprint(model=model), n)


# -- no false positives ------------------------------------------------------


def test_identical_target_rarely_regresses(cases):
    """Same model, same everything, different RNG draw -> should stay green.

    Asserted in aggregate, not per-seed: FDR control at alpha=0.05 permits a
    small rate of false discoveries by definition, so demanding zero from any
    single run would be asserting a stronger guarantee than the gate makes.
    """
    flagged = 0
    for seed in range(1, 11):
        a = MockTarget(vulnerability=0.15, seed=seed)
        b = MockTarget(vulnerability=0.15, seed=seed + 1000)
        bl = _baseline(_run(a, cases, 40), 40)
        flagged += len(compare(bl, _run(b, cases, 40), GatePolicy()).regressions)
    # 10 runs x 12 cases = 120 comparisons; at alpha=0.05 with FDR control we
    # expect ~0-2. Anything above 6 means the correction is not working.
    assert flagged <= 6, f"{flagged} spurious regressions across 120 comparisons"


def test_small_improvement_is_not_a_regression(cases):
    bl = _baseline(_run(MockTarget(vulnerability=0.30, seed=7), cases, 40), 40)
    report = compare(bl, _run(MockTarget(vulnerability=0.22, seed=8), cases, 40), GatePolicy())
    assert report.passed


# -- true positives ----------------------------------------------------------


def test_large_regression_is_caught(cases):
    bl = _baseline(_run(MockTarget(vulnerability=0.02, seed=1), cases, 40), 40)
    report = compare(bl, _run(MockTarget(vulnerability=0.60, seed=2), cases, 40), GatePolicy())
    assert not report.passed
    assert len(report.regressions) >= 5


def test_zero_tolerance_fires_on_critical_without_significance(cases):
    """A critical case going 0 -> 1 is a fail even though p is nowhere near 0.05."""
    bl = Baseline(
        cases={"pi-001": {"title": "t", "severity": "critical", "successes": 0, "samples": 30}}
    )
    results = _run(MockTarget(vulnerability=1.0, seed=3), [c for c in cases if c.id == "pi-001"], 1)
    report = compare(bl, results, GatePolicy())
    assert not report.passed
    assert "zero-tolerance" in report.regressions[0].reason


def test_improvement_is_reported_not_failed(cases):
    bl = _baseline(_run(MockTarget(vulnerability=0.70, seed=4), cases, 40), 40)
    report = compare(bl, _run(MockTarget(vulnerability=0.05, seed=5), cases, 40), GatePolicy())
    assert report.passed
    assert report.improvements


# -- under-powered detection -------------------------------------------------


def test_underpowered_case_advises_instead_of_failing():
    """0/10 -> 3/10 is a 30pp jump but p=0.105. Advise, do not fail."""
    bl = Baseline(
        cases={"x": {"title": "t", "severity": "high", "successes": 0, "samples": 10}}
    )
    from driftgate.types import CaseResult

    results = [CaseResult("x", "high", "t", samples=10, successes=3)]
    report = compare(bl, results, GatePolicy())
    assert report.passed
    assert report.advisories and "not significant" in report.advisories[0]


# -- statistics --------------------------------------------------------------


def test_fisher_symmetry_and_bounds():
    assert fisher_exact_greater(5, 20, 5, 20) > 0.5
    assert fisher_exact_greater(0, 20, 20, 20) < 1e-6
    assert fisher_exact_greater(20, 20, 0, 20) == pytest.approx(1.0)
    for a, n1, c, n2 in [(0, 5, 0, 5), (3, 10, 7, 10), (1, 1, 1, 1)]:
        assert 0.0 <= fisher_exact_greater(a, n1, c, n2) <= 1.0


def test_wilson_handles_extremes():
    assert wilson_interval(0, 30)[0] == 0.0
    assert wilson_interval(30, 30)[1] == 1.0
    lo, hi = wilson_interval(15, 30)
    assert lo < 0.5 < hi


def test_required_samples_grows_as_delta_shrinks():
    assert required_samples(0.0, 0.05) > required_samples(0.0, 0.20)


# -- fingerprint -------------------------------------------------------------


def test_fingerprint_detects_surface_change():
    a = Fingerprint(model="claude-sonnet-5", prompt_sha="aaa", tools_sha="bbb")
    b = Fingerprint(model="claude-sonnet-5", prompt_sha="aaa", tools_sha="ccc")
    assert a.diff(b) == ["tools_sha"]
    assert a.diff(a) == []


def test_baseline_roundtrip(tmp_path, cases):
    bl = _baseline(_run(MockTarget(vulnerability=0.1, seed=9), cases, 5), 5)
    p = tmp_path / "b.json"
    bl.save(p)
    assert Baseline.load(p).cases == bl.cases


# -- multiple comparisons ----------------------------------------------------


def test_false_positive_rate_across_clean_runs(cases):
    """The suite-level guarantee. Without BH correction this was 25%.

    An unchanged target must almost never report a regression, or the gate
    gets disabled and protects nothing.
    """
    fp = 0
    runs = 20
    for s in range(runs):
        a = _run(MockTarget(vulnerability=0.15, seed=s), cases, 40)
        b = _run(MockTarget(vulnerability=0.15, seed=s + 500), cases, 40)
        if compare(_baseline(a, 40), b, GatePolicy()).regressions:
            fp += 1
    assert fp <= 1, f"{fp}/{runs} clean runs reported a spurious regression"


def test_correction_does_not_mask_real_regressions(cases):
    """FDR control must not cost us the true positives it exists to protect."""
    bl = _baseline(_run(MockTarget(vulnerability=0.02, seed=11), cases, 40), 40)
    report = compare(bl, _run(MockTarget(vulnerability=0.55, seed=12), cases, 40), GatePolicy())
    caught = {c.case_id for c in report.regressions}
    assert len(caught) >= 6, f"correction swallowed real regressions: only {caught}"
