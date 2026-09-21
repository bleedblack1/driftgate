"""Tool roles and coverage accounting.

The bug these fix: the corpus used to name driftguard's own tools, so the
moment anyone supplied their own toolkit, cases errored out, benign cases
demanded tools that did not exist, and the run still reported a confident
0% attack rate. A wrong number that looks right is worse than an error.
"""

import asyncio

import pytest

from driftguard import corpus
from driftguard.adapters.agent import AgentTarget
from driftguard.baseline import Baseline, Fingerprint
from driftguard.diff import GatePolicy, compare
from driftguard.metrics import compute
from driftguard.providers import EchoModel
from driftguard.roles import build, infer_role
from driftguard.runner import run_corpus


# A toolkit sharing no names with driftguard's built-in one.
def search_flights(origin: str, destination: str) -> str:
    "Search for available flights."
    return "3 results"


def book_flight(flight_id: str) -> str:
    "Book a flight for the user."
    return "booked"


def cancel_booking(ref: str) -> str:
    "Permanently cancel a booking and refund it."
    return "cancelled"


def get_passenger(pid: str) -> str:
    "Look up a passenger record."
    return "{}"


def email_itinerary(to: str, body: str) -> str:
    "Send the itinerary by email."
    return "sent"


FLIGHTS = {
    "search_flights": search_flights,
    "book_flight": book_flight,
    "cancel_booking": cancel_booking,
    "get_passenger": get_passenger,
    "email_itinerary": email_itinerary,
}


def _run(tools, roles=None, samples=2):
    t = AgentTarget(EchoModel(), tools=tools, system_prompt="sys", tool_roles=roles)
    return t, asyncio.run(run_corpus(t, corpus.load(), samples, concurrency=8))


# -- inference ---------------------------------------------------------------


def test_infers_roles_on_a_foreign_toolkit():
    rm = build(FLIGHTS)
    assert rm.tools("destructive") == ["cancel_booking"]
    assert rm.tools("external_send") == ["email_itinerary"]
    assert rm.tools("untrusted_source") == ["search_flights"]
    assert rm.tools("sensitive_read") == ["get_passenger"]


def test_destructive_beats_benign_write():
    """`cancel_booking` contains 'book'. It must not be classed as harmless."""
    assert "destructive" in infer_role("cancel_booking", cancel_booking)
    assert "benign_write" not in infer_role("cancel_booking", cancel_booking)


def test_declared_roles_override_inference():
    rm = build(FLIGHTS, {"destructive": ["book_flight"]})
    assert rm.tools("destructive") == ["book_flight"]
    assert "destructive" not in rm.inferred


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError, match="unknown tool role"):
        build(FLIGHTS, {"not_a_role": ["book_flight"]})


def test_unmapped_tools_are_reported():
    rm = build({"frobnicate": lambda x: x})
    assert rm.unmapped_tools == ["frobnicate"]


# -- the original bug --------------------------------------------------------


def test_custom_toolkit_no_longer_errors_out():
    """Before roles: 4 cases errored and utility read 17% off broken cases."""
    _, results = _run(FLIGHTS)
    assert not [r for r in results if r.harness_errors], "cases still erroring"
    m = compute(results)
    assert m.coverage >= 0.9, f"coverage only {m.coverage:.0%}: {m.skipped}"


def test_skipped_case_is_not_a_pass():
    """A missing role must produce zero samples, never a silent success."""
    # A toolkit with nothing destructive and nothing that fetches.
    _, results = _run({"book_flight": book_flight})
    skipped = [r for r in results if r.skipped]
    assert skipped, "nothing skipped despite a near-empty toolkit"
    for r in skipped:
        assert r.samples == 0 and r.successes == 0
        assert r.skip_reason


def test_skipped_cases_excluded_from_rates():
    _, results = _run({"book_flight": book_flight})
    m = compute(results)
    ran = [r for r in results if not r.skipped]
    assert m.attack_samples == sum(r.samples for r in ran if r.kind == "attack")
    assert m.total_cases == len(results)
    assert len(m.skipped) == len(results) - len(ran)


def test_coverage_is_surfaced_in_markdown():
    from driftguard.report import metrics_markdown

    _, results = _run({"book_flight": book_flight})
    md = metrics_markdown(compute(results))
    assert "could not run" in md
    assert "coverage" in md


# -- losing coverage is a regression ----------------------------------------


def test_baselined_case_that_stops_running_is_a_regression():
    """Drop a tool and the check that used to guard it silently vanishes.

    Nothing else in the system would report that, so the gate must.
    """
    _, full = _run(FLIGHTS)
    bl = Baseline.from_results(full, Fingerprint(model="m"), 2)

    # The destructive tool is removed, so every case guarding it stops running.
    reduced = {k: v for k, v in FLIGHTS.items() if k != "cancel_booking"}
    _, after = _run(reduced)

    report = compare(bl, after, GatePolicy())
    lost = [c for c in report.regressions if "coverage lost" in c.reason]
    assert lost, "losing a check was not reported as a regression"
    assert not report.passed


def test_never_baselined_skip_is_reported_but_not_a_failure():
    """A case that never ran is a gap to fix, not a regression to block on."""
    _, after = _run({"book_flight": book_flight})
    report = compare(Baseline(cases={}), after, GatePolicy())
    assert report.skipped
    assert not report.regressions
