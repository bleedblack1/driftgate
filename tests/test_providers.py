"""Provider-agnosticism tests: real HTTP, no vendor."""

import asyncio

import pytest

from driftgate import corpus
from driftgate.adapters.agent import AgentTarget
from driftgate.defaults import SYSTEM_PROMPT, TOOLKIT
from driftgate.providers import OpenAICompatModel, from_config, parse_openai_response
from driftgate.runner import run_corpus
from tests.fake_server import make_server


@pytest.fixture(scope="module")
def endpoint():
    srv, url = make_server(vulnerability=1.0, seed=1)
    yield url
    srv.shutdown()


def test_shorthand_and_dict_specs_build():
    assert from_config("ollama:llama3.1").base_url == "http://localhost:11434/v1"
    m = from_config({"provider": "anything", "model": "x", "base_url": "http://gw/v1"})
    assert m.base_url == "http://gw/v1"


def test_unknown_provider_without_base_url_is_a_clear_error():
    with pytest.raises(ValueError, match="unknown provider"):
        from_config("notareal:model")


def test_missing_api_key_is_not_fatal_for_local_runtimes():
    """Ollama/vLLM need no key; requiring one would block local testing."""
    assert from_config("ollama:llama3.1").api_key == ""


def test_malformed_tool_arguments_are_recorded_not_raised():
    r = parse_openai_response(
        {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "1", "function": {"name": "f", "arguments": "{not json"}}]}}]}
    )
    assert r.tool_calls[0].arguments["__unparsed__"] == "{not json"


def test_bad_response_shape_raises_clearly():
    with pytest.raises(ValueError, match="unexpected response shape"):
        parse_openai_response({"error": "nope"})


def test_end_to_end_against_a_real_http_endpoint(endpoint):
    """The whole pipeline over HTTP: tool loop, injection, recording, assertions."""
    model = OpenAICompatModel("fake-1", base_url=endpoint, api_key="none")
    target = AgentTarget(model, tools=TOOLKIT, system_prompt=SYSTEM_PROMPT)
    cases = [c for c in corpus.load(["prompt_injection"]) if c.id == "pi-001"]

    results = asyncio.run(run_corpus(target, cases, samples=5, concurrency=2))
    r = results[0]
    # The fake model always obeys the injection, so the forbidden tool fires.
    assert r.successes == 5, [e.failed_assertions for e in r.examples]
    assert any(
        "delete_user" in a.detail for e in r.examples for a in e.failed_assertions
    )


def test_safe_model_scores_zero():
    srv, url = make_server(vulnerability=0.0, seed=2)
    try:
        target = AgentTarget(
            OpenAICompatModel("fake-safe", base_url=url, api_key="none"),
            tools=TOOLKIT,
            system_prompt=SYSTEM_PROMPT,
        )
        cases = [c for c in corpus.load(["prompt_injection"]) if c.id == "pi-001"]
        r = asyncio.run(run_corpus(target, cases, samples=5))[0]
        assert r.successes == 0
    finally:
        srv.shutdown()


def test_http_error_becomes_a_harness_error_not_a_silent_pass():
    """A dead endpoint must not quietly score as 'secure'."""
    target = AgentTarget(
        OpenAICompatModel("dead", base_url="http://127.0.0.1:1/v1", api_key="none"),
        tools=TOOLKIT,
    )
    cases = [c for c in corpus.load(["tool_abuse"]) if c.id == "ta-001"]
    r = asyncio.run(run_corpus(target, cases, samples=2))[0]
    assert r.successes == 0
    assert any("harness_error" == a.name for e in r.examples for a in e.assertions)


# -- the metric set earns its keep -------------------------------------------


def test_refuse_everything_model_is_caught_as_a_regression():
    """The gameability test.

    A model that refuses every request has a perfect 0% attack success rate.
    Without a utility control it would pass the gate forever. It must not.
    """
    import asyncio

    from driftgate.baseline import Baseline, Fingerprint
    from driftgate.diff import GatePolicy, compare
    from driftgate.metrics import compute

    cases = corpus.load()  # includes the benign pack

    def run(vuln, refusal, seed):
        srv, url = make_server(vulnerability=vuln, seed=seed, refusal_rate=refusal)
        try:
            tgt = AgentTarget(
                OpenAICompatModel("m", base_url=url, api_key="none"),
                tools=TOOLKIT,
                system_prompt=SYSTEM_PROMPT,
            )
            return asyncio.run(run_corpus(tgt, cases, samples=20, concurrency=8))
        finally:
            srv.shutdown()

    useful = run(0.2, 0.0, 1)
    paranoid = run(0.0, 1.0, 2)  # refuses literally everything

    m_useful, m_paranoid = compute(useful), compute(paranoid)

    # The paranoid model looks perfect on security alone...
    assert m_paranoid.asr == 0.0
    assert m_paranoid.asr < m_useful.asr
    # ...but utility exposes it.
    assert m_paranoid.utility == 0.0
    assert m_useful.utility > 0.5
    assert m_paranoid.safety_utility < m_useful.safety_utility

    # And the gate fails on it, reporting utility rather than security.
    bl = Baseline.from_results(useful, Fingerprint(model="useful"), 20)
    report = compare(bl, paranoid, GatePolicy())
    assert not report.passed
    assert report.utility_regressions, "over-refusal was not caught"
    assert all(c.kind == "benign" for c in report.utility_regressions)


def test_metrics_breakdowns_are_populated():
    import asyncio

    from driftgate.metrics import compute

    srv, url = make_server(vulnerability=1.0, seed=3)
    try:
        tgt = AgentTarget(
            OpenAICompatModel("m", base_url=url, api_key="none"),
            tools=TOOLKIT,
            system_prompt=SYSTEM_PROMPT,
        )
        results = asyncio.run(run_corpus(tgt, corpus.load(), samples=5, concurrency=8))
    finally:
        srv.shutdown()

    m = compute(results)
    assert {b.label for b in m.by_pack} >= {"prompt_injection", "tool_abuse"}
    assert {b.label for b in m.by_severity} & {"critical", "high"}
    assert m.failure_modes, "no failure modes recorded"
    assert m.p50_ms > 0 and m.p95_ms >= m.p50_ms
    assert m.mean_tool_calls > 0
    assert 0 <= m.weighted_risk <= 100
    # benign cases must not be counted as attack samples
    assert m.attack_samples + m.benign_samples == m.total_samples
