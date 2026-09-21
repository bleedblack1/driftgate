"""Cache tests.

The headline property is that caching must not change any measured number.
A cache that quietly alters rates would be worse than no cache at all: the
whole tool is a rate comparison.
"""

import asyncio

import pytest

from driftgate import corpus
from driftgate.adapters.agent import AgentTarget
from driftgate.cache import CachedModel, ResponseCache
from driftgate.defaults import SYSTEM_PROMPT, TOOLKIT
from driftgate.providers import ChatResponse, OpenAICompatModel
from driftgate.runner import derive_canary, run_corpus
from tests.fake_server import make_server

CASES = [c for c in corpus.load() if c.id in ("pi-001", "bn-001", "ta-001")]


def _target(url, cache):
    model = OpenAICompatModel("fake-1", base_url=url, api_key="none")
    return AgentTarget(
        CachedModel(model, cache) if cache else model,
        tools=TOOLKIT,
        system_prompt=SYSTEM_PROMPT,
    )


def _run(url, cache, samples=10):
    return asyncio.run(
        run_corpus(
            _target(url, cache), CASES, samples, concurrency=4, canary_salt=cache.salt()
        )
    )


def _rates(results):
    return {r.case_id: (r.successes, r.samples) for r in results}


# -- the property that matters ----------------------------------------------


def test_cached_run_reproduces_rates_exactly(tmp_path):
    """Second run is served entirely from disk and must match the first."""
    srv, url = make_server(vulnerability=0.5, seed=7)
    try:
        cache = ResponseCache(dir=tmp_path / "c")
        live = _run(url, cache)
        calls_after_live = srv.handler_cls.calls
        assert cache.stats.writes > 0

        cache2 = ResponseCache(dir=tmp_path / "c")
        replayed = _run(url, cache2)

        assert _rates(replayed) == _rates(live)
        assert cache2.stats.hits > 0
        assert cache2.stats.misses == 0, "a warm cache should not miss"
        # And it genuinely did not call the model again.
        assert srv.handler_cls.calls == calls_after_live
    finally:
        srv.shutdown()


def test_cache_does_not_collapse_samples(tmp_path):
    """The trap: one entry per case would turn every rate into 0/N or N/N.

    Per-sample canaries keep the N requests distinct, so a partially
    vulnerable model still produces an intermediate rate.
    """
    srv, url = make_server(vulnerability=0.5, seed=11)
    try:
        cache = ResponseCache(dir=tmp_path / "c")
        results = {r.case_id: r for r in _run(url, cache, samples=20)}
        pi = results["pi-001"]
        assert 0 < pi.successes < 20, f"rate collapsed to {pi.successes}/20"
    finally:
        srv.shutdown()


def test_cache_actually_reduces_calls(tmp_path):
    srv, url = make_server(vulnerability=0.3, seed=13)
    try:
        cache = ResponseCache(dir=tmp_path / "c")
        _run(url, cache)
        first = srv.handler_cls.calls
        assert first > 0

        _run(url, ResponseCache(dir=tmp_path / "c"))
        assert srv.handler_cls.calls == first, "warm cache still called the model"
    finally:
        srv.shutdown()


# -- invalidation ------------------------------------------------------------


def _key(model_id="m", system="sys", tools=None):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": "hi"}]
    return ResponseCache.key(model_id, msgs, tools or [{"function": {"name": "a"}}])


def test_model_change_invalidates():
    assert _key(model_id="gpt-4o") != _key(model_id="gpt-5")


def test_system_prompt_change_invalidates():
    assert _key(system="be careful") != _key(system="be very careful")


def test_tool_schema_change_invalidates():
    assert _key(tools=[{"function": {"name": "a"}}]) != _key(
        tools=[{"function": {"name": "a"}}, {"function": {"name": "b"}}]
    )


def test_key_is_order_stable():
    """Same content, different dict insertion order, same key."""
    a = ResponseCache.key("m", [{"role": "user", "content": "x"}], None)
    b = ResponseCache.key("m", [{"content": "x", "role": "user"}], None)
    assert a == b


# -- canary derivation -------------------------------------------------------


def test_canary_unique_per_sample_stable_across_runs():
    salt = "s3cr3t"
    a = [derive_canary(salt, "pi-001", i) for i in range(5)]
    assert len(set(a)) == 5, "samples must differ or they share a cache entry"
    assert a == [derive_canary(salt, "pi-001", i) for i in range(5)], "must be stable"
    assert derive_canary("other-salt", "pi-001", 0) != a[0], "salt must matter"
    assert derive_canary(salt, "ta-001", 0) != a[0], "case must matter"


def test_salt_is_persisted(tmp_path):
    c1 = ResponseCache(dir=tmp_path / "c")
    assert c1.salt() == ResponseCache(dir=tmp_path / "c").salt()
    assert len(c1.salt()) >= 16


# -- behaviour and safety ----------------------------------------------------


def test_read_disabled_still_writes(tmp_path):
    """`baseline` uses this: ground truth is measured live, then cached for
    the `check` runs that follow."""
    srv, url = make_server(vulnerability=0.4, seed=17)
    try:
        cache = ResponseCache(dir=tmp_path / "c", read=False, write=True)
        _run(url, cache)
        assert cache.stats.hits == 0
        assert cache.stats.writes > 0
        assert ResponseCache(dir=tmp_path / "c").entries() > 0
    finally:
        srv.shutdown()


def test_ttl_expires_entries(tmp_path):
    c = ResponseCache(dir=tmp_path / "c")
    k = "a" * 64
    c.put(k, ChatResponse(content="hello"))
    assert c.get(k) is not None

    expired = ResponseCache(dir=tmp_path / "c", ttl_seconds=-1)
    assert expired.get(k) is None, "TTL must be able to force a re-measure"


def test_unwritable_cache_never_fails_the_run(tmp_path):
    """A broken cache must degrade to no cache, never break the gate."""
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    c = ResponseCache(dir=blocker)
    c.put("b" * 64, ChatResponse(content="x"))  # must not raise
    assert c.get("b" * 64) is None


def test_corrupt_entry_is_a_miss_not_a_crash(tmp_path):
    c = ResponseCache(dir=tmp_path / "c")
    k = "c" * 64
    c.put(k, ChatResponse(content="ok"))
    (tmp_path / "c" / k[:2] / f"{k}.json").write_text("{ truncated")
    assert c.get(k) is None
    assert c.stats.misses == 1


def test_tool_calls_survive_the_round_trip(tmp_path):
    """A cached response must replay tool calls, or every assertion changes."""
    from driftgate.providers import ToolCallRequest

    c = ResponseCache(dir=tmp_path / "c")
    k = "d" * 64
    c.put(
        k,
        ChatResponse(
            content="",
            tool_calls=[ToolCallRequest(id="1", name="delete_user", arguments={"user_id": "all"})],
            input_tokens=10,
            output_tokens=4,
        ),
    )
    got = c.get(k)
    assert got.tool_calls[0].name == "delete_user"
    assert got.tool_calls[0].arguments == {"user_id": "all"}
    assert (got.input_tokens, got.output_tokens) == (10, 4)
    assert c.stats.saved_input_tokens == 10
