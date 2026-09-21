import asyncio

from driftguard.recorder import Recorder


def test_records_sync_tool_with_named_args():
    rec = Recorder()

    def send_email(to: str, body: str) -> str:
        return "sent"

    wrapped = rec.wrap(send_email)
    wrapped("a@b.c", body="hi")
    assert rec.tool_calls[0].name == "send_email"
    assert rec.tool_calls[0].args == {"to": "a@b.c", "body": "hi"}
    assert rec.tool_calls[0].result == "sent"


def test_records_async_tool():
    rec = Recorder()

    async def fetch(url: str) -> str:
        return "body"

    asyncio.run(rec.wrap(fetch)("https://x.test"))
    assert rec.tool_calls[0].args == {"url": "https://x.test"}


def test_exception_is_recorded_and_reraised():
    rec = Recorder()

    def boom() -> None:
        raise ValueError("nope")

    try:
        rec.wrap(boom)()
    except ValueError:
        pass
    else:
        raise AssertionError("should have re-raised")
    assert "ValueError" in rec.tool_calls[0].error
