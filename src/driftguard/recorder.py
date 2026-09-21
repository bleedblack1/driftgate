"""In-process instrumentation: capture tool calls and outbound HTTP.

This is the piece a text-only red-team harness does not have. Adapters wrap the
agent's real tool callables with `Recorder.wrap`, so every invocation is recorded
with its arguments regardless of which framework dispatched it.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlparse

from .types import EgressEvent, ToolCall


class Recorder:
    def __init__(self) -> None:
        self.tool_calls: list[ToolCall] = []
        self.egress: list[EgressEvent] = []

    # -- tools ---------------------------------------------------------------

    def wrap(self, fn: Callable[..., Any], name: str | None = None) -> Callable[..., Any]:
        """Wrap a tool callable so its invocations land in `tool_calls`.

        Handles both sync and async tools. The wrapper is transparent: the
        agent still gets the real return value or exception.
        """
        tool_name = name or getattr(fn, "__name__", repr(fn))

        def _record(args: tuple, kwargs: dict) -> ToolCall:
            call = ToolCall(name=tool_name, args=_describe_args(fn, args, kwargs))
            self.tool_calls.append(call)
            return call

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                call = _record(args, kwargs)
                try:
                    call.result = await fn(*args, **kwargs)
                except Exception as exc:
                    call.error = f"{type(exc).__name__}: {exc}"
                    raise
                return call.result

            return awrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call = _record(args, kwargs)
            try:
                call.result = fn(*args, **kwargs)
            except Exception as exc:
                call.error = f"{type(exc).__name__}: {exc}"
                raise
            return call.result

        return wrapper

    def wrap_all(self, tools: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        return {name: self.wrap(fn, name) for name, fn in tools.items()}

    # -- egress --------------------------------------------------------------

    def note_egress(self, url: str, body: str = "") -> None:
        self.egress.append(
            EgressEvent(host=urlparse(url).hostname or "", url=url, body_preview=body[:512])
        )

    @contextlib.contextmanager
    def patch_http(self) -> Iterator[None]:
        """Best-effort capture of outbound HTTP made by tools during a run.

        Opt-in and defensive: if httpx/requests are absent we simply record
        nothing rather than failing the run. Tools that shell out or use raw
        sockets are NOT covered -- for those, call `note_egress` explicitly.
        """
        undo: list[Callable[[], None]] = []

        try:
            import httpx

            orig = httpx.Client.send

            def patched(client: Any, request: Any, **kw: Any) -> Any:
                self.note_egress(str(request.url))
                return orig(client, request, **kw)

            httpx.Client.send = patched  # type: ignore[method-assign]
            undo.append(lambda: setattr(httpx.Client, "send", orig))
        except Exception:
            pass

        try:
            import requests

            orig_r = requests.Session.send

            def patched_r(session: Any, request: Any, **kw: Any) -> Any:
                self.note_egress(str(request.url))
                return orig_r(session, request, **kw)

            requests.Session.send = patched_r  # type: ignore[method-assign]
            undo.append(lambda: setattr(requests.Session, "send", orig_r))
        except Exception:
            pass

        try:
            yield
        finally:
            for fn in reversed(undo):
                with contextlib.suppress(Exception):
                    fn()


def _describe_args(fn: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    """Normalise positional+keyword args into a name->value dict for assertions."""
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {"args": list(args), "kwargs": kwargs}
