"""Response cache.

Running the corpus costs real money: cases x samples x models API calls per
invocation. A gate people cannot afford to run is a gate that gets switched
off, so `check`, `scan` and `compare` replay from disk by default.

Two things make caching here harder than it looks.

1. driftguard measures a RATE over N samples. A cache keyed only on
   (model, messages, tools) would collapse all N samples of a case onto one
   entry and return the same response every time, turning every measured rate
   into 0/N or N/N. The per-sample canary keeps the requests distinct, which
   is why `runner.derive_canary` is deterministic rather than random: distinct
   within a run, identical across runs, so the N samples stay N samples and
   still hit the cache on a re-run.

2. The key covers what you DECLARED, not what the provider actually served.
   If a vendor silently changes the model behind a stable alias -- exactly the
   drift this tool exists to catch -- a warm cache will hide it. Hence
   `baseline` writes the cache but never reads it, a TTL is supported, and
   `--no-cache` always forces a live run.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .providers import ChatModel, ChatResponse, ToolCallRequest

DEFAULT_DIR = Path(".driftguard-cache")
SCHEMA = 1


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    # Tokens we did not have to buy again, from the cached payloads.
    saved_input_tokens: int = 0
    saved_output_tokens: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.lookups if self.lookups else 0.0

    @property
    def saved_usd(self) -> float:
        """Same blended rate as metrics.est_cost_usd, for comparability."""
        return self.saved_input_tokens / 1e6 * 3.0 + self.saved_output_tokens / 1e6 * 15.0


@dataclass
class ResponseCache:
    """Content-addressed store of model responses on disk.

    Writes are atomic (temp file + rename), so the default concurrent runner
    is safe without a lock: two workers computing the same key simply write
    the same bytes.
    """

    dir: Path = DEFAULT_DIR
    ttl_seconds: float = 0.0  # 0 = never expire
    read: bool = True
    write: bool = True
    stats: CacheStats = field(default_factory=CacheStats)

    def __post_init__(self) -> None:
        self.dir = Path(self.dir)

    # -- salt ---------------------------------------------------------------

    def salt(self) -> str:
        """Per-project canary salt, generated once and kept beside the cache.

        Canaries are derived from it rather than being a fixed pattern: a
        predictable sentinel could be learned and specifically avoided, which
        would quietly defeat every exfiltration check.
        """
        env = os.environ.get("DRIFTGUARD_CANARY_SALT")
        if env:
            return env
        path = self.dir / "salt"
        try:
            return path.read_text().strip()
        except OSError:
            value = secrets.token_hex(16)
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                path.write_text(value + "\n")
            except OSError:
                pass  # read-only filesystem: a per-run salt still works
            return value

    # -- keys ---------------------------------------------------------------

    @staticmethod
    def key(model_id: str, messages: list[dict[str, Any]], tools: list[dict] | None) -> str:
        payload = json.dumps(
            {"v": SCHEMA, "model": model_id, "messages": messages, "tools": tools or []},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.dir / key[:2] / f"{key}.json"

    # -- access -------------------------------------------------------------

    def get(self, key: str) -> ChatResponse | None:
        if not self.read:
            self.stats.misses += 1
            return None
        path = self._path(key)
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            self.stats.misses += 1
            return None

        if self.ttl_seconds and (time.time() - raw.get("stored_at", 0)) > self.ttl_seconds:
            self.stats.misses += 1
            return None

        self.stats.hits += 1
        self.stats.saved_input_tokens += raw.get("input_tokens", 0)
        self.stats.saved_output_tokens += raw.get("output_tokens", 0)
        return ChatResponse(
            content=raw.get("content", ""),
            tool_calls=[ToolCallRequest(**tc) for tc in raw.get("tool_calls", [])],
            input_tokens=raw.get("input_tokens", 0),
            output_tokens=raw.get("output_tokens", 0),
        )

    def put(self, key: str, resp: ChatResponse) -> None:
        if not self.write:
            return
        path = self._path(key)
        record = {
            "v": SCHEMA,
            "stored_at": time.time(),
            "content": resp.content,
            "tool_calls": [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in resp.tool_calls
            ],
            "input_tokens": resp.input_tokens,
            "output_tokens": resp.output_tokens,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            with os.fdopen(fd, "w") as fh:
                json.dump(record, fh)
            os.replace(tmp, path)  # atomic; concurrent writers are harmless
            self.stats.writes += 1
        except OSError:
            pass  # a cache that cannot write must never fail the run

    # -- maintenance --------------------------------------------------------

    def entries(self) -> int:
        return sum(1 for _ in self.dir.glob("*/*.json"))

    def size_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.dir.glob("*/*.json"))

    def clear(self) -> int:
        n = 0
        for p in self.dir.glob("*/*.json"):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
        return n


class CachedModel:
    """Wraps any ChatModel. Knows nothing about providers, by design."""

    def __init__(self, inner: ChatModel, cache: ResponseCache) -> None:
        self.inner = inner
        self.cache = cache

    @property
    def id(self) -> str:
        return self.inner.id

    async def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        key = self.cache.key(self.inner.id, messages, tools)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        resp = await self.inner.chat(messages, tools)
        self.cache.put(key, resp)
        return resp
