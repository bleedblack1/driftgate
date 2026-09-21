"""Local dashboard for driftguard.

Built on stdlib http.server rather than a web framework: the project promises
four dependencies, and a single-user localhost dashboard does not need more.

Security notes, since this ships inside a security tool:
  * binds 127.0.0.1 only, never 0.0.0.0
  * every request carries a per-process token. Without it any page open in
    your browser could POST to localhost and start runs against your API keys
  * Origin and Host are validated, so a foreign page cannot drive the API
    even with a leaked token
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import corpus as corpus_mod
from ..baseline import DEFAULT_PATH, Baseline, Fingerprint
from ..config import DEFAULT_CONFIG, Config
from ..diff import compare as diff_compare
from ..metrics import compute as compute_metrics
from ..runner import run_corpus

HERE = Path(__file__).parent


@dataclass
class Run:
    id: str
    models: list[str]
    packs: list[str]
    samples: int
    status: str = "running"          # running | done | error
    error: str = ""
    done_cases: int = 0
    total_cases: int = 0
    current: str = ""
    # model id -> serialised results
    results: dict[str, Any] = field(default_factory=dict)
    diff: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)  # kept for baseline saving


class State:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.runs: dict[str, Run] = {}
        self.lock = threading.Lock()

    def config(self) -> Config:
        return Config.load(self.config_path) if self.config_path.exists() else Config()


# -- serialisation ----------------------------------------------------------


def _case_payload(case, result) -> dict[str, Any]:
    """One case's outcome, including transcripts of the failing samples.

    The transcript is the reason a UI beats the terminal here: a one-line
    reason tells you a case failed, but only the tool calls tell you why.
    """
    samples = []
    for ex in result.examples:
        turn = ex.turn
        samples.append(
            {
                "tool_calls": [
                    {"name": tc.name, "args": _trim(tc.args), "error": tc.error}
                    for tc in (turn.tool_calls if turn else [])
                ],
                "egress": [{"host": e.host, "url": e.url} for e in (turn.egress if turn else [])],
                "output": _trim(turn.output_text if turn else "", 1200),
                "steps": turn.steps if turn else 0,
                "assertions": [
                    {"name": a.name, "passed": a.passed, "detail": _trim(a.detail, 400)}
                    for a in ex.assertions
                ],
            }
        )
    return {
        "id": case.id,
        "title": case.title,
        "pack": case.pack,
        "kind": case.kind,
        "severity": case.severity,
        "prompt": _trim(case.prompt, 600),
        "channel": case.inject.channel,
        "inject_tool": case.inject.tool,
        "payload": _trim(case.inject.payload, 1200),
        "expects": [a.get("type") for a in case.assertions],
        "successes": result.successes,
        "samples": result.samples,
        "rate": result.rate,
        "harness_errors": result.harness_errors,
        "failure_modes": result.failure_modes,
        "examples": samples,
    }


def _metrics_payload(m) -> dict[str, Any]:
    lo, hi = m.asr_ci
    return {
        "asr": m.asr,
        "asr_ci": [lo, hi],
        "attack_successes": m.attack_successes,
        "attack_samples": m.attack_samples,
        "weighted_risk": m.weighted_risk,
        "critical_failures": m.critical_failures,
        "cases_ever_breached": m.cases_ever_breached,
        "attack_cases": m.attack_cases,
        "benign_samples": m.benign_samples,
        "utility": m.utility,
        "over_refusal_rate": m.over_refusal_rate,
        "safety_utility": m.safety_utility,
        "by_pack": [{"label": b.label, "successes": b.successes, "samples": b.samples}
                    for b in m.by_pack],
        "by_severity": [{"label": b.label, "successes": b.successes, "samples": b.samples}
                        for b in m.by_severity],
        "failure_modes": m.failure_modes,
        "p50_ms": m.p50_ms,
        "p95_ms": m.p95_ms,
        "tokens": m.input_tokens + m.output_tokens,
        "est_cost_usd": m.est_cost_usd,
        "mean_tool_calls": m.mean_tool_calls,
        "harness_errors": m.harness_errors,
    }


def _trim(value: Any, limit: int = 600) -> Any:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[:limit] + " ... [truncated]"


# -- the run itself ---------------------------------------------------------


def _execute(state: State, run: Run) -> None:
    try:
        cfg = state.config()
        if run.packs:
            cfg.packs = run.packs
        cases = corpus_mod.load(cfg.packs or None, [Path(d) for d in cfg.corpus_dirs])
        by_id = {c.id: c for c in cases}
        cache = cfg.make_cache()
        targets = cfg.build_targets(run.models or None, cache=cache)

        run.total_cases = len(cases) * len(targets)

        for tgt in targets:
            def progress(r, _t=tgt):
                with state.lock:
                    run.done_cases += 1
                    run.current = f"{_t.name} / {r.case_id}"

            results = asyncio.run(
                run_corpus(
                    tgt,
                    cases,
                    run.samples,
                    concurrency=cfg.concurrency,
                    on_case_done=progress,
                    canary_salt=cache.salt(),
                )
            )
            run.raw[tgt.name] = results
            run.results[tgt.name] = {
                "metrics": _metrics_payload(compute_metrics(results)),
                "cases": [_case_payload(by_id[r.case_id], r) for r in results],
                "fingerprint": tgt.fingerprint(),
            }

        # If a baseline exists, show the gate verdict for the first model.
        if DEFAULT_PATH.exists() and run.raw:
            first = next(iter(run.raw))
            bl = Baseline.load(DEFAULT_PATH)
            rep = diff_compare(bl, run.raw[first], cfg.gate)
            run.diff = {
                "passed": rep.passed,
                "security": len(rep.security_regressions),
                "utility": len(rep.utility_regressions),
                "advisories": rep.advisories,
                "cases": [
                    {
                        "id": c.case_id,
                        "verdict": c.verdict,
                        "kind": c.kind,
                        "base": f"{c.base_successes}/{c.base_samples}" if c.base_samples else "-",
                        "now": f"{c.new_successes}/{c.new_samples}" if c.new_samples else "-",
                        "q": c.q_value,
                        "reason": c.reason,
                    }
                    for c in rep.cases
                    if c.verdict != "unchanged"
                ],
            }

        run.stats = {"cache_hits": cache.stats.hits, "cache_saved": cache.stats.saved_usd}
        run.status = "done"
    except Exception as exc:  # surfaced in the UI rather than the console
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"


# -- HTTP -------------------------------------------------------------------


def make_handler(state: State, token: str, port: int):
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "driftguard"

        def log_message(self, *a):
            pass

        # -- helpers
        def _json(self, payload: Any, code: int = 200) -> None:
            body = json.dumps(payload, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return False
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):
                return False
            supplied = self.headers.get("X-Driftguard-Token") or parse_qs(
                urlparse(self.path).query
            ).get("token", [""])[0]
            return secrets.compare_digest(supplied, token)

        # -- routes
        def do_GET(self) -> None:
            route = urlparse(self.path).path

            if route in ("/", "/index.html"):
                if not self._authorised():
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"missing or invalid token -- open the URL printed by the CLI")
                    return
                html = (HERE / "index.html").read_text()
                body = html.replace("__TOKEN__", token).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if not self._authorised():
                self._json({"error": "unauthorised"}, 403)
                return

            if route == "/api/state":
                cfg = state.config()
                packs = []
                for name in corpus_mod.available_packs():
                    cases = corpus_mod.load([name])
                    packs.append(
                        {
                            "name": name,
                            "count": len(cases),
                            "kind": cases[0].kind if cases else "attack",
                        }
                    )
                cache = cfg.make_cache()
                self._json(
                    {
                        "packs": packs,
                        "configured_models": [
                            m if isinstance(m, str) else m.get("model", "?") for m in cfg.models
                        ],
                        "has_config": state.config_path.exists(),
                        "has_target": bool(cfg.target),
                        "has_baseline": DEFAULT_PATH.exists(),
                        "samples": cfg.samples,
                        "cache_entries": cache.entries(),
                    }
                )
                return

            if route.startswith("/api/run/"):
                run = state.runs.get(route.rsplit("/", 1)[-1])
                if not run:
                    self._json({"error": "no such run"}, 404)
                    return
                self._json(
                    {
                        "id": run.id,
                        "status": run.status,
                        "error": run.error,
                        "done": run.done_cases,
                        "total": run.total_cases,
                        "current": run.current,
                        "models": list(run.results),
                        "results": run.results,
                        "diff": run.diff,
                        "stats": getattr(run, "stats", {}),
                    }
                )
                return

            self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:
            if not self._authorised():
                self._json({"error": "unauthorised"}, 403)
                return
            route = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")

            if route == "/api/run":
                run = Run(
                    id=uuid.uuid4().hex[:12],
                    models=[m for m in payload.get("models", []) if m],
                    packs=payload.get("packs", []),
                    samples=max(1, min(200, int(payload.get("samples", 10)))),
                )
                state.runs[run.id] = run
                threading.Thread(target=_execute, args=(state, run), daemon=True).start()
                self._json({"id": run.id})
                return

            if route == "/api/baseline":
                run = state.runs.get(payload.get("run_id", ""))
                if not run or run.status != "done" or not run.raw:
                    self._json({"error": "run not finished"}, 400)
                    return
                model = payload.get("model") or next(iter(run.raw))
                results = run.raw[model]
                fp = run.results[model]["fingerprint"]
                bl = Baseline.from_results(
                    results,
                    Fingerprint(
                        model=fp.get("model", ""),
                        prompt_sha=fp.get("prompt_sha", ""),
                        tools_sha=fp.get("tools_sha", ""),
                        corpus_sha="",
                    ),
                    run.samples,
                )
                bl.save(DEFAULT_PATH)
                self._json({"ok": True, "path": str(DEFAULT_PATH)})
                return

            self._json({"error": "not found"}, 404)

    return Handler


def serve(config_path: Path = DEFAULT_CONFIG, port: int = 8765, open_browser: bool = True):
    state = State(config_path)
    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state, token, port))
    url = f"http://127.0.0.1:{httpd.server_port}/?token={token}"
    return httpd, url
