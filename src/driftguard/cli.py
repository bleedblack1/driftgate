"""driftguard CLI: init / baseline / check / packs / demo."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from . import corpus as corpus_mod
from .baseline import DEFAULT_PATH, Baseline, Fingerprint
from .config import DEFAULT_CONFIG, TEMPLATE, Config
from .diff import compare as diff_compare
from .metrics import compute as compute_metrics
from .report import metrics_markdown, metrics_panel, to_markdown, to_terminal
from .runner import run_corpus
from .stats import required_samples

app = typer.Typer(
    add_completion=False,
    help="Detect security regressions in LLM agents when the model, prompt, or tools change.",
)
console = Console()


def _load(
    config: Path,
    samples: int | None,
    packs: list[str] | None,
    models: list[str] | None = None,
    *,
    cache_read: bool = True,
    cache_write: bool = True,
    no_cache: bool = False,
):
    cfg = Config.load(config)
    if no_cache:
        cfg.cache_enabled = False
    if samples:
        cfg.samples = samples
    if packs:
        cfg.packs = packs
    cases = corpus_mod.load(cfg.packs, [Path(d) for d in cfg.corpus_dirs])
    cache = cfg.make_cache(read=cache_read, write=cache_write)
    target = cfg.build_target(models or None, cache=cache)
    return cfg, cases, target, cache


def _fingerprint(target, cases) -> Fingerprint:
    fp = target.fingerprint()
    return Fingerprint(
        model=fp.get("model", ""),
        prompt_sha=fp.get("prompt_sha", ""),
        tools_sha=fp.get("tools_sha", ""),
        corpus_sha=corpus_mod.corpus_sha(cases),
    )


@app.command()
def init() -> None:
    """Create driftguard.yaml in the current directory."""
    if DEFAULT_CONFIG.exists():
        console.print(f"[yellow]{DEFAULT_CONFIG} already exists[/]")
        raise typer.Exit(1)
    DEFAULT_CONFIG.write_text(TEMPLATE)
    console.print(f"[green]wrote {DEFAULT_CONFIG}[/]")
    console.print("Next: point `target:` at your agent, then run `driftguard baseline`.")


@app.command()
def packs() -> None:
    """List built-in attack packs and their cases."""
    for name in corpus_mod.available_packs():
        cases = corpus_mod.load([name])
        console.print(f"[bold]{name}[/] ({len(cases)} cases)")
        for c in cases:
            console.print(f"  [dim]{c.id}[/] [{c.severity}] {c.title}")


@app.command()
def baseline(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    out: Path = typer.Option(DEFAULT_PATH, "--out", "-o"),
    samples: int = typer.Option(None, "--samples", "-n"),
    pack: list[str] = typer.Option(None, "--pack", "-p"),
    model: list[str] = typer.Option(None, "--model", "-m", help="override configured model(s)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="do not write the response cache"),
    force: bool = typer.Option(False, "--force", help="overwrite an existing baseline"),
) -> None:
    """Record the current security posture. Commit the resulting file."""
    if out.exists() and not force:
        console.print(f"[yellow]{out} exists. Re-baselining hides prior regressions.[/]")
        console.print("Pass --force if that is what you intend.")
        raise typer.Exit(1)

    # A baseline is ground truth: never replayed, always measured live.
    cfg, cases, target, cache = _load(
        config, samples, pack, model, cache_read=False, no_cache=no_cache
    )
    console.print(f"Running {len(cases)} cases x {cfg.samples} samples against [bold]{target.name}[/]")

    results = asyncio.run(
        run_corpus(
            target,
            cases,
            cfg.samples,
            concurrency=cfg.concurrency,
            canary_salt=cache.salt(),
        )
    )
    bl = Baseline.from_results(results, _fingerprint(target, cases), cfg.samples)
    bl.save(out)

    vulnerable = [r for r in results if r.successes]
    console.print(f"[green]wrote {out}[/]  ({len(vulnerable)}/{len(results)} cases with >0 successes)")
    for r in sorted(vulnerable, key=lambda r: -r.rate):
        console.print(f"  [red]{r.case_id}[/] {r.successes}/{r.samples}  {r.title}")

    worst = max((r.rate for r in results), default=0.0)
    need = required_samples(worst, cfg.gate.min_delta)
    if need > cfg.samples:
        console.print(
            f"\n[yellow]note:[/] at n={cfg.samples} you cannot reliably detect a "
            f"{cfg.gate.min_delta:.0%} regression. Consider --samples {need}."
        )
    console.print("\n[bold]Commit this file.[/] It is the record `driftguard check` compares against.")


@app.command()
def check(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    baseline_path: Path = typer.Option(DEFAULT_PATH, "--baseline", "-b"),
    samples: int = typer.Option(None, "--samples", "-n"),
    pack: list[str] = typer.Option(None, "--pack", "-p"),
    model: list[str] = typer.Option(None, "--model", "-m", help="override configured model(s)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="force live calls, ignore the cache"),
    refresh_cache: bool = typer.Option(False, "--refresh-cache", help="re-call and overwrite cached entries"),
    allow_skipped: bool = typer.Option(False, "--allow-skipped", help="pass even if some cases cannot run"),
    markdown: Path = typer.Option(None, "--markdown", help="also write a PR-comment file"),
) -> None:
    """Re-run the corpus and fail (exit 1) if security got worse."""
    if not baseline_path.exists():
        console.print(f"[red]no baseline at {baseline_path}[/] -- run `driftguard baseline` first")
        raise typer.Exit(2)

    bl = Baseline.load(baseline_path)
    cfg, cases, target, cache = _load(
        config, samples, pack, model, cache_read=not refresh_cache, no_cache=no_cache
    )
    n = samples or bl.samples or cfg.samples

    console.print(f"Running {len(cases)} cases x {n} samples against [bold]{target.name}[/]")
    results = asyncio.run(
        run_corpus(target, cases, n, concurrency=cfg.concurrency, canary_salt=cache.salt())
    )

    report = diff_compare(bl, results, cfg.gate)
    report.fingerprint_changed = bl.fingerprint.diff(_fingerprint(target, cases))
    to_terminal(report, console)
    m = compute_metrics(results)
    metrics_panel(m, console, title="current metrics")
    _cache_line(cache, console)

    if markdown:
        markdown.write_text(to_markdown(report) + metrics_markdown(m))
        console.print(f"[dim]wrote {markdown}[/]")

    # A gate that could not run part of itself is not a green gate.
    blocked = report.skipped
    if blocked and not allow_skipped:
        console.print(
            f"\n[bold red]FAIL[/] {len(blocked)} case(s) could not run, so this gate "
            f"did not check what it claims to."
        )
        console.print(
            "[yellow]Fix the tool-role mapping (`driftguard roles`), or pass "
            "--allow-skipped to accept the gap.[/]"
        )
        raise typer.Exit(1)

    raise typer.Exit(0 if report.passed else 1)


@app.command()
def demo(
    vulnerability: float = typer.Option(0.5, "--vulnerability", "-v"),
    samples: int = typer.Option(30, "--samples", "-n"),
) -> None:
    """Run the whole flow against a built-in fake agent. No API keys needed.

    Shows what a real regression looks like: baseline a 'safe' model, then
    check against a 'worse' one and watch the gate fail.
    """
    from .adapters.mock import MockTarget
    from .diff import GatePolicy

    cases = corpus_mod.load()
    safe = MockTarget(model="mock-safe", vulnerability=0.02, seed=1)
    console.print(f"[bold]1.[/] baseline against a safe model ({len(cases)} cases x {samples})")
    base_results = asyncio.run(run_corpus(safe, cases, samples))
    bl = Baseline.from_results(base_results, _fingerprint(safe, cases), samples)

    risky = MockTarget(model="mock-upgraded", vulnerability=vulnerability, seed=2)
    console.print(f"[bold]2.[/] check after 'upgrading' to a model with vulnerability={vulnerability}\n")
    new_results = asyncio.run(run_corpus(risky, cases, samples))

    report = diff_compare(bl, new_results, GatePolicy())
    report.fingerprint_changed = bl.fingerprint.diff(_fingerprint(risky, cases))
    to_terminal(report, console)
    raise typer.Exit(0 if report.passed else 1)


@app.command()
def scan(
    model: list[str] = typer.Option(None, "--model", "-m", help="provider:model, repeatable"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    samples: int = typer.Option(10, "--samples", "-n"),
    pack: list[str] = typer.Option(None, "--pack", "-p"),
    concurrency: int = typer.Option(4, "--concurrency"),
    no_cache: bool = typer.Option(False, "--no-cache", help="force live calls, ignore the cache"),
) -> None:
    """Run the corpus against a model once. No baseline, no config needed.

        driftguard scan --model openai:gpt-4o
        driftguard scan --model ollama:llama3.1

    This is a snapshot of where a model stands, not a gate. Use `baseline`
    and `check` to catch changes over time.
    """
    cfg = Config.load(config) if config.exists() else Config()
    if pack:
        cfg.packs = list(pack)
    if no_cache:
        cfg.cache_enabled = False
    cases = corpus_mod.load(cfg.packs or None, [Path(d) for d in cfg.corpus_dirs])
    cache = cfg.make_cache()
    target = cfg.build_target(list(model) or None, cache=cache)

    console.print(f"{len(cases)} cases x {samples} samples against [bold]{target.name}[/]\n")
    results = asyncio.run(
        run_corpus(target, cases, samples, concurrency=concurrency, canary_salt=cache.salt())
    )

    from rich.table import Table

    t = Table(box=None, header_style="bold")
    t.add_column("case")
    t.add_column("sev")
    t.add_column("violations", justify="right")
    t.add_column("title", overflow="ellipsis", max_width=48)
    for r in sorted(results, key=lambda r: (r.kind, -r.rate, r.case_id)):
        colour = "red" if r.rate >= 0.3 else "yellow" if r.rate else "green"
        label = "task failed" if r.kind == "benign" else "attack ok"
        t.add_row(
            r.case_id,
            r.severity,
            f"[{colour}]{r.successes}/{r.samples}[/] [dim]{label}[/]",
            r.title,
        )
    console.print(t)

    metrics_panel(compute_metrics(results), console, title=f"metrics -- {target.name}")
    _cache_line(cache, console)
    console.print("\n[dim]Snapshot only. `driftguard baseline` to start gating changes.[/]")


@app.command()
def compare(
    model: list[str] = typer.Option(None, "--model", "-m", help="provider:model, repeatable"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    samples: int = typer.Option(10, "--samples", "-n"),
    pack: list[str] = typer.Option(None, "--pack", "-p"),
    concurrency: int = typer.Option(4, "--concurrency"),
    no_cache: bool = typer.Option(False, "--no-cache", help="force live calls, ignore the cache"),
) -> None:
    """Run the same corpus against several models side by side.

        driftguard compare -m openai:gpt-4o -m anthropic:claude-sonnet-5 -m ollama:llama3.1

    Answers "which model is safest for MY agent and MY tools" -- a question
    generic public benchmarks cannot answer, because they do not know your
    tools. Significance is measured against the first model listed.
    """
    from rich.table import Table

    from .stats import benjamini_hochberg, fisher_exact_greater

    cfg = Config.load(config) if config.exists() else Config()
    if pack:
        cfg.packs = list(pack)
    if no_cache:
        cfg.cache_enabled = False
    cases = corpus_mod.load(cfg.packs or None, [Path(d) for d in cfg.corpus_dirs])
    cache = cfg.make_cache()
    targets = cfg.build_targets(list(model) or None, cache=cache)
    if len(targets) < 2:
        console.print("[red]compare needs at least two models[/] (repeat --model)")
        raise typer.Exit(2)

    console.print(
        f"{len(cases)} cases x {samples} samples x {len(targets)} models "
        f"= {len(cases) * samples * len(targets)} calls\n"
    )

    by_model: dict[str, dict[str, Any]] = {}
    for tgt in targets:
        console.print(f"[dim]running {tgt.name}...[/]")
        res = asyncio.run(
            run_corpus(tgt, cases, samples, concurrency=concurrency, canary_salt=cache.salt())
        )
        by_model[tgt.name] = {r.case_id: r for r in res}

    names = list(by_model)
    ref = names[0]

    # Significance of each model vs the reference, corrected across the suite.
    qs: dict[str, dict[str, float]] = {}
    for name in names[1:]:
        ps = [
            fisher_exact_greater(
                by_model[ref][c.id].successes, samples, by_model[name][c.id].successes, samples
            )
            for c in cases
        ]
        qs[name] = dict(zip([c.id for c in cases], benjamini_hochberg(ps)))

    t = Table(box=None, header_style="bold")
    t.add_column("case")
    t.add_column("sev")
    for name in names:
        t.add_column(name, justify="right")

    for c in sorted(cases, key=lambda c: c.id):
        row = [c.id, c.severity]
        for name in names:
            r = by_model[name][c.id]
            colour = "red" if r.rate >= 0.3 else "yellow" if r.rate else "green"
            cell = f"[{colour}]{r.successes}/{samples}[/]"
            if name != ref and qs[name].get(c.id, 1.0) < 0.05:
                cell += " [red]*[/]"
            row.append(cell)
        t.add_row(*row)

    mets = {name: compute_metrics(list(by_model[name].values())) for name in names}
    t.add_section()

    def row(label: str, fmt, best=min, dim=False):
        vals = {n: fmt(mets[n]) for n in names}
        try:
            winner = best(vals, key=lambda n: vals[n][1])
        except (TypeError, ValueError):
            winner = None
        cells = [f"[dim]{label}[/]" if dim else f"[bold]{label}[/]", ""]
        for n in names:
            text = vals[n][0]
            cells.append(f"[bold green]{text}[/]" if n == winner and not dim else text)
        t.add_row(*cells)

    row("attack success", lambda m: (f"{m.asr:.0%}", m.asr), min)
    row("weighted risk", lambda m: (f"{m.weighted_risk:.0f}", m.weighted_risk), min)
    row("critical breaches", lambda m: (str(m.critical_failures), m.critical_failures), min)
    if any(m.benign_samples for m in mets.values()):
        row("benign success", lambda m: (f"{m.utility:.0%}", -m.utility), min)
        row("over-refusal", lambda m: (f"{m.over_refusal_rate:.0%}", m.over_refusal_rate), min)
        row("safety/utility", lambda m: (f"{m.safety_utility:.2f}", -m.safety_utility), min)
    row("latency p95", lambda m: (f"{m.p95_ms:.0f}ms", m.p95_ms), min, dim=True)
    row("est. cost", lambda m: (f"${m.est_cost_usd:.3f}", m.est_cost_usd), min, dim=True)
    console.print(t)
    console.print(
        f"\n[dim]* = significantly worse than {ref} (BH-adjusted q < 0.05). "
        f"Lower is safer.[/]"
    )
    console.print(
        "[dim]These numbers describe YOUR tools and prompt, not the models in general.[/]"
    )
    _cache_line(cache, console)
    if not any(m.benign_samples for m in mets.values()):
        console.print(
            "[yellow]No benign cases ran -- a low attack rate here might just mean "
            "the model refuses everything. Include the `benign` pack to tell them apart.[/]"
        )


@app.command()
def roles(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    model: list[str] = typer.Option(None, "--model", "-m"),
) -> None:
    """Show how your tools map to the roles the corpus refers to.

    Cases name roles, not tool names, so the same corpus works on any agent.
    Roles are inferred from your tool names and docstrings; anything wrong
    here should be corrected with `tool_roles:` in driftguard.yaml.
    """
    from rich.table import Table

    from . import roles as roles_mod

    cfg = Config.load(config) if config.exists() else Config()
    target = cfg.build_target(list(model) or None)
    rm = getattr(target, "role_map", None)
    if rm is None:
        console.print("[yellow]this target does not expose a role map[/]")
        raise typer.Exit(1)

    t = Table(box=None, header_style="bold")
    t.add_column("role")
    t.add_column("your tools")
    t.add_column("source")
    for role in roles_mod.ROLES:
        got = rm.tools(role)
        src = "inferred" if role in rm.inferred else ("declared" if got else "")
        t.add_row(
            role,
            ", ".join(got) if got else "[red]none[/]",
            f"[dim]{src}[/]" if src else "",
        )
    console.print(t)

    cases = corpus_mod.load(cfg.packs or None, [Path(d) for d in cfg.corpus_dirs])
    blocked = [(c.id, target.skip_reason(c)) for c in cases]
    blocked = [(i, r) for i, r in blocked if r]
    if blocked:
        console.print(
            f"\n[red]{len(blocked)} of {len(cases)} cases cannot run[/] with this mapping:"
        )
        for cid, why in blocked:
            console.print(f"  [red]-[/] {cid}: {why}")
        console.print(
            "\n[yellow]Add the missing roles under `tool_roles:` in driftguard.yaml.[/]"
        )
    else:
        console.print(f"\n[green]all {len(cases)} cases can run[/]")
    if rm.unmapped_tools:
        console.print(
            f"[dim]tools with no role: {', '.join(rm.unmapped_tools)} "
            f"-- no case targets them[/]"
        )


@app.command()
def ui(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
    port: int = typer.Option(8765, "--port"),
    no_browser: bool = typer.Option(False, "--no-browser"),
) -> None:
    """Open the local dashboard: configure, run, and inspect results in a browser.

    Binds 127.0.0.1 only and requires a per-process token, so another page
    open in your browser cannot drive it against your API keys.
    """
    import webbrowser

    from .ui.server import serve

    httpd, url = serve(config, port)
    console.print(f"[bold]driftguard ui[/] -> [underline]{url}[/]")
    console.print("[dim]local only; the token in the URL is required. Ctrl-C to stop.[/]")
    if not no_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\nstopped")
    finally:
        httpd.server_close()


def _cache_line(cache, console) -> None:
    st = cache.stats
    if not st.lookups:
        return
    if st.hits:
        console.print(
            f"[dim]cache: {st.hits}/{st.lookups} hits ({st.hit_rate:.0%}), "
            f"~${st.saved_usd:.3f} saved[/]"
        )
    else:
        console.print(f"[dim]cache: cold, {st.writes} entries written[/]")


@app.command()
def cache(
    clear: bool = typer.Option(False, "--clear", help="delete all cached responses"),
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c"),
) -> None:
    """Show or clear the response cache."""
    cfg = Config.load(config) if config.exists() else Config()
    c = cfg.make_cache()
    if clear:
        n = c.clear()
        console.print(f"[green]removed {n} cached response(s)[/] from {c.dir}")
        return
    entries = c.entries()
    if not entries:
        console.print(f"cache is empty ({c.dir})")
        return
    console.print(f"[bold]{entries}[/] cached responses in {c.dir}")
    console.print(f"[dim]{c.size_bytes() / 1024:.0f} KiB on disk[/]")
    if cfg.cache_ttl_days:
        console.print(f"[dim]entries expire after {cfg.cache_ttl_days} day(s)[/]")
    else:
        console.print(
            "[dim]no expiry set. If your provider may change the model behind a "
            "stable alias, set cache.ttl_days so a warm cache cannot hide it.[/]"
        )


def main() -> None:
    sys.exit(app())


if __name__ == "__main__":
    main()
