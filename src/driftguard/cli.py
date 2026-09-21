"""driftguard CLI: init / baseline / check / packs / demo."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console

from . import corpus as corpus_mod
from .baseline import DEFAULT_PATH, Baseline, Fingerprint
from .config import DEFAULT_CONFIG, TEMPLATE, Config
from .diff import compare
from .report import to_markdown, to_terminal
from .runner import run_corpus
from .stats import required_samples

app = typer.Typer(
    add_completion=False,
    help="Detect security regressions in LLM agents when the model, prompt, or tools change.",
)
console = Console()


def _load(config: Path, samples: int | None, packs: list[str] | None):
    cfg = Config.load(config)
    if samples:
        cfg.samples = samples
    if packs:
        cfg.packs = packs
    cases = corpus_mod.load(cfg.packs, [Path(d) for d in cfg.corpus_dirs])
    target = cfg.build_target()
    return cfg, cases, target


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
    force: bool = typer.Option(False, "--force", help="overwrite an existing baseline"),
) -> None:
    """Record the current security posture. Commit the resulting file."""
    if out.exists() and not force:
        console.print(f"[yellow]{out} exists. Re-baselining hides prior regressions.[/]")
        console.print("Pass --force if that is what you intend.")
        raise typer.Exit(1)

    cfg, cases, target = _load(config, samples, pack)
    console.print(f"Running {len(cases)} cases x {cfg.samples} samples against [bold]{target.name}[/]")

    results = asyncio.run(run_corpus(target, cases, cfg.samples, concurrency=cfg.concurrency))
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
    markdown: Path = typer.Option(None, "--markdown", help="also write a PR-comment file"),
) -> None:
    """Re-run the corpus and fail (exit 1) if security got worse."""
    if not baseline_path.exists():
        console.print(f"[red]no baseline at {baseline_path}[/] -- run `driftguard baseline` first")
        raise typer.Exit(2)

    bl = Baseline.load(baseline_path)
    cfg, cases, target = _load(config, samples, pack)
    n = samples or bl.samples or cfg.samples

    console.print(f"Running {len(cases)} cases x {n} samples against [bold]{target.name}[/]")
    results = asyncio.run(run_corpus(target, cases, n, concurrency=cfg.concurrency))

    report = compare(bl, results, cfg.gate)
    report.fingerprint_changed = bl.fingerprint.diff(_fingerprint(target, cases))
    to_terminal(report, console)

    if markdown:
        markdown.write_text(to_markdown(report))
        console.print(f"[dim]wrote {markdown}[/]")

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

    report = compare(bl, new_results, GatePolicy())
    report.fingerprint_changed = bl.fingerprint.diff(_fingerprint(risky, cases))
    to_terminal(report, console)
    raise typer.Exit(0 if report.passed else 1)


def main() -> None:
    sys.exit(app())


if __name__ == "__main__":
    main()
