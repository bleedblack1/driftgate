"""Human-readable output: a terminal table and a markdown block for the PR."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .diff import DiffReport

_ICON = {
    "regressed": "[bold red]REGRESSED[/]",
    "improved": "[green]improved[/]",
    "unchanged": "[dim]unchanged[/]",
    "new": "[yellow]new[/]",
    "removed": "[dim]removed[/]",
}


def to_terminal(report: DiffReport, console: Console | None = None) -> None:
    console = console or Console()

    if report.fingerprint_changed:
        console.print(
            f"[yellow]Attack surface changed since baseline:[/] "
            f"{', '.join(report.fingerprint_changed)}"
        )

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("case")
    table.add_column("sev")
    table.add_column("baseline", justify="right")
    table.add_column("now", justify="right")
    table.add_column("q", justify="right")
    table.add_column("verdict")
    table.add_column("title", overflow="ellipsis", max_width=44)

    order = {"regressed": 0, "new": 1, "improved": 2, "unchanged": 3, "removed": 4}
    for c in sorted(report.cases, key=lambda c: (order[c.verdict], c.case_id)):
        if c.verdict == "unchanged":
            continue
        table.add_row(
            c.case_id,
            c.severity,
            f"{c.base_successes}/{c.base_samples}" if c.base_samples else "-",
            f"{c.new_successes}/{c.new_samples}" if c.new_samples else "-",
            f"{c.q_value:.3f}" if c.base_samples and c.new_samples else "-",
            _ICON[c.verdict],
            c.title,
        )

    unchanged = sum(1 for c in report.cases if c.verdict == "unchanged")
    console.print(table)
    if unchanged:
        console.print(f"[dim]{unchanged} case(s) unchanged[/]")

    for a in report.advisories:
        console.print(f"[yellow]under-powered:[/] {a}")

    if report.regressions:
        console.print()
        for c in report.regressions:
            console.print(f"[bold red]x[/] [bold]{c.case_id}[/] {c.title}")
            console.print(f"  {c.reason}")
        console.print(
            f"\n[bold red]FAIL[/] {len(report.regressions)} security regression(s)"
        )
    else:
        console.print("\n[bold green]PASS[/] no security regressions")


def to_markdown(report: DiffReport) -> str:
    """Suitable for posting as a PR comment."""
    lines: list[str] = []
    if report.passed:
        lines.append("### driftguard: no security regressions")
    else:
        lines.append(f"### driftguard: {len(report.regressions)} security regression(s)")

    if report.fingerprint_changed:
        lines.append("")
        lines.append(f"Attack surface changed: `{'`, `'.join(report.fingerprint_changed)}`")

    shown = [c for c in report.cases if c.verdict != "unchanged"]
    if shown:
        lines += [
            "",
            "| case | sev | baseline | now | q | verdict |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for c in shown:
            base = f"{c.base_successes}/{c.base_samples}" if c.base_samples else "-"
            now = f"{c.new_successes}/{c.new_samples}" if c.new_samples else "-"
            p = f"{c.q_value:.3f}" if c.base_samples and c.new_samples else "-"
            lines.append(f"| `{c.case_id}` | {c.severity} | {base} | {now} | {p} | {c.verdict} |")

    if report.regressions:
        lines += ["", "<details><summary>Regression detail</summary>", ""]
        for c in report.regressions:
            lines.append(f"- **{c.case_id}** {c.title} — {c.reason}")
        lines += ["", "</details>"]

    if report.advisories:
        lines += ["", "**Under-powered cases** (raise `--samples` to resolve):", ""]
        lines += [f"- {a}" for a in report.advisories]

    return "\n".join(lines) + "\n"
