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
        sec, util = len(report.security_regressions), len(report.utility_regressions)
        parts = []
        if sec:
            parts.append(f"{sec} security")
        if util:
            parts.append(f"{util} utility")
        console.print(f"\n[bold red]FAIL[/] {' + '.join(parts)} regression(s)")
        if util and not sec:
            console.print(
                "[yellow]Note: nothing got less safe -- the agent got less useful. "
                "Refusing legitimate work is a regression too.[/]"
            )
    else:
        console.print("\n[bold green]PASS[/] no security or utility regressions")


def to_markdown(report: DiffReport) -> str:
    """Suitable for posting as a PR comment."""
    lines: list[str] = []
    if report.passed:
        lines.append("### driftguard: no security or utility regressions")
    else:
        sec, util = len(report.security_regressions), len(report.utility_regressions)
        parts = [f"{n} {k}" for n, k in ((sec, "security"), (util, "utility")) if n]
        lines.append(f"### driftguard: {' + '.join(parts)} regression(s)")

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


def metrics_panel(m, console: Console | None = None, *, title: str = "metrics") -> None:
    """Print the full metric set: security, utility, breakdowns, operational."""
    from rich.table import Table

    console = console or Console()

    def risk_colour(v: float) -> str:
        return "red" if v >= 30 else "yellow" if v >= 10 else "green"

    head = Table(box=None, show_header=False, pad_edge=False)
    head.add_column(style="dim", width=22)
    head.add_column()

    lo, hi = m.asr_ci
    head.add_row(
        "attack success rate",
        f"[{risk_colour(m.asr * 100)}]{m.asr:.1%}[/]  "
        f"[dim]95% CI {lo:.0%}-{hi:.0%}  ({m.attack_successes}/{m.attack_samples})[/]",
    )
    head.add_row(
        "weighted risk",
        f"[{risk_colour(m.weighted_risk)}]{m.weighted_risk:.1f}[/] [dim]/100, "
        f"severity-weighted[/]",
    )
    head.add_row(
        "critical breaches",
        f"[{'red' if m.critical_failures else 'green'}]{m.critical_failures}[/]",
    )
    head.add_row(
        "cases ever breached", f"{m.cases_ever_breached}/{m.attack_cases}"
    )

    if m.benign_samples:
        util_colour = "green" if m.utility >= 0.9 else "yellow" if m.utility >= 0.7 else "red"
        head.add_row("", "")
        head.add_row(
            "benign task success",
            f"[{util_colour}]{m.utility:.1%}[/] [dim]({m.benign_samples - m.benign_failures}"
            f"/{m.benign_samples})[/]",
        )
        head.add_row(
            "over-refusal rate",
            f"[{'red' if m.over_refusal_rate > 0.1 else 'green'}]{m.over_refusal_rate:.1%}[/]",
        )
        head.add_row("safety/utility", f"[bold]{m.safety_utility:.2f}[/] [dim]/1.00[/]")
    else:
        head.add_row("", "")
        head.add_row(
            "[yellow]utility[/]",
            "[yellow]not measured -- add the `benign` pack, or a 0% attack rate "
            "may just mean the agent refuses everything[/]",
        )

    console.print(f"\n[bold]{title}[/]")
    if m.skipped:
        # Printed before the numbers, because the numbers are incomplete.
        console.print(
            f"[bold red]{len(m.skipped)} of {m.total_cases} cases could not run[/] "
            f"[red](coverage {m.coverage:.0%}). The scores below cover only the rest.[/]"
        )
        for cid, why in m.skipped[:6]:
            console.print(f"  [red]-[/] {cid}: {why}")
        if len(m.skipped) > 6:
            console.print(f"  [dim]... and {len(m.skipped) - 6} more[/]")
        console.print(
            "  [yellow]Map your tools to the missing roles in driftguard.yaml "
            "(`driftguard roles`), or these risks go unchecked.[/]\n"
        )
    console.print(head)

    if m.by_pack:
        t = Table(box=None, header_style="bold dim", pad_edge=False)
        t.add_column("by pack")
        t.add_column("rate", justify="right")
        t.add_column("")
        for b in m.by_pack:
            bar = "#" * int(round(b.rate * 20))
            t.add_row(b.label, f"{b.successes}/{b.samples}", f"[{risk_colour(b.rate*100)}]{bar}[/]")
        console.print(t)

    if m.by_severity:
        t = Table(box=None, header_style="bold dim", pad_edge=False)
        t.add_column("by severity")
        t.add_column("rate", justify="right")
        for b in m.by_severity:
            t.add_row(b.label, f"{b.successes}/{b.samples}")
        console.print(t)

    if m.failure_modes:
        modes = ", ".join(
            f"{k} x{v}" for k, v in sorted(m.failure_modes.items(), key=lambda kv: -kv[1])
        )
        console.print(f"[dim]failure modes:[/] {modes}")

    ops = (
        f"[dim]latency p50 {m.p50_ms:.0f}ms / p95 {m.p95_ms:.0f}ms   "
        f"tokens {m.input_tokens + m.output_tokens:,}   "
        f"~${m.est_cost_usd:.3f}   "
        f"{m.mean_tool_calls:.1f} tool calls/sample[/]"
    )
    if m.harness_errors:
        ops += f"   [red]{m.harness_errors} harness errors[/]"
    console.print(ops)


def metrics_markdown(m) -> str:
    lines = [""]
    if m.skipped:
        lines += [
            f"> **{len(m.skipped)} of {m.total_cases} cases could not run** "
            f"(coverage {m.coverage:.0%}). Scores below cover only the rest.",
            "",
        ]
    lines += [
        "| metric | value |",
        "| --- | --- |",
        f"| coverage | {m.coverage:.0%} ({m.total_cases - len(m.skipped)}/{m.total_cases} cases ran) |",
        f"| attack success rate | {m.asr:.1%} ({m.attack_successes}/{m.attack_samples}) |",
        f"| weighted risk | {m.weighted_risk:.1f}/100 |",
        f"| critical breaches | {m.critical_failures} |",
    ]
    if m.benign_samples:
        lines += [
            f"| benign task success | {m.utility:.1%} |",
            f"| over-refusal rate | {m.over_refusal_rate:.1%} |",
            f"| safety/utility | {m.safety_utility:.2f} |",
        ]
    lines += [
        f"| latency p50 / p95 | {m.p50_ms:.0f}ms / {m.p95_ms:.0f}ms |",
        f"| tokens | {m.input_tokens + m.output_tokens:,} (~${m.est_cost_usd:.3f}) |",
    ]
    return "\n".join(lines) + "\n"
