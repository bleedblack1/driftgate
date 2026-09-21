"""Corpus loading. Attack cases are versioned data, not code.

Keeping them as YAML separate from the engine is deliberate: the corpus is the
part that should grow by community contribution, and the part whose content
hash must feed the baseline fingerprint (adding cases changes what a pass means).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from ..types import AttackCase, Injection

PACKS_DIR = Path(__file__).parent / "packs"


def available_packs() -> list[str]:
    return sorted(p.stem for p in PACKS_DIR.glob("*.yaml"))


def load_pack(path: Path) -> list[AttackCase]:
    data: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    pack_name = data.get("pack", path.stem)
    cases = []
    for raw in data.get("cases", []):
        inj = raw.get("inject") or {}
        cases.append(
            AttackCase(
                id=raw["id"],
                pack=pack_name,
                title=raw.get("title", raw["id"]),
                prompt=raw.get("prompt", ""),
                severity=raw.get("severity", "medium"),
                inject=Injection(
                    channel=inj.get("channel", "user_message"),
                    payload=inj.get("payload", ""),
                    tool=inj.get("tool"),
                ),
                assertions=raw.get("assertions", []),
                tags=raw.get("tags", []),
            )
        )
    return cases


def load(packs: list[str] | None = None, extra_dirs: list[Path] | None = None) -> list[AttackCase]:
    """Load built-in packs by name, plus any user-supplied corpus directories."""
    wanted = packs or available_packs()
    cases: list[AttackCase] = []
    seen: set[str] = set()

    paths = [PACKS_DIR / f"{name}.yaml" for name in wanted]
    for d in extra_dirs or []:
        paths.extend(sorted(Path(d).glob("*.yaml")))

    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"corpus pack not found: {p}")
        for case in load_pack(p):
            if case.id in seen:
                raise ValueError(f"duplicate case id {case.id!r} (in {p})")
            seen.add(case.id)
            cases.append(case)
    return cases


def corpus_sha(cases: list[AttackCase]) -> str:
    """Content hash of the loaded corpus -- part of the baseline fingerprint."""
    h = hashlib.sha256()
    for c in sorted(cases, key=lambda c: c.id):
        h.update(f"{c.id}|{c.prompt}|{c.inject.payload}|{c.assertions}".encode())
    return h.hexdigest()[:16]
