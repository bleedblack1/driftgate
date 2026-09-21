"""The baseline is a file you commit, not a row in someone's database.

Consequences of that choice:
  * the security posture change shows up in the PR diff, reviewable by a human
  * v0 needs no server, no account, no vendor
  * `git log` on this file is an audit trail of when your posture moved
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .types import CaseResult

SCHEMA_VERSION = 1
DEFAULT_PATH = Path(".driftgate-baseline.json")


@dataclass
class Fingerprint:
    """What the agent's attack surface looked like when the baseline was taken.

    A diff here is the *reason* to re-run the gate: model bump, prompt edit, or
    a new tool exposed. All three change the surface; only the first is obvious.
    """

    model: str = ""
    prompt_sha: str = ""
    tools_sha: str = ""
    corpus_sha: str = ""

    def diff(self, other: Fingerprint) -> list[str]:
        changed = []
        for f in ("model", "prompt_sha", "tools_sha", "corpus_sha"):
            if getattr(self, f) != getattr(other, f):
                changed.append(f)
        return changed


@dataclass
class Baseline:
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    samples: int = 0
    created_at: str = ""
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_results(
        cls, results: list[CaseResult], fingerprint: Fingerprint, samples: int
    ) -> Baseline:
        return cls(
            fingerprint=fingerprint,
            samples=samples,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            cases={
                r.case_id: {
                    "title": r.title,
                    "kind": r.kind,
                    "severity": r.severity,
                    "successes": r.successes,
                    "samples": r.samples,
                }
                for r in sorted(results, key=lambda r: r.case_id)
            },
        )

    def to_json(self) -> str:
        payload = {
            "schema": SCHEMA_VERSION,
            "created_at": self.created_at,
            "samples": self.samples,
            "fingerprint": self.fingerprint.__dict__,
            "cases": self.cases,
        }
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"

    def save(self, path: Path = DEFAULT_PATH) -> None:
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path = DEFAULT_PATH) -> Baseline:
        data = json.loads(path.read_text())
        schema = data.get("schema")
        if schema != SCHEMA_VERSION:
            raise ValueError(
                f"baseline schema {schema} is not supported by this version "
                f"(expected {SCHEMA_VERSION}); re-run `driftgate baseline`"
            )
        return cls(
            fingerprint=Fingerprint(**data.get("fingerprint", {})),
            samples=data.get("samples", 0),
            created_at=data.get("created_at", ""),
            cases=data.get("cases", {}),
        )


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]
