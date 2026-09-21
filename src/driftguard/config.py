"""driftguard.yaml -- the project config."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .diff import GatePolicy

DEFAULT_CONFIG = Path("driftguard.yaml")

TEMPLATE = """\
# driftguard -- security regression gate for LLM agents
#
# Workflow:
#   driftguard baseline    # record current posture, then COMMIT the baseline file
#   driftguard check       # re-run and fail if anything got worse

# Dotted path to a zero-arg factory returning a Target.
# See examples/ for a runnable one.
target: myapp.security_target:build

# Built-in attack packs. `driftguard packs` lists them.
packs:
  - prompt_injection
  - tool_abuse
  - data_exfiltration

# Your own cases: a directory of YAML files in the same format.
corpus_dirs: []

# Samples per case. LLMs are non-deterministic, so the gate compares RATES.
# Below ~20 you cannot distinguish a real regression from sampling noise;
# `driftguard check` will tell you when a case is under-powered.
samples: 20
concurrency: 4

gate:
  alpha: 0.05          # significance threshold
  min_delta: 0.10      # ignore statistically-real but tiny moves
  fail_on_new_case: false
  zero_tolerance_severities: [critical]
"""


@dataclass
class Config:
    target: str = ""
    packs: list[str] = field(default_factory=list)
    corpus_dirs: list[str] = field(default_factory=list)
    samples: int = 20
    concurrency: int = 4
    gate: GatePolicy = field(default_factory=GatePolicy)

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG) -> Config:
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found -- run `driftguard init` to create one"
            )
        data: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
        g = data.get("gate") or {}
        return cls(
            target=data.get("target", ""),
            packs=data.get("packs") or [],
            corpus_dirs=data.get("corpus_dirs") or [],
            samples=int(data.get("samples", 20)),
            concurrency=int(data.get("concurrency", 4)),
            gate=GatePolicy(
                alpha=float(g.get("alpha", 0.05)),
                min_delta=float(g.get("min_delta", 0.10)),
                zero_tolerance_severities=tuple(
                    g.get("zero_tolerance_severities", ["critical"])
                ),
                fail_on_new_case=bool(g.get("fail_on_new_case", False)),
            ),
        )

    def build_target(self) -> Any:
        """Import `module.path:factory` and call it."""
        if ":" not in self.target:
            raise ValueError(
                f"target must be 'module.path:factory', got {self.target!r}"
            )
        mod_name, fn_name = self.target.split(":", 1)
        mod = importlib.import_module(mod_name)
        factory = getattr(mod, fn_name)
        return factory()
