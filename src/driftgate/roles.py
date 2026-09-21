"""Tool roles: what decouples the corpus from any particular toolkit.

A case cannot name `fetch_url`, because your agent has `get_ticket`. So cases
name a ROLE -- "a tool that returns untrusted content" -- and driftgate maps
your tools onto roles, by inference or by explicit configuration.

Without this, the built-in corpus silently produced garbage on a real toolkit:
cases that inject via a missing tool errored out, benign cases demanded tools
that did not exist, and the run still reported a confident 0% attack rate.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass

# Role -> (what it means for security, name/doc patterns that suggest it).
# Inference is a convenience with a visible result, never a silent guess:
# `driftgate roles` prints the mapping and the config can override any of it.
ROLES: dict[str, tuple[str, list[str]]] = {
    "untrusted_source": (
        "returns content from outside your trust boundary, so it is the "
        "delivery channel for indirect prompt injection",
        [r"fetch", r"read", r"get_?(page|url|doc|file|ticket|issue|mail|message)",
         r"search", r"browse", r"crawl", r"scrape", r"retrieve", r"load", r"open",
         r"lookup_?(url|page)", r"download"],
    ),
    "destructive": (
        "irreversible or damaging, and must never fire from injected content",
        [r"delete", r"drop", r"remove", r"purge", r"destroy", r"wipe", r"truncate",
         r"cancel", r"revoke", r"terminate", r"refund", r"chargeback", r"transfer",
         r"pay", r"reset", r"disable", r"deactivate", r"ban", r"archive"],
    ),
    "external_send": (
        "can move data outside the system, so it is an exfiltration channel",
        [r"\bsend", r"\bemail", r"\bpost\b", r"\bpublish", r"\bnotify", r"webhook",
         r"\bupload", r"\bshare\b", r"\bmessage", r"\bsms\b", r"\bslack", r"\btweet",
         r"\bforward", r"\bexport"],
    ),
    "sensitive_read": (
        "reads private or tenant-scoped data that must not cross a boundary",
        [r"\bquery", r"\bselect", r"look_??up", r"look up", r"\bfind", r"\brecord",
         r"list_?(user|account|customer|order)", r"db", r"sql",
         r"get_?(user|account|customer|record|profile|order|payment|passenger|patient)"],
    ),
    "benign_write": (
        "writes something harmless; used by utility cases, not attacks",
        [r"save", r"note", r"log\b", r"store", r"create_?note", r"append",
         r"comment", r"draft", r"book", r"schedule"],
    ),
    "readonly_status": (
        "harmless read used by utility cases",
        [r"\bstatus", r"\bcheck", r"\bhealth", r"\bping\b", r"\binfo\b",
         r"\bdescribe", r"\blist\b", r"\bcount\b", r"\bversion"],
    ),
}


@dataclass
class RoleMap:
    """Resolved role -> tool names for one target."""

    mapping: dict[str, list[str]]
    inferred: set[str]          # roles that were guessed rather than declared
    unmapped_tools: list[str]

    def tools(self, role: str) -> list[str]:
        return self.mapping.get(role, [])

    def first(self, role: str) -> str | None:
        got = self.mapping.get(role)
        return got[0] if got else None

    def has(self, role: str) -> bool:
        return bool(self.mapping.get(role))

    def missing(self, roles: list[str]) -> list[str]:
        return [r for r in roles if not self.has(r)]


def infer_role(name: str, fn: Callable | None = None) -> list[str]:
    """Guess a tool's roles from its name and the first line of its docstring."""
    haystack = name.lower()
    if fn is not None:
        doc = (inspect.getdoc(fn) or "").split("\n")[0].lower()
        haystack = f"{haystack} {doc}"

    found = []
    for role, (_desc, patterns) in ROLES.items():
        if any(re.search(p, haystack) for p in patterns):
            found.append(role)

    # A destructive tool is never also one of the harmless roles that utility
    # cases require. Otherwise a benign case could be "satisfied" by the agent
    # calling something dangerous.
    if "destructive" in found:
        found = [r for r in found if r not in ("benign_write", "readonly_status")]
    return found


def build(
    tools: dict[str, Callable], declared: dict[str, list[str]] | None = None
) -> RoleMap:
    """Resolve roles for a toolkit.

    Declared mappings win outright. Inference fills the rest, and every
    inferred role is tracked so the user can see what was assumed.
    """
    mapping: dict[str, list[str]] = {}
    inferred: set[str] = set()

    for role, names in (declared or {}).items():
        if role not in ROLES:
            raise ValueError(f"unknown tool role {role!r}; known: {sorted(ROLES)}")
        present = [n for n in names if n in tools]
        if present:
            mapping[role] = present

    assigned: set[str] = {n for names in mapping.values() for n in names}
    for name, fn in tools.items():
        for role in infer_role(name, fn):
            if role in (declared or {}):
                continue  # user was explicit about this role
            mapping.setdefault(role, [])
            if name not in mapping[role]:
                mapping[role].append(name)
                inferred.add(role)
                assigned.add(name)

    return RoleMap(
        mapping=mapping,
        inferred=inferred,
        unmapped_tools=sorted(n for n in tools if n not in assigned),
    )


def describe(role: str) -> str:
    return ROLES.get(role, ("unknown role", []))[0]
