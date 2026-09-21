"""Derive JSON-Schema tool definitions from plain Python callables.

Deliberately small. The goal is that exposing a tool to driftguard costs you
nothing beyond writing the function and its type hints.
"""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable
from typing import Any

_JSON_TYPES: dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


def _json_type(annotation: Any) -> dict[str, Any]:
    if annotation is inspect.Parameter.empty:
        return {"type": "string"}
    origin = typing.get_origin(annotation)
    if origin in (list, set, tuple):
        return {"type": "array", "items": {"type": "string"}}
    if origin is dict:
        return {"type": "object"}
    if origin is typing.Union:  # includes X | None
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        return _json_type(args[0]) if args else {"type": "string"}
    return {"type": _JSON_TYPES.get(annotation, "string")}


def schema_for(fn: Callable[..., Any], name: str | None = None) -> dict[str, Any]:
    sig = inspect.signature(fn)
    props: dict[str, Any] = {}
    required: list[str] = []
    for pname, p in sig.parameters.items():
        if pname in ("self", "cls") or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        props[pname] = _json_type(p.annotation)
        if p.default is inspect.Parameter.empty:
            required.append(pname)

    doc = inspect.getdoc(fn) or ""
    return {
        "type": "function",
        "function": {
            "name": name or fn.__name__,
            "description": doc.split("\n\n")[0].strip(),
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


def schemas_for(tools: dict[str, Callable[..., Any]]) -> list[dict[str, Any]]:
    return [schema_for(fn, name) for name, fn in tools.items()]
