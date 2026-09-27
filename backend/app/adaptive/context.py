"""
Generic structural context for configuration lines.

Many configuration dialects are hierarchical, so a leaf line such as
``set timeout 5`` only has meaning inside its parent block. This module
recovers each line's ancestor headers with one forward pass, using three
vendor-neutral signals:

* braces            ``system {`` … ``}``
* block keywords    ``config …`` / ``edit …`` closed by ``end`` / ``next`` / ``exit`` / ``quit``
* indentation       a less-indented preceding line is a parent

It is deliberately not a parser: it never interprets keywords beyond
opening/closing blocks, and unbalanced input simply yields shorter paths.
"""

from __future__ import annotations

MAX_PATH_DEPTH = 6
MAX_HEADER_CHARS = 120

_BLOCK_OPENERS = frozenset({"config", "edit"})
_BLOCK_CLOSERS = frozenset({"}", "};", "end", "next", "exit", "quit"})

_INDENT = "indent"
_BLOCK = "block"


def _indent_width(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" \t"))


def _header(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_HEADER_CHARS else text[: MAX_HEADER_CHARS - 1] + "…"


def structural_paths(raw_lines: list[str]) -> list[tuple[str, ...]]:
    """
    Return the ancestor block headers for every line (same indexing as
    ``raw_lines``). The line itself is never part of its own path.
    """
    stack: list[tuple[str, int, str]] = []  # (header, indent, kind)
    paths: list[tuple[str, ...]] = []

    for raw in raw_lines:
        stripped = raw.strip()
        if not stripped or stripped[0] in "#!":
            paths.append(tuple(h for h, _, _ in stack)[-MAX_PATH_DEPTH:])
            continue

        indent = _indent_width(raw)
        # An indentation parent only stays an ancestor of more-indented lines
        while stack and stack[-1][2] == _INDENT and stack[-1][1] >= indent:
            stack.pop()
        paths.append(tuple(h for h, _, _ in stack)[-MAX_PATH_DEPTH:])

        lowered = stripped.lower()
        if lowered in _BLOCK_CLOSERS:
            while stack and stack[-1][2] == _INDENT:
                stack.pop()
            if stack and stack[-1][1] >= indent:
                stack.pop()
            continue

        if stripped.endswith("{"):
            stack.append((_header(stripped[:-1]) or "{", indent, _BLOCK))
        elif lowered.split()[0] in _BLOCK_OPENERS:
            stack.append((_header(stripped), indent, _BLOCK))
        else:
            stack.append((_header(stripped), indent, _INDENT))

    return paths


def redaction_paths(raw_lines: list[str]) -> list[tuple[str, ...]]:
    """``structural_paths`` plus the RouterOS ``/section`` a line is in, for redaction only.

    ``/snmp community`` followed by ``add name=…`` puts a community string in a line that names no SNMP
    itself; a one-line ``/snmp community set … name=…`` is its own section. The tokenizer scopes
    sections itself, so this never changes how a line is read."""
    section: tuple[str, ...] = ()
    out = []
    for raw, path in zip(raw_lines, structural_paths(raw_lines)):
        stripped = raw.strip()
        if stripped.startswith("/") and not stripped.startswith("/*"):
            section = (_header(stripped),)
        out.append(section + path)
    return out
