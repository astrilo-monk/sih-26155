"""
Generic statement tokenizer.

Every configuration line becomes a ``Statement``: its scope, its keyword
tokens, its typed values and its polarity. No vendor grammar is involved.

Scope comes from ``adaptive.context.structural_paths`` (braces,
``config``/``edit``/``next``/``end``, indentation) plus two flat dialects:

* ``/section`` headers (``/ip service`` … until the next ``/`` header)
* flat prefix blocks: consecutive lines sharing a leading keyword
  (``remote-console state enabled`` / ``remote-console protocol telnet``)

Polarity: ``no …`` / ``unset …`` / ``delete …``, ``enable(d)`` / ``disable(d)``,
``on`` / ``off``, ``true`` / ``false``, ``yes`` / ``no``, including combinations
such as ``disabled=yes`` and ``disable-telnet no``.

Free text never yields keywords: descriptions, remarks and banner bodies are dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from app.adaptive.context import structural_paths

POSITIVE = frozenset({"enable", "enabled", "on", "true", "yes"})
NEGATIVE = frozenset({"disable", "disabled", "off", "false", "no"})
NEGATORS = frozenset({"no", "unset", "delete", "undo"})
# Words that only switch a polarity word before them: ``disabled=yes``
SWITCHES = frozenset({"yes", "no", "true", "false"})
FREE_TEXT = frozenset({"description", "remark", "comment", "alias"})
_IGNORED = frozenset({"set", "{", "}", "};", ";"})
_CLOSERS = frozenset({"end", "next", "exit", "quit"})

IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$|^[0-9a-f]*:[0-9a-f:]+(/\d{1,3})?$")
NUMBER = re.compile(r"^\d+(\.\d+)?[a-z]{0,7}$")


@dataclass
class Statement:
    line: int  # 1-indexed
    text: str
    scope_path: tuple[str, ...] = ()
    key_tokens: list[str] = field(default_factory=list)
    # IPs, numbers (with an attached unit such as ``600s``) and quoted strings
    values: list[str] = field(default_factory=list)
    # True = enabled, False = negated / disabled, None = not stated on this line
    polarity: Optional[bool] = None
    # First line of the flat prefix block (0 = none): blank-separated blocks with the same prefix stay apart
    block: int = 0


def _split(text: str) -> list[str]:
    tokens = []
    for token in re.findall(r'"[^"]*"|\'[^\']*\'|[^\s;]+', text):
        if token[0] in "\"'" or "=" not in token.strip("="):
            tokens.append(token)
        else:
            tokens.extend(token.split("=", 1))
    return tokens


def tokenize_line(text: str, line: int = 1, scope_path: tuple[str, ...] = ()) -> Optional[Statement]:
    """One statement for a line, or None for blank lines, comments, block closers and free text."""
    tokens = _split(text.strip())
    if not tokens or tokens[0][0] in "#!" or tokens[0].lower() in _CLOSERS:
        return None

    polarities: list[bool] = []
    if tokens[0].lower() in NEGATORS and len(tokens) > 1:
        polarities.append(False)
        tokens = tokens[1:]

    statement = Statement(line=line, text=text, scope_path=scope_path)
    for token in tokens:
        lowered = token.lower()
        if token[0] in "\"'":
            statement.values.append(token.strip("\"'"))
        elif lowered in _IGNORED:
            continue
        elif IP.match(lowered) or NUMBER.match(lowered):
            statement.values.append(lowered)
        elif lowered in POSITIVE or lowered in NEGATIVE:
            if polarities and lowered in SWITCHES:
                # ``disabled=yes`` keeps the polarity, ``disabled=no`` inverts it
                polarities[-1] = polarities[-1] if lowered in POSITIVE else not polarities[-1]
            else:
                polarities.append(lowered in POSITIVE)
        elif lowered.startswith("disable-") and len(lowered) > 8:
            # ``disable-telnet no``: the keyword carries its own negation
            polarities.append(False)
            statement.key_tokens.append(lowered[8:])
        else:
            statement.key_tokens.append(lowered)

    if not statement.key_tokens or statement.key_tokens[0] in FREE_TEXT:
        return None
    if polarities:
        statement.polarity = polarities[-1]
    return statement


def tokenize(raw_lines: list[str]) -> list[Statement]:
    paths = structural_paths(raw_lines)
    statements: list[Statement] = []
    section: tuple[str, ...] = ()
    banner_delimiter: Optional[str] = None

    for index, raw in enumerate(raw_lines):
        stripped = raw.strip()
        if banner_delimiter is not None:
            if banner_delimiter in stripped:
                banner_delimiter = None
            continue
        if stripped.startswith("/"):
            section = (" ".join(stripped.split()),)
            continue
        statement = tokenize_line(raw, index + 1, section + paths[index])
        if statement is None:
            continue
        if statement.key_tokens[0] == "banner":
            banner_delimiter = _banner_delimiter(stripped)
            statement.key_tokens = statement.key_tokens[:2]
        statements.append(statement)

    _scope_flat_prefix_blocks(statements, raw_lines)
    return statements


def _banner_delimiter(stripped: str) -> Optional[str]:
    """Delimiter of a multi-line ``banner <type> <delim>`` body, None when the banner ends on this line."""
    parts = stripped.split(None, 2)
    if len(parts) < 3 or parts[2].lower() in POSITIVE | NEGATIVE or parts[2][0] in "\"'":
        return None
    body = parts[2]
    delimiter = body[:2] if body.startswith("^") else body[0]
    return None if delimiter in body[len(delimiter):] else delimiter


def _scope_flat_prefix_blocks(statements: list[Statement], raw_lines: list[str]) -> None:
    """Consecutive statements (no blank line between) sharing scope and leading keyword form a block."""
    groups: list[list[Statement]] = []
    for statement in statements:
        previous = groups[-1][-1] if groups else None
        if (previous and previous.scope_path == statement.scope_path
                and previous.key_tokens[0] == statement.key_tokens[0]
                and all(raw_lines[n - 1].strip() for n in range(previous.line + 1, statement.line))):
            groups[-1].append(statement)
        else:
            groups.append([statement])
    for group in groups:
        if len(group) > 1:
            for statement in group:
                statement.scope_path = statement.scope_path + (group[0].key_tokens[0],)
                statement.block = group[0].line
