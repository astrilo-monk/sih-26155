"""
Step-by-step CLI for a verified configuration change.

A fix is verified as a change to a copy of the configuration file (``engine.py``, ``writeback.py``). An
administrator applies it at the device's command line, so the same change is also written as the commands that
make it, in the configuration's own dialect:

* indented blocks (Cisco IOS / NX-OS, Arista EOS, Aruba, Dell): ``configure terminal``, each changed line
  under its parent blocks, ``no`` for a removed one, ``end``, ``write memory``. Huawei VRP: ``system-view``,
  ``undo``, ``return``, ``save``.
* FortiOS ``config`` / ``edit`` blocks: parents re-entered, ``set`` or ``unset``, then ``next`` / ``end``.
* set-style (Junos ``set``, PAN-OS ``set``, VyOS) and Junos braces: one ``set`` / ``delete`` command per line,
  between ``configure`` and ``commit``.
* RouterOS ``/export``: each line prefixed with its ``/section``.

Nothing here decides whether a fix is right: only a change the rescan verified is rendered. A dialect this cannot
write (JSON, Terraform, XML) gets no commands, and the file change is shown instead.
"""

from __future__ import annotations

import difflib
from typing import Optional

from app.adaptive.context import _BLOCK_CLOSERS, structural_paths

INDENT, HUAWEI, FORTI, SET, BRACES, ROUTEROS = "indent", "huawei", "forti", "set", "braces", "routeros"

_WRAP = {
    INDENT: (["configure terminal"], ["end", "write memory"]),
    HUAWEI: (["system-view"], ["return", "save"]),
    SET: (["configure"], ["commit"]),
    BRACES: (["configure"], ["commit"]),
    FORTI: ([], []),
    ROUTEROS: ([], []),
}


_COMMENTS = ("#", "!", ";", "/*", "*")


def dialect(lines: list[str]) -> Optional[str]:
    """How this configuration is written, or None when it is not a CLI (JSON, Terraform, XML)."""
    statements = [l.strip() for l in lines if l.strip() and not l.strip().startswith(_COMMENTS)]
    if not statements or statements[0][0] in "{[<" or any(l.startswith(("resource ", "<?xml")) for l in statements):
        return None
    top = [l for l in lines if l.strip() and not l[0].isspace() and not l.startswith(_COMMENTS)]
    if any(l.startswith("/") for l in top[:5]):
        return ROUTEROS
    if any(l.endswith("{") for l in statements):
        return BRACES
    if sum(l.startswith("config ") for l in top) and any(l.startswith(("set ", "edit ")) for l in statements):
        return FORTI
    if top and sum(l.startswith(("set ", "delete ")) for l in top) >= 0.8 * len(top):
        return SET
    if any(l.startswith(("sysname ", "user-interface ")) for l in top):
        return HUAWEI
    return INDENT


def _skip(line: str) -> bool:
    text = line.strip()
    return not text or text[0] in "#!" or text.lower().rstrip(";") in _BLOCK_CLOSERS


def _changes(before: list[str], after: list[str]) -> list[tuple[str, int, bool]]:
    """(which text, line index, removed?) for every line the change adds or removes, in file order. A line that
    replaces another is only added: a dialect's new value overrides the old one."""
    changes = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
        if op == "equal":
            continue
        removed, added = range(i1, i2), range(j1, j2)
        changes += [("after", j, False) for j in added]
        changes += [("before", i, True) for i in list(removed)[len(added):]]
    return [c for c in changes if not _skip((before if c[0] == "before" else after)[c[1]])]


def _indent(depth: int, line: str) -> str:
    return "   " * depth + line


def _negate(line: str, style: str) -> str:
    if style == HUAWEI:
        return line[5:] if line.startswith("undo ") else f"undo {line}"
    return line[3:] if line.startswith("no ") else f"no {line}"


def cli_body(before_text: str, after_text: str) -> tuple[Optional[str], list[str]]:
    """The commands that turn ``before_text`` into ``after_text``, without the enter / save wrapper."""
    before, after = before_text.splitlines(), after_text.splitlines()
    style = dialect(before)
    if style is None:
        return None, []
    paths = {"before": structural_paths(before), "after": structural_paths(after)}
    texts = {"before": before, "after": after}
    # a block header is a parent of some statement (a comment's path also names the line above it)
    headers = {h for which in paths for line, p in zip(texts[which], paths[which]) if not _skip(line) for h in p}
    out: list[str] = []
    open_path: tuple[str, ...] = ()

    def close(depth: int):
        nonlocal open_path
        while len(open_path) > depth:
            header = open_path[-1]
            open_path = open_path[:-1]
            closer = ("next" if header.startswith("edit ") else "end") if style == FORTI else "exit"
            out.append(_indent(len(open_path), closer))

    for which, index, removed in _changes(before, after):
        line = " ".join(texts[which][index].split())
        path = paths[which][index]
        if style in (SET, BRACES):
            if line.endswith("{"):
                continue  # a brace block's header is written into each of its lines' paths
            words = " ".join((*path, line)).rstrip(";").split()
            if words[0] in ("set", "delete"):
                words = words[1:]
            out.append(("delete " if removed else "set ") + " ".join(words))
            continue
        if style == ROUTEROS:
            section = next((l.strip() for l in reversed(texts[which][:index]) if l.startswith("/")), "")
            if removed:
                return style, []  # RouterOS removes by [find ...]: no faithful one-line form
            out.append(f"{section} {line}".strip())
            continue
        common = 0
        while common < min(len(open_path), len(path)) and open_path[common] == path[common]:
            common += 1
        close(common)
        for header in path[common:]:
            out.append(_indent(len(open_path), header))
            open_path += (header,)
        depth = len(open_path)
        if removed:
            out.append(_indent(depth, "unset " + line.split()[1] if style == FORTI and line.startswith("set ") else
                               _negate(line, style)))
            continue
        out.append(_indent(depth, line))
        if line in headers:
            open_path += (line,)
    close(0)
    return style, out


def wrap(style: Optional[str], body: list[str]) -> list[str]:
    if style is None or not body:
        return []
    enter, leave = _WRAP[style]
    return [*enter, *body, *leave]


def cli_steps(before_text: str, after_text: str) -> list[str]:
    return wrap(*cli_body(before_text, after_text))
