"""
Structured configurations (JSON): cloud security groups, NSGs, firewall-policy exports, SONiC config_db.

The tokenizer reads statements, one per line. A JSON export has no statements: a security-group rule is
an object spread over a dozen lines, so nothing in it could be read or taught. Flattening turns every
object into one statement:

    {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    →  IpPermissions FromPort 22 IpProtocol tcp IpRanges CidrIp 0.0.0.0/0 ToPort 22

* the line starts with the keys leading to the object (array positions are dropped), then its own
  ``key value`` pairs, keys sorted, so the same object reads the same whatever order it was exported in
* a nested value that holds only scalars and has no ``name`` (``IpRanges: [{"CidrIp": …}]``, GCP ``allowed: [{"IPProtocol": "tcp",
  "ports": ["22"]}]``) is inlined into its parent under its own key: it qualifies the rule, it is not a statement
  of its own, and the key keeps ``allowed`` apart from ``denied``; empty values say nothing and are dropped
* metadata that is never a setting (``etag``, ``id``, ``selfLink``, ``creationTimestamp``, …) and free-text
  ``description`` are dropped, so a rule reads the same whichever tool exported it
* a value containing whitespace stays one quoted token

The flattened text *is* the configuration from then on: evidence cites its lines, and the Training
interface shows them, so an administrator teaches a JSON dialect exactly like a CLI one.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional


# never a setting: identity, timestamps and export bookkeeping of Azure / GCP / AWS exports; free text
_METADATA = frozenset({"etag", "id", "selflink", "creationtimestamp", "kind", "provisioningstate", "resourceguid",
                       "description"})


def _scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def _keys(node: dict) -> list[str]:
    return sorted(k for k in node if k.lower() not in _METADATA)


def _scalars(value: Any) -> bool:
    """A scalar, or a list of scalars (GCP ``ports: ["22", "443"]``)."""
    return _scalar(value) or isinstance(value, list) and all(_scalar(v) for v in value)


def _token(value: Any) -> str:
    text = json.dumps(value) if isinstance(value, bool) or value is None else str(value)
    return json.dumps(text) if not text or any(c.isspace() for c in text) else text


def _flat(value: Any) -> bool:
    """Only scalars below: an object of scalars, or a list of scalars / of such objects. A named object (an Azure
    security rule) is a thing of its own, never a qualifier of its parent: it gets its own line."""
    if isinstance(value, dict):
        return not any(k.lower() == "name" for k in value) and all(_scalars(v) for v in value.values())
    if isinstance(value, list):
        return all(_scalar(v) or (isinstance(v, dict) and _flat(v)) for v in value)
    return True


def _pairs(key: str, value: Any) -> list[str]:
    if _scalar(value):
        return [key, _token(value)]
    items = value if isinstance(value, list) else [value]
    out: list[str] = []
    for item in items:
        if isinstance(item, dict):
            own = [t for k in _keys(item) for v in (item[k] if isinstance(item[k], list) else [item[k]])
                   for t in (k, _token(v))]
            out += [key, *own] if own else []
        else:
            out += [key, _token(item)]
    return out


def flatten_json(text: str) -> Optional[list[str]]:
    """One line per JSON object, or None when the text is not a JSON object or array."""
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    lines: list[str] = []

    def walk(node: Any, path: list[str]) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, path)
            return
        if not isinstance(node, dict):
            return
        own = [t for k in _keys(node) if _flat(node[k]) for t in _pairs(k, node[k])]
        if own:
            lines.append(" ".join([*path, *own]))
        for k in _keys(node):
            if not _flat(node[k]):
                walk(node[k], [*path, k])

    walk(data, [])
    return lines or None


# ── HCL (Terraform) ──────────────────────────────────────────────────────────
#
# A Terraform rule is a block of ``key = value`` lines, so like a JSON object it becomes one statement: the
# block's header, then its own pairs, keys sorted. The blocks stay blocks, so a child is read inside its parent:
#
#     resource "aws_security_group" "web" {        resource aws_security_group web name web-tier-sg {
#       name = "web-tier-sg"
#       ingress {                                    ingress cidr_blocks 0.0.0.0/0 from_port 22 protocol tcp to_port 22 {
#         from_port   = 22
#         protocol    = "tcp"
#         cidr_blocks = ["0.0.0.0/0"]
#       }                                            }
#
# Unlike JSON, the output keeps the file's line numbers: each statement sits on its block's header line and
# the assignment lines are blank, so evidence cites the block in the uploaded file. A reference the file does not
# resolve (``var.admin_cidr``, ``"${local.x}/32"``) is kept as ``${…}``: no ``{enum}`` slot can match it, so it
# never decides a result. ``description`` is free text and is dropped, as the tokenizer drops it.

_HCL_HEADER = re.compile(r'^([A-Za-z_][\w-]*)((?:\s+(?:"[^"]*"|[A-Za-z_][\w-]*))*)\s*=?\s*\{$')
_HCL_ASSIGN = re.compile(r"^([A-Za-z_][\w-]*)\s*=\s*(.+)$")
_HCL_ITEM = re.compile(r'"(?:[^"\\]|\\.)*"|[^,\s\[\]]+')
_HCL_FREE_TEXT = frozenset({"description"})


def _hcl_value(item: str) -> str:
    if item.startswith('"'):
        text = item[1:-1]
        return json.dumps(text) if not text or any(c.isspace() for c in text) else text
    if re.fullmatch(r"-?\d+(\.\d+)?|true|false|null", item) or item.startswith("${"):
        return item
    return "${" + item + "}"


def _depth(text: str) -> int:
    """Open ``( [ {`` minus closed ones, outside quotes."""
    depth, quoted = 0, False
    for i, c in enumerate(text):
        if c == '"' and (i == 0 or text[i - 1] != "\\"):
            quoted = not quoted
        elif not quoted:
            depth += (c in "([{") - (c in ")]}")
    return depth


def _hcl_code(line: str) -> str:
    """The line without a trailing ``#`` / ``//`` comment (outside quotes)."""
    quoted = False
    for i, c in enumerate(line):
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            quoted = not quoted
        elif not quoted and (c == "#" or line.startswith("//", i)):
            return line[:i].strip()
    return line.strip()


def _looks_like_hcl(lines: list[str]) -> bool:
    """Structure, not a vendor name: labelled blocks and ``key = value`` assignments, no ``;`` statements."""
    code = [c for c in map(_hcl_code, lines) if c]
    headers = sum(1 for c in code if _HCL_HEADER.match(c) and '"' in c)
    assigns = sum(1 for c in code if _HCL_ASSIGN.match(c) and not c.endswith(";"))
    return headers >= 1 and assigns >= 1 and not any(c.endswith(";") for c in code)


def flatten_hcl(text: str) -> Optional[list[str]]:
    """One statement per HCL block, on the block's own line (same line count), or None when not HCL."""
    lines = text.splitlines()
    if not _looks_like_hcl(lines):
        return None
    out = [""] * len(lines)
    stack: list[tuple[int, list[str], list[tuple[str, str]]]] = []  # (header line, type + labels, own pairs)
    pending: Optional[tuple[str, str]] = None  # a value spread over lines: (key, text so far)
    heredoc: Optional[str] = None
    in_comment = False

    for index, raw in enumerate(lines):
        if heredoc is not None:
            heredoc = None if raw.strip() == heredoc else heredoc
            continue
        stripped = raw.strip()
        if in_comment or stripped.startswith("/*"):
            in_comment = "*/" not in stripped
            continue
        code = _hcl_code(raw)
        if pending is not None:
            pending = (pending[0], pending[1] + " " + code)
            if _depth(pending[1]) > 0:
                continue
            code, pending = f"{pending[0]} = {pending[1]}", None
        if not code:
            continue
        if code == "}" or code == "]":
            if stack:
                line, header, pairs = stack.pop()
                out[line] = " ".join([*header, *(t for k, v in sorted(pairs) for t in (k, v)), "{"])
                out[index] = "}"
            continue
        if header := _HCL_HEADER.match(code):
            labels = [w.strip('"') for w in re.findall(r'"[^"]*"|\S+', header.group(2))]
            stack.append((index, [header.group(1), *labels], []))
            continue
        if not (assign := _HCL_ASSIGN.match(code)) or not stack:
            continue
        key, value = assign.groups()
        if value.startswith("<<"):
            heredoc = value.lstrip("<-").strip()
            continue
        if _depth(value) > 0:
            pending = (key, value)
            continue
        if key in _HCL_FREE_TEXT:
            continue
        value = value.strip()
        if value.startswith("[") and not any(c in value[1:-1] for c in "([{"):
            items = _HCL_ITEM.findall(value[1:-1])
        elif re.fullmatch(r'"[^"]*"|[^\s"]+', value):
            items = [value]
        else:
            items = ["${expression}"]  # a function call, a map, a template: nothing to read without evaluating it
        stack[-1][2].extend((key, _hcl_value(item)) for item in items)

    return out if any(line.strip("{} ") for line in out) else None


if __name__ == "__main__":
    sg = ('{"SecurityGroups": [{"GroupName": "web admin", "IpPermissions": [{"ToPort": 22, "IpProtocol": "tcp",'
          ' "FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]}]}')
    assert flatten_json(sg) == ['SecurityGroups GroupName "web admin"',
                                "SecurityGroups IpPermissions FromPort 22 IpProtocol tcp IpRanges CidrIp 0.0.0.0/0 ToPort 22"]
    assert flatten_json("hostname R1") is None and flatten_json("{not json") is None
    print("ok")
