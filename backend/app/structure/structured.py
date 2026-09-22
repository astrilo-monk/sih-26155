"""
Structured configurations (JSON): cloud security groups, NSGs, firewall-policy exports, SONiC config_db.

The tokenizer reads statements, one per line. A JSON export has no statements: a security-group rule is
an object spread over a dozen lines, so nothing in it could be read or taught. Flattening turns every
object into one statement:

    {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    →  IpPermissions FromPort 22 IpProtocol tcp CidrIp 0.0.0.0/0 ToPort 22

* the line starts with the keys leading to the object (array positions are dropped), then its own
  ``key value`` pairs, keys sorted, so the same object reads the same whatever order it was exported in
* a nested value that holds only scalars (``IpRanges: [{"CidrIp": …}]``) is inlined into its parent:
  it qualifies the rule, it is not a statement of its own; empty values say nothing and are dropped
* a value containing whitespace stays one quoted token

The flattened text *is* the configuration from then on: evidence cites its lines, and the Training
interface shows them, so an administrator teaches a JSON dialect exactly like a CLI one.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def _scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def _token(value: Any) -> str:
    text = json.dumps(value) if isinstance(value, bool) or value is None else str(value)
    return json.dumps(text) if not text or any(c.isspace() for c in text) else text


def _flat(value: Any) -> bool:
    """Only scalars below: an object of scalars, or a list of scalars / of such objects."""
    if isinstance(value, dict):
        return all(_scalar(v) for v in value.values())
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
            out += [t for k in sorted(item) for t in (k, _token(item[k]))]
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
        own = [t for k in sorted(node) if _flat(node[k]) for t in _pairs(k, node[k])]
        if own:
            lines.append(" ".join([*path, *own]))
        for k in sorted(node):
            if not _flat(node[k]):
                walk(node[k], [*path, k])

    walk(data, [])
    return lines or None


if __name__ == "__main__":
    sg = ('{"SecurityGroups": [{"GroupName": "web admin", "IpPermissions": [{"ToPort": 22, "IpProtocol": "tcp",'
          ' "FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]}]}')
    assert flatten_json(sg) == ['SecurityGroups GroupName "web admin"',
                                "SecurityGroups IpPermissions FromPort 22 IpProtocol tcp CidrIp 0.0.0.0/0 ToPort 22"]
    assert flatten_json("hostname R1") is None and flatten_json("{not json") is None
    print("ok")
