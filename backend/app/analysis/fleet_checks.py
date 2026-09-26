"""
Checks across devices: problems no single-device check can see.

Built from the normalized facts of every configuration in one scan, decided facts only (parser, confirmed,
default), so a finding is never a guess. A shared secret is compared by its hash and never shown: the finding
names the devices and line numbers, not the value.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

DECISIVE = {"parser", "confirmed", "default"}


def _decided(facts, predicate):
    return [f for f in facts if f.predicate == predicate and f.assurance.value in DECISIVE]


def _shared_community(per_device):
    groups = defaultdict(dict)  # hash -> {config_index: lines}
    for i, facts in enumerate(per_device):
        for f in _decided(facts, "snmp.community"):
            name = f.value.get("name") if isinstance(f.value, dict) else None
            if name:
                key = hashlib.sha256(name.encode()).hexdigest()
                groups[key].setdefault(i, []).extend(f.evidence.line_numbers)
    return [{
        "check": "shared-snmp-community", "severity": "high",
        "title": f"The same SNMP community string is used on {len(devices)} devices",
        "why": "One leaked or guessed community string opens every one of them. The value is not shown.",
        "devices": [{"config_index": i, "lines": sorted(set(lines)), "value": None} for i, lines in devices.items()],
    } for devices in groups.values() if len(devices) > 1]


def _disagree(per_device, predicate, check, what):
    stated = {}
    for i, facts in enumerate(per_device):
        found = [f for f in _decided(facts, predicate) if isinstance(f.value, list)]
        if found:
            stated[i] = (sorted({v for f in found for v in f.value}), sorted({n for f in found for n in f.evidence.line_numbers}))
    if len(stated) < 2 or len({tuple(v) for v, _ in stated.values()}) == 1:
        return []
    return [{
        "check": check, "severity": "low",
        "title": f"Devices use different {what}",
        "why": f"Mismatched {what} make timelines and incident investigation across devices unreliable.",
        "devices": [{"config_index": i, "lines": lines, "value": ", ".join(values)} for i, (values, lines) in stated.items()],
    }]


def fleet_findings(per_device: list[list]) -> list[dict]:
    """``per_device``: the facts of each configuration, in upload order. Empty for fewer than two devices."""
    if len(per_device) < 2:
        return []
    return (_shared_community(per_device)
            + _disagree(per_device, "time.ntp.server", "ntp-mismatch", "NTP servers")
            + _disagree(per_device, "log.remote.destination", "syslog-mismatch", "syslog servers"))
