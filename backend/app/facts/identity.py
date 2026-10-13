"""
Device identity: serial number, hardware model and OS version, read only where an uploaded text states them.

A configuration rarely carries the serial number. The commands that do (``show version``, ``show inventory``,
``show chassis hardware``, ``get system status``, ``show system info``, ``display version``) print output, not
configuration. So an upload may hold both, and a command output is attached to the configuration it belongs to
as identity evidence: it is never scanned as a device of its own, and it never decides a check.

Nothing is inferred. A missing item stays missing, and an output that cannot be tied to exactly one
configuration is reported as unpaired rather than guessed onto one.
"""

from __future__ import annotations

import re
from pathlib import PurePath
from typing import Optional

_I = re.IGNORECASE | re.MULTILINE

# What a file can state about the hardware: a configuration rarely does, but ``show version`` /
# ``show inventory`` output, PAN-OS ``show system info`` and XML exports pasted with it do.
_IDENTITY = {
    "serial": [re.compile(p, re.IGNORECASE) for p in (
        r"\b(?:system\s+|chassis\s+|device\s+)?serial(?:[\s_-]*(?:number|num|no\.?))?\s*[:=]\s*\"?([A-Z0-9][A-Z0-9-]{3,})",
        r"\bserial-number\s+\"?([A-Z0-9][A-Z0-9-]{3,})",
        r"\bprocessor board id\s+([A-Z0-9]{6,})",
        r"\bSN\s*:\s*([A-Z0-9][A-Z0-9-]{3,})",
        r"<serial>\s*([^<\s]+)\s*</serial>",
    )],
    "model": [re.compile(p, re.IGNORECASE) for p in (
        r"\b(?:hardware\s+)?model(?:[\s_-]*(?:number|name))?\s*[:=]\s*\"?([A-Z0-9][\w./+-]{2,})",
        r"<model>\s*([^<\s]+)\s*</model>",
        r"\bPID\s*:\s*([A-Z0-9][\w./+-]{2,})",
        r"^\s*cisco\s+(\S+)\s+\(.*\)\s+processor",
    )],
    # a version is only one the line says is the software's, and it starts with a digit (never ``ssh version 2``)
    "os_version": [re.compile(p, re.IGNORECASE) for p in (
        r"^\s*(?:#+\s*)?(?:junos|sw-version|software\s+version|os\s+version|firmware(?:\s+version)?)\s*[:=]\s*"
        r"([0-9][\w.()-]*)",
        r"^\s*version\s+([0-9][\w.()-]*);?\s*$",
    )],
}

# Lines only command output prints. Read from command output alone: in a configuration, ``chassis cluster``
# or a ``Version:`` comment would be misread as hardware.
_OUTPUT_IDENTITY = {
    "serial": [re.compile(p, re.IGNORECASE) for p in (
        r"^Chassis\s+(?-i:([A-Z0-9]{8,}))\s+\S+",                     # Junos show chassis hardware
        r"^ESN of (?:slot|device|master)[^:]*:\s*([A-Z0-9]{8,})",       # Huawei display esn
    )],
    "model": [re.compile(p, re.IGNORECASE) for p in (
        r"^Chassis\s+[A-Z0-9]{8,}\s+(\S+)",
        r"^ *Version: *(Forti\w+-\w+) +v",                              # FortiOS get system status
        r"^Arista\s+((?:DCS|CCS)-\S+)",                                 # Arista show version
        r"^HUAWEI\s+(\S+)\s+uptime is",
    )],
    "os_version": [re.compile(p, re.IGNORECASE) for p in (
        r"^Cisco [^,]*Software[^,]*(?:,[^,]*)*?, Version ([0-9][\w.()]*)", # IOS, IOS-XE, IOS-XR
        r"^ *NXOS: *version +([0-9][\w.()]*)",
        r"^ *Version: *Forti\S+ +v([0-9][\w.]*)",
        r"^Software image version:\s*([0-9][\w.]*)",
        r"^VRP \(R\) software, Version\s+([0-9][\w.]*)",
    )],
}

# Each one is printed by a command, never written in a configuration
_OUTPUT_SIGNATURES = re.compile("|".join((
    r"^\S+ uptime is ",                                  # Cisco, Huawei show/display version
    r"^Cisco (?:IOS|Nexus|Adaptive Security).*Software",
    r"^[ \t]*Processor board ID ",
    r"^NAME: \"[^\"\n]*\",[ \t]*DESCR: ",               # show inventory
    r"^Hardware inventory:",                             # Junos show chassis hardware
    r"^Junos: [0-9]",                                    # Junos show version
    r"^sw-version: ",                                    # PAN-OS show system info
    r"^Version: Forti",                                  # FortiOS get system status
    r"^Software image version: ",                        # Arista
    r"^Huawei Versatile Routing Platform",
    r"^ESN of ",
    r"^[ \t]*routerboard: yes",                          # MikroTik /system routerboard print
)), _I)

_OUTPUT_HOSTNAME = (re.compile(r"^(\S+) uptime is ", _I), re.compile(r"^[ \t]*hostname[ \t]*:[ \t]*(\S+)[ \t]*$", _I))
# Identity lines are short: a longer line is not one, and reading only this much keeps every pattern linear
_MAX_LINE = 300

# Extensions a configuration or an output is commonly saved with; dropped before names are compared
_EXTENSIONS = {".cfg", ".conf", ".config", ".txt", ".log", ".rsc", ".xml", ".json", ".tf", ".set", ".out"}


def stated_identity(raw_lines: list[str], output: bool = False) -> dict[str, str]:
    """Serial number, hardware model and OS version, where the text states them; the first statement wins
    (``show inventory`` lists the chassis first). ``output``: the text is command output, so the lines only
    output prints are read too. Nothing is inferred: a missing item stays missing."""
    tables = (_IDENTITY, _OUTPUT_IDENTITY) if output else (_IDENTITY,)
    found: dict[str, str] = {}
    for line in raw_lines:
        line = line[:_MAX_LINE]
        if not line.strip():
            continue
        for table in tables:
            for item, patterns in table.items():
                if item in found:
                    continue
                m = next(filter(None, (p.search(line) for p in patterns)), None)
                if m:
                    found[item] = m.group(1).strip("\"';,")
        if len(found) == len(_IDENTITY):
            break
    return found


def is_command_output(text: str) -> bool:
    """Whether the text carries a line only identity command output prints. The caller still checks that it
    is not a configuration: a ``show running-config`` capture can begin with ``show version``."""
    return bool(_OUTPUT_SIGNATURES.search(text))


def output_hostname(text: str) -> Optional[str]:
    names = {m.group(1) for p in _OUTPUT_HOSTNAME for m in p.finditer(text)}
    return names.pop() if len(names) == 1 else None


def _stem(name: str) -> str:
    path = PurePath(name.replace("\\", "/"))
    return (path.stem if path.suffix.lower() in _EXTENSIONS else path.name).lower()


def pair_outputs(outputs: list[tuple[str, str]], configs: list[tuple[str, str]]) -> dict[int, Optional[int]]:
    """For each command output ``(name, text)``, the index of the configuration ``(name, hostname)`` it
    belongs to, or None when that is not certain.

    In order: the hostname the output states; else the configuration whose file name the output's file name
    starts with (``core-01.cfg`` and ``core-01-show-version.txt``); else the only configuration uploaded.
    An output whose stated hostname differs from the configuration's is never attached to it.
    """
    known = [(_stem(name), (hostname or "").lower()) for name, hostname in configs]

    def compatible(idx: int, host: Optional[str]) -> bool:
        return not host or known[idx][1] in ("", "unknown", host.lower())

    pairs: dict[int, Optional[int]] = {}
    for n, (name, text) in enumerate(outputs):
        host = output_hostname(text)
        by_host = [i for i, (_, h) in enumerate(known) if host and h == host.lower()]
        stem = _stem(name)
        # the longest configuration name the output's name extends: ``core-01-1`` beats ``core-01``
        by_name = [i for i, (s, _) in enumerate(known)
                   if s and (stem == s or (stem.startswith(s) and stem[len(s)] in "-_. "))]
        longest = max((len(known[i][0]) for i in by_name), default=0)
        by_name = [i for i in by_name if len(known[i][0]) == longest]
        if len(by_host) == 1:
            pairs[n] = by_host[0]
        elif len(by_name) == 1 and compatible(by_name[0], host):
            pairs[n] = by_name[0]
        elif len(known) == 1 and compatible(0, host):
            pairs[n] = 0
        else:
            pairs[n] = None
    return pairs


def apply_identity(device, text: str, source: str) -> bool:
    """Fill what the configuration did not state from a command output. A version the output states more
    precisely (``15.2(4)E10`` for ``15.2``) replaces the configuration's; any other disagreement keeps the
    configuration's value. Returns whether the output added anything."""
    added = False
    for item, value in stated_identity(text.splitlines(), output=True).items():
        current = getattr(device, item)
        if not current or (item == "os_version" and value != current and value.startswith(current)):
            setattr(device, item, value)
            added = True
    if added:
        device.identity_source = source
    return added

