"""
Parse coverage: how much of a configuration follows the detected vendor's grammar.

The detector only looks for a handful of fingerprints, and many dialects share
them (Arista EOS, NX-OS, IOS-XR and Dell OS10 all have ``hostname``, ``!``
and ``interface`` just like Cisco IOS). Before a vendor profile is trusted,
every meaningful line is checked against that vendor's grammar:

* FortiOS — a closed statement grammar (``config`` / ``edit`` / ``set`` /
  ``next`` / ``end`` …) whose nesting must balance, plus a FortiGate-only
  section, since other Fortinet products share the grammar.
* Cisco IOS / IOS-XE — known global command roots with argument checks where
  look-alike dialects diverge (case-sensitive interface names, ``line``
  ranges, ``username``, ``enable``, ``service``, ``vrf``, ``router``,
  ``ip access-list``). ``no`` forms are checked the same way. Children of
  ``interface`` and ``line`` blocks are validated; children of other block
  roots are accepted; indented lines under a non-block command are foreign.
  Banner bodies are free text and covered for every banner type.

Besides the overall ratio the report records the longest run of consecutive
foreign top-level statements, which exposes a foreign block pasted into an
otherwise valid config.

This is a syntax check, not extraction: a covered line is one the vendor would
accept, whether or not a security rule reads it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from app.models.normalized import NormalizedConfig, Vendor


@dataclass
class CoverageReport:
    total_lines: int
    covered_lines: int
    uncovered_line_numbers: list[int] = field(default_factory=list)
    # Longest run of consecutive top-level statements outside the grammar
    longest_foreign_run: int = 0
    # Set when the syntax matches but the product profile does not
    profile_mismatch: Optional[str] = None

    @property
    def ratio(self) -> float:
        return 1.0 if self.total_lines == 0 else self.covered_lines / self.total_lines

    @property
    def uncovered_count(self) -> int:
        return len(self.uncovered_line_numbers)


def _meaningful(raw: str) -> bool:
    stripped = raw.strip()
    return bool(stripped) and stripped[0] not in "!#"


def _indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" \t"))


def _report(raw_lines: list[str], covered: set[int], longest_run: int, mismatch: Optional[str] = None) -> CoverageReport:
    numbers = [i + 1 for i, raw in enumerate(raw_lines) if _meaningful(raw)]
    uncovered = [n for n in numbers if n not in covered]
    return CoverageReport(len(numbers), len(numbers) - len(uncovered), uncovered, longest_run, mismatch)


# ── FortiOS ──────────────────────────────────────────────────────────────────

_FORTI_LEAF_VERBS = frozenset({
    "set", "unset", "append", "select", "unselect", "purge", "rename", "move", "delete", "clone",
})
_FORTIGATE_SECTION = re.compile(r"^config\s+(?:firewall|vpn)\s", re.IGNORECASE)
_FORTIGATE_VERSION = re.compile(r"^#config-version=FG", re.IGNORECASE)


def _fortinet_report(raw_lines: list[str]) -> CoverageReport:
    covered: set[int] = set()
    stack: list[str] = []  # "config" | "edit"
    in_quote = False
    run = longest = 0
    fortigate = False

    for i, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()
        if in_quote:  # continuation of a multi-line quoted value
            covered.add(i)
            in_quote = raw.count('"') % 2 == 0
            continue
        if _FORTIGATE_VERSION.match(stripped) or _FORTIGATE_SECTION.match(stripped):
            fortigate = True
        if not _meaningful(raw):
            continue

        verb = stripped.split()[0].lower()
        ok = False
        if verb == "config":
            stack.append("config")
            ok = True
        elif verb == "edit":
            ok = bool(stack) and stack[-1] == "config"
            if ok:
                stack.append("edit")
        elif verb == "next":
            ok = bool(stack) and stack[-1] == "edit"
            if ok:
                stack.pop()
        elif verb == "end":
            ok = "config" in stack
            while stack and stack.pop() != "config":
                pass
        elif verb in _FORTI_LEAF_VERBS:
            ok = bool(stack)
            in_quote = ok and stripped.count('"') % 2 == 1

        if ok:
            covered.add(i)
            run = 0
        else:
            run += 1
            longest = max(longest, run)

    mismatch = None if fortigate else (
        "the syntax matches FortiOS but no FortiGate-only section (config firewall / config vpn) is present"
    )
    return _report(raw_lines, covered, longest, mismatch)


# ── Cisco IOS / IOS-XE ───────────────────────────────────────────────────────

_IOS_ROOTS = frozenset({
    "aaa", "access-list", "access-session", "alias", "app-hosting", "archive", "arp",
    "authentication", "banner", "bfd", "boot", "boot-end-marker", "boot-start-marker",
    "bridge-domain", "building", "call-home", "card", "cdp", "chat-script", "class-map", "clock",
    "control-plane", "controller", "crypto", "cts", "current", "device-tracking", "diagnostic",
    "dial-peer", "dialer-list", "dot1x", "enable", "end", "energywise", "epm", "errdisable",
    "ethernet", "event", "exception", "file", "flow", "hostname", "hw-module", "interface", "iox",
    "ip", "ipv6", "key", "kron", "l2vpn", "lacp", "license", "line", "lldp", "logging", "login",
    "mac", "macro", "memory", "monitor", "mls", "mpls", "multilink", "netconf-yang",
    "network-policy", "ntp", "object-group", "parameter-map", "parser", "password", "platform",
    "pnp", "policy-map", "port-channel", "power", "privilege", "process", "pseudowire-class", "qos",
    "radius", "radius-server", "redundancy", "resource", "restconf", "rmon", "route-map", "router",
    "sampler", "scheduler", "sdm", "security", "service", "service-template", "snmp",
    "snmp-server", "spanning-tree", "stack-power", "stackwise-virtual", "subscriber", "switch",
    "system", "table-map", "tacacs", "tacacs-server", "telemetry", "template", "tftp-server",
    "track", "transceiver", "udld", "username", "version", "virtual-service", "vlan", "voice",
    "vpdn", "vrf", "vtp", "wsma", "zone", "zone-pair",
})
# Roots that are valid without arguments
_IOS_STANDALONE_ROOTS = frozenset({
    "end", "boot-start-marker", "boot-end-marker", "control-plane", "redundancy", "archive",
    "iox", "netconf-yang", "restconf",
})
# Roots that open a block whose children are not validated here
_IOS_BLOCK_ROOTS = frozenset({
    "aaa", "app-hosting", "archive", "bridge-domain", "call-home", "card", "class-map",
    "control-plane", "controller", "crypto", "cts", "device-tracking", "dial-peer", "epm",
    "ethernet", "event", "flow", "ip", "ipv6", "key", "kron", "l2vpn", "macro", "monitor", "mpls",
    "network-policy", "object-group", "parameter-map", "pnp", "policy-map", "pseudowire-class",
    "radius", "redundancy", "route-map", "router", "sampler", "service-template", "spanning-tree",
    "stack-power", "stackwise-virtual", "subscriber", "table-map", "tacacs", "telemetry",
    "template", "track", "transceiver", "virtual-service", "vlan", "voice", "vpdn", "vrf", "wsma",
    "zone", "zone-pair",
})

_IOS_INTERFACE = re.compile(
    r"range\s+.+|(?:"
    r"(?:Gigabit|TenGigabit|TwoGigabit|FiveGigabit|FortyGigabit|AppGigabit)Ethernet"
    r"|FastEthernet|TwentyFiveGigE|HundredGigE|FourHundredGigE|Ethernet(?=\d+/)"
    r"|Serial|Loopback|Tunnel|Vlan|Port-channel|Dialer|Virtual-Template|Virtual-Access"
    r"|Virtual-PortGroup|VirtualPortGroup|BVI|BDI|Null|Cellular|Async|Group-Async|Multilink|NVI|ATM"
    r"|Embedded-Service-Engine|Service-Engine|Wlan-GigabitEthernet|nve|LISP|CEM|Dot11Radio"
    r")\s?\d+(?:[/.:]\d+)*(?:\s+(?:point-to-point|multipoint))?"
)  # case-sensitive: IOS always prints the canonical capitalization
_IOS_LINE_RANGE = re.compile(r"(?:con|console|aux|vty|tty)\s+\d+(?:\s+\d+)?|\d+(?:/\d+)*(?:\s+\d+(?:/\d+)*)?", re.IGNORECASE)
_IOS_SERVICE = frozenset({
    "timestamps", "password-encryption", "pad", "tcp-keepalives-in", "tcp-keepalives-out",
    "sequence-numbers", "config", "dhcp", "finger", "udp-small-servers", "tcp-small-servers",
    "call-home", "compress-config", "internal", "counters", "nagle", "slave-log",
    "linenumber", "prompt", "alignment", "unsupported-transceiver", "private-config",
    "password-recovery", "exec-wait", "hide-telnet-addresses",
})
_IOS_ROUTING_PROTOCOLS = frozenset({"ospf", "ospfv3", "bgp", "eigrp", "rip", "isis", "odr", "mobile", "lisp", "nhrp"})
_IOS_ACCESS_LIST_KINDS = frozenset({"standard", "extended", "resequence", "logging", "log-update", "role-based", "persistent"})
_IOS_SECRET_VALUE = r"(?:[0-9]\s+)?\S+"
_IOS_USERNAME = re.compile(
    r"username\s+\S+"
    r"(?:\s+(?:privilege\s+\d+|view\s+\S+|access-class\s+\S+|autocommand\s+.+|nopassword|noescape"
    r"|nohangup|one-time|user-maintenance|dnis|mac|callback-dialstring\s+\S+|algorithm-type\s+\w+"
    r"|common-criteria-policy\s+\S+))*"
    rf"(?:\s+(?:secret|password)\s+{_IOS_SECRET_VALUE})?\s*",
    re.IGNORECASE,
)
_IOS_ENABLE = re.compile(
    rf"enable\s+(?:algorithm-type\s+\w+\s+)?(?:secret|password)(?:\s+level\s+\d+)?\s+{_IOS_SECRET_VALUE}\s*"
    r"|enable\s+view(?:\s+\S+)?\s*",
    re.IGNORECASE,
)

_IOS_INTERFACE_CHILDREN = frozenset({
    "access-session", "arp", "authentication", "auto", "backup", "bandwidth", "bfd", "bridge-group",
    "carrier-delay", "cdp", "channel-group", "channel-protocol", "crypto", "cts", "datalink", "delay",
    "description", "device-tracking", "dialer", "dialer-group", "dot1x", "duplex", "encapsulation",
    "energywise", "ethernet", "flowcontrol", "frame-relay", "glbp", "hold-queue", "host-reachability",
    "ip", "ipv6", "isis", "keepalive", "lacp", "lldp", "load-interval", "logging", "mab", "mac",
    "mac-address", "macro", "macsec", "media-type", "member", "mka", "mls", "mpls", "mtu", "nat",
    "negotiation", "nmsp", "ntp", "ospfv3", "pagp", "peer", "platform", "power", "ppp", "pppoe",
    "pppoe-client", "priority-queue", "pvc", "queue-set", "rcv-queue", "rewrite", "service",
    "service-policy", "shutdown", "snmp", "source", "source-interface", "spanning-tree", "speed",
    "srr-queue", "standby", "storm-control", "switchport", "trust", "tunnel", "udld", "vrf", "vrrp",
    "wrr-queue", "xconnect", "zone-member",
})
_IOS_LINE_CHILDREN = frozenset({
    "absolute-timeout", "access-class", "accounting", "activation-character", "authorization",
    "autocommand", "autohangup", "autoselect", "databits", "disconnect-character",
    "escape-character", "exec", "exec-banner", "exec-character-bits", "exec-timeout", "flowcontrol",
    "full-help", "history", "ip", "ipv6", "length", "location", "lockable", "logging", "login",
    "logout-warning", "modem", "monitor", "motd-banner", "notify", "padding", "parity", "password",
    "privilege", "refuse-message", "rotary", "session-disconnect-warning", "session-limit",
    "session-timeout", "special-character-bits", "speed", "start-character", "stop-character",
    "stopbits", "terminal-type", "transport", "vacant-message", "width",
})
_BANNER_TYPES = frozenset({"login", "motd", "exec", "incoming", "slip-ppp", "prompt-timeout", "config-save"})
_BANNER_OPEN = re.compile(r"^banner\s+(\S+)\s+(\S)(.*)$")


def _ios_ip_ok(rest: list[str], negated: bool) -> bool:
    if not rest:
        return False
    if rest[0].lower() == "access-list":
        return len(rest) > 1 and rest[1].lower() in _IOS_ACCESS_LIST_KINDS
    return True


_IOS_TOP_VALIDATORS = {
    "interface": lambda rest, neg: bool(rest) and bool(_IOS_INTERFACE.fullmatch(" ".join(rest))),
    "line": lambda rest, neg: bool(_IOS_LINE_RANGE.fullmatch(" ".join(rest))),
    "username": lambda rest, neg: bool(rest) and (neg or bool(_IOS_USERNAME.fullmatch("username " + " ".join(rest)))),
    "enable": lambda rest, neg: bool(rest) and (
        rest[0].lower() in ("secret", "password", "algorithm-type", "view") if neg
        else bool(_IOS_ENABLE.fullmatch("enable " + " ".join(rest)))
    ),
    "service": lambda rest, neg: bool(rest) and rest[0].lower() in _IOS_SERVICE,
    "vrf": lambda rest, neg: bool(rest) and rest[0].lower() in ("definition", "list"),
    "router": lambda rest, neg: bool(rest) and rest[0].lower() in _IOS_ROUTING_PROTOCOLS,
    "transceiver": lambda rest, neg: bool(rest) and rest[0].lower() == "type",
    "password": lambda rest, neg: [t.lower() for t in rest[:2]] == ["encryption", "aes"],
    "ip": _ios_ip_ok,
}


def _ios_statement(tokens: list[str]) -> Optional[str]:
    """Block kind of a valid top-level statement ("interface", "line", "any", "leaf"), or None."""
    negated = tokens[0].lower() == "no"
    if negated:
        tokens = tokens[1:]
        if not tokens:
            return None
    root, rest = tokens[0].lower(), tokens[1:]
    if root not in _IOS_ROOTS:
        return None
    validator = _IOS_TOP_VALIDATORS.get(root)
    if validator is not None:
        ok = validator(rest, negated)
    else:
        ok = bool(rest) or negated or root in _IOS_STANDALONE_ROOTS
    if not ok:
        return None
    if negated:
        return "leaf"
    if root in ("interface", "line"):
        return root
    return "any" if root in _IOS_BLOCK_ROOTS else "leaf"


def _ios_child_ok(kind: Optional[str], tokens: list[str]) -> bool:
    if kind == "any":
        return True
    if kind not in ("interface", "line"):
        return False
    if tokens[0].lower() == "no" and len(tokens) > 1:
        tokens = tokens[1:]
    root = tokens[0].lower()
    if kind == "line":
        return root in _IOS_LINE_CHILDREN
    if root == "vrf":
        return len(tokens) > 1 and tokens[1].lower() == "forwarding"
    return root in _IOS_INTERFACE_CHILDREN


def _banner_delimiter(stripped: str) -> Optional[str]:
    """For a banner statement: "" when it closes on the same line, the delimiter when it opens a body."""
    match = _BANNER_OPEN.match(stripped)
    if not match or match.group(1).lower() not in _BANNER_TYPES:
        return None
    delimiter, rest = match.group(2), match.group(3)
    return "" if delimiter in rest else delimiter


def _cisco_report(config: NormalizedConfig) -> CoverageReport:
    parser_banner_lines = set(config.banners.source_lines)
    covered: set[int] = set()
    block_kind: Optional[str] = None
    child_indent: Optional[int] = None
    last_child_ok = False
    banner_delimiter: Optional[str] = None
    run = longest = 0

    for i, raw in enumerate(config.raw_lines, 1):
        if banner_delimiter:
            covered.add(i)
            if banner_delimiter in raw:
                banner_delimiter = None
            continue
        if i in parser_banner_lines:
            covered.add(i)
            continue
        if not _meaningful(raw):
            continue

        stripped = raw.strip()
        if raw[:1] in (" ", "\t"):
            indent = _indent(raw)
            if child_indent is None or indent <= child_indent:
                child_indent = indent
                last_child_ok = _ios_child_ok(block_kind, stripped.split())
            if last_child_ok:
                covered.add(i)
            continue

        child_indent = None
        delimiter = _banner_delimiter(stripped)
        if delimiter is not None:
            block_kind, banner_delimiter = "leaf", delimiter or None
            ok = True
        else:
            block_kind = _ios_statement(stripped.split())
            ok = block_kind is not None

        if ok:
            covered.add(i)
            run = 0
        else:
            run += 1
            longest = max(longest, run)

    return _report(config.raw_lines, covered, longest)


def parse_coverage(config: NormalizedConfig) -> CoverageReport:
    """Grammar coverage of ``config.raw_lines`` for ``config.device.vendor``."""
    vendor = config.device.vendor
    if vendor == Vendor.CISCO_IOS:
        return _cisco_report(config)
    if vendor == Vendor.FORTINET:
        return _fortinet_report(config.raw_lines)
    return _report(config.raw_lines, set(), 0)
