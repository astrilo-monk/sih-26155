"""
Deterministic remediation recipes, keyed by (control id, confirmed vendor).

A recipe reads the decisive FAIL results of one control on one configuration and
returns the edited configuration lines. It never takes command text from a caller
or from AI: every line it writes is a fixed template filled only with validated
inputs (an IPv4 address, a subnet, an NTP key). Parameters are bound from the
parser model and the FAIL results' cited lines, never parsed out of evidence text.

Edits are line-level and local: a setting is replaced in place (keeping its
indentation) or added as the last child of the block it belongs to; unrelated
lines, comments and ``config/edit/next/end`` nesting are left untouched.

A recipe raises ``NeedsInput`` when a value only the operator knows is missing and
``ManualReview`` when no known-safe deterministic change exists.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Optional

from app.controls.judges import (
    DEFAULT_SNMP_COMMUNITIES, MAX_IDLE_TIMEOUT_MINUTES, STRONG_PASSWORD_STORAGE, WEAK_DH_GROUPS, WEAK_ENCRYPTION,
    WEAK_HASH,
)
from app.facts import lexicon as L
from app.facts.predicates import PASSWORD_STORAGE
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import ControlResult


class NeedsInput(Exception):
    def __init__(self, names: list[str]):
        self.names = names
        super().__init__(f"Required input(s) missing: {', '.join(names)}")


class ManualReview(Exception):
    """No known-safe deterministic change exists for this configuration."""


# ── inputs (validated at the trust boundary: they are the only caller data written into a config) ──

def _ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        raise ValueError("enter an IPv4 address, e.g. 10.20.0.5") from None


def _subnet(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError:
        raise ValueError("enter a network with its prefix, e.g. 10.10.0.0/24") from None
    if network.prefixlen == 0:
        raise ValueError("0.0.0.0/0 would allow every source")
    return network


def _key_id(value: str) -> int:
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValueError("enter a whole number from 1 to 65535, e.g. 1") from None
    if not 1 <= number <= 65535:
        raise ValueError("enter a whole number from 1 to 65535, e.g. 1")
    return number


_KEY = re.compile(r"[A-Za-z0-9._+=@%-]{8,32}")


def _key(value: str) -> str:
    if not _KEY.fullmatch(value):
        raise ValueError(f"use 8-32 letters, digits or . _ + = @ % - (you entered {len(value)} characters), "
                         "e.g. NtpKey-2026")
    return value


# Written into the configuration as one quoted token: no quote, newline, brace, semicolon or comment character
_BANNER = re.compile(r"[A-Za-z0-9 .,:()/_-]{8,200}")


def _banner(value: str) -> str:
    text = " ".join(value.split())
    if not _BANNER.fullmatch(text):
        raise ValueError("use 8-200 letters, digits, spaces or . , : ( ) / _ -, "
                         "e.g. Authorized access only. Activity is monitored.")
    return text


@dataclass(frozen=True)
class InputSpec:
    name: str
    label: str
    help: str
    parse: Callable[[str], object]


INPUTS: dict[str, InputSpec] = {spec.name: spec for spec in (
    InputSpec("syslog_server", "Syslog server", "IPv4 address of the remote log collector, e.g. 10.20.0.5", _ipv4),
    InputSpec("ntp_server", "NTP server", "IPv4 address of a trusted NTP server, e.g. 10.20.0.123", _ipv4),
    InputSpec("ntp_key_id", "NTP key ID", "A number from 1 to 65535 that names the key, e.g. 1. It must match the NTP server", _key_id),
    InputSpec("ntp_key", "NTP key", "The secret shared with the NTP server, 8-32 characters, e.g. NtpKey-2026; written only into the "
              "generated configuration",
              _key),
    InputSpec("banner_text", "Login banner", "The warning shown before login, e.g. Authorized access only. "
              "Activity is monitored.", _banner),
    InputSpec("management_subnet", "Management subnet", "Trusted administration network in CIDR, e.g. 10.10.0.0/24",
              _subnet),
)}


def parse_inputs(raw: dict) -> tuple[dict, dict[str, str]]:
    """Validated input values and per-input errors. Blank values count as not given."""
    values, errors = {}, {}
    for name, value in (raw or {}).items():
        spec = INPUTS.get(name)
        if spec is None:
            errors[name] = "unknown input"
            continue
        if value is None or not str(value).strip():
            continue
        try:
            values[name] = spec.parse(str(value))
        except ValueError as e:
            errors[name] = str(e) or "invalid value"
    return values, errors


# ── edit helpers ────────────────────────────────────────────────────────────

@dataclass
class Context:
    lines: list[str]
    config: NormalizedConfig
    # decisive FAIL results of the control being remediated
    fails: list[ControlResult]
    inputs: dict

    def need(self, *names: str) -> list:
        missing = [n for n in names if n not in self.inputs]
        if missing:
            raise NeedsInput(missing)
        return [self.inputs[n] for n in names]

    def scopes(self, prefix: str) -> set[str]:
        return {r.scope.removeprefix(prefix) for r in self.fails if r.scope and r.scope.startswith(prefix)}


class Edits:
    """Line edits against the unchanged lines, applied at once so indices stay valid while a recipe runs."""

    def __init__(self, lines: list[str]):
        self.lines = lines
        self._replace: dict[int, list[str]] = {}
        self._after: dict[int, list[str]] = {}

    def set(self, index: int, text: str) -> None:
        self._replace[index] = [text]

    def delete(self, index: int) -> None:
        self._replace[index] = []

    def insert_after(self, index: int, texts: list[str]) -> None:
        self._after.setdefault(index, []).extend(texts)

    def apply(self) -> list[str]:
        out = list(self._after.get(-1, []))
        for index, line in enumerate(self.lines):
            out.extend(self._replace.get(index, [line]))
            out.extend(self._after.get(index, []))
        return out


def _indent(line: str) -> str:
    return line[:len(line) - len(line.lstrip(" \t"))]


def _top_level(lines: list[str], text: str, candidates=None) -> list[int]:
    """Indices of non-indented lines equal to ``text`` (whitespace-normalized), among ``candidates`` if given."""
    wanted = " ".join(text.split())
    indices = range(len(lines)) if candidates is None else candidates
    return [i for i in indices if 0 <= i < len(lines) and lines[i][:1] not in (" ", "\t")
            and " ".join(lines[i].split()) == wanted]


# Cisco IOS: a block is a non-indented header followed by indented children

def _ios_children(lines: list[str], header: int) -> list[int]:
    children = []
    for i in range(header + 1, len(lines)):
        if lines[i][:1] in (" ", "\t"):
            children.append(i)
        elif lines[i].strip():
            break
    return children


def _ios_set_child(edits: Edits, header: int, pattern: str, text: str) -> None:
    """Replace the block's child matching ``pattern`` (dropping duplicates), else add ``text`` as its last child."""
    lines = edits.lines
    children = _ios_children(lines, header)
    matches = [i for i in children if re.match(pattern, lines[i].strip(), re.IGNORECASE)]
    if matches:
        edits.set(matches[0], _indent(lines[matches[0]]) + text)
        for i in matches[1:]:
            edits.delete(i)
    else:
        indent = _indent(lines[children[0]]) if children else " "
        edits.insert_after(children[-1] if children else header, [indent + text])


def _ios_insert_global(edits: Edits, texts: list[str]) -> None:
    """Add global commands just before the final ``end`` (or at the end of the file)."""
    ends = _top_level(edits.lines, "end")
    edits.insert_after((ends[-1] - 1) if ends else len(edits.lines) - 1, texts)


def _header(lines: list[str], source_lines: list[int], prefix: str) -> Optional[int]:
    return next((n - 1 for n in source_lines if 0 < n <= len(lines) and lines[n - 1].strip().startswith(prefix)), None)


def _bad_timeout(line) -> bool:
    if line.exec_timeout_minutes is None:
        return True
    minutes = line.exec_timeout_minutes + (line.exec_timeout_seconds or 0) / 60
    return minutes == 0 or minutes > MAX_IDLE_TIMEOUT_MINUTES


# FortiOS: config/edit blocks closed by end/next

class _FortiTree:
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.close: dict[int, int] = {}
        self.parent: list[Optional[int]] = []
        stack: list[int] = []
        in_quote = False
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            self.parent.append(stack[-1] if stack else None)
            if in_quote:
                in_quote = raw.count('"') % 2 == 0
                continue
            if not stripped or stripped.startswith("#"):
                continue
            verb = stripped.split()[0].lower()
            if verb in ("config", "edit"):
                stack.append(i)
            elif verb == "next":
                if stack and lines[stack[-1]].strip().lower().startswith("edit"):
                    self.close[stack.pop()] = i
            elif verb == "end":
                while stack:
                    header = stack.pop()
                    self.close[header] = i
                    if lines[header].strip().lower().startswith("config"):
                        break
            else:
                in_quote = stripped.count('"') % 2 == 1

    def children(self, header: int) -> list[int]:
        return [i for i in range(header + 1, self.close.get(header, header)) if self.parent[i] == header]

    def find(self, text: str, parent: Optional[int] = None) -> Optional[int]:
        wanted = " ".join(text.split()).lower()
        return next((i for i, raw in enumerate(self.lines)
                     if self.parent[i] == parent and " ".join(raw.split()).lower() == wanted), None)


def _forti_set(edits: Edits, tree: _FortiTree, header: int, key: str, value: str) -> None:
    """Replace ``set <key> …`` directly inside the block, else add it just before the block closes."""
    if header not in tree.close:
        raise ManualReview(f"The block '{tree.lines[header].strip()}' is not closed; it cannot be edited safely")
    lines = edits.lines
    children = tree.children(header)
    matches = [i for i in children if re.match(rf"(set|unset)\s+{re.escape(key)}(\s|$)", lines[i].strip(), re.IGNORECASE)]
    text = f"set {key} {value}"
    if matches:
        edits.set(matches[0], _indent(lines[matches[0]]) + text)
        for i in matches[1:]:
            edits.delete(i)
    else:
        indent = _indent(lines[children[0]]) if children else _indent(lines[header]) + "    "
        edits.insert_after(tree.close[header] - 1, [indent + text])


def _forti_global(edits: Edits, tree: _FortiTree, block: str, settings: list[tuple[str, str]]) -> None:
    header = tree.find(block)
    if header is None:
        edits.insert_after(len(edits.lines) - 1, [block, *(f"    set {k} {v}" for k, v in settings), "end"])
        return
    for key, value in settings:
        _forti_set(edits, tree, header, key, value)


# ── Cisco IOS recipes ───────────────────────────────────────────────────────

MGMT_ACL = "NETAUDIT_MGMT"
BANNER = "banner login ^Authorized access only. Activity on this device is monitored and logged.^"


def _vty_headers(ctx: Context, predicate) -> list[int]:
    headers = []
    for vty in ctx.config.management.vty_lines:
        header = _header(ctx.lines, vty.source_lines, "line vty")
        if header is not None and predicate(vty):
            headers.append(header)
    return headers


def ios_telnet(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    # implicit transport too: the platform default may allow Telnet, so the control cannot PASS without it
    for header in _vty_headers(ctx, lambda v: not v.transport_input or {"telnet", "all"} & set(v.transport_input)):
        _ios_set_child(edits, header, r"transport\s+input\b", "transport input ssh")
    return edits.apply()


def ios_http(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    cited = [n - 1 for r in ctx.fails for n in r.evidence.line_numbers]
    for index in _top_level(ctx.lines, "ip http server", cited):
        edits.set(index, "no ip http server")
    return edits.apply()


def ios_management_acl(ctx: Context) -> list[str]:
    headers = _vty_headers(ctx, lambda v: not v.access_class)
    if not headers:
        raise ManualReview("Every VTY range already has an access-class; review which source restriction is failing")
    edits = Edits(ctx.lines)
    if not any(acl.name == MGMT_ACL for acl in ctx.config.access_lists):
        (subnet,) = ctx.need("management_subnet")
        first = min(_vty_headers(ctx, lambda v: True))
        edits.insert_after(first - 1, [
            f"ip access-list standard {MGMT_ACL}",
            f" permit {subnet.network_address} {subnet.hostmask}",
            " deny any log",
            "!",
        ])
    for header in headers:
        _ios_set_child(edits, header, r"access-class\b", f"access-class {MGMT_ACL} in")
    return edits.apply()


def ios_snmp(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    for result in ctx.fails:
        for n in result.evidence.line_numbers:
            if re.match(r"snmp-server\s+community\s", ctx.lines[n - 1].strip(), re.IGNORECASE):
                # the community string is a secret: the comment names the scope, never the value
                edits.set(n - 1, f"! NetAuditAI: removed {result.scope} (default string or read-write without ACL)")
    return edits.apply()


def ios_passwords(ctx: Context) -> list[str]:
    if any(f.predicate == PASSWORD_STORAGE for r in ctx.fails for f in r.facts):
        raise ManualReview(
            "A weak password must be replaced with a new secret on the device "
            "('enable algorithm-type scrypt secret …', 'username … algorithm-type scrypt secret …'); "
            "a strong hash cannot be derived from the configuration"
        )
    edits = Edits(ctx.lines)
    negated = _top_level(ctx.lines, "no service password-encryption")
    if negated:
        edits.set(negated[0], "service password-encryption")
    else:
        hostname = _top_level(ctx.lines, f"hostname {ctx.config.device.hostname}")
        if hostname:
            edits.insert_after(hostname[0], ["service password-encryption"])
        else:
            _ios_insert_global(edits, ["service password-encryption"])
    return edits.apply()


def ios_idle_timeout(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    headers = _vty_headers(ctx, _bad_timeout)
    console = ctx.config.management.console
    if console and _bad_timeout(console):
        headers += [n - 1 for n in console.source_lines if ctx.lines[n - 1].strip().startswith("line con")]
    for header in headers:
        _ios_set_child(edits, header, r"exec-timeout\b", "exec-timeout 5 0")
    return edits.apply()


def ios_ssh_version(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    for index in _top_level(ctx.lines, "ip ssh version 1", [n - 1 for r in ctx.fails for n in r.evidence.line_numbers]):
        edits.set(index, "ip ssh version 2")
    return edits.apply()


def ios_aaa(ctx: Context) -> list[str]:
    auth = ctx.config.authentication
    if not any(str(u.password_type).lower() in STRONG_PASSWORD_STORAGE for u in auth.local_users):
        raise ManualReview(
            "No local account with a strong secret exists: enabling AAA with local login could lock administrators "
            "out. Create one first ('username … algorithm-type scrypt secret …') or configure TACACS+/RADIUS"
        )
    added = []
    if not auth.aaa_auth_methods:
        added.append("aaa authentication login default local")
    if not any(line.strip().startswith("aaa authorization exec") for line in ctx.lines):
        added.append("aaa authorization exec default local")
    edits = Edits(ctx.lines)
    negated = _top_level(ctx.lines, "no aaa new-model")
    if negated:
        edits.set(negated[0], "aaa new-model")
        edits.insert_after(negated[0], added)
    else:
        _ios_insert_global(edits, ["aaa new-model", *added])
    return edits.apply()


def ios_banner(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    _ios_insert_global(edits, [BANNER])
    return edits.apply()


def permit_any(ctx: Context) -> list[str]:
    raise ManualReview(
        "Replacing an any-to-any permit needs the intended sources, destinations and services; "
        "a deterministic rewrite could cut production traffic"
    )


LOGIN_BLOCK = "login block-for 900 attempts 3 within 120"
PASSWORD_MIN_LENGTH_LINE = "security passwords min-length 12"


def _ios_replace_global(ctx: Context, pattern: str, text: str) -> list[str]:
    """Remove every global line matching ``pattern`` and add ``text`` once."""
    edits = Edits(ctx.lines)
    for index, line in enumerate(ctx.lines):
        if not line[:1].isspace() and re.match(pattern, line.strip(), re.IGNORECASE):
            edits.delete(index)
    _ios_insert_global(edits, [text])
    return edits.apply()


def ios_login_block(ctx: Context) -> list[str]:
    return _ios_replace_global(ctx, r"login\s+block-for\s", LOGIN_BLOCK)


def ios_password_length(ctx: Context) -> list[str]:
    return _ios_replace_global(ctx, r"security\s+passwords\s+min-length\s", PASSWORD_MIN_LENGTH_LINE)


def forti_password_policy(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    _forti_global(edits, _FortiTree(ctx.lines), "config system password-policy",
                  [("status", "enable"), ("minimum-length", "12")])
    return edits.apply()


IOS_STRONG_ALGORITHMS = {
    "encryption": "aes256-ctr aes192-ctr aes128-ctr",
    "mac": "hmac-sha2-512 hmac-sha2-256",
    "kex": "ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group14-sha256",
}


def ios_management_crypto(ctx: Context) -> list[str]:
    """Replace each SSH algorithm list that allows a weak algorithm with a strong one of the same kind."""
    edits = Edits(ctx.lines)
    for index, line in enumerate(ctx.lines):
        match = re.match(r"^ip\s+ssh\s+server\s+algorithm\s+(encryption|mac|kex)\s+(.+)$", line.strip(), re.IGNORECASE)
        if match and any(L.is_weak_algorithm(t) for t in match.group(2).split()):
            edits.set(index, f"ip ssh server algorithm {match.group(1).lower()} {IOS_STRONG_ALGORITHMS[match.group(1).lower()]}")
        elif re.match(r"^ip\s+http\s+secure-ciphersuite\s", line.strip(), re.IGNORECASE):
            raise ManualReview("An HTTPS cipher-suite list depends on the browsers and tools that manage the device; "
                               "choose its strong suites by hand")
    return edits.apply()


def forti_management_crypto(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    settings = [("strong-crypto", "enable")]
    for switch in ("ssh-cbc-cipher", "ssh-hmac-md5", "ssh-kex-sha1"):
        if any(re.match(rf"^\s*set\s+{switch}\s+enable\s*$", line, re.IGNORECASE) for line in ctx.lines):
            settings.append((switch, "disable"))
    _forti_global(edits, _FortiTree(ctx.lines), "config system global", settings)
    return edits.apply()


def forti_policy_logging(ctx: Context) -> list[str]:
    edits, tree = Edits(ctx.lines), _FortiTree(ctx.lines)
    failing = ctx.scopes("firewall policy ")
    for policy in ctx.config.firewall_policies:
        if policy.policy_id in failing and policy.source_lines:
            _forti_set(edits, tree, tree.parent[policy.source_lines[0] - 1], "logtraffic", "all")
    return edits.apply()


def default_account_review(ctx: Context) -> list[str]:
    raise ManualReview(
        "Replacing a default account needs a new named administrator with its own password, created and tested "
        "before the default one is removed; doing it from here could lock every administrator out"
    )


def snmp_v3_migration(ctx: Context) -> list[str]:
    raise ManualReview(
        "Moving to SNMPv3 needs users with authentication and privacy keys that only the operator can choose, "
        "and every SNMP manager has to be reconfigured to match; removing the communities alone would cut "
        "monitoring without replacing it"
    )


def ios_source_route(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    for index in _top_level(ctx.lines, "ip source-route", [n - 1 for r in ctx.fails for n in r.evidence.line_numbers]):
        edits.set(index, "no ip source-route")
    return edits.apply()


def ios_cdp(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    for iface in ctx.config.interfaces:
        header = _header(ctx.lines, iface.source_lines, "interface")
        if iface.is_wan and iface.cdp_enabled is not False and header is not None:
            _ios_set_child(edits, header, r"(no\s+)?cdp\s+enable\b", "no cdp enable")
    return edits.apply()


def ios_router_services(ctx: Context) -> list[str]:
    edits = Edits(ctx.lines)
    failing = ctx.scopes("interface ")
    for iface in ctx.config.interfaces:
        header = _header(ctx.lines, iface.source_lines, "interface")
        if iface.name in failing and header is not None:
            _ios_set_child(edits, header, r"(no\s+)?ip\s+redirects\b", "no ip redirects")
            _ios_set_child(edits, header, r"(no\s+)?ip\s+proxy-arp\b", "no ip proxy-arp")
            _ios_set_child(edits, header, r"(no\s+)?ip\s+directed-broadcast\b", "no ip directed-broadcast")
    return edits.apply()


def ios_syslog(ctx: Context) -> list[str]:
    (server,) = ctx.need("syslog_server")
    edits = Edits(ctx.lines)
    _ios_insert_global(edits, [f"logging host {server}"])
    return edits.apply()


def ios_ntp(ctx: Context) -> list[str]:
    ntp = ctx.config.ntp
    names = ["ntp_key_id"]
    if not ntp.authentication_enabled:
        names.append("ntp_key")
    if not ntp.servers:
        names.append("ntp_server")
    values = dict(zip(names, ctx.need(*names)))
    key_id = values["ntp_key_id"]

    edits = Edits(ctx.lines)
    added = []
    if not ntp.authentication_enabled:
        added += [f"ntp authentication-key {key_id} md5 {values['ntp_key']}", "ntp authenticate",
                  f"ntp trusted-key {key_id}"]
    for n in ntp.source_lines:
        line = ctx.lines[n - 1]
        if re.match(r"ntp\s+server\s", line.strip()) and not re.search(r"\skey\s", line):
            edits.set(n - 1, f"{line.rstrip()} key {key_id}")
    if not ntp.servers:
        added.append(f"ntp server {values['ntp_server']} key {key_id}")
    _ios_insert_global(edits, added)
    return edits.apply()


_IOS_TRANSFORM = {"esp-des": "esp-aes 256", "esp-3des": "esp-aes 256"}


def ios_crypto(ctx: Context) -> list[str]:
    names = ctx.scopes("proposal ")
    edits = Edits(ctx.lines)
    for proposal in ctx.config.vpn.ipsec_proposals:
        if proposal.name not in names or not proposal.source_lines:
            continue
        header = proposal.source_lines[0] - 1
        text = ctx.lines[header].strip()
        if text.startswith("crypto isakmp policy"):
            encryption = (proposal.encryption or "").lower()
            if not encryption or any(w in encryption for w in WEAK_ENCRYPTION):
                _ios_set_child(edits, header, r"encr(yption)?\b", "encr aes 256")
            if any(w in (proposal.hash_algorithm or "").lower() for w in WEAK_HASH):
                _ios_set_child(edits, header, r"hash\b", "hash sha256")
            if proposal.dh_group in WEAK_DH_GROUPS:
                _ios_set_child(edits, header, r"group\b", "group 14")
        elif text.startswith("crypto ipsec transform-set"):
            tokens = text.split()
            fixed = tokens[:4] + [_IOS_TRANSFORM.get(t.lower(), t.lower().replace("md5", "sha256")
                                                     if "md5" in t.lower() else t) for t in tokens[4:]]
            edits.set(header, " ".join(fixed))
        else:
            raise ManualReview(f"Proposal '{proposal.name}' is not an ISAKMP policy or transform set")
    return edits.apply()


# ── FortiGate recipes ───────────────────────────────────────────────────────

def _forti_allowaccess(ctx: Context, interfaces: set[str], remove: set[str]) -> list[str]:
    edits = Edits(ctx.lines)
    for iface in ctx.config.interfaces:
        if iface.name not in interfaces:
            continue
        for n in iface.source_lines:
            line = ctx.lines[n - 1]
            if re.match(r"set\s+allowaccess\s", line.strip(), re.IGNORECASE):
                kept = [t for t in line.split()[2:] if t.lower() not in remove]
                edits.set(n - 1, _indent(line) + ("set allowaccess " + " ".join(kept) if kept else "unset allowaccess"))
    return edits.apply()


def forti_telnet(ctx: Context) -> list[str]:
    return _forti_allowaccess(ctx, ctx.scopes("interface "), {"telnet"})


def forti_http(ctx: Context) -> list[str]:
    return _forti_allowaccess(ctx, ctx.scopes("interface "), {"http"})


def forti_wan_management(ctx: Context) -> list[str]:
    return _forti_allowaccess(ctx, ctx.scopes("interface "), {"telnet", "http", "https", "ssh"})


def forti_wan_exposure(ctx: Context) -> list[str]:
    # CIS FortiGate 1.3: every management-related service, not only the login protocols
    return _forti_allowaccess(ctx, ctx.scopes("interface "), {"telnet", "http", "https", "ssh", "snmp", "fgfm"})


def remove_default_snmp_communities(config_text: str) -> str:
    """Comment out whole SNMP community edit blocks with default names like 'public'.

    The block is buffered from its ``edit`` to the matching ``next`` so nested
    sections (``config hosts`` / ``edit`` / ``next`` / ``end``) are commented
    together with it; commenting only some of them unbalances the FortiOS
    config/edit nesting and the output no longer verifies as FortiOS.
    """
    import shlex

    default_names = DEFAULT_SNMP_COMMUNITIES
    result: list[str] = []
    in_section = False
    block: list[str] | None = None  # lines of the current community edit block
    depth = 0                       # nested config/edit levels inside that block
    is_default = False

    for line in config_text.splitlines():
        stripped = line.strip()
        verb = stripped.split()[0] if stripped else ''

        if not in_section:
            result.append(line)
            in_section = stripped == 'config system snmp community'
            continue

        if block is None:
            if verb == 'edit':
                block, depth, is_default = [line], 0, False
            else:
                result.append(line)
                if verb == 'end':
                    in_section = False
            continue

        block.append(line)
        if verb in ('config', 'edit'):
            depth += 1
        elif verb in ('next', 'end') and depth > 0:
            depth -= 1
        elif verb == 'set' and depth == 0 and stripped.split()[1:2] == ['name']:
            try:
                name = shlex.split(stripped)[2]
            except (ValueError, IndexError):
                name = stripped.split('"')[1] if '"' in stripped else ''
            is_default = name.lower() in default_names
        elif verb == 'next':  # closes the community edit block
            if is_default:
                result.extend(
                    f'# {l.lstrip()}  # REMEDIATED: default community removed'
                    if l.strip().startswith('set name') else f'# {l.lstrip()}'
                    for l in block
                )
            else:
                result.extend(block)
            block = None

    if block is not None:  # unterminated block: leave it untouched
        result.extend(block)
    return '\n'.join(result)


def forti_snmp(ctx: Context) -> list[str]:
    return remove_default_snmp_communities("\n".join(ctx.lines)).split("\n")


def _forti_global_recipe(block: str, key: str, value: str) -> Callable[[Context], list[str]]:
    def build(ctx: Context) -> list[str]:
        edits = Edits(ctx.lines)
        _forti_global(edits, _FortiTree(ctx.lines), block, [(key, value)])
        return edits.apply()
    return build


def forti_lldp(ctx: Context) -> list[str]:
    edits, tree = Edits(ctx.lines), _FortiTree(ctx.lines)
    names = ctx.scopes("interface ")
    for iface in ctx.config.interfaces:
        if iface.name in names and iface.lldp_enabled and iface.source_lines:
            _forti_set(edits, tree, tree.parent[iface.source_lines[0] - 1], "lldp-transmission", "disable")
    return edits.apply()


def forti_syslog(ctx: Context) -> list[str]:
    (server,) = ctx.need("syslog_server")
    edits = Edits(ctx.lines)
    _forti_global(edits, _FortiTree(ctx.lines), "config log syslogd setting",
                  [("status", "enable"), ("server", f'"{server}"')])
    return edits.apply()


def forti_ntp(ctx: Context) -> list[str]:
    ntp = ctx.config.ntp
    names = ["ntp_key_id", "ntp_key"] + ([] if ntp.servers else ["ntp_server"])
    values = dict(zip(names, ctx.need(*names)))
    auth = ["set authentication enable", f"set key-id {values['ntp_key_id']}", f"set key {values['ntp_key']}"]
    edits, tree = Edits(ctx.lines), _FortiTree(ctx.lines)

    def new_server(indent: str, edit_id: int) -> list[str]:
        inner = indent + "    "
        return [f"{indent}edit {edit_id}", f'{inner}set server "{values.get("ntp_server")}"',
                *(inner + a for a in auth), f"{indent}next"]

    header = tree.find("config system ntp")
    if header is None:
        edits.insert_after(len(ctx.lines) - 1, [
            "config system ntp", "    set ntpsync enable", "    set type custom", "    set authentication enable",
            "    config ntpserver", *new_server("        ", 1), "    end", "end",
        ])
        return edits.apply()

    _forti_set(edits, tree, header, "authentication", "enable")
    servers = tree.find("config ntpserver", header)
    entries = [i for i in tree.children(servers) if ctx.lines[i].strip().startswith("edit")] if servers is not None else []
    if ntp.servers:
        for entry in entries:
            _forti_set(edits, tree, entry, "authentication", "enable")
            _forti_set(edits, tree, entry, "key-id", str(values["ntp_key_id"]))
            _forti_set(edits, tree, entry, "key", values["ntp_key"])
        return edits.apply()

    _forti_set(edits, tree, header, "ntpsync", "enable")
    _forti_set(edits, tree, header, "type", "custom")
    indent = _indent(ctx.lines[header]) + "    "
    if servers is None:
        edits.insert_after(tree.close[header] - 1, [f"{indent}config ntpserver", *new_server(indent + "    ", 1),
                                                    f"{indent}end"])
    else:
        ids = [int(t) for i in entries if (t := ctx.lines[i].split()[1].strip('"')).isdigit()]
        edits.insert_after(tree.close[servers] - 1, new_server(_indent(ctx.lines[servers]) + "    ", max(ids, default=0) + 1))
    return edits.apply()


def _weak_forti_proposal(token: str) -> bool:
    encryption, _, hash_algorithm = token.lower().partition("-")
    return encryption in WEAK_ENCRYPTION or any(w in hash_algorithm for w in WEAK_HASH)


def forti_crypto(ctx: Context) -> list[str]:
    names = ctx.scopes("proposal ")
    edits, tree = Edits(ctx.lines), _FortiTree(ctx.lines)
    for proposal in ctx.config.vpn.ipsec_proposals:
        if proposal.name not in names or not proposal.source_lines:
            continue
        header = tree.parent[proposal.source_lines[0] - 1]
        children = {ctx.lines[i].split()[1].lower(): i for i in tree.children(header)
                    if len(ctx.lines[i].split()) > 1 and ctx.lines[i].strip().startswith("set ")}
        if "proposal" in children:
            tokens = ctx.lines[children["proposal"]].split()[2:]
            kept = [t for t in tokens if not _weak_forti_proposal(t)] or ["aes256-sha256"]
            edits.set(children["proposal"], _indent(ctx.lines[children["proposal"]]) + "set proposal " + " ".join(kept))
        else:
            _forti_set(edits, tree, header, "proposal", "aes256-sha256")
        if "dhgrp" in children:
            groups = ctx.lines[children["dhgrp"]].split()[2:]
            kept = [g for g in groups if not (g.isdigit() and int(g) in WEAK_DH_GROUPS)] or ["14"]
            edits.set(children["dhgrp"], _indent(ctx.lines[children["dhgrp"]]) + "set dhgrp " + " ".join(kept))
    return edits.apply()


# ── registry ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Recipe:
    build: Callable[[Context], list[str]]
    explanation: str
    inputs: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


_PEER = "Both VPN peers must be changed together, or the tunnel will not come up."
_LOCKOUT = "Confirm you can still reach the device from the trusted network before deploying."

RECIPES: dict[tuple[str, Vendor], Recipe] = {
    ("MGMT-001", Vendor.CISCO_IOS): Recipe(
        ios_telnet, "Sets 'transport input ssh' on every VTY range that allows Telnet or relies on the default.",
        warnings=("SSH must be configured (host keys, 'ip ssh version 2') or remote access is lost.",)),
    ("MGMT-001", Vendor.FORTINET): Recipe(forti_telnet, "Removes 'telnet' from allowaccess on the failing interfaces."),
    ("MGMT-002", Vendor.CISCO_IOS): Recipe(ios_http, "Replaces 'ip http server' with 'no ip http server'."),
    ("MGMT-002", Vendor.FORTINET): Recipe(forti_http, "Removes 'http' from allowaccess on the failing WAN interfaces."),
    ("MGMT-003", Vendor.CISCO_IOS): Recipe(
        ios_management_acl, f"Creates standard ACL {MGMT_ACL} for the management subnet and applies it with "
                            "'access-class … in' to every VTY range without one.",
        inputs=("management_subnet",), warnings=(_LOCKOUT,)),
    ("MGMT-003", Vendor.FORTINET): Recipe(
        forti_wan_management, "Removes management services (telnet, http, https, ssh) from allowaccess on WAN interfaces.",
        warnings=(_LOCKOUT,)),
    ("MGMT-010", Vendor.FORTINET): Recipe(
        forti_wan_exposure, "Removes every management service (telnet, http, https, ssh, snmp, fgfm) from "
                            "allowaccess on the failing WAN interfaces.",
        warnings=(_LOCKOUT,)),
    ("MGMT-004", Vendor.CISCO_IOS): Recipe(
        ios_snmp, "Comments out SNMP communities that use a default string or grant read-write access without an ACL.",
        warnings=("SNMP managers using these communities lose access; configure SNMPv3 for monitoring.",)),
    ("MGMT-004", Vendor.FORTINET): Recipe(
        forti_snmp, "Comments out every SNMP community block with a default name, nested hosts included.",
        warnings=("SNMP managers using these communities lose access; configure SNMPv3 for monitoring.",
                  "The removed block is kept as '#' comment lines. NetAuditAI's FortiOS grammar ignores them, but "
                  "whether your restore method accepts them was not verified on a device: delete those lines "
                  "(or run 'delete <id>' under 'config system snmp community') if it does not.")),
    ("MGMT-005", Vendor.CISCO_IOS): Recipe(
        ios_passwords, "Enables 'service password-encryption'. Weak stored passwords need a new secret set on the device."),
    ("MGMT-006", Vendor.CISCO_IOS): Recipe(
        ios_idle_timeout, "Sets 'exec-timeout 5 0' on every VTY range and console line without a valid idle timeout."),
    ("MGMT-006", Vendor.FORTINET): Recipe(_forti_global_recipe("config system global", "admintimeout", "5"),
                                          "Sets 'set admintimeout 5' in system global."),
    ("MGMT-007", Vendor.CISCO_IOS): Recipe(ios_ssh_version, "Replaces 'ip ssh version 1' with 'ip ssh version 2'."),
    ("MGMT-007", Vendor.FORTINET): Recipe(_forti_global_recipe("config system global", "admin-ssh-v1", "disable"),
                                          "Sets 'set admin-ssh-v1 disable' in system global."),
    ("MGMT-008", Vendor.CISCO_IOS): Recipe(
        ios_aaa, "Enables 'aaa new-model' with local login and exec authorization, only when a local account "
                 "with a strong secret exists.", warnings=(_LOCKOUT,)),
    ("MGMT-009", Vendor.CISCO_IOS): Recipe(ios_banner, "Adds a login banner with a legal warning."),
    ("MGMT-009", Vendor.FORTINET): Recipe(_forti_global_recipe("config system global", "pre-login-banner", "enable"),
                                          "Sets 'set pre-login-banner enable' in system global."),
    ("MGMT-011", Vendor.CISCO_IOS): Recipe(snmp_v3_migration, "SNMPv3 users and keys are the operator's to choose."),
    ("MGMT-011", Vendor.FORTINET): Recipe(snmp_v3_migration, "SNMPv3 users and keys are the operator's to choose."),
    ("AUTH-001", Vendor.CISCO_IOS): Recipe(
        ios_login_block, f"Adds '{LOGIN_BLOCK}': three failed logins within two minutes block logins for 15 minutes.",
        warnings=("During a block, legitimate administrators cannot log in either; define a 'login quiet-mode "
                  "access-class' for the management network if needed.",)),
    ("AUTH-001", Vendor.FORTINET): Recipe(_forti_global_recipe("config system global", "admin-lockout-threshold", "3"),
                                          "Sets 'set admin-lockout-threshold 3' in system global."),
    ("AUTH-002", Vendor.CISCO_IOS): Recipe(
        ios_password_length, f"Adds '{PASSWORD_MIN_LENGTH_LINE}'.",
        warnings=("Applies to passwords set from now on; existing shorter passwords keep working until changed.",)),
    ("AUTH-002", Vendor.FORTINET): Recipe(
        forti_password_policy, "Enables 'config system password-policy' with a minimum length of 12.",
        warnings=("Applies to passwords set from now on; existing shorter passwords keep working until changed.",)),
    ("AUTH-003", Vendor.CISCO_IOS): Recipe(default_account_review, "Named accounts need new credentials."),
    ("AUTH-003", Vendor.FORTINET): Recipe(default_account_review, "Named accounts need new credentials."),
    ("BOUNDARY-004", Vendor.CISCO_IOS): Recipe(
        ios_router_services, "Adds 'no ip redirects', 'no ip proxy-arp' and 'no ip directed-broadcast' to the failing "
                             "interfaces.",
        warnings=("Hosts that relied on proxy-ARP (a missing default gateway or a wrong subnet mask) lose "
                  "connectivity until they are configured correctly.",)),
    ("CRYPTO-002", Vendor.CISCO_IOS): Recipe(
        ios_management_crypto, "Replaces each weak SSH algorithm list with AES-CTR ciphers, SHA-2 MACs and ECDH / "
                               "DH group 14 key exchange.",
        warnings=("Old SSH clients that only speak the removed algorithms can no longer connect.",)),
    ("CRYPTO-002", Vendor.FORTINET): Recipe(
        forti_management_crypto, "Sets 'set strong-crypto enable' and disables the weak SSH switches in system global.",
        warnings=("Old SSH / HTTPS clients that only speak the removed algorithms can no longer connect.",)),
    ("LOG-003", Vendor.FORTINET): Recipe(forti_policy_logging, "Sets 'set logtraffic all' on the failing policies.",
                                         warnings=("Logging all traffic raises log volume; size the log server for it.",)),
    ("BOUNDARY-001", Vendor.CISCO_IOS): Recipe(permit_any, "Any-to-any rules need an operator-defined replacement."),
    ("BOUNDARY-001", Vendor.FORTINET): Recipe(permit_any, "Any-to-any policies need an operator-defined replacement."),
    ("BOUNDARY-002", Vendor.CISCO_IOS): Recipe(ios_source_route, "Replaces 'ip source-route' with 'no ip source-route'."),
    ("BOUNDARY-002", Vendor.FORTINET): Recipe(_forti_global_recipe("config system settings", "ip-src-routing", "disable"),
                                              "Sets 'set ip-src-routing disable' in system settings."),
    ("BOUNDARY-003", Vendor.CISCO_IOS): Recipe(ios_cdp, "Adds 'no cdp enable' to every external interface running CDP."),
    ("BOUNDARY-003", Vendor.FORTINET): Recipe(forti_lldp, "Sets 'set lldp-transmission disable' on the failing WAN interfaces."),
    ("LOG-001", Vendor.CISCO_IOS): Recipe(ios_syslog, "Adds 'logging host <syslog server>'.", inputs=("syslog_server",)),
    ("LOG-001", Vendor.FORTINET): Recipe(forti_syslog, "Enables syslogd with the given server.", inputs=("syslog_server",)),
    ("LOG-002", Vendor.CISCO_IOS): Recipe(
        ios_ntp, "Adds an NTP authentication key, 'ntp authenticate', the trusted key, and the key on every NTP server "
                 "(adding a server when none is configured).", inputs=("ntp_server", "ntp_key_id", "ntp_key")),
    ("LOG-002", Vendor.FORTINET): Recipe(
        forti_ntp, "Enables NTP authentication with the given key on every NTP server (adding a server when none is "
                   "configured).", inputs=("ntp_server", "ntp_key_id", "ntp_key")),
    ("CRYPTO-001", Vendor.CISCO_IOS): Recipe(
        ios_crypto, "Upgrades weak ISAKMP policies and transform sets to AES-256, SHA-256 and DH group 14.",
        warnings=(_PEER,)),
    ("CRYPTO-001", Vendor.FORTINET): Recipe(
        forti_crypto, "Removes weak proposals (DES/3DES/MD5) and DH groups 1/2/5 from the failing phase1 interfaces.",
        warnings=(_PEER,)),
}
