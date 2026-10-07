"""
Facts from a NormalizedConfig.

* Confirmed vendor (Cisco IOS, FortiGate): facts come from the parser model,
  assurance PARSER (or the weaker assurance of adaptive mappings the parser
  model absorbed on the cited lines). Vendor knowledge lives here: which block
  answers a question and when absence is meaningful (``NOT_SET``).
* Any other vendor: admin-confirmed recognizers (CONFIRMED), applied adaptive mappings
  (assurance of their source) and lexicon heuristics (HEURISTIC). Absence is never evidence.

Citations reproduce the lines the Phase 0 rules cited, so findings stay identical.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional

from app.facts import lexicon as L
from app.facts.heuristics import heuristic_facts
from app.facts.recognizers import recognize
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, FIELD_PREDICATES, IDLE_TIMEOUT, IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, LOGIN_BANNER,
    MGMT_EXPOSED, LOGIN_MAX_ATTEMPTS, PASSWORD_MIN_LENGTH, ADMIN_ACCOUNT, MGMT_WEAK_CRYPTO, RULE_LOGGING,
    ROUTER_UNSAFE_SERVICE, SNMPV3_SECURITY, ROUTING_AUTH, MGMT_TLS_MIN, INTERFACE_UNUSED_UP,
    NOT_SET, NTP_AUTHENTICATED, NTP_SERVER, PASSWORD_ENCRYPTION_SERVICE, PASSWORD_STORAGE, PERMIT_ANY,
    PREDICATES, PROTOCOL_ENABLED, SNMP_COMMUNITY, SOURCE_RESTRICTED, SOURCE_ROUTING, SSH_VERSION, SecurityFact,
)
from app.models.field_catalog import FIELD_REGISTRY, TYPE_LIST_STR
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import Assurance, Evidence

SOURCE_ASSURANCE = {
    "learned_mapping": Assurance.CONFIRMED,
    "admin_confirmed": Assurance.CONFIRMED,
    "ai_auto_mapped": Assurance.AI_VERIFIED,
}
# Weakest first: a decision is only as strong as its weakest evidence
ASSURANCE_STRENGTH = [
    Assurance.AI_VERIFIED, Assurance.HEURISTIC, Assurance.DEFAULT, Assurance.CONFIRMED, Assurance.PARSER,
]

# Predicates each vendor parser reads. A confirmed vendor with no fact for a
# covered predicate has it not configured; an uncovered one stays UNKNOWN.
PARSER_COVERAGE: dict[Vendor, frozenset[str]] = {
    Vendor.CISCO_IOS: PREDICATES,
    Vendor.FORTINET: PREDICATES - {CENTRAL_AAA, PASSWORD_STORAGE, PASSWORD_ENCRYPTION_SERVICE},
}

_MGMT_SERVICES = {"ssh", "https", "http", "telnet"}
# services that manage the device (fgfm: FortiManager access); ping is a diagnostic, not a management service
_EXPOSED_SERVICES = _MGMT_SERVICES | {"snmp", "fgfm"}
_ANY_ADDRESS = {"any", "all", "0.0.0.0", "0.0.0.0/0"}


def weakest(levels: Iterable[Optional[Assurance]]) -> Optional[Assurance]:
    present = [level for level in levels if level is not None]
    return min(present, key=ASSURANCE_STRENGTH.index) if present else None


def facts_from_config(config: NormalizedConfig, extra_recognizers: Iterable = ()) -> list[SecurityFact]:
    """``extra_recognizers``: unsaved recognizers applied as if stored (replay)."""
    if config.device.vendor in PARSER_COVERAGE:
        return _ParserFacts(config).build()
    # A recognizer answers the lines it matches; mappings and heuristics on those lines step aside.
    # Other lines still speak, so a recognizer never hides a contradicting statement elsewhere.
    recognized, skip, absence = recognize(config.raw_lines, extra_recognizers)
    # A recognizer answers for the whole setting, not only for its own line: a heuristic elsewhere that
    # repeats that answer (the server address inside a block whose header was recognized) adds nothing
    # but its weaker assurance, which would drag the control down to provisional. One that contradicts
    # it still speaks, so a recognizer never hides a statement that disagrees with it.
    answered = {(f.predicate, f.subject): repr(f.value) for f in recognized}
    # An admin-confirmed mapping answers its predicate. AI mappings and lexicon heuristics are both
    # provisional: when they disagree neither wins, the fact is undetermined and cites both.
    facts = [m for m in _mapped_facts(config) if not (skip and set(m.evidence.line_numbers) <= skip)]
    by_key = {(f.predicate, f.subject): index for index, f in enumerate(facts)}
    for heuristic in heuristic_facts(config.raw_lines, skip):
        if answered.get((heuristic.predicate, heuristic.subject)) == repr(heuristic.value):
            continue
        index = by_key.get((heuristic.predicate, heuristic.subject))
        if index is None:
            facts.append(heuristic)
            continue
        mapped = facts[index]
        if (mapped.assurance == Assurance.CONFIRMED or mapped.value is None or isinstance(mapped.value, list)
                or repr(mapped.value) == repr(heuristic.value)):
            continue
        lines = sorted({*mapped.evidence.line_numbers, *heuristic.evidence.line_numbers})
        facts[index] = SecurityFact(
            mapped.predicate, None, Assurance.AI_VERIFIED,
            Evidence(line_numbers=lines, text=[config.raw_lines[n - 1] for n in lines]),
            subject=mapped.subject, scope=mapped.scope, unit=mapped.unit,
            provenance=f"The AI mapping and the lexicon heuristic disagree (lines {', '.join(map(str, lines))})",
        )
    # AI judge facts (provisional) step aside for any line a recognizer answered or an admin rejected
    judged = [f for f in config.ai_facts if not set(f.evidence.line_numbers) & skip]
    known = recognized + facts + judged
    # a setting no device ships with, that this understood dialect would state and nothing does, is not set
    return known + absence(known)


# ── confirmed vendors ───────────────────────────────────────────────────────

def _lines(*objects) -> list[int]:
    return [n for obj in objects for n in obj.source_lines]


class _ParserFacts:
    def __init__(self, config: NormalizedConfig):
        self.config = config
        self.facts: list[SecurityFact] = []
        self.mapped = {
            m.line_number: SOURCE_ASSURANCE[m.source]
            for m in config.ai_mappings if m.applied and m.source in SOURCE_ASSURANCE
        }

    def build(self) -> list[SecurityFact]:
        cisco = self.config.device.vendor == Vendor.CISCO_IOS
        (self._cisco if cisco else self._fortinet)()
        self._common()
        return self.facts

    def add(self, predicate, value, lines: Iterable[int] = (), subject=None, scope=None, unit=None, provenance=""):
        config = self.config
        numbers = [n for n in lines if 1 <= n <= len(config.raw_lines)]
        levels = {self.mapped[n] for n in numbers if n in self.mapped}
        if not numbers or any(n not in self.mapped for n in numbers):
            levels.add(Assurance.PARSER)
        self.facts.append(SecurityFact(
            predicate, value, weakest(levels),
            Evidence(line_numbers=numbers, text=[config.raw_lines[n - 1] for n in numbers]),
            subject=subject, scope=scope, unit=unit,
            provenance=provenance or f"{config.device.vendor.value} parser",
        ))

    def matching(self, lines: Iterable[int], pattern: str) -> list[int]:
        regex = re.compile(pattern, re.IGNORECASE)
        raw = self.config.raw_lines
        return [n for n in lines if 1 <= n <= len(raw) and regex.search(raw[n - 1])]

    def with_mapped(self, lines: Iterable[int], *fields: str) -> list[int]:
        """``lines`` plus the lines of adaptive mappings that wrote ``fields`` (ordered, unique)."""
        mapped = [m.line_number for m in self.config.ai_mappings if m.applied and m.normalized_field in fields]
        return list(dict.fromkeys([*lines, *mapped]))

    # Cisco IOS ----------------------------------------------------------------

    def _cisco(self):
        c = self.config
        mgmt, auth, services = c.management, c.authentication, c.services
        vtys = mgmt.vty_lines

        # Several VTY ranges answer as one scope: the first offending range, else all of them
        if vtys:
            telnet = [v for v in vtys if {"telnet", "all"} & set(v.transport_input)]
            implicit = [v for v in vtys if not v.transport_input]
            if telnet:
                self.add(PROTOCOL_ENABLED, True, telnet[0].source_lines, "telnet", f"line vty {telnet[0].line_range}")
            elif implicit:
                self.add(PROTOCOL_ENABLED, None, _lines(*implicit), "telnet", f"line vty {implicit[0].line_range}",
                         provenance=f"VTY {implicit[0].line_range} has no 'transport input'; the platform default decides")
            else:
                self.add(PROTOCOL_ENABLED, False, _lines(*vtys), "telnet", "line vty")

            open_vty = next((v for v in vtys if not v.access_class), None)
            if open_vty:
                self.add(SOURCE_RESTRICTED, False, open_vty.source_lines, scope=f"line vty {open_vty.line_range}",
                         provenance=f"VTY lines ({open_vty.line_range}) have no access-class")
            else:
                self.add(SOURCE_RESTRICTED, True, _lines(*vtys), scope="line vty")

            no_timeout = next((v for v in vtys if not v.has_timeout), None)
            if no_timeout:
                self.add(IDLE_TIMEOUT, _timeout(no_timeout), no_timeout.source_lines,
                         scope=f"line vty {no_timeout.line_range}", unit="min")
            else:
                worst = max(vtys, key=_timeout)
                self.add(IDLE_TIMEOUT, _timeout(worst), _lines(*vtys), scope="line vty", unit="min")

        if mgmt.console:
            self.add(IDLE_TIMEOUT, _timeout(mgmt.console), mgmt.console.source_lines, scope="line con 0", unit="min")

        if mgmt.http_enabled:
            self.add(PROTOCOL_ENABLED, True, mgmt.source_lines, "http")
        elif disabled := self.matching(mgmt.source_lines, r"^\s*no ip http server\s*$"):
            self.add(PROTOCOL_ENABLED, False, disabled, "http")

        if auth.enable_password_type:
            self.add(PASSWORD_STORAGE, auth.enable_password_type, auth.source_lines, "enable", "enable password")
        for user in auth.local_users:
            self.add(PASSWORD_STORAGE, user.password_type, user.source_lines,
                     f"user {user.username}", f"user {user.username}")
        self.add(PASSWORD_ENCRYPTION_SERVICE, True if services.password_encryption else NOT_SET,
                 services.source_lines, scope="service password-encryption")

        if auth.aaa_enabled:
            self.add(CENTRAL_AAA, True, self.matching(auth.source_lines, r"^\s*aaa new-model"))
        else:
            self.add(CENTRAL_AAA, NOT_SET, auth.source_lines)

        present = bool(c.banners.login_banner or c.banners.motd_banner)
        self.add(LOGIN_BANNER, True if present else NOT_SET, c.banners.source_lines)

        # IOS has no failed-login limit and no password length rule unless one is configured
        limits = [(n, int(m.group(1))) for n, line in enumerate(c.raw_lines, 1) if (m := _IOS_LOGIN_LIMIT.match(line))]
        if limits:
            number, attempts = min(limits, key=lambda item: item[1])
            self.add(LOGIN_MAX_ATTEMPTS, attempts, [number])
        else:
            self.add(LOGIN_MAX_ATTEMPTS, NOT_SET, ())
        lengths = [(n, int(m.group(1))) for n, line in enumerate(c.raw_lines, 1) if (m := _IOS_MIN_LENGTH.match(line))]
        if lengths:
            self.add(PASSWORD_MIN_LENGTH, lengths[-1][1], [lengths[-1][0]])
        else:
            self.add(PASSWORD_MIN_LENGTH, NOT_SET, ())
        # IOS sends ICMP redirects and answers proxy-ARP on a routed interface unless told not to; directed
        # broadcasts are off unless turned on. A verdict that rests on those defaults says so (assurance DEFAULT).
        for iface in c.interfaces:
            if not iface.ip_address or iface.shutdown or re.match(r"(?i)(loopback|null)", iface.name):
                continue
            texts = [" ".join(c.raw_lines[n - 1].split()).lower() for n in iface.source_lines
                     if 1 <= n <= len(c.raw_lines)]
            on, by_default = [], False
            for feature, off in (("ICMP redirects", "no ip redirects"), ("proxy-ARP", "no ip proxy-arp")):
                if off not in texts:
                    on.append(feature)
                    by_default = by_default or feature.split()[-1].lower() not in " ".join(texts)
            if "ip directed-broadcast" in texts:
                on.append("directed broadcasts")
            numbers = [n for n in iface.source_lines if 1 <= n <= len(c.raw_lines)]
            self.facts.append(SecurityFact(
                ROUTER_UNSAFE_SERVICE, bool(on), Assurance.DEFAULT if by_default else Assurance.PARSER,
                Evidence(line_numbers=numbers, text=[c.raw_lines[n - 1] for n in numbers]),
                scope=f"interface {iface.name}",
                provenance=(f"{' and '.join(on)} are enabled on interface {iface.name}"
                            + (" (IOS defaults: nothing turns them off)" if by_default else "")) if on else "",
            ))

        # An algorithm list is the whole allowed set; with none, the IOS release's defaults decide (not claimed)
        for number, line in enumerate(c.raw_lines, 1):
            if match := _IOS_ALGORITHMS.match(line):
                weak = [t for t in match.group(2).split() if L.is_weak_algorithm(t)]
                what = "HTTPS cipher suites" if match.group(1).lower().startswith("http") else \
                    f"SSH {match.group(1).split()[-1].lower()} algorithms"
                self.add(MGMT_WEAK_CRYPTO, bool(weak), [number], scope=what,
                         provenance=f"The {what} include {', '.join(weak)}" if weak else "")
        for user in auth.local_users:
            self.add(ADMIN_ACCOUNT, user.username, user.source_lines, scope=f"user {user.username}")
        if not auth.local_users:
            self.add(ADMIN_ACCOUNT, NOT_SET, ())

        for acl in c.access_lists:
            for entry in acl.entries:
                permit_any = (entry.action == "permit" and _is_any(entry.source) and _is_any(entry.destination)
                              and entry.protocol in (None, "ip"))
                self.add(PERMIT_ANY, permit_any, entry.source_lines, scope=f"acl {acl.name}")

        # CDP is enabled globally by default on IOS
        wan = [i for i in c.interfaces if i.is_wan]
        if services.cdp_globally_enabled is False:
            self.add(DISCOVERY_PROTOCOL, False, self.matching(services.source_lines, r"^\s*no cdp run"), "cdp", "global")
        elif wan:
            active = next((i for i in wan if i.cdp_enabled is not False), None)
            if active:
                self.add(DISCOVERY_PROTOCOL, True, active.source_lines, "cdp", f"interface {active.name}")
            else:
                self.add(DISCOVERY_PROTOCOL, False, _lines(*wan), "cdp", "external interfaces")
        else:
            self.add(DISCOVERY_PROTOCOL, None, (), "cdp", provenance="No interface is identified as external")
        self._cisco_added()

    def _cisco_added(self):
        """SNMPv3 security level, HTTPS TLS version, BGP / OSPF authentication, unused interfaces: read from the
        configuration's own lines (the IOS model does not keep them)."""
        raw = self.config.raw_lines
        for number, line in enumerate(raw, 1):
            if m := _IOS_SNMP_GROUP.match(line):
                self.add(SNMPV3_SECURITY, m.group(2).lower(), [number], scope=f"SNMPv3 group {m.group(1)}")

        tls = [(n, float(m.group(1))) for n, line in enumerate(raw, 1) if (m := _IOS_TLS_VERSION.match(line))]
        secure_server = [n for n, line in enumerate(raw, 1) if re.match(r"^ip\s+http\s+secure-server\s*$", line, re.I)]
        if tls:
            number, version = tls[-1]
            self.add(MGMT_TLS_MIN, version, [number], scope="ip http")
        elif secure_server:
            self.add(MGMT_TLS_MIN, None, secure_server, scope="ip http",
                     provenance="The HTTPS server is on and no 'ip http tls-version' is set, so the IOS release "
                                "default decides which TLS versions it accepts")

        blocks = _ios_blocks(raw)
        for header, body in blocks:
            text = raw[header - 1].strip()
            if re.match(r"(?i)^router\s+bgp\s+\d+", text):
                self._ios_bgp(header, body)
            elif re.match(r"(?i)^router\s+ospf\s+\d+", text):
                self._ios_ospf(header, body, blocks)

        for iface in self.config.interfaces:
            if not _IOS_PHYSICAL.match(iface.name) or "." in iface.name:
                continue
            body = [n for n in iface.source_lines if 1 <= n <= len(raw)][1:]
            settings = [" ".join(raw[n - 1].split()).lower() for n in body]
            settings = [s for s in settings if s and s != "!" and not any(s.startswith(d) for d in _IOS_DEFAULT_LINES)]
            if not iface.shutdown and not settings:
                self.add(INTERFACE_UNUSED_UP, True, iface.source_lines[:1], scope=f"interface {iface.name}")
        physical = [i for i in self.config.interfaces if _IOS_PHYSICAL.match(i.name) and "." not in i.name]
        if physical and not any(f.predicate == INTERFACE_UNUSED_UP for f in self.facts):
            self.add(INTERFACE_UNUSED_UP, False, [i.source_lines[0] for i in physical if i.source_lines],
                     scope="physical interfaces")

    def _ios_bgp(self, header: int, body: list[int]):
        raw = self.config.raw_lines
        password, peers, member = set(), {}, {}
        for n in body:
            words = raw[n - 1].split()
            if len(words) < 3 or words[0].lower() != "neighbor":
                continue
            name, keyword = words[1], words[2].lower()
            if keyword == "password":
                password.add(name)
            elif keyword == "remote-as" and _IP.match(name):
                peers.setdefault(name, n)
            elif keyword == "peer-group" and len(words) > 3 and _IP.match(name):
                peers.setdefault(name, n)
                member[name] = words[3]
        lines = {name: [n for n in body if raw[n - 1].split()[1:2] == [name]] for name in {*password, *member.values()}}
        for peer, first in peers.items():
            group = member.get(peer)
            ok = peer in password or group in password
            cited = [first, *lines.get(peer, []), *lines.get(group, [])] if ok else [header, first]
            self.add(ROUTING_AUTH, ok, sorted(set(cited)), subject="bgp", scope=f"neighbor {peer}",
                     provenance="" if ok else f"BGP neighbor {peer} has no 'neighbor … password'")

    def _ios_ospf(self, header: int, body: list[int], blocks):
        raw = self.config.raw_lines
        process = raw[header - 1].split()[2]
        areas: dict[str, int] = {}
        auth: dict[str, tuple[bool, int]] = {}
        networks: list[tuple[ipaddress.IPv4Network, str]] = []
        for n in body:
            text = " ".join(raw[n - 1].split()).lower()
            if m := re.match(r"^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", text):
                areas.setdefault(m.group(3), n)
                if (net := _wildcard_network(m.group(1), m.group(2))) is not None:
                    networks.append((net, m.group(3)))
            elif m := re.match(r"^area\s+(\S+)\s+authentication(\s+message-digest)?\s*$", text):
                auth[m.group(1)] = (bool(m.group(2)), n)
        # per area: the interfaces running OSPF in it, and which of them authenticate (MD5 / key chain)
        members: dict[str, list[tuple[int, bool]]] = {}
        unplaced = []
        for h, b in blocks:
            if not raw[h - 1].lower().startswith("interface"):
                continue
            texts = {n: " ".join(raw[n - 1].split()).lower() for n in b}
            secure = [n for n, t in texts.items() if re.match(r"^ip\s+ospf\s+authentication\s+(message-digest|key-chain)", t)]
            area = next((m.group(1) for t in texts.values()
                         if (m := re.match(rf"^ip\s+ospf\s+{re.escape(process)}\s+area\s+(\S+)", t))), None)
            if area is not None:
                areas.setdefault(area, next(n for n, t in texts.items() if t.startswith("ip ospf " + process)))
            else:
                address = next((m.group(1) for t in texts.values()
                                if (m := re.match(r"^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s", t))), None)
                if address:
                    area = next((a for net, a in networks if ipaddress.IPv4Address(address) in net), None)
            if area is not None:
                members.setdefault(area, []).append((secure[0] if secure else h, bool(secure)))
            elif secure:
                unplaced.extend(secure)
        for area, first in areas.items():
            scope = f"OSPF {process} area {area}"
            inside = members.get(area, [])
            if area in auth:
                md5, n = auth[area]
                self.add(ROUTING_AUTH, md5, [first, n], subject="ospf", scope=scope,
                         provenance="" if md5 else f"{scope} uses a cleartext authentication key")
            elif inside and all(ok for _, ok in inside):
                self.add(ROUTING_AUTH, True, [first, *(n for n, _ in inside)], subject="ospf", scope=scope)
            elif inside and any(ok for _, ok in inside):
                bare = [n for n, ok in inside if not ok]
                names = ", ".join(raw[n - 1].split()[1] for n in bare)
                self.add(ROUTING_AUTH, False, [first, *bare], subject="ospf", scope=scope,
                         provenance=f"{scope} has no area authentication and interface {names} in it does not "
                                    "authenticate")
            elif unplaced and not inside:
                self.add(ROUTING_AUTH, None, [first, *unplaced], subject="ospf", scope=scope,
                         provenance=f"{scope} has no area authentication; some interfaces authenticate, and which "
                                    "area they are in was not read")
            else:
                self.add(ROUTING_AUTH, False, [header, first], subject="ospf", scope=scope,
                         provenance=f"{scope} has no authentication, on the area or any of its interfaces")

    # FortiGate ----------------------------------------------------------------

    def _forti_added(self):
        _forti_added_impl(self)

    def _fortinet(self):
        c = self.config
        wan = [i for i in c.interfaces if i.is_wan]
        no_wan = "No interface is identified as WAN"

        for iface in c.interfaces:
            if iface.allowed_services:
                self.add(PROTOCOL_ENABLED, "telnet" in iface.allowed_services, iface.source_lines,
                         "telnet", f"interface {iface.name}")

        if not wan:
            self.add(PROTOCOL_ENABLED, None, (), "http", provenance=no_wan)
            self.add(SOURCE_RESTRICTED, None, (), provenance=no_wan)
            self.add(MGMT_EXPOSED, None, (), provenance=no_wan)
            self.add(DISCOVERY_PROTOCOL, None, (), "lldp", provenance=no_wan)
        for iface in wan:
            scope = f"interface {iface.name}"
            self.add(PROTOCOL_ENABLED, "http" in iface.allowed_services, iface.source_lines, "http", scope)
            # CIS FortiGate 1.3: every management-related service counts, not only the login protocols
            reachable = sorted(_EXPOSED_SERVICES.intersection(iface.allowed_services))
            self.add(MGMT_EXPOSED, bool(reachable), iface.source_lines, scope=scope,
                     provenance=f"Management services ({', '.join(reachable)}) are allowed on WAN {scope}"
                     if reachable else "")
            exposed = sorted(_MGMT_SERVICES.intersection(iface.allowed_services))
            self.add(SOURCE_RESTRICTED, not exposed, iface.source_lines, scope=scope,
                     provenance=f"Management services ({', '.join(exposed)}) are accessible on WAN {scope}" if exposed else "")
            self.add(DISCOVERY_PROTOCOL, iface.lldp_enabled, iface.source_lines, "lldp", scope,
                     provenance="" if iface.lldp_enabled is not None
                     else f"LLDP transmission is not set on WAN {scope}; the FortiOS default applies")

        mgmt = c.management
        if mgmt.admin_timeout is not None:
            self.add(IDLE_TIMEOUT, mgmt.admin_timeout, mgmt.source_lines, unit="min")

        # Settings the parser model does not keep, read from their own sections. Absent: the FortiOS defaults
        # in app/facts/defaults.py (admin-lockout-threshold 3, the shipped 'admin' account) apply.
        raw = c.raw_lines
        found = [(n, int(m.group(1))) for n in _forti_section(raw, "config system global")
                 if (m := _FORTI_LOCKOUT.match(raw[n - 1]))]
        if found:
            self.add(LOGIN_MAX_ATTEMPTS, found[-1][1], [found[-1][0]])
        policy = _forti_section(raw, "config system password-policy")
        enabled = [n for n in policy if re.match(r"^\s*set\s+status\s+enable\s*$", raw[n - 1], re.IGNORECASE)]
        lengths = [(n, int(m.group(1))) for n in policy if (m := _FORTI_MIN_LENGTH.match(raw[n - 1]))]
        if enabled:
            # FortiOS enforces 8 characters when the policy is on and no minimum-length is set
            self.add(PASSWORD_MIN_LENGTH, lengths[-1][1] if lengths else 8, [*enabled, *(n for n, _ in lengths[-1:])])
        else:
            self.add(PASSWORD_MIN_LENGTH, NOT_SET, policy)
        weak = [(n, m.group(1).lower()) for n in _forti_section(raw, "config system global")
                if (m := _FORTI_WEAK_CRYPTO.match(raw[n - 1]))]
        if weak:
            self.add(MGMT_WEAK_CRYPTO, True, [n for n, _ in weak],
                     provenance=f"System global allows weak management cryptography ({', '.join(s for _, s in weak)})")
        elif _forti_section(raw, "config system global"):
            strong = [n for n in _forti_section(raw, "config system global")
                      if re.match(r"^\s*set\s+strong-crypto\s+enable\s*$", raw[n - 1], re.IGNORECASE)]
            if strong:
                self.add(MGMT_WEAK_CRYPTO, False, strong)
        for policy in c.firewall_policies:
            if policy.action != "accept":
                continue
            stated = [n for n in policy.source_lines if re.match(r"^\s*set\s+logtraffic\s", raw[n - 1], re.IGNORECASE)]
            # unset, FortiOS logs security events ('logtraffic utm'); only 'disable' turns logging off
            self.add(RULE_LOGGING, policy.logging_enabled if stated else True, stated or policy.source_lines,
                     scope=f"firewall policy {policy.policy_id}",
                     provenance="" if stated else "FortiOS default 'set logtraffic utm'")
        self._forti_added()
        admins = _forti_section(raw, "config system admin")
        edits = [(n, m.group(1)) for n in admins if (m := _FORTI_EDIT.match(raw[n - 1]))]
        top = min((len(raw[n - 1]) - len(raw[n - 1].lstrip()) for n, _ in edits), default=0)
        for number, name in edits:
            if len(raw[number - 1]) - len(raw[number - 1].lstrip()) == top:
                self.add(ADMIN_ACCOUNT, name, [number], scope=f"admin {name}")
        if c.banners.pre_login_banner_enabled is not None:
            self.add(LOGIN_BANNER, c.banners.pre_login_banner_enabled, c.banners.source_lines)

        for policy in c.firewall_policies:
            permit_any = (policy.action == "accept" and _is_any(policy.src_address) and _is_any(policy.dst_address)
                          and any(s.strip().upper() == "ALL" for s in policy.service))
            self.add(PERMIT_ANY, permit_any, policy.source_lines, scope=f"firewall policy {policy.policy_id}",
                     provenance=f"{policy.src_interface} → {policy.dst_interface}")

    # Both vendors -------------------------------------------------------------

    def _common(self):
        c = self.config

        if c.management.ssh_version is not None:
            self.add(SSH_VERSION, c.management.ssh_version, c.management.source_lines)

        for index, community in enumerate(c.snmp.communities, 1):
            # The community string is a secret: identify it by position only
            self.add(SNMP_COMMUNITY, {"name": community.name, "permission": community.permission, "acl": community.acl},
                     community.source_lines, scope=f"snmp community #{index}")

        if c.services.ip_source_route is not None:
            self.add(SOURCE_ROUTING, c.services.ip_source_route,
                     self.with_mapped(c.services.source_lines, "services.ip_source_route"))

        log = c.logging
        if log.remote_hosts:
            lines = [n for n in log.source_lines
                     if 1 <= n <= len(c.raw_lines) and any(h in c.raw_lines[n - 1] for h in log.remote_hosts)]
            self.add(LOG_REMOTE_DESTINATION, list(log.remote_hosts),
                     self.with_mapped(lines or log.source_lines, "logging.remote_hosts"))
        else:
            self.add(LOG_REMOTE_DESTINATION, NOT_SET, log.source_lines)

        ntp = c.ntp
        lines = self.with_mapped(ntp.source_lines, "ntp.servers", "ntp.authentication_enabled")
        self.add(NTP_SERVER, list(ntp.servers) if ntp.servers else NOT_SET, lines)
        self.add(NTP_AUTHENTICATED, True if ntp.authentication_enabled else NOT_SET, lines)

        for proposal in c.vpn.ipsec_proposals:
            self.add(IPSEC_PROPOSAL,
                     {"encryption": proposal.encryption, "hash": proposal.hash_algorithm, "dh_group": proposal.dh_group},
                     proposal.source_lines, scope=f"proposal {proposal.name}")


def _forti_added_impl(self):
    """SNMPv3 users' security level, admin HTTPS TLS versions, BGP / OSPF authentication, unused ports."""
    raw = self.config.raw_lines
    paths = _forti_paths(raw)

    for edit, lines in _forti_edits(raw, paths, ("config system snmp user",)).items():
        levels = [(n, m.group(1).lower()) for n in lines if (m := _FORTI_SNMP_LEVEL.match(raw[n - 1]))]
        level = _FORTI_LEVELS.get(levels[-1][1]) if levels else None
        self.add(SNMPV3_SECURITY, level, [levels[-1][0]] if levels else lines[:1], scope=f"SNMPv3 user {edit}",
                 provenance="" if levels else f"SNMPv3 user {edit} does not state its security level")

    https = [i for i in self.config.interfaces if "https" in i.allowed_services]
    versions = [(n, m.group(1)) for n in _forti_section(raw, "config system global")
                if (m := re.match(r"^\s*set\s+admin-https-ssl-versions\s+(.+)$", raw[n - 1], re.IGNORECASE))]
    if versions:
        number, listed = versions[-1]
        found = [float(v) for v in re.findall(r"tlsv1-([0-3])", listed.lower()) for v in [f"1.{v}"]]
        self.add(MGMT_TLS_MIN, min(found) if found else None, [number], scope="system global")
    elif https:
        self.add(MGMT_TLS_MIN, None, https[0].source_lines[:1], scope="system global",
                 provenance="HTTPS administration is allowed and 'admin-https-ssl-versions' is not set, so the "
                            "FortiOS release default decides which TLS versions it accepts")

    for peer, lines in _forti_edits(raw, paths, ("config router bgp", "config neighbor")).items():
        password = [n for n in lines if re.match(r"^\s*set\s+password\s", raw[n - 1], re.IGNORECASE)]
        self.add(ROUTING_AUTH, bool(password), password or lines[:1], subject="bgp", scope=f"neighbor {peer}",
                 provenance="" if password else f"BGP neighbor {peer} has no 'set password'")

    stated = False
    for block in (("config router ospf", "config area"), ("config router ospf", "config ospf-interface")):
        for name, lines in _forti_edits(raw, paths, block).items():
            modes = [(n, m.group(1).lower()) for n in lines if (m := _FORTI_OSPF_AUTH.match(raw[n - 1]))]
            if not modes:
                continue
            stated = True
            number, mode = modes[-1]
            ok = mode in ("md5", "message-digest")
            what = "area" if block[1] == "config area" else "interface"
            self.add(ROUTING_AUTH, ok, [number], subject="ospf", scope=f"OSPF {what} {name}",
                     provenance="" if ok else f"OSPF {what} {name} uses '{mode}' authentication")
    ospf = _forti_section(raw, "config router ospf")
    if ospf and not stated and any(p[1:2] in (("config area",), ("config ospf-interface",), ("config network",))
                                   for p in (paths[n - 1] for n in ospf) if len(p) > 1):
        self.add(ROUTING_AUTH, False, ospf[:1], subject="ospf", scope="OSPF",
                 provenance="OSPF is configured and no area or interface sets authentication")

    ports = _forti_edits(raw, paths, ("config system interface",))
    unused, physical = [], []
    for name, lines in ports.items():
        texts = [" ".join(raw[n - 1].split()).lower() for n in lines]
        if "set type physical" not in texts:
            continue
        physical.append(lines[0])
        if "set status down" in texts:
            continue
        configured = [s for s in texts if s.startswith(("set ip ", "set allowaccess", "set role", "set member",
                                                         "set description", "set alias", "set vlanid"))
                      and not s.startswith("set ip 0.0.0.0 0.0.0.0")]
        own = set(lines)
        quoted = re.compile(rf'"{re.escape(name)}"')
        referenced = any(quoted.search(raw[n - 1]) for n in range(1, len(raw) + 1) if n not in own)
        if not configured and not referenced:
            unused.append((name, lines[0]))
    for name, number in unused:
        self.add(INTERFACE_UNUSED_UP, True, [number], scope=f"interface {name}")
    if physical and not unused:
        self.add(INTERFACE_UNUSED_UP, False, physical, scope="physical interfaces")


def _forti_paths(raw: list[str]) -> list[tuple[str, ...]]:
    """The ``config`` / ``edit`` headers each line sits in (a header line's own path excludes itself)."""
    stack: list[str] = []
    out = []
    for line in raw:
        text = " ".join(line.split())
        low = text.lower()
        out.append(tuple(stack))
        if low.startswith("config "):
            stack.append(low)
        elif low.startswith("edit "):
            stack.append(text)
        elif low == "next" and stack and stack[-1].lower().startswith("edit "):
            stack.pop()
        elif low == "end" and stack:
            while stack and stack[-1].lower().startswith("edit "):
                stack.pop()
            if stack:
                stack.pop()
    return out


def _forti_edits(raw: list[str], paths, block: tuple[str, ...]) -> dict[str, list[int]]:
    """``edit`` entries directly inside a chain of ``config`` blocks: name -> its line numbers (header first)."""
    out: dict[str, list[int]] = {}
    for number, path in enumerate(paths, 1):
        # a multi-VDOM file nests the block under ``config vdom`` / ``edit root``: read from the block's own header
        starts = [i for i, p in enumerate(path) if p == block[0]]
        if not starts:
            continue
        rest = path[starts[-1]:]
        configs = tuple(p for p in rest if not p.lower().startswith("edit "))
        edits = [p for p in rest if p.lower().startswith("edit ")]
        if configs != block or len(edits) > 1 or (edits and rest[-1] != edits[0]):
            continue
        text = " ".join(raw[number - 1].split())
        if edits:
            out.setdefault(edits[0][5:].strip().strip('"\''), []).append(number)
        elif text.lower().startswith("edit "):
            out.setdefault(text[5:].strip().strip('"\''), []).append(number)
    return out


def _ios_blocks(raw: list[str]) -> list[tuple[int, list[int]]]:
    """Top-level IOS blocks: (header line, its indented child lines), nested children included."""
    blocks, current = [], None
    for number, line in enumerate(raw, 1):
        if not line.strip():
            continue
        if line[:1].isspace():
            if current is not None:
                current[1].append(number)
            continue
        current = None if line.strip() == "!" else (number, [])
        if current is not None:
            blocks.append(current)
    return blocks


def _wildcard_network(address: str, wildcard: str) -> Optional[ipaddress.IPv4Network]:
    """``network 10.0.0.0 0.0.0.255`` as a network; None for a non-contiguous or unreadable wildcard."""
    try:
        inverse = int(ipaddress.IPv4Address(wildcard))
        return ipaddress.IPv4Network(f"{address}/{32 - inverse.bit_length()}", strict=False) \
            if inverse & (inverse + 1) == 0 else None
    except ValueError:
        return None


_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-f:]*:[0-9a-f:]+$", re.IGNORECASE)
_IOS_SNMP_GROUP = re.compile(r"^\s*snmp-server\s+group\s+(\S+)\s+v3\s+(noauth|auth|priv)\b", re.IGNORECASE)
_IOS_TLS_VERSION = re.compile(r"^\s*ip\s+http\s+tls-version\s+TLSv(1\.[0-3])\s*$", re.IGNORECASE)
_IOS_PHYSICAL = re.compile(r"(?i)^(?:gigabitethernet|fastethernet|tengigabitethernet|twentyfivegige|fortygigabitethernet|"
                           r"hundredgige|ethernet|serial)\d")
# lines a physical interface carries without anyone configuring it
_IOS_DEFAULT_LINES = ("no ip address", "negotiation auto", "duplex auto", "speed auto", "no mop enabled",
                      "no mop sysid", "media-type", "no shutdown")
_FORTI_SNMP_LEVEL = re.compile(r"^\s*set\s+security-level\s+(\S+)", re.IGNORECASE)
_FORTI_LEVELS = {"no-auth-no-priv": "noauth", "auth-no-priv": "auth", "auth-priv": "priv"}
_FORTI_OSPF_AUTH = re.compile(r"^\s*set\s+authentication\s+(\S+)", re.IGNORECASE)


def _timeout(line) -> object:
    """Idle timeout of a VTY / console line in minutes; 0 = disabled, NOT_SET = no exec-timeout."""
    if line.exec_timeout_minutes is None:
        return NOT_SET
    return line.exec_timeout_minutes + (line.exec_timeout_seconds or 0) / 60


_IOS_LOGIN_LIMIT = re.compile(
    r"^\s*(?:login\s+block-for\s+\d+\s+attempts|aaa\s+local\s+authentication\s+attempts\s+max-fail)\s+(\d+)",
    re.IGNORECASE)
_IOS_MIN_LENGTH = re.compile(r"^\s*security\s+passwords\s+min-length\s+(\d+)", re.IGNORECASE)
_FORTI_LOCKOUT = re.compile(r"^\s*set\s+admin-lockout-threshold\s+(\d+)", re.IGNORECASE)
_FORTI_MIN_LENGTH = re.compile(r"^\s*set\s+minimum-length\s+(\d+)", re.IGNORECASE)
_IOS_ALGORITHMS = re.compile(
    r"^\s*ip\s+(ssh\s+server\s+algorithm\s+(?:encryption|mac|kex)|http\s+secure-ciphersuite)\s+(.+)$", re.IGNORECASE)
# FortiOS switches that allow weak management crypto: strong-crypto off, CBC ciphers, MD5 MACs, SHA-1 key exchange
_FORTI_WEAK_CRYPTO = re.compile(
    r"^\s*set\s+(strong-crypto\s+disable|ssh-cbc-cipher\s+enable|ssh-hmac-md5\s+enable|ssh-kex-sha1\s+enable)\s*$",
    re.IGNORECASE)
_FORTI_EDIT = re.compile(r"""^\s*edit\s+["']?([^"'\s]+)["']?\s*$""", re.IGNORECASE)


def _forti_section(raw: list[str], header: str) -> list[int]:
    """Line numbers of a top-level FortiOS ``config`` section, header and closing ``end`` included."""
    for index, line in enumerate(raw):
        if line.strip().lower() == header and not line[:1].isspace():
            for close in range(index + 1, len(raw)):
                if raw[close].strip().lower() == "end" and not raw[close][:1].isspace():
                    return list(range(index + 1, close + 2))
            return list(range(index + 1, len(raw) + 1))
    return []


def _is_any(address: Optional[str]) -> bool:
    return address is not None and address.strip().lower() in _ANY_ADDRESS


# ── other vendors: applied adaptive mappings ────────────────────────────────

_TEXT_PRESENT = {"banners.login_banner", "banners.motd_banner"}


def _mapped_facts(config: NormalizedConfig) -> list[SecurityFact]:
    """One fact per mapped field; lists collect every item, conflicting scalars become undetermined."""
    by_field: dict[str, list] = {}
    for m in config.ai_mappings:
        if m.applied and m.normalized_field in FIELD_PREDICATES and m.final_value is not None:
            by_field.setdefault(m.normalized_field, []).append(m)

    facts = []
    for field_path, mappings in by_field.items():
        predicate, subject, scope, unit = FIELD_PREDICATES[field_path]
        info = FIELD_REGISTRY[field_path]
        if info.type_category == TYPE_LIST_STR:
            value = [item for m in mappings for item in info.convert(str(m.final_value))]
            provenance = ""
        else:
            values = {True if field_path in _TEXT_PRESENT else info.convert(str(m.final_value)) for m in mappings}
            value = values.pop() if len(values) == 1 else None
            provenance = "" if value is not None else f"Conflicting values were mapped to {field_path}"
        numbers = list(dict.fromkeys(m.line_number for m in mappings if 1 <= m.line_number <= len(config.raw_lines)))
        facts.append(SecurityFact(
            predicate, value, weakest(SOURCE_ASSURANCE[m.source] for m in mappings),
            Evidence(line_numbers=numbers, text=[config.raw_lines[n - 1] for n in numbers]),
            subject=subject, scope=scope, unit=unit,
            provenance=provenance or f"adaptive mapping ({field_path})",
        ))
    return facts
