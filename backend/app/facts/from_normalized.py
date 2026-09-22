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

import re
from typing import Iterable, Optional

from app.facts.heuristics import heuristic_facts
from app.facts.recognizers import recognizer_facts
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, FIELD_PREDICATES, IDLE_TIMEOUT, IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, LOGIN_BANNER,
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
    recognized, skip = recognizer_facts(config.raw_lines, extra_recognizers)
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
    return recognized + facts + judged


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

    # FortiGate ----------------------------------------------------------------

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
            self.add(DISCOVERY_PROTOCOL, None, (), "lldp", provenance=no_wan)
        for iface in wan:
            scope = f"interface {iface.name}"
            self.add(PROTOCOL_ENABLED, "http" in iface.allowed_services, iface.source_lines, "http", scope)
            exposed = sorted(_MGMT_SERVICES.intersection(iface.allowed_services))
            self.add(SOURCE_RESTRICTED, not exposed, iface.source_lines, scope=scope,
                     provenance=f"Management services ({', '.join(exposed)}) are accessible on WAN {scope}" if exposed else "")
            self.add(DISCOVERY_PROTOCOL, iface.lldp_enabled, iface.source_lines, "lldp", scope,
                     provenance="" if iface.lldp_enabled is not None
                     else f"LLDP transmission is not set on WAN {scope}; the FortiOS default applies")

        mgmt = c.management
        if mgmt.admin_timeout is not None:
            self.add(IDLE_TIMEOUT, mgmt.admin_timeout, mgmt.source_lines, unit="min")
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


def _timeout(line) -> object:
    """Idle timeout of a VTY / console line in minutes; 0 = disabled, NOT_SET = no exec-timeout."""
    if line.exec_timeout_minutes is None:
        return NOT_SET
    return line.exec_timeout_minutes + (line.exec_timeout_seconds or 0) / 60


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
