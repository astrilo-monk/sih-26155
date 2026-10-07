"""
Security-fact vocabulary.

A SecurityFact is one cited statement a control needs, e.g. "Telnet is allowed
on line vty 0 4". Controls read facts, never vendor structures, so every
control runs on every config whatever produced its facts (a vendor parser, an
admin-confirmed mapping, an AI mapping, a vendor default).

A predicate exists only if a control consumes it.

``value`` conventions:

* a concrete value -what the configuration states
* ``None`` -the setting exists but its value could not be determined
  (``provenance`` says why)
* ``NOT_SET`` -a confirmed vendor parser read the whole configuration and the
  setting is absent; the consuming control decides what absence means
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.results import Assurance, Evidence

# subject: telnet | http
PROTOCOL_ENABLED = "mgmt.remote_access.protocol_enabled"
SOURCE_RESTRICTED = "mgmt.remote_access.source_restricted"
# True: a management service (SSH, HTTP/S, Telnet, ping, SNMP) is reachable on an external interface or zone;
# scope: the interface or zone
MGMT_EXPOSED = "mgmt.remote_access.exposed_externally"
SSH_VERSION = "mgmt.ssh.version"
# unit: min
IDLE_TIMEOUT = "mgmt.session.idle_timeout"
CENTRAL_AAA = "auth.central_aaa.enabled"
# subject: enable | user <name> | console; value: storage type (plaintext, type7, type9_scrypt …)
PASSWORD_STORAGE = "auth.password.storage"
PASSWORD_ENCRYPTION_SERVICE = "auth.password.encryption_service"
# value: failed logins allowed before the device locks out, blocks or disconnects the attempt
LOGIN_MAX_ATTEMPTS = "auth.login.max_attempts"
# value: minimum password length the device enforces
PASSWORD_MIN_LENGTH = "auth.password.min_length"
# value: a local administrative account's name; scope: the account
ADMIN_ACCOUNT = "auth.account.name"
# True: management SSH / HTTPS accepts a weak algorithm (DES, 3DES, RC4, CBC ciphers, MD5 MACs, DH group 1)
MGMT_WEAK_CRYPTO = "mgmt.crypto.weak_allowed"
# True: a traffic rule logs what it matches; scope: the rule
RULE_LOGGING = "boundary.policy.logging"
# True: a routed interface sends ICMP redirects, answers proxy-ARP or forwards directed broadcasts;
# subject: redirects | proxy-arp | directed-broadcast (None when one fact covers the interface); scope: interface
ROUTER_UNSAFE_SERVICE = "boundary.interface.unsafe_service"
# value: {"name", "permission", "acl"}
SNMP_COMMUNITY = "snmp.community"
# value: list of hosts
LOG_REMOTE_DESTINATION = "log.remote.destination"
# value: list of servers
NTP_SERVER = "time.ntp.server"
NTP_AUTHENTICATED = "time.ntp.authenticated"
LOGIN_BANNER = "banner.login.present"
SOURCE_ROUTING = "boundary.source_routing.enabled"
# subject: cdp | lldp
DISCOVERY_PROTOCOL = "boundary.discovery_protocol.enabled"
PERMIT_ANY = "boundary.policy.permit_any"
# value: {"encryption", "hash", "dh_group"}
IPSEC_PROPOSAL = "crypto.ipsec.proposal"
# value: the security level an SNMPv3 group or user requires: "noauth", "auth" (no encryption) or "priv"; scope: it
SNMPV3_SECURITY = "snmp.v3.security_level"
# True: a routing peer, area or interface authenticates its routing messages (MD5 / SHA, not a cleartext key);
# subject: bgp | ospf; scope: the neighbor, area or process
ROUTING_AUTH = "boundary.routing.authenticated"
# value: the lowest TLS version HTTPS management accepts (1.0, 1.1, 1.2, 1.3)
MGMT_TLS_MIN = "mgmt.https.tls_min_version"
# True: a physical interface with no configuration of its own is administratively up; scope: the interface
INTERFACE_UNUSED_UP = "boundary.interface.unused_enabled"

# Optional features whose absence an understood configuration shows by never naming them (see
# ``recognizers._absent_features``): NOT_SET for one of these makes its control N/A, not a finding
ABSENT_FEATURE_PREDICATES = {SNMPV3_SECURITY: "SNMPv3", ROUTING_AUTH: "BGP or OSPF"}

PREDICATES = frozenset({
    PROTOCOL_ENABLED, SOURCE_RESTRICTED, MGMT_EXPOSED, SSH_VERSION, IDLE_TIMEOUT, CENTRAL_AAA, PASSWORD_STORAGE,
    PASSWORD_ENCRYPTION_SERVICE, SNMP_COMMUNITY, LOG_REMOTE_DESTINATION, NTP_SERVER, NTP_AUTHENTICATED,
    LOGIN_BANNER, SOURCE_ROUTING, DISCOVERY_PROTOCOL, PERMIT_ANY, IPSEC_PROPOSAL,
    LOGIN_MAX_ATTEMPTS, PASSWORD_MIN_LENGTH, ADMIN_ACCOUNT, MGMT_WEAK_CRYPTO, RULE_LOGGING, ROUTER_UNSAFE_SERVICE,
    SNMPV3_SECURITY, ROUTING_AUTH, MGMT_TLS_MIN, INTERFACE_UNUSED_UP,
})


# Mechanical migration of the adaptive NormalizedConfig fields a control consumes:
# normalized field → (predicate, subject, scope, unit). Other fields have no predicate.
FIELD_PREDICATES = {
    "management.telnet_enabled": (PROTOCOL_ENABLED, "telnet", None, None),
    "management.http_enabled": (PROTOCOL_ENABLED, "http", None, None),
    "management.ssh_version": (SSH_VERSION, None, None, None),
    "management.admin_timeout": (IDLE_TIMEOUT, None, None, "min"),
    "management.console.exec_timeout_minutes": (IDLE_TIMEOUT, None, "console", "min"),
    "management.console.password_type": (PASSWORD_STORAGE, "console", "console", None),
    "authentication.enable_password_type": (PASSWORD_STORAGE, "enable", "enable password", None),
    "authentication.aaa_enabled": (CENTRAL_AAA, None, None, None),
    "authentication.password_encryption_service": (PASSWORD_ENCRYPTION_SERVICE, None, None, None),
    "services.password_encryption": (PASSWORD_ENCRYPTION_SERVICE, None, None, None),
    "logging.remote_hosts": (LOG_REMOTE_DESTINATION, None, None, None),
    "ntp.servers": (NTP_SERVER, None, None, None),
    "ntp.authentication_enabled": (NTP_AUTHENTICATED, None, None, None),
    "banners.login_banner": (LOGIN_BANNER, None, None, None),
    "banners.motd_banner": (LOGIN_BANNER, None, None, None),
    "banners.pre_login_banner_enabled": (LOGIN_BANNER, None, None, None),
    "services.ip_source_route": (SOURCE_ROUTING, None, None, None),
    "services.cdp_globally_enabled": (DISCOVERY_PROTOCOL, "cdp", "global", None),
    "services.lldp_globally_enabled": (DISCOVERY_PROTOCOL, "lldp", "global", None),
}


class _NotSet:
    def __repr__(self) -> str:
        return "NOT_SET"


NOT_SET = _NotSet()


@dataclass
class SecurityFact:
    predicate: str
    value: Any
    assurance: Assurance
    evidence: Evidence = field(default_factory=Evidence)
    subject: Optional[str] = None
    # The object the fact is about (an interface, a VTY range, an ACL …)
    scope: Optional[str] = None
    unit: Optional[str] = None
    # Where the fact came from, or why its value is undetermined
    provenance: str = ""
    # Set on AI judge facts: only this control may read the fact
    control_id: Optional[str] = None
