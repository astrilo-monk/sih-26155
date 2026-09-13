"""
Security-fact vocabulary.

A SecurityFact is one cited statement a control needs, e.g. "Telnet is allowed
on line vty 0 4". Controls read facts, never vendor structures, so every
control runs on every config whatever produced its facts (a vendor parser, an
admin-confirmed mapping, an AI mapping, a vendor default).

A predicate exists only if a control consumes it.

``value`` conventions:

* a concrete value — what the configuration states
* ``None`` — the setting exists but its value could not be determined
  (``provenance`` says why)
* ``NOT_SET`` — a confirmed vendor parser read the whole configuration and the
  setting is absent; the consuming control decides what absence means
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.results import Assurance, Evidence

# subject: telnet | http
PROTOCOL_ENABLED = "mgmt.remote_access.protocol_enabled"
SOURCE_RESTRICTED = "mgmt.remote_access.source_restricted"
SSH_VERSION = "mgmt.ssh.version"
# unit: min
IDLE_TIMEOUT = "mgmt.session.idle_timeout"
CENTRAL_AAA = "auth.central_aaa.enabled"
# subject: enable | user <name> | console; value: storage type (plaintext, type7, type9_scrypt …)
PASSWORD_STORAGE = "auth.password.storage"
PASSWORD_ENCRYPTION_SERVICE = "auth.password.encryption_service"
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

PREDICATES = frozenset({
    PROTOCOL_ENABLED, SOURCE_RESTRICTED, SSH_VERSION, IDLE_TIMEOUT, CENTRAL_AAA, PASSWORD_STORAGE,
    PASSWORD_ENCRYPTION_SERVICE, SNMP_COMMUNITY, LOG_REMOTE_DESTINATION, NTP_SERVER, NTP_AUTHENTICATED,
    LOGIN_BANNER, SOURCE_ROUTING, DISCOVERY_PROTOCOL, PERMIT_ANY, IPSEC_PROPOSAL,
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
