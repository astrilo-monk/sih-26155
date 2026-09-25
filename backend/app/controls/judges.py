"""
Control judges: what one security fact means for one control.

``judge(fact, facts, vendor)`` returns an Outcome (PASS / FAIL / UNKNOWN with a
reason) or None when the fact does not bear on the control. Judges never ask
which vendor produced a fact; ``vendor`` only selects recommendation wording.
The generic evaluator (``controls/evaluate.py``) combines the outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from app.facts import lexicon as L
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, IDLE_TIMEOUT, IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, LOGIN_BANNER,
    NOT_SET, NTP_AUTHENTICATED, NTP_SERVER, PASSWORD_ENCRYPTION_SERVICE, PASSWORD_STORAGE, PERMIT_ANY,
    PROTOCOL_ENABLED, SNMP_COMMUNITY, SOURCE_RESTRICTED, SOURCE_ROUTING, SSH_VERSION, SecurityFact,
)
from app.models.findings import Severity
from app.models.normalized import Vendor
from app.models.results import FailureDetail, Status

DEFAULT_SNMP_COMMUNITIES = {"public", "private", "community", "snmp", "default"}
WEAK_PASSWORD_STORAGE = {"plaintext", "type7", "type0"}
STRONG_PASSWORD_STORAGE = {"secret", "encrypted", "hashed", "type5_md5", "type8_sha256", "type9_scrypt"}
MAX_IDLE_TIMEOUT_MINUTES = 15
WEAK_ENCRYPTION = {"des", "3des", "des-cbc", "3des-cbc"}
WEAK_HASH = {"md5", "md5-hmac", "esp-md5-hmac"}
WEAK_DH_GROUPS = {1: 768, 2: 1024, 5: 1536}


@dataclass
class Outcome:
    status: Status
    reason: str
    failure: Optional[FailureDetail] = None
    # Facts cited besides the judged one
    also: list[SecurityFact] = field(default_factory=list)


Judge = Callable[[SecurityFact, list[SecurityFact], Vendor], Optional[Outcome]]


def _pass(reason: str, *also: SecurityFact) -> Outcome:
    return Outcome(Status.PASS, reason, also=list(also))


def _unknown(fact: SecurityFact, reason: str) -> Outcome:
    return Outcome(Status.UNKNOWN, fact.provenance if fact.value is None and fact.provenance else reason)


def _fail(severity: Severity, description: str, impact: str, recommendation: str, *also: SecurityFact) -> Outcome:
    return Outcome(Status.FAIL, description, FailureDetail(severity, description, impact, recommendation), list(also))


def _on(fact: SecurityFact) -> str:
    return f" on {fact.scope}" if fact.scope else ""


def _advice(vendor: Vendor, generic: str, cisco: str = "", fortinet: str = "") -> str:
    return {Vendor.CISCO_IOS: cisco, Vendor.FORTINET: fortinet}.get(vendor) or generic


# ── management ──────────────────────────────────────────────────────────────

def telnet(fact, facts, vendor):
    if fact.predicate != PROTOCOL_ENABLED or fact.subject != "telnet" or fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Whether Telnet is allowed could not be determined")
    if not fact.value:
        return _pass("Telnet is not allowed for remote management")
    return _fail(
        Severity.CRITICAL,
        f"Telnet is allowed for remote management{_on(fact)}. Telnet transmits credentials "
        "and commands in cleartext, making them visible to anyone who can sniff the network.",
        "An attacker on the network path can capture admin credentials by passively eavesdropping on Telnet sessions.",
        _advice(vendor, "Disable Telnet and allow only SSH for remote management.",
                cisco="Disable Telnet and use SSH only: set 'transport input ssh' on all VTY lines.",
                fortinet=f"Remove 'telnet' from allowaccess{_on(fact)}."),
    )


def http(fact, facts, vendor):
    if fact.predicate != PROTOCOL_ENABLED or fact.subject != "http" or fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Whether HTTP management is enabled could not be determined")
    if not fact.value:
        return _pass("Cleartext HTTP management is disabled")
    return _fail(
        Severity.HIGH,
        f"Cleartext HTTP management is enabled{_on(fact)}. HTTP transmits web management traffic "
        "in cleartext, including session cookies and credentials.",
        "Web management sessions can be hijacked via cookie theft or credential interception.",
        _advice(vendor, "Disable HTTP management and use HTTPS only.",
                cisco="Disable HTTP and enable HTTPS: 'no ip http server' and 'ip http secure-server'.",
                fortinet=f"Remove 'http' from allowaccess{_on(fact)}. Use HTTPS only."),
    )


def source_restricted(fact, facts, vendor):
    if fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Whether management access is restricted could not be determined")
    if fact.value:
        return _pass("Management access is restricted to trusted sources")
    return _fail(
        Severity.CRITICAL,
        f"{fact.provenance or 'Management access is not restricted'}{_on(fact) if not fact.provenance else ''}. "
        "Any host that can reach the device can attempt to log in.",
        "The management interface is exposed to brute-force and exploit attempts from untrusted networks.",
        _advice(vendor, "Restrict management access to a trusted management network.",
                cisco="Apply an access-class with a management ACL: 'access-class MGMT_ACL in'.",
                fortinet="Remove management services from WAN interfaces. Only allow management "
                         "from internal/management networks."),
    )


def snmp_community(fact, facts, vendor):
    value = fact.value
    if value is NOT_SET:
        return _pass("No SNMP community is configured")
    if not isinstance(value, dict):
        return _unknown(fact, "An SNMP community was found but could not be read")
    is_default = str(value["name"]).lower() in DEFAULT_SNMP_COMMUNITIES
    open_write = value["permission"] == "RW" and value["acl"] is None
    if not (is_default or open_write):
        return _pass("No SNMP community uses a default string or grants read-write access without an ACL")
    problems = []
    if is_default:
        problems.append(f"uses the well-known default string '{value['name']}'")
    if open_write:
        problems.append("grants read-write access without an ACL restriction")
    return _fail(
        Severity.CRITICAL if value["permission"] == "RW" else Severity.HIGH,
        f"SNMP community '{value['name']}' ({value['permission']}) {' and '.join(problems)}.",
        "Default SNMP community strings are the first thing attackers try. "
        "Read-write access allows full device reconfiguration via SNMP.",
        "Remove default communities. Use SNMPv3 with authentication and encryption, "
        "or at minimum use non-default community strings with ACL restrictions.",
    )


def passwords(fact, facts, vendor):
    if fact.predicate == PASSWORD_ENCRYPTION_SERVICE:
        if fact.value is True:
            return _pass("Stored passwords are encrypted")
        if fact.value is None:
            return _unknown(fact, "Whether stored passwords are encrypted could not be determined")
        return _fail(
            Severity.HIGH,
            "Password encryption is not enabled. Some passwords in the configuration may be stored in cleartext.",
            "Cleartext passwords are visible to anyone viewing the config.",
            _advice(vendor, "Enable encryption of passwords stored in the configuration.",
                    cisco="Enable 'service password-encryption'. Note: this only provides Type 7 "
                          "encoding which is weak, but it's better than plaintext."),
        )
    storage = str(fact.value).lower() if fact.value not in (None, NOT_SET) else None
    if storage in STRONG_PASSWORD_STORAGE:
        return _pass("Passwords use non-reversible or encrypted storage")
    if storage not in WEAK_PASSWORD_STORAGE:
        return _unknown(fact, f"The storage of the {fact.subject} password could not be classified")
    if fact.subject == "enable":
        description = (f"The enable password uses {storage} encoding, which is trivially reversible. "
                       "Anyone with access to the config file can recover the password instantly.")
        impact = ("Enable password protects privileged EXEC mode. If it's reversible, "
                  "any config backup leak gives full device control.")
        advice = _advice(vendor, "Store the privileged password with a strong one-way hash.",
                         cisco="Use 'enable algorithm-type scrypt secret' instead of 'enable password'.")
    else:
        who = fact.subject.removeprefix("user ") if fact.subject else "account"
        description = (f"User '{who}' has a {storage} password. Type 7 passwords can be decoded in milliseconds "
                       "with freely available tools. Plaintext passwords are visible directly.")
        impact = "Compromised user credentials allow unauthorized device access."
        advice = _advice(vendor, "Store the password with a strong one-way hash.",
                         cisco=f"Change user '{who}' to use 'username {who} algorithm-type scrypt secret <password>'.")
    return _fail(Severity.CRITICAL, description, impact, advice)


def idle_timeout(fact, facts, vendor):
    where = fact.scope or "Admin sessions"
    if fact.value is NOT_SET or fact.value == 0:
        return _fail(
            Severity.MEDIUM,
            f"{where} has no idle timeout or the timeout is set to 0 (disabled). Idle sessions stay open indefinitely.",
            "An unattended session left logged in can be used by anyone with physical or remote access "
            "to the admin workstation.",
            _advice(vendor, f"Set an idle timeout of {MAX_IDLE_TIMEOUT_MINUTES} minutes or less.",
                    cisco="Set a reasonable timeout: 'exec-timeout 5 0' (5 minutes).",
                    fortinet="Set admintimeout to 5 minutes or less."),
        )
    if fact.value is None or fact.unit != "min" or not isinstance(fact.value, (int, float)):
        return _unknown(fact, f"The idle timeout of {where.lower()} is stated without a known unit")
    if fact.value > MAX_IDLE_TIMEOUT_MINUTES:
        return _fail(
            Severity.MEDIUM,
            f"The idle timeout of {where.lower()} is {fact.value:g} minutes, which is excessively long "
            "for a management session.",
            "Long session timeouts increase the risk of session hijacking or unauthorized use of "
            "unattended admin sessions.",
            _advice(vendor, "Set the idle timeout to 5 minutes or less.",
                    cisco="Set 'exec-timeout 5 0'.", fortinet="Set admintimeout to 5 minutes or less."),
        )
    return _pass(f"Idle management sessions time out after {fact.value:g} minutes or less")


def ssh_version(fact, facts, vendor):
    if fact.value == 2:
        return _pass("SSH is restricted to version 2")
    if fact.value != 1:
        return _unknown(fact, f"The SSH version '{fact.value}' could not be interpreted")
    return _fail(
        Severity.HIGH,
        "SSH version 1 is enabled. SSHv1 has known cryptographic weaknesses and is vulnerable "
        "to man-in-the-middle attacks.",
        "SSHv1 sessions can be intercepted and decrypted.",
        _advice(vendor, "Allow SSH version 2 only.",
                cisco="Set 'ip ssh version 2'.", fortinet="Disable SSHv1: 'set admin-ssh-v1 disable' in system global."),
    )


def central_aaa(fact, facts, vendor):
    if fact.value is True:
        return _pass("Centralized AAA is enabled")
    if fact.value is None:
        return _unknown(fact, "Whether AAA is enabled could not be determined")
    return _fail(
        Severity.HIGH,
        "AAA is not configured. The device uses basic line-level authentication with no centralized "
        "access control, authorization, or accounting.",
        "Without AAA, there's no per-user accountability, no centralized authentication (TACACS+/RADIUS), "
        "and no audit trail of admin actions.",
        _advice(vendor, "Enable centralized AAA (TACACS+ or RADIUS) for administrative access.",
                cisco="Enable AAA: 'aaa new-model' and configure authentication methods."),
    )


def login_banner(fact, facts, vendor):
    if fact.value is True:
        return _pass("A login banner is configured")
    if fact.value is None:
        return _unknown(fact, "Whether a login banner is shown could not be determined")
    description = ("No login or MOTD banner is configured." if fact.value is NOT_SET
                   else "The pre-login banner is disabled.")
    return _fail(
        Severity.LOW,
        f"{description} A warning banner is a legal requirement in many jurisdictions for "
        "prosecuting unauthorized access.",
        "Without a banner, unauthorized access may be harder to prosecute.",
        _advice(vendor, "Configure a login banner with a legal warning message.",
                fortinet="Enable pre-login banner: 'set pre-login-banner enable' in system global."),
    )


# ── boundary ────────────────────────────────────────────────────────────────

def permit_any(fact, facts, vendor):
    if fact.value is None:
        return _unknown(fact, f"Whether {fact.scope} permits all traffic could not be determined")
    if not fact.value:
        return _pass("No ACL entry or firewall policy permits all traffic from any source to any destination")
    return _fail(
        Severity.CRITICAL,
        f"{(fact.scope or 'A rule').capitalize()} permits all traffic from any source to any destination"
        f"{f' ({fact.provenance})' if '→' in fact.provenance else ''}. This effectively disables the access control.",
        "An any-any permit rule bypasses all firewall and ACL protection.",
        f"Replace the any-any permit in {fact.scope or 'the rule'} with specific source, destination "
        "and service rules.",
    )


def source_routing(fact, facts, vendor):
    if fact.value is False:
        return _pass("IP source routing is disabled")
    if fact.value is not True:
        return _unknown(fact, "Whether IP source routing is enabled could not be determined")
    return _fail(
        Severity.MEDIUM,
        "IP source routing is enabled. This allows the sender of a packet to specify the route it takes "
        "through the network, potentially bypassing firewall rules and security controls.",
        "Attackers can use source routing to bypass security devices and reach internal networks "
        "through unintended paths.",
        _advice(vendor, "Disable IP source routing.",
                cisco="Disable IP source routing: 'no ip source-route'.",
                fortinet="Disable IP source routing: 'set ip-src-routing disable'."),
    )


def discovery_protocol(fact, facts, vendor):
    name = (fact.subject or "discovery protocol").upper()
    if fact.value is False:
        return _pass(f"{name} is disabled {'globally' if fact.scope == 'global' else 'on external interfaces'}")
    if fact.value is not True or fact.scope in (None, "global"):
        return _unknown(fact, f"{name} is enabled, but its exposure on external interfaces could not be determined")
    return _fail(
        Severity.MEDIUM,
        f"{name} is active on external {fact.scope}. Discovery protocols broadcast the device hostname, "
        "software version, addresses and hardware model to adjacent devices in cleartext.",
        "Device information leaked via discovery protocols helps attackers fingerprint the network and "
        "find version-specific vulnerabilities.",
        _advice(vendor, f"Disable {name} on external interfaces.",
                cisco=f"Disable CDP on external interfaces: 'no cdp enable' on '{fact.scope.removeprefix('interface ')}'.",
                fortinet=f"Disable LLDP on '{fact.scope.removeprefix('interface ')}': 'set lldp-transmission disable'."),
    )


# ── logging & time ──────────────────────────────────────────────────────────

def remote_log(fact, facts, vendor):
    if fact.value is NOT_SET:
        return _fail(
            Severity.HIGH,
            "No remote syslog server is configured. Logs are only stored locally on the device, where "
            "they can be lost during a reboot or deliberately cleared by an attacker.",
            "Without remote logging, forensic evidence is destroyed when the device reboots or when an "
            "attacker covers their tracks.",
            "Configure a remote syslog server to forward logs to a SIEM or log collector.",
        )
    if not fact.value:
        return _unknown(fact, "A remote log destination was found but could not be read")
    return _pass(f"Logs are forwarded to {', '.join(fact.value)}")


def ntp(fact, facts, vendor):
    if fact.predicate != NTP_SERVER:
        return None
    if fact.value is NOT_SET:
        return _fail(
            Severity.MEDIUM,
            "No NTP servers are configured. Without synchronized time, log timestamps will drift and become "
            "unreliable for correlating events across devices during incident investigation.",
            "Inaccurate timestamps make forensic timeline reconstruction impossible across multiple devices.",
            "Configure at least two NTP servers for time synchronization.",
        )
    auth = next((f for f in facts if f.predicate == NTP_AUTHENTICATED), None)
    if not fact.value or auth is None or auth.value is None:
        return _unknown(fact, "An NTP server was found, but whether NTP authentication is enabled "
                              "could not be determined")
    if auth.value is True:
        return _pass("NTP servers are configured with authentication", auth)
    return _fail(
        Severity.MEDIUM,
        "NTP is configured but authentication is not enabled. An attacker could spoof NTP responses "
        "to manipulate the device's clock.",
        "Clock manipulation can be used to bypass certificate validation, alter log timestamps, and "
        "disrupt time-sensitive security mechanisms.",
        "Enable NTP authentication with trusted keys.",
        auth,
    )


# ── cryptography ────────────────────────────────────────────────────────────

def ipsec_proposal(fact, facts, vendor):
    value = fact.value if isinstance(fact.value, dict) else {}
    encryption, hash_algorithm, group = value.get("encryption") or "", value.get("hash") or "", value.get("dh_group")
    problems = []
    if any(weak in encryption.lower() for weak in WEAK_ENCRYPTION):
        problems.append(f"weak encryption '{encryption}'")
    if any(weak in hash_algorithm.lower() for weak in WEAK_HASH):
        problems.append(f"weak hash '{hash_algorithm}'")
    if group in WEAK_DH_GROUPS:
        problems.append(f"weak DH group {group} ({WEAK_DH_GROUPS[group]}-bit)")
    if problems:
        return _fail(
            Severity.HIGH,
            f"VPN {fact.scope or 'proposal'} uses {', '.join(problems)}. These algorithms have known weaknesses "
            "and can potentially be broken by well-resourced attackers.",
            "VPN traffic encrypted with weak algorithms may be decryptable, exposing all data flowing through the tunnel.",
            "Use AES-256 or AES-128 for encryption, SHA-256 or SHA-384 for hashing, and DH group 14 "
            "(2048-bit) or higher.",
        )
    if not encryption:
        return _unknown(fact, f"{(fact.scope or 'A proposal').capitalize()} does not state its encryption; "
                              "the platform default applies")
    return _pass("No proposal uses weak encryption, hashing or DH groups")


def exposed_management(fact, facts, vendor):
    if fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Whether management services are reachable from an external interface could not "
                              "be determined")
    if not fact.value:
        return _pass("No management service is reachable on an external interface")
    return _fail(
        Severity.CRITICAL,
        f"{fact.provenance or 'A management service is reachable'}{_on(fact) if not fact.provenance else ''}. "
        "The device can be managed, or probed, from the internet side.",
        "Management services on an internet-facing interface are exposed to scanning, brute force and exploits "
        "against the management plane.",
        _advice(vendor, "Remove every management service from external interfaces and zones; manage the device "
                        "from an internal or dedicated management network only.",
                fortinet=f"Remove all management services from allowaccess{_on(fact)} (CIS FortiGate 1.3)."),
    )


def snmp_version(fact, facts, vendor):
    if fact.value is NOT_SET:
        return _pass("No SNMPv1/v2c community is configured")
    # a community exists only in SNMPv1/v2c, whatever its string or access level
    return _fail(
        Severity.HIGH,
        "An SNMPv1/v2c community is configured. Community-based SNMP sends the community string, "
        "and every value it reads or writes, in cleartext, with no per-user authentication.",
        "Anyone on the network path can capture the community string and query (or reconfigure) the device.",
        _advice(vendor, "Remove every SNMP community and use SNMPv3 with authentication and privacy (authPriv).",
                cisco="Remove 'snmp-server community' lines and configure an SNMPv3 group with 'priv' and users.",
                fortinet="Delete the communities under 'config system snmp community' and use 'config system snmp "
                         "user' with auth and priv protocols (CIS FortiGate 2.3.1)."),
    )


_ROUTER_SERVICES = {"redirects": "ICMP redirects", "proxy-arp": "proxy-ARP", "directed-broadcast": "directed broadcasts"}


def router_services(fact, facts, vendor):
    if fact.value is NOT_SET:
        return None
    what = _ROUTER_SERVICES.get(fact.subject, "ICMP redirects, proxy-ARP and directed broadcasts")
    if fact.value is None:
        return _unknown(fact, f"Whether {what} are enabled{_on(fact)} could not be determined")
    if not fact.value:
        return _pass(f"{what[0].upper()}{what[1:]} are disabled{_on(fact)}")
    return _fail(
        Severity.MEDIUM,
        f"{fact.provenance or f'{what[0].upper()}{what[1:]} are enabled'}"
        f"{_on(fact) if not fact.provenance else ''}. These services help attackers map, redirect or amplify "
        "traffic through the router.",
        "ICMP redirects can reroute hosts through an attacker; proxy-ARP hides where networks really end; directed "
        "broadcasts are the amplifier in smurf-style denial-of-service attacks.",
        _advice(vendor, "Disable ICMP redirects, proxy-ARP and directed broadcasts on every routed interface.",
                cisco=f"Add 'no ip redirects', 'no ip proxy-arp' and 'no ip directed-broadcast'{_on(fact)}."),
    )


def rule_logging(fact, facts, vendor):
    if fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Whether the rule logs could not be determined")
    if fact.value:
        return _pass("Every permitting rule logs the traffic it matches")
    return _fail(
        Severity.MEDIUM,
        f"Logging is turned off{_on(fact)}. Traffic this rule permits leaves no record.",
        "Without traffic logs an intrusion, or data leaving through this rule, cannot be detected or investigated.",
        _advice(vendor, "Enable logging on every rule that permits traffic, and forward the logs to a remote server.",
                fortinet=f"Set 'set logtraffic all'{_on(fact)}."),
    )


def weak_management_crypto(fact, facts, vendor):
    if fact.value is NOT_SET:
        return None
    if fact.value is None:
        return _unknown(fact, "Which algorithms SSH / HTTPS management accepts could not be determined")
    if not fact.value:
        return _pass("Management SSH / HTTPS accepts no weak algorithm")
    return _fail(
        Severity.HIGH,
        f"{fact.provenance or 'Management cryptography accepts a weak algorithm'}"
        f"{_on(fact) if not fact.provenance else ''}. Weak ciphers, MACs and key exchange let an attacker on the "
        "path decrypt or tamper with management sessions.",
        "A downgrade to a weak algorithm exposes administrator credentials and commands despite using SSH / HTTPS.",
        _advice(vendor, "Allow only strong algorithms: AES-CTR or AES-GCM ciphers, SHA-2 MACs, and DH group 14 or "
                        "stronger key exchange.",
                cisco="Set 'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr' and "
                      "'ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256'.",
                fortinet="Set 'set strong-crypto enable' and disable 'ssh-cbc-cipher', 'ssh-hmac-md5' and "
                         "'ssh-kex-sha1' in system global."),
    )


# ── authentication ──────────────────────────────────────────────────────────

MAX_LOGIN_ATTEMPTS = 10
MIN_PASSWORD_LENGTH = 8
DEFAULT_ACCOUNTS = L.DEFAULT_ACCOUNT_NAMES


def login_attempts(fact, facts, vendor):
    if fact.value is None:
        return _unknown(fact, "The failed-login limit could not be determined")
    if fact.value is not NOT_SET and 0 < fact.value <= MAX_LOGIN_ATTEMPTS:
        return _pass(f"Failed logins are limited to {fact.value:g} before a lockout or disconnect")
    missing = fact.value is NOT_SET or fact.value == 0
    return _fail(
        Severity.HIGH,
        "Failed logins are not limited: nothing locks out, blocks or slows an attacker guessing passwords."
        if missing else f"Failed logins are limited to {fact.value:g} attempts, more than {MAX_LOGIN_ATTEMPTS}.",
        "Management accounts can be brute-forced online until a password is found.",
        _advice(vendor, f"Limit failed logins to {MAX_LOGIN_ATTEMPTS} or fewer, with a lockout or back-off.",
                cisco="Add 'login block-for 900 attempts 3 within 120' (or 'aaa local authentication attempts "
                      "max-fail 3').",
                fortinet="Set 'set admin-lockout-threshold 3' and an 'admin-lockout-duration' in system global."),
    )


def password_length(fact, facts, vendor):
    if fact.value is None:
        return _unknown(fact, "The enforced minimum password length could not be determined")
    if fact.value is not NOT_SET and fact.value >= MIN_PASSWORD_LENGTH:
        return _pass(f"Passwords must be at least {fact.value:g} characters")
    return _fail(
        Severity.MEDIUM,
        "No minimum password length is enforced." if fact.value is NOT_SET
        else f"The minimum password length is {fact.value:g}, below {MIN_PASSWORD_LENGTH}.",
        "Short passwords can be guessed or cracked quickly, online or from a captured hash.",
        _advice(vendor, f"Enforce a minimum password length of at least {MIN_PASSWORD_LENGTH} (12 or more is better).",
                cisco="Add 'security passwords min-length 12'.",
                fortinet="Enable 'config system password-policy' with 'set status enable' and "
                         "'set minimum-length 12'."),
    )


def default_account(fact, facts, vendor):
    if fact.value is NOT_SET:
        return _pass("No local account uses a vendor-default name")
    if fact.value is None:
        return _unknown(fact, "The account name could not be read")
    if str(fact.value).lower() not in DEFAULT_ACCOUNTS:
        return _pass("No local account uses a vendor-default name")
    return _fail(
        Severity.MEDIUM,
        f"The local account '{fact.value}' uses a vendor-default name.",
        "A default account name is the first one attackers try, so a password guess is all that stands between "
        "them and administrative access.",
        _advice(vendor, "Create a named administrator account for each person, then remove or disable the default "
                        "account.",
                fortinet="Create a named admin account, then rename or delete 'admin' under 'config system admin'."),
    )


JUDGES: dict[str, Judge] = {
    "MGMT-001": telnet,
    "MGMT-002": http,
    "MGMT-003": source_restricted,
    "MGMT-004": snmp_community,
    "MGMT-005": passwords,
    "MGMT-006": idle_timeout,
    "MGMT-007": ssh_version,
    "MGMT-008": central_aaa,
    "MGMT-009": login_banner,
    "MGMT-010": exposed_management,
    "MGMT-011": snmp_version,
    "AUTH-001": login_attempts,
    "AUTH-002": password_length,
    "AUTH-003": default_account,
    "BOUNDARY-001": permit_any,
    "BOUNDARY-002": source_routing,
    "BOUNDARY-003": discovery_protocol,
    "LOG-001": remote_log,
    "LOG-002": ntp,
    "CRYPTO-001": ipsec_proposal,
    "LOG-003": rule_logging,
    "CRYPTO-002": weak_management_crypto,
    "BOUNDARY-004": router_services,
}
