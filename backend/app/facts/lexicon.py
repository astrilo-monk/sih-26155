"""
Lexicon: vendor-neutral words for the concepts the controls need.

Seeded from ``adaptive/relevance.py``, narrowed to what a predicate consumes.
Words are matched against whole tokens or their hyphen parts
(``syslog-server`` → ``syslog``), never against substrings.
"""

import re

# Places remote management is configured: a protocol named after one of these is a management protocol
REMOTE_ACCESS = frozenset({
    "remote-console", "remote-access", "vty", "line", "admin-access", "allowaccess", "management",
    "management-plane", "mgmt", "service", "services", "transport", "input", "ip", "web", "webui",
})
# A protocol keyword followed by one of these names its server: ``telnet server enable``
SERVER_WORDS = frozenset({"server", "service", "access"})
MGMT_PROTOCOLS = {
    "telnet": frozenset({"telnet", "telnet-server", "telnetd"}),
    "http": frozenset({"http", "http-server", "httpd"}),
}
# Keywords that only switch a block on or off: ``remote-console state enabled``
STATE_WORDS = frozenset({"state", "status", "admin-state", "admin-status", "service"})
# Traffic rules mention protocols without configuring management
RULE_WORDS = frozenset({"permit", "deny", "accept", "action", "rule", "rules", "rulebase", "access-list", "acl",
                        # cloud security groups / NSGs, as flattened JSON (app.structure.structured)
                        "ippermissions", "securityrules",
                        # Terraform (HCL) rule blocks: ``ingress { … }``, ``security_rule { … }``
                        "ingress", "security_rule",
                        # GCP firewall exports: ``allowed [{"IPProtocol": …}]`` / ``denied``
                        "allowed", "denied"})

SOURCE_RESTRICTION = frozenset({
    "source-restriction", "allowed-source", "allowed-sources", "allowed-hosts", "trusted-host", "trusthost",
    "permitted-ip", "permitted-hosts", "source-policy", "management-acl",
})
UNRESTRICTED = frozenset({"unrestricted", "any", "all", "open", "permissive"})
RESTRICTED = frozenset({"restricted", "enforced", "strict"})
ANY_ADDRESS = frozenset({"0.0.0.0", "0.0.0.0/0", "::", "::/0"})

SSH = frozenset({"ssh", "secure-shell", "sshd"})
VERSION = frozenset({"version", "protocol-version"})

IDLE = frozenset({"idle", "inactivity"})
TIMEOUT_KEYWORDS = frozenset({"exec-timeout", "session-timeout", "admintimeout", "admin-timeout", "console-timeout",
                              "cli-timeout"})
TIMEOUT_CONTEXT = frozenset({"session", "admin", "console", "vty", "cli", "management"})
MINUTES = frozenset({"m", "min", "mins", "minute", "minutes"})
SECONDS = frozenset({"s", "sec", "secs", "second", "seconds"})
HOURS = frozenset({"h", "hr", "hrs", "hour", "hours"})

REMOTE_LOG = frozenset({"syslog", "syslogd", "syslog-server", "syslog-host", "logging", "log", "loghost",
                        "log-host", "log-server", "remote-log", "audit-stream"})

TIME_SYNC = frozenset({"ntp", "sntp", "time-sync", "timesync", "chrony"})
AUTHENTICATED = frozenset({"authenticate", "authenticated", "authentication", "auth"})

AAA_SERVERS = frozenset({"radius", "tacacs", "tacacs+", "radius-server", "tacacs-server",
                         # Junos spells TACACS+ "tacplus"
                         "tacplus", "tacplus-server"})

# Keywords that name the device: ``hostname X``, ``system-name X``, ``set system host-name X``
HOSTNAME = frozenset({"hostname", "host-name", "system-name", "sysname"})
CENTRAL = frozenset({"centralized", "central", "aaa"})

IPSEC = frozenset({"ipsec", "ike", "ikev1", "ikev2", "isakmp", "esp", "transform-set", "proposal", "phase1",
                   "phase2", "crypto", "vpn"})
DH_KEYWORDS = frozenset({"group", "dh-group", "dhgroup", "dhgrp", "pfs", "pfs-group"})

# How a configuration writes "stored password" -a line must use one of these to teach password storage
PASSWORD_RELATED = frozenset({
    "password", "passwd", "password-encryption", "encrypted-password", "passphrase", "credential",
    # PAN-OS stores an administrator password as a hash: `mgt-config users <name> phash <hash>`
    "phash",
    # NX-OS names its password rules after the passphrase: `userpassphrase min-length 16`
    "userpassphrase",
    "secret", "hash", "hashed", "encrypted", "plaintext", "cipher", "irreversible-cipher", "algorithm-type",
})

SNMP = frozenset({"snmp", "snmp-server", "snmpd"})
# A zone or interface named for the outside world. Only a name that says so marks a place external: a zone
# called "dmz" or "vlan20" says nothing, and nothing is concluded from it.
EXTERNAL_ZONES = frozenset({"untrust", "untrusted", "outside", "internet", "external", "wan", "public"})
# How a configuration says which management services an interface or zone accepts
MGMT_EXPOSURE_RELATED = frozenset({
    "host-inbound-traffic", "system-services", "allowaccess", "interface-management-profile",
    "management-profile", "management-access", "permitted-services",
})
# How a configuration states a limit on failed logins
LOCKOUT_RELATED = frozenset({
    "lockout", "lockout-threshold", "admin-lockout-threshold", "retry-options", "tries-before-disconnect",
    "max-auth-attempts", "max-fail", "attempts", "block-for", "failed-attempts",
    # Check Point Gaia ``set password-controls deny-on-fail failures-allowed 3``, Huawei
    # ``ssh server authentication-retries 3``
    "deny-on-fail", "failures-allowed", "authentication-retries",
    # EXOS ``configure cli max-failed-logins 3``
    "max-failed-logins",
    # Dell OS10: `password-attributes max-retry 3 lockout-period 15`
    "max-retry",
})
# How a configuration names a local account
ACCOUNT_RELATED = frozenset({"user", "users", "username", "account", "local-user", "mgt-config"})
# Account names vendors ship or attackers try first
DEFAULT_ACCOUNT_NAMES = frozenset({"admin", "administrator", "root", "cisco", "manager",
                                   # VyOS ships with the account 'vyos' (password 'vyos')
                                   "vyos"})
# The services MGMT-010 counts as management (ping is a diagnostic: reachable, not manageable)
MGMT_SERVICES = frozenset({"ssh", "https", "http", "telnet", "snmp", "all"})
READ_WRITE = frozenset({"rw", "read-write", "write"})
READ_ONLY = frozenset({"ro", "read-only", "read"})

SOURCE_ROUTING = frozenset({"source-route", "source-routing", "ip-src-routing", "src-routing", "source-routed",
                            # RouterOS ``/ip settings set accept-source-route=no``, EXOS ``ip-option loose-source-route``
                            "accept-source-route", "loose-source-route", "strict-source-route"})
DISCOVERY = frozenset({"cdp", "lldp"})
BANNER_TYPES = frozenset({"login", "motd", "pre-login", "prelogin"})

# ── related vocabulary (Phase 7 AI judge) ──────────────────────────────────
# Broader than the extractors: an unfamiliar line naming one of these may state the setting. The AI reads
# its meaning; the verifier still requires the line's own value (polarity, number with a unit, address).
SOURCE_RELATED = SOURCE_RESTRICTION | RESTRICTED | frozenset({
    "allowed", "permitted", "trusted", "allowlist", "whitelist", "access-class", "restrict", "restriction",
    # a rule names the sources it lets in: ``allow-address``, ``source-address``, ``permitted-ip``
    "allow", "allow-address", "source-address", "src-address", "trusthost1", "access-group",
    # EXOS binds a service to an ACL: ``configure ssh2 access-profile MGMT-SSH``
    "access-profile",
    # an ACL bound to the management lines: Huawei ``acl 2000 inbound`` under ``user-interface vty 0 4``, OS10
    # ``ip access-class`` under ``line vty``, AOS-CX ``apply access-list ip MGMT control-plane``
    "acl", "access-list", "access-class",
    # a cloud rule names its source prefix: AWS ``CidrIp``, Azure ``sourceAddressPrefix``, GCP ``sourceRanges``
    "cidrip", "cidripv6", "sourceaddressprefix", "sourceranges",
    # the same keys in Terraform: ``cidr_blocks``, ``cidr_ipv4``, ``source_address_prefix``, ``source_ranges``
    "cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6", "source_address_prefix", "source_ranges",
})
IDLE_RELATED = IDLE | TIMEOUT_KEYWORDS | frozenset({
    "timeout", "lock", "autolock", "logout", "autologout", "inactive",
})
SSH_VERSION_RELATED = VERSION | frozenset({"protocol", "proto", "ver", "v1", "v2"})
LOG_RELATED = REMOTE_LOG | frozenset({"logs", "audit", "event", "events", "siem"})
TIME_RELATED = TIME_SYNC | frozenset({"time", "clock", "time-source", "timesource", "timeserver"})
AUTH_RELATED = AUTHENTICATED | frozenset({"signed", "trusted", "auth-key", "authentication-key",
                                         # Network Time Security (VyOS 1.4 ``set service ntp server … nts``)
                                         "nts"})
AAA_RELATED = AAA_SERVERS | CENTRAL | frozenset({"ldap", "remote-auth", "tacacs-plus",
                                                 # Huawei ``authentication-mode hwtacacs local``
                                                 "hwtacacs", "hwtacacs-server"})
BANNER_RELATED = frozenset({"banner", "motd", "pre-login", "prelogin", "login-message", "legal-notice",
                            # Junos ``login { message "…"; }``, Huawei ``header login information "…"``
                            "message", "header"})
# A protocol named with one of these is not its management server: ``http-proxy``, ``telnet client``
NOT_A_SERVER = frozenset({"proxy", "client", "redirect", "forward", "forwarding", "filter", "inspect", "inspection"})
# Limits, counters and lockouts: a line naming one never states any of the related settings above
UNRELATED = frozenset({
    "max", "maximum", "limit", "sessions", "retries", "retry", "attempts", "failed", "failure", "failures",
    "threshold", "lockout", "quarantine", "count", "rate", "size",
})

PERMIT = frozenset({"permit", "allow", "accept"})
DENY = frozenset({"deny", "discard", "drop", "reject", "block"})
# A rule naming any of these is narrower than "all traffic"
NARROWING = frozenset({"tcp", "udp", "icmp", "sctp", "gre", "esp", "eq", "range", "host", "port", "dst-port",
                       "src-port", "application", "service"})

# ── management cryptography (CRYPTO-002) ────────────────────────────────────
# Words that introduce an SSH / TLS algorithm list
ALGORITHM_WORDS = frozenset({
    "cipher", "ciphers", "encryption", "mac", "macs", "hmac", "kex", "key-exchange", "algorithm", "algorithms",
    "ciphersuite", "secure-ciphersuite",
})
# An algorithm name that is weak for management sessions: DES / 3DES / RC4 / Blowfish ciphers, any CBC mode,
# MD5 MACs, and SHA-1 Diffie-Hellman group 1 key exchange
_WEAK_ALGORITHM = re.compile(
    r"^(?:3?des|arcfour\d*|rc4[\w-]*|blowfish[\w-]*)$|(?:^|[-_])(?:3des|des|rc4)(?:[-_]|$)|[-_]cbc(?:[-_@]|$)"
    r"|(?:^|-)md5(?:-|$)|diffie-hellman-group1-", re.IGNORECASE)


def is_weak_algorithm(token: str) -> bool:
    return bool(_WEAK_ALGORITHM.search(token.strip("\"',;")))
# Settings that switch weak management cryptography on or off (``strong-crypto``, ``ssh-cbc-cipher`` …)
CRYPTO_SETTING_RELATED = ALGORITHM_WORDS | frozenset({"strong-crypto", "ssh-cbc-cipher", "ssh-hmac-md5", "ssh-kex-sha1"})
# How a traffic rule says it logs
RULE_LOG_WORDS = frozenset({"log", "log-end", "log-start", "logtraffic", "log-setting"})
# Router interface services BOUNDARY-004 wants off
ROUTER_SERVICE_WORDS = frozenset({"redirects", "proxy-arp", "directed-broadcast",
                                  # Huawei ``undo icmp redirect send``, RouterOS ``set send-redirects=no``
                                  "redirect", "send-redirects"})
