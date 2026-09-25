"""
Lexicon: vendor-neutral words for the concepts the controls need.

Seeded from ``adaptive/relevance.py``, narrowed to what a predicate consumes.
Words are matched against whole tokens or their hyphen parts
(``syslog-server`` → ``syslog``), never against substrings.
"""

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
                        "ippermissions", "securityrules"})

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
    "secret", "hash", "hashed", "encrypted", "plaintext", "cipher", "irreversible-cipher", "algorithm-type",
})

SNMP = frozenset({"snmp", "snmp-server", "snmpd"})
READ_WRITE = frozenset({"rw", "read-write", "write"})
READ_ONLY = frozenset({"ro", "read-only", "read"})

SOURCE_ROUTING = frozenset({"source-route", "source-routing", "ip-src-routing", "src-routing", "source-routed"})
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
    # a cloud rule names its source prefix: AWS ``CidrIp``, Azure ``sourceAddressPrefix``, GCP ``sourceRanges``
    "cidrip", "cidripv6", "sourceaddressprefix", "sourceranges",
})
IDLE_RELATED = IDLE | TIMEOUT_KEYWORDS | frozenset({
    "timeout", "lock", "autolock", "logout", "autologout", "inactive",
})
SSH_VERSION_RELATED = VERSION | frozenset({"protocol", "proto", "ver"})
LOG_RELATED = REMOTE_LOG | frozenset({"logs", "audit", "event", "events", "siem"})
TIME_RELATED = TIME_SYNC | frozenset({"time", "clock", "time-source", "timesource", "timeserver"})
AUTH_RELATED = AUTHENTICATED | frozenset({"signed", "trusted", "auth-key", "authentication-key"})
AAA_RELATED = AAA_SERVERS | CENTRAL | frozenset({"ldap", "remote-auth", "tacacs-plus"})
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
