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
RULE_WORDS = frozenset({"permit", "deny", "accept", "action", "rule", "rules", "rulebase", "access-list", "acl"})

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

AAA_SERVERS = frozenset({"radius", "tacacs", "tacacs+", "radius-server", "tacacs-server"})
CENTRAL = frozenset({"centralized", "central", "aaa"})

IPSEC = frozenset({"ipsec", "ike", "ikev1", "ikev2", "isakmp", "esp", "transform-set", "proposal", "phase1",
                   "phase2", "crypto", "vpn"})
DH_KEYWORDS = frozenset({"group", "dh-group", "dhgroup", "dhgrp", "pfs", "pfs-group"})

SNMP = frozenset({"snmp", "snmp-server", "snmpd"})
READ_WRITE = frozenset({"rw", "read-write", "write"})
READ_ONLY = frozenset({"ro", "read-only", "read"})

SOURCE_ROUTING = frozenset({"source-route", "source-routing", "ip-src-routing", "src-routing", "source-routed"})
DISCOVERY = frozenset({"cdp", "lldp"})
BANNER_TYPES = frozenset({"login", "motd", "pre-login", "prelogin"})

PERMIT = frozenset({"permit", "allow", "accept"})
# A rule naming any of these is narrower than "all traffic"
NARROWING = frozenset({"tcp", "udp", "icmp", "sctp", "gre", "esp", "eq", "range", "host", "port", "dst-port",
                       "src-port", "application", "service"})
