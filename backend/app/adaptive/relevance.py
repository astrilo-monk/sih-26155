"""
Security Relevance Filter for Adaptive Parsing.

This filter identifies configuration lines that are potentially security-relevant
and should be captured for adaptive processing (AI interpretation, learned mappings).

The filter is intentionally broad (high recall) to avoid missing security issues.
It is NOT a compliance decision - it only generates candidates for further analysis.

Strategy:
1. First, exclude obviously irrelevant structural lines (descriptions, IP addressing, etc.)
2. Then, detect security-relevant patterns using:
   - Security domain root keywords (catches variations like "secure-shell", "hardening", etc.)
   - Security action verbs (enable, disable, permit, deny, restrict, enforce, harden, etc.)
   - Security noun patterns (policy, profile, rule, mechanism, authentication, etc.)
   - Common security command structures (security X, authentication X, access-control X)
3. This generalizes to novel syntax without requiring exhaustive keyword lists.
"""

import re
from typing import Iterable


# Root security keywords - these catch variations via word-boundary matching
# e.g., "secure" matches "secure-shell", "secured", "security"
# e.g., "auth" matches "authentication", "authorization", "authenticate"
SECURITY_ROOT_KEYWORDS = [
    # Core security concepts
    "secure", "security", "harden", "hardening", "lockdown", "protect", "protection",
    "auth", "authenticate", "authentication", "authorization", "authorize", "authorised",
    "encrypt", "encryption", "decrypt", "cipher", "hash", "digest", "sign", "signature",
    "certif", "certificate", "pki", "ca", "trustpoint", "enroll", "revoke", "crl", "ocsp",
    "access", "permit", "deny", "allow", "block", "restrict", "restriction", "filter",
    "firewall", "acl", "policy", "profile", "rule", "rulebase", "rule-set",
    "audit", "compliance", "log", "logging", "syslog", "monitor", "monitoring",
    "account", "accounting", "aaa", "radius", "tacacs", "ldap", "kerberos",
    "ssh", "telnet", "ssl", "tls", "dtls", "ipsec", "ike", "isakmp", "vpn", "tunnel",
    "snmp", "community", "trap", "inform",
    "banner", "motd", "login", "logout", "session", "timeout", "idle", "exec-timeout",
    "password", "secret", "credential", "key", "passphrase", "passwd",
    "privilege", "role", "rbac", "admin", "administrator", "root", "superuser",
    "enable", "disable", "activate", "deactivate", "enforce", "enforced",
    "crypto", "cryptographic", "ikev", "ipsec", "transform", "proposal", "sa",
    "dhcp", "snoop", "arp", "inspection", "source-guard", "port-security",
    "dot1x", "nac", "eap", "radius-server", "tacacs-server",
    "utm", "ips", "ids", "antivirus", "antimalware", "webfilter", "appctrl",
    "application-control", "content-filter", "url-filter", "dns-filter",
    "nat", "pat", "port-forward", "dmz", "zone", "interface", "zone-pair",
    "management", "remote-access", "remote", "console", "vty", "tty", "aux",
    "transport", "input", "output", "preferred", "protocol",
    "cisco", "fortinet", "palo", "alto", "checkpoint", "juniper", "arista",
    "huawei", "zyxel", "mikrotik", "ubiquiti", "edge", "router", "switch",
    # Time/sync related (often security-relevant for logging, certs, etc.)
    "ntp", "time", "clock", "timezone", "sync", "synchroniz",
]


# Security action verbs - words that indicate a security configuration action
SECURITY_ACTION_VERBS = [
    "enable", "disable", "activate", "deactivate", "set", "configure", "config",
    "permit", "deny", "allow", "block", "restrict", "limit", "enforce", "require",
    "harden", "secure", "protect", "lockdown", "encrypt", "sign", "verify",
    "authenticate", "authorize", "validate", "check", "inspect", "monitor",
    "log", "audit", "alert", "notify", "quarantine", "isolate", "block",
    "apply", "attach", "bind", "assign", "map", "define", "create", "add",
    "remove", "delete", "revoke", "expire", "renew", "rotate", "update",
]


# Security noun patterns - nouns that typically appear in security configuration
SECURITY_NOUN_PATTERNS = [
    r"\b(policy|profile|rule|rulebase|ruleset|rule-set|mechanism|method|mode)\b",
    r"\b(authentication|authorization|accounting|access|access-control|access-list)\b",
    r"\b(encryption|cipher|hash|digest|signature|certificate|cert|pki|ca|trustpoint)\b",
    r"\b(firewall|acl|zone|zone-pair|security-zone|security-policy)\b",
    r"\b(vpn|tunnel|ipsec|ike|isakmp|transform|proposal|sa|dh-group)\b",
    r"\b(aaa|radius|tacacs|ldap|kerberos|tacacs-server|radius-server)\b",
    r"\b(ssh|telnet|ssl|tls|dtls|sftp|scp|https|http|web|management)\b",
    r"\b(snmp|community|trap|inform|v3|user|group|view)\b",
    r"\b(banner|motd|login|logout|session|timeout|idle|exec-timeout)\b",
    r"\b(password|secret|credential|key|passphrase|passwd|private-key|public-key)\b",
    r"\b(privilege|role|rbac|admin|administrator|root|superuser)\b",
    r"\b(utm|ips|ids|antivirus|antimalware|webfilter|appctrl|application-control)\b",
    r"\b(content-filter|url-filter|dns-filter|file-filter|sandbox)\b",
    r"\b(nat|pat|port-forward|dmz|interface|zone|security-zone)\b",
    r"\b(management|remote-access|remote|console|vty|tty|aux|line)\b",
    r"\b(transport|protocol|input|output|preferred)\b",
    r"\b(hardening|lockdown|compliance|audit|logging|syslog|monitoring)\b",
    r"\b(secure-shell|ssh-server|ssh-client|ssh-config)\b",
    r"\b(idle-lock|idle-timeout|session-lock|auto-lock)\b",
    r"\b(audit|collector|remote-console|control-plane)\b",
]


# Compile security root keyword patterns (word boundary matching)
# Allow hyphens in the match to catch variations like "ntp-server", "secure-shell", etc.
_ROOT_KEYWORD_PATTERNS = [
    re.compile(rf"\b{re.escape(kw)}[\w-]*\b", re.IGNORECASE) for kw in SECURITY_ROOT_KEYWORDS
]

# Compile action verb patterns
_ACTION_VERB_PATTERNS = [
    re.compile(rf"\b{re.escape(v)}\b", re.IGNORECASE) for v in SECURITY_ACTION_VERBS
]

# Compile noun patterns (already regex)
_NOUN_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SECURITY_NOUN_PATTERNS]


# Patterns that indicate structural/irrelevant lines
# These should NOT be captured even if they contain security keywords
IRRELEVANT_PATTERNS = [
    re.compile(r"^\s*!\s*$"),  # Comment-only lines
    re.compile(r"^\s*#\s*$"),  # Comment-only lines
    re.compile(r"^\s*description\s+"),  # Interface descriptions
    re.compile(r"^\s*ip address\s+"),  # IP addressing
    re.compile(r"^\s*ipv6 address\s+"),  # IPv6 addressing
    re.compile(r"^\s*vlan\s+\d+"),  # VLAN configuration
    re.compile(r"^\s*router\s+\w+"),  # Routing protocol declaration
    re.compile(r"^\s*network\s+"),  # Network statements
    re.compile(r"^\s*redistribute\s+"),  # Redistribution
    re.compile(r"^\s*passive-interface\s+"),  # Passive interfaces
    re.compile(r"^\s*default-information\s+"),  # Default info originate
    re.compile(r"^\s*auto-cost\s+"),  # OSPF auto-cost
    re.compile(r"^\s*timers\s+"),  # Routing timers
    re.compile(r"^\s*metric\s+"),  # Metrics
    re.compile(r"^\s*bandwidth\s+"),  # Bandwidth settings
    re.compile(r"^\s*delay\s+"),  # Delay settings
    re.compile(r"^\s*load-interval\s+"),  # Load interval
    re.compile(r"^\s*carrier-delay\s+"),  # Carrier delay
    re.compile(r"^\s*duplex\s+"),  # Duplex settings
    re.compile(r"^\s*speed\s+"),  # Speed settings
    re.compile(r"^\s*media-type\s+"),  # Media type
    re.compile(r"^\s*flowcontrol\s+"),  # Flow control
    re.compile(r"^\s*negotiation\s+"),  # Auto-negotiation
    re.compile(r"^\s*mtu\s+"),  # MTU settings
    re.compile(r"^\s*encapsulation\s+"),  # Encapsulation
    re.compile(r"^\s*switchport\s+"),  # Switchport settings
    re.compile(r"^\s*spanning-tree\s+"),  # Spanning tree
    re.compile(r"^\s*channel-group\s+"),  # EtherChannel
    re.compile(r"^\s*lacp\s+"),  # LACP
    re.compile(r"^\s*pagp\s+"),  # PAgP
    re.compile(r"^\s*udld\s+"),  # UDLD
    re.compile(r"^\s*lldp\s+(?!.*(?:security|med|tlv))"),  # LLDP (but not lldp security settings)
    re.compile(r"^\s*cdp\s+(?!.*(?:security|enable))"),  # CDP (but not cdp security settings)
    re.compile(r"^\s*object\s+network\s+\S+"),  # Object network declarations
]

_IRRELEVANT_COMPILED = [p for p in IRRELEVANT_PATTERNS]


def _has_security_root_keyword(line: str) -> bool:
    """Check if line contains a security root keyword (catches variations)."""
    for pattern in _ROOT_KEYWORD_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _has_security_action_verb(line: str) -> bool:
    """Check if line contains a security action verb."""
    for pattern in _ACTION_VERB_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _has_security_noun_pattern(line: str) -> bool:
    """Check if line contains a security noun pattern."""
    for pattern in _NOUN_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _has_security_command_structure(line: str) -> bool:
    """
    Check for common security command structures.
    Patterns like: security X, authentication X, access-control X, etc.
    """
    stripped = line.strip().lower()
    
    # Common security command prefixes
    security_prefixes = [
        "security ",
        "authentication ",
        "authorization ",
        "accounting ",
        "access-control ",
        "access-list ",
        "crypto ",
        "ipsec ",
        "ike ",
        "isakmp ",
        "firewall ",
        "policy ",
        "profile ",
        "rule ",
        "aaa ",
        "radius ",
        "tacacs ",
        "ldap ",
        "kerberos ",
        "ssh ",
        "telnet ",
        "ssl ",
        "tls ",
        "dtls ",
        "vpn ",
        "tunnel ",
        "snmp ",
        "banner ",
        "login ",
        "logout ",
        "session ",
        "password ",
        "secret ",
        "privilege ",
        "role ",
        "admin ",
        "management ",
        "remote-access ",
        "remote ",
        "control-plane ",
        "hardening ",
        "lockdown ",
        "compliance ",
        "audit ",
        "logging ",
        "syslog ",
        "monitor ",
        "dot1x ",
        "port-security ",
        "dhcp-snooping ",
        "arp-inspection ",
        "source-guard ",
        "storm-control ",
        "utm ",
        "ips ",
        "ids ",
        "antivirus ",
        "webfilter ",
        "application-control ",
        "content-filter ",
        "url-filter ",
        "dns-filter ",
        "nat ",
        "zone ",
        "zone-pair ",
        "transport ",
        "protocol ",
    ]
    
    for prefix in security_prefixes:
        if stripped.startswith(prefix):
            return True
    
    return False


def is_security_relevant(line: str) -> bool:
    """
    Check if a configuration line is potentially security-relevant.
    
    This is a candidate-generation filter, NOT a compliance decision.
    It errs on the side of inclusion (high recall) to avoid missing issues.
    
    Uses multiple detection strategies:
    1. Security root keywords (catches variations like secure-shell, hardening, etc.)
    2. Security action verbs (enable, disable, permit, deny, enforce, etc.)
    3. Security noun patterns (policy, profile, mechanism, authentication, etc.)
    4. Security command structures (security X, authentication X, etc.)
    
    Args:
        line: A single configuration line (raw, with indentation)
        
    Returns:
        True if the line appears security-relevant and is not
        purely structural/irrelevant.
    """
    stripped = line.strip()
    
    if not stripped:
        return False
    
    # Check if line matches irrelevant patterns (structural config)
    for pattern in _IRRELEVANT_COMPILED:
        if pattern.search(stripped):
            return False
    
    # Multiple detection strategies - any match = candidate
    if _has_security_root_keyword(stripped):
        return True
    
    if _has_security_action_verb(stripped):
        # Action verb alone is weak signal, require at least one other indicator
        # or a security noun pattern
        if _has_security_noun_pattern(stripped):
            return True
        # Also allow if it looks like a security command structure
        if _has_security_command_structure(stripped):
            return True
        # Or if it has a root keyword
        if _has_security_root_keyword(stripped):
            return True
    
    if _has_security_noun_pattern(stripped):
        return True
    
    if _has_security_command_structure(stripped):
        return True
    
    return False


def filter_security_relevant(lines: Iterable[str]) -> list[str]:
    """
    Filter an iterable of lines, returning only security-relevant ones.
    
    Args:
        lines: Iterable of configuration lines
        
    Returns:
        List of lines that pass the security relevance filter
    """
    return [line for line in lines if is_security_relevant(line)]


def get_context_lines(
    raw_lines: list[str],
    line_number: int,
    context_size: int = 2
) -> tuple[list[str], list[str]]:
    """
    Get surrounding context lines for a given line number.
    
    Args:
        raw_lines: All configuration lines (1-indexed line numbers)
        line_number: Target line number (1-indexed)
        context_size: Number of lines before/after to include
        
    Returns:
        Tuple of (context_before, context_after)
    """
    # Convert to 0-indexed
    idx = line_number - 1
    
    if idx < 0 or idx >= len(raw_lines):
        return [], []
    
    # Get context before
    start = max(0, idx - context_size)
    context_before = raw_lines[start:idx]
    
    # Get context after
    end = min(len(raw_lines), idx + 1 + context_size)
    context_after = raw_lines[idx + 1:end]
    
    return context_before, context_after