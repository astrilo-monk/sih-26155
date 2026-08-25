"""
Vendor auto-detection.

Looks at the raw config text and figures out which vendor it belongs to.
Uses simple heuristic pattern matching — no need for anything fancy here.
"""

import re
from app.models.normalized import Vendor


# Patterns that strongly indicate a specific vendor
_CISCO_PATTERNS = [
    re.compile(r"^version \d+\.\d+", re.MULTILINE),
    re.compile(r"^hostname \S+", re.MULTILINE),
    re.compile(r"^interface (GigabitEthernet|FastEthernet|Loopback|Vlan)", re.MULTILINE),
    re.compile(r"^line vty \d+", re.MULTILINE),
    re.compile(r"^(ip access-list|access-list \d+)", re.MULTILINE),
    re.compile(r"^service (timestamps|password-encryption)", re.MULTILINE),
    re.compile(r"^enable (secret|password)", re.MULTILINE),
    re.compile(r"^!\s*$", re.MULTILINE),  # Cisco uses ! as section separators
]

_FORTINET_PATTERNS = [
    re.compile(r"^config \S+", re.MULTILINE),
    re.compile(r"^\s+edit \S+", re.MULTILINE),
    re.compile(r"^\s+set \S+ .+", re.MULTILINE),
    re.compile(r"^\s+next\s*$", re.MULTILINE),
    re.compile(r"^end\s*$", re.MULTILINE),
    re.compile(r"config system global", re.MULTILINE),
    re.compile(r"config firewall policy", re.MULTILINE),
    re.compile(r"config system interface", re.MULTILINE),
]


def detect_vendor(raw_config: str) -> Vendor:
    """
    Figure out which vendor a config file belongs to.
    
    Scores each vendor based on how many characteristic patterns
    match. The vendor with the highest score wins. If nothing
    matches well enough, returns UNKNOWN.
    """
    cisco_score = sum(1 for p in _CISCO_PATTERNS if p.search(raw_config))
    fortinet_score = sum(1 for p in _FORTINET_PATTERNS if p.search(raw_config))

    # Need at least 3 pattern matches to be reasonably confident
    min_confidence = 3

    if cisco_score >= min_confidence and cisco_score > fortinet_score:
        return Vendor.CISCO_IOS
    elif fortinet_score >= min_confidence and fortinet_score > cisco_score:
        return Vendor.FORTINET
    elif cisco_score >= min_confidence:
        return Vendor.CISCO_IOS
    elif fortinet_score >= min_confidence:
        return Vendor.FORTINET

    return Vendor.UNKNOWN
