"""
Vendor auto-detection.

Looks at the raw config text and figures out which vendor it belongs to.
Uses simple heuristic pattern matching -no need for anything fancy here.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from app.models.normalized import NormalizedConfig, Vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.coverage import CoverageReport, parse_coverage
from app.parsers.fortinet import FortinetParser

logger = logging.getLogger(__name__)


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


# ── Vendor identification: fingerprint → parser → parse coverage ─────────────

STATUS_CONFIRMED = "confirmed"
STATUS_UNVERIFIED = "unverified"
STATUS_UNKNOWN = "unknown"

# Tiny configs make the coverage ratio noisy: a vendor is only rejected on the
# ratio when at least this many lines fall outside its grammar.
MIN_UNCOVERED_LINES = 3
# This many consecutive foreign top-level statements reject the vendor whatever
# the ratio -a block of another dialect pasted into a valid config.
MAX_FOREIGN_RUN = 5

PARSERS = {
    Vendor.CISCO_IOS: CiscoIOSParser(),
    Vendor.FORTINET: FortinetParser(),
}


@dataclass
class VendorIdentification:
    """Deterministic vendor decision for one config. AI output never feeds this."""
    detected_vendor: Vendor
    status: str
    coverage: Optional[CoverageReport] = None
    # Parser output -only kept when the vendor profile is confirmed
    config: Optional[NormalizedConfig] = None
    # Why an UNVERIFIED profile was rejected
    reason: Optional[str] = None

    @property
    def confirmed(self) -> bool:
        return self.status == STATUS_CONFIRMED

    @property
    def vendor(self) -> Vendor:
        return self.detected_vendor if self.confirmed else Vendor.UNKNOWN


def identify_vendor(raw_config: str, threshold: Optional[float] = None) -> VendorIdentification:
    """
    Detect the vendor, run its parser, and confirm the profile by parse coverage.

    The config merely *resembles* the vendor, and is reported UNVERIFIED so it
    goes through the unknown-vendor path instead of vendor-specific rules, when:

    * the syntax matches but the product profile does not (FortiOS without a
      FortiGate-only section), or
    * ``MAX_FOREIGN_RUN`` consecutive top-level statements are foreign, or
    * coverage is below ``threshold`` (default
      ``settings.vendor_parse_coverage_threshold``) with at least
      ``MIN_UNCOVERED_LINES`` foreign lines.
    """
    detected = detect_vendor(raw_config)
    parser = PARSERS.get(detected)
    if parser is None:
        return VendorIdentification(detected_vendor=detected, status=STATUS_UNKNOWN)

    if threshold is None:
        from app.config import settings
        threshold = settings.vendor_parse_coverage_threshold

    config = parser.parse(raw_config)
    coverage = parse_coverage(config)

    reason = None
    if coverage.profile_mismatch:
        reason = coverage.profile_mismatch
    elif coverage.longest_foreign_run >= MAX_FOREIGN_RUN:
        reason = (
            f"{coverage.longest_foreign_run} consecutive statements do not follow its syntax "
            "(mixed or foreign configuration)"
        )
    elif coverage.ratio < threshold and coverage.uncovered_count >= MIN_UNCOVERED_LINES:
        reason = f"only {coverage.ratio:.0%} of {coverage.total_lines} lines follow its syntax"

    if reason:
        logger.warning("Config resembles %s but %s -vendor unverified", detected.value, reason)
        return VendorIdentification(
            detected_vendor=detected, status=STATUS_UNVERIFIED, coverage=coverage, reason=reason,
        )

    return VendorIdentification(detected_vendor=detected, status=STATUS_CONFIRMED, coverage=coverage, config=config)
