"""
Data models for security findings and scan results.

A Finding is a single detected security issue. A ScanResult
is the complete output of analyzing one or more config files.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceMapping:
    """Maps a finding to a compliance framework control."""
    framework: str  # "CIS", "NIST_800_53", "PCI_DSS"
    control_id: str  # e.g., "AC-17", "2.1.1", "1.3.1"
    description: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    device_hostname: str = "unknown"
    vendor: str = "unknown"

    # The actual config lines that triggered this finding
    evidence_lines: list[str] = field(default_factory=list)
    line_numbers: list[int] = field(default_factory=list)

    # Why this is dangerous — short, technical
    security_impact: str = ""

    # What to do about it
    recommendation: str = ""

    # Compliance framework mappings
    compliance: list[ComplianceMapping] = field(default_factory=list)

    # AI-generated explanation (filled in later, may be empty)
    ai_explanation: Optional[str] = None

    # Category for grouping in the dashboard
    category: str = "general"

    @property
    def severity_score(self) -> int:
        """Penalty points for the security score calculation."""
        return {
            Severity.CRITICAL: 12,
            Severity.HIGH: 6,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
        }[self.severity]


@dataclass
class ScanResult:
    """Complete result of scanning one or more config files."""
    scan_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Overall score out of 100
    score: int = 100

    # All findings
    findings: list[Finding] = field(default_factory=list)

    # Devices that were scanned
    devices: list[dict] = field(default_factory=list)

    # Counts by severity
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "score": self.score,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "devices": self.devices,
        }
