# Data Models

This document describes the Python dataclasses used by the backend. These objects carry parsed configuration data into the rules engine and carry findings back to the API.

## `NormalizedConfig` (backend/app/models/normalized.py)

This is the generic model that all supported vendor configs are mapped into. It is implemented in `backend/app/models/normalized.py`.

```python
@dataclass
class NormalizedConfig:
    device: DeviceInfo
    interfaces: list[Interface]
    management: ManagementAccess
    authentication: Authentication
    snmp: SnmpConfig
    logging: LoggingConfig
    ntp: NtpConfig
    access_lists: list[AccessList]
    firewall_policies: list[FirewallPolicy]
    vpn: VpnConfig
    banners: BannerConfig
    services: ServiceConfig
    raw_config: str
    raw_lines: list[str]
```

## `Finding` (backend/app/models/findings.py)

When a rule fails, it generates a Finding.

```python
@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence_lines: list[str]
    line_numbers: list[int]
    security_impact: str
    recommendation: str
    compliance: list[ComplianceMapping]
    ai_explanation: Optional[str]
    category: str
```

## `ScanResult` (backend/app/models/findings.py)

The final payload sent to the frontend.

```python
@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    score: int
    findings: list[Finding]
    devices: list[dict]
```
