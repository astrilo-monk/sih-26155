# Data Models

This document outlines the core Pydantic data models that currently exist in our backend. These are the lifeblood of the application.

## `NormalizedConfig` (backend/app/models/normalized.py)

This is the generic model that all vendor configs get mapped into. 
*(Status: Implemented, though we may add fields as we build parsers.)*

```python
class NormalizedConfig(BaseModel):
    vendor: str # "cisco_ios", "fortigate", etc.
    hostname: Optional[str]
    os_version: Optional[str]
    
    # Generic security settings
    users: List[UserAccount] = []
    management_protocols: List[str] = [] # e.g. ["ssh", "https"]
    snmp_version: Optional[str]
    
    # Interfaces
    interfaces: List[Interface] = []
    
    # Firewall / ACL rules
    acls: List[AccessControlList] = []
```

## `Finding` (backend/app/models/findings.py)

When a rule fails, it generates a Finding.

```python
class Finding(BaseModel):
    rule_id: str         # e.g., "SEC-003"
    title: str           # e.g., "Telnet Enabled"
    severity: str        # "Critical", "High", "Medium", "Low"
    description: str     # Technical explanation of what triggered it
    raw_config_lines: List[str] # The exact lines from the uploaded file
```

## `ScanResult` (backend/app/models/findings.py)

The final payload sent to the frontend.

```python
class ScanResult(BaseModel):
    scan_id: str
    timestamp: datetime
    vendor: str
    overall_score: int    # 0-100
    findings: List[Finding]
```
