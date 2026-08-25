"""
Normalized data model for network device configurations.

Every vendor parser converts its vendor-specific config into these
dataclasses. Security rules run against this structure, not against
raw config text. This is what makes the multi-vendor approach work:
one set of rules, multiple vendor parsers feeding into the same model.

Some fields are vendor-specific and may be None for vendors that don't
have the concept (e.g. Cisco Type 7 passwords don't apply to FortiGate).
That's expected — rules check for None before using those fields.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    UNKNOWN = "unknown"


@dataclass
class Interface:
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    description: Optional[str] = None
    shutdown: bool = False
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None
    # FortiGate: which management protocols are allowed on this interface
    allowed_services: list[str] = field(default_factory=list)
    # Best guess based on description/name/config context
    is_wan: bool = False
    cdp_enabled: Optional[bool] = None
    lldp_enabled: Optional[bool] = None
    # Original config lines that defined this interface (for evidence)
    source_lines: list[int] = field(default_factory=list)


@dataclass
class VtyLine:
    """Represents a VTY line range (e.g., line vty 0 4)."""
    line_range: str = ""
    access_class: Optional[str] = None
    transport_input: list[str] = field(default_factory=list)
    exec_timeout_minutes: Optional[int] = None
    exec_timeout_seconds: Optional[int] = None
    login_method: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)

    @property
    def has_timeout(self) -> bool:
        if self.exec_timeout_minutes is None:
            return False
        # exec-timeout 0 0 means disabled
        return not (self.exec_timeout_minutes == 0 and
                    (self.exec_timeout_seconds or 0) == 0)


@dataclass
class ConsoleLine:
    exec_timeout_minutes: Optional[int] = None
    exec_timeout_seconds: Optional[int] = None
    login_method: Optional[str] = None
    password_type: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)

    @property
    def has_timeout(self) -> bool:
        if self.exec_timeout_minutes is None:
            return False
        return not (self.exec_timeout_minutes == 0 and
                    (self.exec_timeout_seconds or 0) == 0)


@dataclass
class ManagementAccess:
    ssh_enabled: bool = False
    ssh_version: Optional[int] = None
    ssh_timeout: Optional[int] = None
    ssh_retries: Optional[int] = None
    telnet_enabled: bool = False
    http_enabled: bool = False
    https_enabled: bool = False
    vty_lines: list[VtyLine] = field(default_factory=list)
    console: Optional[ConsoleLine] = None
    # FortiGate admin timeout in minutes
    admin_timeout: Optional[int] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class LocalUser:
    username: str
    privilege: Optional[int] = None
    # "plaintext", "type7", "type5_md5", "type8_sha256", "type9_scrypt", "secret", "encrypted", "unknown"
    password_type: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class Authentication:
    aaa_enabled: bool = False
    aaa_auth_methods: list[str] = field(default_factory=list)
    local_users: list[LocalUser] = field(default_factory=list)
    password_encryption_service: bool = False
    enable_password_type: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class SnmpCommunity:
    name: str
    permission: str = "RO"  # "RO" or "RW"
    acl: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class SnmpConfig:
    enabled: bool = False
    communities: list[SnmpCommunity] = field(default_factory=list)
    v3_configured: bool = False
    source_lines: list[int] = field(default_factory=list)


@dataclass
class LoggingConfig:
    buffered: bool = False
    buffer_size: Optional[int] = None
    remote_hosts: list[str] = field(default_factory=list)
    trap_level: Optional[str] = None
    timestamps_enabled: bool = False
    timestamps_msec: bool = False
    source_lines: list[int] = field(default_factory=list)


@dataclass
class NtpConfig:
    servers: list[str] = field(default_factory=list)
    authentication_enabled: bool = False
    source_lines: list[int] = field(default_factory=list)


@dataclass
class AclEntry:
    action: str = "deny"  # "permit" or "deny"
    protocol: Optional[str] = None
    source: str = "any"
    source_wildcard: Optional[str] = None
    destination: Optional[str] = None
    dest_wildcard: Optional[str] = None
    port: Optional[str] = None
    port_operator: Optional[str] = None  # "eq", "range", "gt", "lt"
    log: bool = False
    source_lines: list[int] = field(default_factory=list)


@dataclass
class AccessList:
    name: str
    acl_type: str = "extended"  # "standard" or "extended"
    entries: list[AclEntry] = field(default_factory=list)
    source_lines: list[int] = field(default_factory=list)


@dataclass
class FirewallPolicy:
    """Primarily used for FortiGate firewall policies."""
    policy_id: str = ""
    name: Optional[str] = None
    src_interface: str = "any"
    dst_interface: str = "any"
    src_address: str = "all"
    dst_address: str = "all"
    service: list[str] = field(default_factory=lambda: ["ALL"])
    action: str = "deny"  # "accept" or "deny"
    logging_enabled: bool = False
    utm_enabled: bool = False
    nat_enabled: bool = False
    schedule: str = "always"
    source_lines: list[int] = field(default_factory=list)


@dataclass
class IpsecProposal:
    name: str = ""
    encryption: str = ""
    hash_algorithm: str = ""
    dh_group: Optional[int] = None
    ike_version: Optional[int] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class VpnConfig:
    ipsec_proposals: list[IpsecProposal] = field(default_factory=list)
    ssl_min_tls_version: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class BannerConfig:
    login_banner: Optional[str] = None
    motd_banner: Optional[str] = None
    # FortiGate pre-login banner
    pre_login_banner_enabled: Optional[bool] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class ServiceConfig:
    """Global service-level settings."""
    ip_source_route: Optional[bool] = None
    cdp_globally_enabled: Optional[bool] = None
    lldp_globally_enabled: Optional[bool] = None
    password_encryption: bool = False
    source_lines: list[int] = field(default_factory=list)


@dataclass
class DeviceInfo:
    hostname: str = "unknown"
    vendor: Vendor = Vendor.UNKNOWN
    os_version: Optional[str] = None
    source_lines: list[int] = field(default_factory=list)


@dataclass
class NormalizedConfig:
    """
    The common representation of a network device configuration.
    
    Vendor parsers produce this. Security rules consume this.
    The raw config is kept around so findings can reference
    the exact original lines as evidence.
    """
    device: DeviceInfo = field(default_factory=DeviceInfo)
    interfaces: list[Interface] = field(default_factory=list)
    management: ManagementAccess = field(default_factory=ManagementAccess)
    authentication: Authentication = field(default_factory=Authentication)
    snmp: SnmpConfig = field(default_factory=SnmpConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    ntp: NtpConfig = field(default_factory=NtpConfig)
    access_lists: list[AccessList] = field(default_factory=list)
    firewall_policies: list[FirewallPolicy] = field(default_factory=list)
    vpn: VpnConfig = field(default_factory=VpnConfig)
    banners: BannerConfig = field(default_factory=BannerConfig)
    services: ServiceConfig = field(default_factory=ServiceConfig)

    # Keep the original config for evidence references
    raw_config: str = ""
    raw_lines: list[str] = field(default_factory=list)

    def get_evidence_lines(self, line_numbers: list[int]) -> list[str]:
        """Pull the actual config text for a list of line numbers (1-indexed)."""
        result = []
        for n in line_numbers:
            if 1 <= n <= len(self.raw_lines):
                result.append(f"  {n}: {self.raw_lines[n - 1]}")
        return result
