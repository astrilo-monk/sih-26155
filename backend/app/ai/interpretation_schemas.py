"""
Pydantic schemas for AI interpretation results.

These models validate structured output from the Groq AI interpreter.
They enforce controlled values for confidence/status and reject
invented normalized fields via an explicit allowlist.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Normalized field allowlist
#
# Derived from app/models/normalized.py. These are the ONLY fields the AI
# is permitted to map unrecognized lines to. The AI MUST NOT invent fields.
# If a line cannot safely map to an existing field, the AI must return
# normalized_field = "unknown".
# ---------------------------------------------------------------------------

NORMALIZED_FIELD_ALLOWLIST: frozenset[str] = frozenset(
    {
        # --- DeviceInfo ---
        "device.hostname",
        "device.vendor",
        "device.os_version",

        # --- Interface ---
        "interfaces[].name",
        "interfaces[].ip_address",
        "interfaces[].subnet_mask",
        "interfaces[].description",
        "interfaces[].shutdown",
        "interfaces[].acl_in",
        "interfaces[].acl_out",
        "interfaces[].allowed_services",
        "interfaces[].is_wan",
        "interfaces[].cdp_enabled",
        "interfaces[].lldp_enabled",

        # --- VtyLine ---
        "management.vty_lines[].line_range",
        "management.vty_lines[].access_class",
        "management.vty_lines[].transport_input",
        "management.vty_lines[].exec_timeout_minutes",
        "management.vty_lines[].exec_timeout_seconds",
        "management.vty_lines[].login_method",

        # --- ConsoleLine ---
        "management.console.exec_timeout_minutes",
        "management.console.exec_timeout_seconds",
        "management.console.login_method",
        "management.console.password_type",

        # --- ManagementAccess ---
        "management.ssh_enabled",
        "management.ssh_version",
        "management.ssh_timeout",
        "management.ssh_retries",
        "management.telnet_enabled",
        "management.http_enabled",
        "management.https_enabled",
        "management.admin_timeout",

        # --- LocalUser ---
        "authentication.local_users[].username",
        "authentication.local_users[].privilege",
        "authentication.local_users[].password_type",

        # --- Authentication ---
        "authentication.aaa_enabled",
        "authentication.aaa_auth_methods",
        "authentication.password_encryption_service",
        "authentication.enable_password_type",

        # --- SnmpCommunity ---
        "snmp.communities[].name",
        "snmp.communities[].permission",
        "snmp.communities[].acl",

        # --- SnmpConfig ---
        "snmp.enabled",
        "snmp.v3_configured",

        # --- LoggingConfig ---
        "logging.buffered",
        "logging.buffer_size",
        "logging.remote_hosts",
        "logging.trap_level",
        "logging.timestamps_enabled",
        "logging.timestamps_msec",

        # --- NtpConfig ---
        "ntp.servers",
        "ntp.authentication_enabled",

        # --- AclEntry ---
        "access_lists[].entries[].action",
        "access_lists[].entries[].protocol",
        "access_lists[].entries[].source",
        "access_lists[].entries[].source_wildcard",
        "access_lists[].entries[].destination",
        "access_lists[].entries[].dest_wildcard",
        "access_lists[].entries[].port",
        "access_lists[].entries[].port_operator",
        "access_lists[].entries[].log",

        # --- AccessList ---
        "access_lists[].name",
        "access_lists[].acl_type",

        # --- FirewallPolicy ---
        "firewall_policies[].policy_id",
        "firewall_policies[].name",
        "firewall_policies[].src_interface",
        "firewall_policies[].dst_interface",
        "firewall_policies[].src_address",
        "firewall_policies[].dst_address",
        "firewall_policies[].service",
        "firewall_policies[].action",
        "firewall_policies[].logging_enabled",
        "firewall_policies[].utm_enabled",
        "firewall_policies[].nat_enabled",
        "firewall_policies[].schedule",

        # --- IpsecProposal ---
        "vpn.ipsec_proposals[].name",
        "vpn.ipsec_proposals[].encryption",
        "vpn.ipsec_proposals[].hash_algorithm",
        "vpn.ipsec_proposals[].dh_group",
        "vpn.ipsec_proposals[].ike_version",

        # --- VpnConfig ---
        "vpn.ssl_min_tls_version",

        # --- BannerConfig ---
        "banners.login_banner",
        "banners.motd_banner",
        "banners.pre_login_banner_enabled",

        # --- ServiceConfig ---
        "services.ip_source_route",
        "services.cdp_globally_enabled",
        "services.lldp_globally_enabled",
        "services.password_encryption",
    }
)


class ConfidenceLevel(str, Enum):
    """Controlled confidence values for AI interpretation."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InterpretationStatus(str, Enum):
    """Status of an AI interpretation attempt."""
    INTERPRETED = "interpreted"
    UNKNOWN = "unknown"
    AI_UNAVAILABLE = "ai_unavailable"


class InterpretationResult(BaseModel):
    """
    A single interpreted configuration line.

    The AI is an interpreter ONLY. It determines semantic meaning,
    never compliance decisions.
    """
    line_number: int = Field(..., description="1-indexed line number in the original config")
    raw_line: str = Field(..., description="The original configuration line text")
    likely_vendor: str = Field(
        ...,
        description="Vendor or vendor family the line likely belongs to",
    )
    security_concept: str = Field(
        ...,
        description="Vendor-independent security concept (e.g. ssh_host_key_minimum)",
    )
    normalized_field: str = Field(
        ...,
        description="Existing normalized field path this maps to, or 'unknown'",
    )
    extracted_value: Optional[str] = Field(
        default=None,
        description="Value extracted from the line, if any",
    )
    confidence: ConfidenceLevel = Field(
        ...,
        description="How confident the AI is in this interpretation",
    )
    reasoning: str = Field(
        ...,
        description="Concise explanation of the interpretation",
    )
    status: InterpretationStatus = Field(
        ...,
        description="Interpretation status",
    )

    @field_validator("normalized_field")
    @classmethod
    def validate_normalized_field(cls, v: str) -> str:
        """Reject invented normalized fields not in the allowlist."""
        from app.ai.interpretation_schemas import NORMALIZED_FIELD_ALLOWLIST
        if v == "unknown":
            return v
        if v not in NORMALIZED_FIELD_ALLOWLIST:
            raise ValueError(
                f"Invented normalized field: {v}. "
                f"Must be one of: {sorted(NORMALIZED_FIELD_ALLOWLIST)} or 'unknown'"
            )
        return v


class BatchedInterpretationResponse(BaseModel):
    """
    Response from a batched Groq interpretation request.

    Contains exactly one result per input line.
    """
    interpretations: list[InterpretationResult] = Field(
        ...,
        description="One interpretation result per input line",
    )