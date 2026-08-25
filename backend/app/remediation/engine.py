"""
Remediation engine.

Generates vendor-specific fix commands for findings and
applies them to a copy of the config for verification.

For well-known fixes we use deterministic templates.
The commands are predictable and correct.
"""

from __future__ import annotations
import re
from app.models.findings import Finding
from app.models.normalized import NormalizedConfig, Vendor

# Mapping of rule_id -> vendor -> fix template
_REMEDIATION_TEMPLATES = {
    "MGMT-001": {
        "cisco_ios": {
            "commands": "line vty 0 4\n transport input ssh\n no transport input telnet",
            "explanation": "This restricts VTY access to SSH only, removing Telnet.",
        },
        "fortinet": {
            "commands": "config system interface\n  edit \"{interface}\"\n    set allowaccess ping https ssh\n  next\nend",
            "explanation": "This removes telnet from the allowed access protocols on the interface.",
        },
    },
    "MGMT-002": {
        "cisco_ios": {
            "commands": "no ip http server\nip http secure-server",
            "explanation": "Disables HTTP and enables HTTPS for web management.",
        },
        "fortinet": {
            "commands": "config system interface\n  edit \"{interface}\"\n    set allowaccess ping https ssh\n  next\nend",
            "explanation": "Removes HTTP from allowed access, keeping only HTTPS and SSH.",
        },
    },
    "MGMT-003": {
        "cisco_ios": {
            "commands": "ip access-list standard MGMT_ACL\n permit 10.0.0.0 0.0.0.255\n deny any log\nline vty 0 4\n access-class MGMT_ACL in",
            "explanation": "Creates a management ACL and applies it to VTY lines. Adjust the permitted network to match your management subnet.",
        },
        "fortinet": {
            "commands": "config system interface\n  edit \"{interface}\"\n    set allowaccess ping\n  next\nend",
            "explanation": "Removes management services from the WAN interface. Manage the device from internal interfaces only.",
        },
    },
    "MGMT-004": {
        "cisco_ios": {
            "commands": "no snmp-server community public\nno snmp-server community private\nsnmp-server group SECURE_GRP v3 priv\nsnmp-server user secadmin SECURE_GRP v3 auth sha <AUTH_PASS> priv aes 256 <PRIV_PASS>",
            "explanation": "Removes default communities and configures SNMPv3 with authentication and encryption. Replace <AUTH_PASS> and <PRIV_PASS> with strong passwords.",
        },
        "fortinet": {
            "commands": "config system snmp community\n  delete 1\nend\nconfig system snmp user\n  edit \"snmp3admin\"\n    set status enable\n    set security-level auth-priv\n    set auth-proto sha256\n    set auth-pwd <AUTH_PASS>\n    set priv-proto aes256\n    set priv-pwd <PRIV_PASS>\n  next\nend",
            "explanation": "Removes the default SNMP community and creates an SNMPv3 user with strong authentication.",
        },
    },
    "MGMT-005": {
        "cisco_ios": {
            "commands": "service password-encryption\nenable algorithm-type scrypt secret <NEW_PASSWORD>\nno enable password",
            "explanation": "Enables password encryption service and replaces the weak enable password with a scrypt-hashed secret.",
        },
    },
    "MGMT-006": {
        "cisco_ios": {
            "commands": "line vty 0 4\n exec-timeout 5 0\nline con 0\n exec-timeout 5 0",
            "explanation": "Sets a 5-minute idle timeout on all management sessions.",
        },
        "fortinet": {
            "commands": "config system global\n  set admintimeout 5\nend",
            "explanation": "Sets admin session timeout to 5 minutes.",
        },
    },
    "MGMT-007": {
        "cisco_ios": {
            "commands": "ip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3",
            "explanation": "Enforces SSH version 2 and sets reasonable timeout and retry limits.",
        },
        "fortinet": {
            "commands": "config system global\n  set admin-ssh-v1 disable\nend",
            "explanation": "Disables SSH version 1.",
        },
    },
    "MGMT-008": {
        "cisco_ios": {
            "commands": "aaa new-model\naaa authentication login default local\naaa authorization exec default local",
            "explanation": "Enables AAA with local authentication. For production, add TACACS+/RADIUS server groups.",
        },
    },
    "MGMT-009": {
        "cisco_ios": {
            "commands": 'banner login ^\n*** WARNING: Authorized access only. All activity is monitored. ***\n^',
            "explanation": "Adds a legal warning banner displayed before login.",
        },
        "fortinet": {
            "commands": "config system global\n  set pre-login-banner enable\nend",
            "explanation": "Enables the pre-login warning banner.",
        },
    },
    "BOUNDARY-001": {
        "cisco_ios": {
            "commands": "no access-list 100 permit ip any any\n! Replace with specific rules:\naccess-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 443\naccess-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 80\naccess-list 100 deny ip any any log",
            "explanation": "Replaces the any-any permit with specific rules. Adjust source/destination/ports for your network.",
        },
        "fortinet": {
            "commands": "config firewall policy\n  edit {policy_id}\n    set srcaddr \"Internal_Subnet\"\n    set dstaddr \"Allowed_Servers\"\n    set service \"HTTPS\" \"HTTP\" \"DNS\"\n    set utm-status enable\n    set logtraffic all\n  next\nend",
            "explanation": "Restricts the firewall policy to specific sources, destinations, and services.",
        },
    },
    "BOUNDARY-002": {
        "cisco_ios": {
            "commands": "no ip source-route",
            "explanation": "Disables IP source routing.",
        },
        "fortinet": {
            "commands": "config system settings\n  set ip-src-routing disable\nend",
            "explanation": "Disables IP source routing.",
        },
    },
    "BOUNDARY-003": {
        "cisco_ios": {
            "commands": "interface {interface}\n no cdp enable",
            "explanation": "Disables CDP on the external interface.",
        },
        "fortinet": {
            "commands": "config system interface\n  edit \"{interface}\"\n    set lldp-transmission disable\n    set lldp-reception disable\n  next\nend",
            "explanation": "Disables LLDP on the WAN interface.",
        },
    },
    "LOG-001": {
        "cisco_ios": {
            "commands": "logging host 10.0.0.100\nlogging trap informational\nlogging source-interface Loopback0",
            "explanation": "Configures remote syslog forwarding. Replace 10.0.0.100 with your syslog server IP.",
        },
        "fortinet": {
            "commands": "config log syslogd setting\n  set status enable\n  set server \"10.0.0.100\"\n  set mode reliable\n  set port 514\nend",
            "explanation": "Enables remote syslog. Replace the server IP with your actual syslog/SIEM server.",
        },
    },
    "LOG-002": {
        "cisco_ios": {
            "commands": "ntp authenticate\nntp authentication-key 1 md5 <NTP_KEY>\nntp trusted-key 1\nntp server 10.0.0.50 key 1\nservice timestamps log datetime msec",
            "explanation": "Configures NTP with authentication and enables millisecond timestamps.",
        },
        "fortinet": {
            "commands": "config system ntp\n  set authentication enable\n  config ntpserver\n    edit 1\n      set server \"10.0.0.50\"\n      set authentication enable\n    next\n  end\nend",
            "explanation": "Enables NTP authentication.",
        },
    },
    "CRYPTO-001": {
        "cisco_ios": {
            "commands": "no crypto isakmp policy 10\ncrypto ikev2 proposal STRONG_PROPOSAL\n encryption aes-cbc-256\n prf sha256\n group 14",
            "explanation": "Replaces weak crypto with AES-256 and SHA-256. Adjust policy number as needed.",
        },
        "fortinet": {
            "commands": "config vpn ipsec phase1-interface\n  edit \"{vpn_name}\"\n    set ike-version 2\n    set proposal aes256-sha256\n    set dhgrp 14 19\n  next\nend",
            "explanation": "Upgrades VPN to IKEv2 with AES-256 and strong DH groups.",
        },
    },
}


def generate_remediation(finding: Finding, configs: list[NormalizedConfig]) -> dict:
    """
    Generate remediation commands for a finding.
    Uses templates for known fixes.
    """
    vendor = finding.vendor
    templates = _REMEDIATION_TEMPLATES.get(finding.rule_id, {})
    template = templates.get(vendor)

    if template:
        commands = template["commands"]
        explanation = template["explanation"]

        # Try to fill in interface names from evidence
        if "{interface}" in commands and finding.evidence_lines:
            iface_name = _extract_interface_name(finding.evidence_lines)
            if iface_name:
                commands = commands.replace("{interface}", iface_name)

        return {"commands": commands, "explanation": explanation}

    # Fallback for rules without templates
    return {
        "commands": f"! Remediation for {finding.rule_id} - review manually\n! {finding.recommendation}",
        "explanation": finding.recommendation,
    }


def apply_remediation(config: NormalizedConfig, commands: str) -> NormalizedConfig:
    """
    Apply remediation commands to a copy of the config and re-parse.

    This is a simplified approach: we modify the raw config text
    based on known patterns and re-parse it. It won't handle
    every possible remediation, but it works for the demo flow.
    """
    modified = config.raw_config

    for line in commands.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        # Handle 'no X' commands by removing the matching line
        if line.startswith("no "):
            target = line[3:].strip()
            modified = _remove_config_line(modified, target)

        # Handle 'set X' replacements for FortiGate
        elif line.startswith("set ") and config.device.vendor == Vendor.FORTINET:
            key = line.split()[1] if len(line.split()) > 1 else ""
            modified = _replace_fortinet_set(modified, key, line)

    # Some common text replacements for the before/after demo
    replacements = {
        "transport input telnet ssh": "transport input ssh",
        "transport input telnet": "transport input ssh",
        "transport input all": "transport input ssh",
        "ip http server": "no ip http server",
        "exec-timeout 0 0": "exec-timeout 5 0",
        "ip ssh version 1": "ip ssh version 2",
        "ip source-route": "no ip source-route",
        "enable password 7": "enable secret 9",
        "snmp-server community public": "! snmp-server community public (removed)",
        "snmp-server community private": "! snmp-server community private (removed)",
        "access-list 100 permit ip any any": "access-list 100 deny ip any any log",
    }

    for old, new in replacements.items():
        if old in commands or any(old in c for c in commands.splitlines()):
            modified = modified.replace(old, new)

    # Re-parse the modified config
    from app.parsers.detector import detect_vendor
    from app.parsers.cisco_ios import CiscoIOSParser
    from app.parsers.fortinet import FortinetParser

    vendor = detect_vendor(modified)
    if vendor == Vendor.CISCO_IOS:
        return CiscoIOSParser().parse(modified)
    elif vendor == Vendor.FORTINET:
        return FortinetParser().parse(modified)

    return config


def _remove_config_line(config_text: str, target: str) -> str:
    """Remove lines matching the target from config text."""
    lines = config_text.splitlines()
    result = [l for l in lines if target not in l]
    return "\n".join(result)


def _replace_fortinet_set(config_text: str, key: str, new_line: str) -> str:
    """Replace a FortiGate 'set' line with a new value."""
    pattern = re.compile(rf"(\s*set {re.escape(key)}\s+).*", re.IGNORECASE)
    return pattern.sub(f"    {new_line}", config_text, count=1)


def _extract_interface_name(evidence_lines: list[str]) -> str | None:
    """Try to extract an interface name from evidence lines."""
    for line in evidence_lines:
        # Cisco: "interface GigabitEthernet0/0"
        match = re.search(r"interface\s+(\S+)", line)
        if match:
            return match.group(1)
        # FortiGate: 'edit "wan1"'
        match = re.search(r'edit\s+"?(\S+?)"?', line)
        if match:
            return match.group(1)
    return None
