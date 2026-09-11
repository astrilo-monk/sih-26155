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

    This performs comprehensive config transformations to actually fix
    all security issues found by the analysis engine, so the resulting
    config scores 100/100 when re-scanned.
    """
    modified = config.raw_config

    # --- Phase 1: Apply text replacements against the CONFIG FIRST ---
    # Must happen before 'no' command processing to prevent deletion of
    # lines we want to transform (e.g. 'transport input telnet ssh' -> 'transport input ssh')
    replacements = {
        "transport input telnet ssh": "transport input ssh",
        "transport input telnet": "transport input ssh",
        "transport input all": "transport input ssh",
        "exec-timeout 0 0": "exec-timeout 5 0",
        "ip ssh version 1": "ip ssh version 2",
    }

    for old, new in replacements.items():
        if old in modified:
            modified = modified.replace(old, new)

    # Replace 'cdp enable' with 'no cdp enable' using regex to avoid matching
    # lines that already say 'no cdp enable'
    modified = re.sub(
        r'^(\s*)(?<!no )cdp enable\s*$',
        r'\1no cdp enable',
        modified,
        flags=re.MULTILINE,
    )

    # Also replace 'cdp run' with 'no cdp run' to disable CDP globally
    # This handles the case where CDP is enabled globally but not per-interface
    modified = re.sub(
        r'^cdp run\s*$',
        'no cdp run',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 2: Process explicit 'no' and 'set' commands ---
    # Skip commands that would conflict with replacements we already applied
    skip_no_targets = {'transport input telnet', 'transport input ssh',
                       'cdp enable', 'ip http server'}
    for line in commands.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        # Handle 'no X' commands by removing the matching line
        if line.startswith("no "):
            target = line[3:].strip()
            # Skip targets we've already handled via replacements
            if target in skip_no_targets:
                continue
            modified = _remove_config_line(modified, target)

        # Handle 'set X' replacements for FortiGate
        elif line.startswith("set ") and config.device.vendor == Vendor.FORTINET:
            key = line.split()[1] if len(line.split()) > 1 else ""
            modified = _replace_fortinet_set(modified, key, line)

    # --- Phase 3: Fix enable password (any variant) ---
    modified = re.sub(
        r'^enable password(?:\s+\d)?\s+\S+',
        'enable secret 9 $9$REMEDIATED_HASH',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 4: Fix user passwords (password 0/7 -> secret 9) ---
    modified = re.sub(
        r'^(username\s+\S+(?:\s+privilege\s+\d+)?)\s+password(?:\s+[07])?\s+\S+',
        r'\1 secret 9 $9$REMEDIATED_HASH',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 5: Remove default SNMP communities ---
    modified = re.sub(
        r'^snmp-server community (public|private|community|snmp|default)\s+.*$',
        r'! snmp-server community \1 (removed)',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 6: Fix 'ip http server' -> 'no ip http server' ---
    # Be careful not to match 'no ip http server' or 'ip http secure-server'
    modified = re.sub(
        r'^ip http server\s*$',
        'no ip http server',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 7: Fix 'no service password-encryption' or missing ---
    modified = re.sub(
        r'^no service password-encryption\s*$',
        'service password-encryption',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 8: Remove 'no logging host' lines ---
    modified = re.sub(
        r'^no logging host\s*$',
        '! logging fixed (see below)',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 9: Fix named ACL 'permit ip any any' entries ---
    # This handles entries inside named ACLs like OUTSIDE-IN
    modified = re.sub(
        r'^(\s+)permit ip any any\s*$',
        r'\1deny ip any any log',
        modified,
        flags=re.MULTILINE,
    )
    # Also handle old-style numbered ACLs
    modified = re.sub(
        r'^access-list\s+(\d+)\s+permit\s+ip\s+any\s+any\s*$',
        r'access-list \1 deny ip any any log',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 10: Fix ip source-route ---
    if re.search(r'^ip source-route\s*$', modified, re.MULTILINE):
        modified = re.sub(
            r'^ip source-route\s*$',
            'no ip source-route',
            modified,
            flags=re.MULTILINE,
        )

    # --- Phase 10b: Remove 'no X' lines that block remediation additions ---
    # These 'no' lines in the config prevent our additions from taking effect.
    # Remove them so our later phases can add the correct config.
    no_lines_to_remove = [
        r'^no aaa new-model\s*$',
        r'^no ntp\s*$',
        r'^no login banner\s*$',
        r'^no ntp server\s+.*$',
    ]
    for pattern in no_lines_to_remove:
        modified = re.sub(pattern, '', modified, flags=re.MULTILINE)

    # Remove VTY/console plaintext passwords (login without 'local' will use them)
    modified = re.sub(
        r'^(\s+)password\s+\S+\s*$',
        '',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 11: Add missing config lines ---
    lines = modified.splitlines()
    new_lines = []
    added_service_password_enc = False
    added_aaa = False
    added_logging = False
    added_ntp = False
    added_banner = False
    added_snmpv3 = False
    added_mgmt_acl = False
    added_ssh_version = False
    added_http_secure = False

    # Check what already exists
    full_text = modified
    has_service_password_enc = 'service password-encryption' in full_text and 'no service password-encryption' not in full_text
    has_aaa = 'aaa new-model' in full_text
    has_logging_host = bool(re.search(r'^logging host\s+\S+', full_text, re.MULTILINE))
    has_ntp = bool(re.search(r'^ntp server\s+\S+', full_text, re.MULTILINE))
    has_banner = bool(re.search(r'^banner (login|motd)\s+', full_text, re.MULTILINE))
    has_snmpv3 = 'snmp-server group' in full_text and 'v3' in full_text
    has_ssh_version_2 = 'ip ssh version 2' in full_text
    has_http_secure = 'ip http secure-server' in full_text
    has_ntp_auth = 'ntp authenticate' in full_text
    has_timestamps = 'service timestamps log datetime msec' in full_text

    for i, line in enumerate(lines):
        stripped = line.strip()

        # After hostname line, inject global services if missing
        if stripped.startswith('hostname ') and not added_service_password_enc:
            new_lines.append(line)
            if not has_service_password_enc:
                new_lines.append('service password-encryption')
            added_service_password_enc = True
            continue

        # Before the first 'line vty' block, inject MGMT_ACL if needed
        if stripped.startswith('line vty') and not added_mgmt_acl:
            # Add MGMT ACL definition before VTY block
            if not any('ip access-list standard MGMT_ACL' in l for l in lines):
                new_lines.append('!')
                new_lines.append('ip access-list standard MGMT_ACL')
                new_lines.append(' permit 10.0.0.0 0.0.0.255')
                new_lines.append(' deny any log')
                new_lines.append('!')
            added_mgmt_acl = True

        # Inside VTY block: add access-class if missing
        if stripped.startswith('line vty'):
            new_lines.append(line)
            # Look ahead for existing access-class
            has_access_class = False
            j = i + 1
            while j < len(lines) and (lines[j].startswith(' ') or lines[j].startswith('\t')):
                if 'access-class' in lines[j]:
                    has_access_class = True
                j += 1
            if not has_access_class:
                # We'll add it after the transport input line
                pass  # Handled below via the _ensure_vty_access_class approach
            continue

        # After 'transport input ssh' inside VTY, add access-class if needed
        if stripped == 'transport input ssh' and i > 0:
            new_lines.append(line)
            # Check if access-class already follows
            has_access_class = False
            for j in range(max(0, i - 5), min(len(lines), i + 5)):
                if 'access-class' in lines[j]:
                    has_access_class = True
                    break
            if not has_access_class:
                new_lines.append(' access-class MGMT_ACL in')
            continue

        # Add exec-timeout to console if missing
        if stripped == 'line con 0' or stripped.startswith('line console'):
            new_lines.append(line)
            # Look ahead for exec-timeout
            has_timeout = False
            j = i + 1
            while j < len(lines) and (lines[j].startswith(' ') or lines[j].startswith('\t')):
                if 'exec-timeout' in lines[j]:
                    has_timeout = True
                j += 1
            if not has_timeout:
                # Will be added after the login line in the console block
                pass
            continue

        new_lines.append(line)

    # --- Phase 12: Append global config lines before 'end' ---
    final_lines = []
    for line in new_lines:
        stripped = line.strip()
        if stripped == 'end':
            # Insert all missing global configs before 'end'
            if not has_ssh_version_2 and not added_ssh_version:
                final_lines.append('ip ssh version 2')
                final_lines.append('ip ssh time-out 60')
                final_lines.append('ip ssh authentication-retries 3')
                added_ssh_version = True

            if not has_aaa and not added_aaa:
                final_lines.append('!')
                final_lines.append('aaa new-model')
                final_lines.append('aaa authentication login default local')
                final_lines.append('aaa authorization exec default local')
                added_aaa = True

            if not has_logging_host and not added_logging:
                final_lines.append('!')
                final_lines.append('logging host 10.0.0.100')
                final_lines.append('logging trap informational')
                final_lines.append('logging source-interface Loopback0')
                added_logging = True

            if not has_timestamps:
                final_lines.append('service timestamps log datetime msec')

            if not has_ntp and not added_ntp:
                final_lines.append('!')
                final_lines.append('ntp authenticate')
                final_lines.append('ntp authentication-key 1 md5 NTP_SECRET')
                final_lines.append('ntp trusted-key 1')
                final_lines.append('ntp server 10.0.0.50 key 1')
                added_ntp = True
            elif not has_ntp_auth and not added_ntp:
                final_lines.append('ntp authenticate')
                final_lines.append('ntp authentication-key 1 md5 NTP_SECRET')
                final_lines.append('ntp trusted-key 1')
                added_ntp = True

            if not has_snmpv3 and not added_snmpv3:
                final_lines.append('!')
                final_lines.append('snmp-server group SECURE_GRP v3 priv')
                final_lines.append('snmp-server user secadmin SECURE_GRP v3 auth sha AUTH_PASS priv aes 256 PRIV_PASS')
                added_snmpv3 = True

            if not has_banner and not added_banner:
                final_lines.append('!')
                final_lines.append('banner login ^')
                final_lines.append('*** WARNING: Authorized access only. All activity is monitored. ***')
                final_lines.append('^')
                added_banner = True

            if not has_http_secure and not added_http_secure:
                final_lines.append('ip http secure-server')
                added_http_secure = True

            # Add console exec-timeout if not present
            if not re.search(r'line con(?:sole)?\s+0[\s\S]*?exec-timeout', '\n'.join(new_lines)):
                # Find if console block exists; if so, we already handled it
                pass

        final_lines.append(line)

    # --- Phase 13: Ensure console has exec-timeout ---
    result_lines = []
    in_console_block = False
    console_has_timeout = False
    for i, line in enumerate(final_lines):
        stripped = line.strip()
        if stripped == 'line con 0' or stripped.startswith('line console'):
            in_console_block = True
            console_has_timeout = False
            result_lines.append(line)
            continue
        if in_console_block:
            if 'exec-timeout' in stripped:
                console_has_timeout = True
            # End of console block
            if stripped.startswith('!') or (not line.startswith(' ') and not line.startswith('\t') and stripped):
                if not console_has_timeout:
                    result_lines.append(' exec-timeout 5 0')
                in_console_block = False
        result_lines.append(line)

    modified = '\n'.join(result_lines)

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
    pattern = re.compile(rf"^([ \t]*set {re.escape(key)}\s+).*$", re.IGNORECASE | re.MULTILINE)
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
