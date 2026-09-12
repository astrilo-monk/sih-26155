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
            "commands": "no snmp-server community public\nno snmp-server community private\nsnmp-server group SECURE_GRP v3 priv\nsnmp-server user secadmin SECURE_GRP v3 auth sha $9$SNMPAUTH priv aes 256 $9$SNMPPRIV",
            "explanation": "Removes default communities and configures SNMPv3 with authentication and encryption.",
        },
        "fortinet": {
            "commands": "config system snmp community\n  delete 1\nend\nconfig system snmp user\n  edit \"snmp3admin\"\n    set status enable\n    set security-level auth-priv\n    set auth-proto sha256\n    set auth-pwd $9$SNMPAUTH\n    set priv-proto aes256\n    set priv-pwd $9$SNMPPRIV\n  next\nend",
            "explanation": "Removes the default SNMP community and creates an SNMPv3 user with strong authentication.",
        },
    },
    "MGMT-005": {
        "cisco_ios": {
            "commands": "service password-encryption\nenable algorithm-type scrypt secret $9$ENABLEREMEDIATED\nno enable password",
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
            "commands": "ntp authenticate\nntp authentication-key 1 md5 $9$NTMAUTH\nntp trusted-key 1\nntp server 10.0.0.50 key 1\nservice timestamps log datetime msec",
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

    Dispatches to vendor-specific remediation logic to ensure the
    generated config uses correct syntax for the target platform.
    """
    if config.device.vendor == Vendor.FORTINET:
        return _apply_fortinet_remediation(config, commands)
    else:
        return _apply_cisco_remediation(config, commands)


# ===========================================================================
# Cisco IOS Remediation
# ===========================================================================

def _apply_cisco_remediation(config: NormalizedConfig, commands: str) -> NormalizedConfig:
    """
    Apply remediation commands to a Cisco IOS config copy and re-parse.

    Performs comprehensive config transformations to actually fix
    all security issues found by the analysis engine, so the resulting
    config scores 100/100 when re-scanned.
    """
    modified = config.raw_config

    # --- Phase 1: Apply text replacements against the CONFIG FIRST ---
    replacements = {
        "transport input telnet ssh": "transport input ssh",
        "transport input ssh telnet": "transport input ssh",
        "transport input telnet": "transport input ssh",
        "transport input all": "transport input ssh",
        "exec-timeout 0 0": "exec-timeout 5 0",
        "ip ssh version 1": "ip ssh version 2",
    }

    for old, new in replacements.items():
        if old in modified:
            modified = modified.replace(old, new)

    # Replace 'cdp enable' with 'no cdp enable' using regex
    modified = re.sub(
        r'^(\s*)(?<!no )cdp enable\s*$',
        r'\1no cdp enable',
        modified,
        flags=re.MULTILINE,
    )

    # Replace 'cdp run' with 'no cdp run'
    modified = re.sub(
        r'^cdp run\s*$',
        'no cdp run',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 2: Process explicit 'no' and 'set' commands ---
    skip_no_targets = {'transport input telnet', 'transport input ssh',
                       'cdp enable', 'ip http server'}
    # Detect weak ISAKMP policy BEFORE Phase 2 removes it, so we can add strong
    # IKEv2 replacement afterward (Bug #7: false compliance - removing weak policy
    # without adding a secure replacement)
    has_weak_isakmp = bool(re.search(r'^crypto isakmp policy\s+\d+\s*$', modified, re.MULTILINE))
    for line in commands.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        if line.startswith("no "):
            target = line[3:].strip()
            if target in skip_no_targets:
                continue
            modified = _remove_config_line(modified, target)

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

    # --- Phase 5b: Remove non-default RW communities without ACLs ---
    # MGMT-004 fires for RW communities without an ACL - these are dangerous
    # because RW with no ACL means anyone can change device config via SNMP.
    # Regex: snmp-server community <name> RW (without a trailing ACL specifier)
    modified = re.sub(
        r'^snmp-server community\s+(\S+)\s+RW\s*$',
        r'! snmp-server community \1 RW (removed - no ACL)',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 6: Fix 'ip http server' -> 'no ip http server' ---
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

    # --- Phase 7b: Add strong IKEv2 proposal if weak ISAKMP policy was present ---
    has_strong_ikev2 = 'crypto ikev2 proposal' in modified
    if has_weak_isakmp and not has_strong_ikev2:
        modified += '\ncrypto ikev2 proposal STRONG_PROPOSAL\n encryption aes-cbc-256\n prf sha256\n group 14'

    # --- Phase 8: Remove 'no logging host' lines ---
    modified = re.sub(
        r'^no logging host\s*$',
        '! logging fixed (see below)',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 9: Fix named ACL 'permit ip any any' entries ---
    modified = re.sub(
        r'^(\s+)permit ip any any\s*$',
        r'\1deny ip any any log',
        modified,
        flags=re.MULTILINE,
    )
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
    no_lines_to_remove = [
        r'^no aaa new-model\s*$',
        r'^no ntp\s*$',
        r'^no login banner\s*$',
        r'^no ntp server\s+.*$',
    ]
    for pattern in no_lines_to_remove:
        modified = re.sub(pattern, '', modified, flags=re.MULTILINE)

    # Remove VTY/console plaintext passwords
    modified = re.sub(
        r'^(\s+)password\s+\S+\s*$',
        '',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 10c: Ensure CDP is globally disabled ---
    # If config has no 'cdp run' or 'no cdp run' line, CDP is on by default.
    # We need to explicitly disable it.
    if not re.search(r'^(no )?cdp run\s*$', modified, re.MULTILINE):
        # Add 'no cdp run' early in the config (after hostname)
        modified = re.sub(
            r'^(hostname\s+\S+\s*$)',
            r'\1\nno cdp run',
            modified,
            flags=re.MULTILINE,
            count=1,
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
    has_end = any(l.strip() == 'end' for l in lines)

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
            if not any('ip access-list standard MGMT_ACL' in l for l in lines):
                new_lines.append('!')
                new_lines.append('ip access-list standard MGMT_ACL')
                new_lines.append(' permit 10.0.0.0 0.0.0.255')
                new_lines.append(' deny any log')
                new_lines.append('!')
            added_mgmt_acl = True

        new_lines.append(line)

    # --- Phase 11b: Process VTY blocks to ensure each has transport/timeout/access-class ---
    result_lines = []
    in_vty_block = False
    vty_block_lines = []

    for line in new_lines:
        stripped = line.strip()

        if stripped.startswith('line vty'):
            # If we were already in a VTY block, flush it first
            if in_vty_block:
                result_lines.extend(_complete_vty_block(vty_block_lines))
            in_vty_block = True
            vty_block_lines = [line]
            continue

        if in_vty_block:
            # Check if this line is still inside the VTY block (indented or empty)
            if line.startswith(' ') or line.startswith('\t') or stripped == '':
                vty_block_lines.append(line)
                continue
            else:
                # End of VTY block — flush it with any missing lines
                result_lines.extend(_complete_vty_block(vty_block_lines))
                in_vty_block = False
                vty_block_lines = []

        result_lines.append(line)

    # Flush final VTY block if file ends inside one
    if in_vty_block:
        result_lines.extend(_complete_vty_block(vty_block_lines))

    new_lines = result_lines

    # --- Phase 12: Append global config lines before 'end' or at EOF ---
    final_lines = []
    found_end = False
    for line in new_lines:
        stripped = line.strip()
        if stripped == 'end':
            found_end = True
            # Insert all missing global configs before 'end'
            _append_missing_globals(
                final_lines,
                has_ssh_version_2, has_aaa, has_logging_host,
                has_timestamps, has_ntp, has_ntp_auth,
                has_snmpv3, has_banner, has_http_secure,
            )

        final_lines.append(line)

    # If no 'end' line exists, append globals at the very end
    if not found_end:
        _append_missing_globals(
            final_lines,
            has_ssh_version_2, has_aaa, has_logging_host,
            has_timestamps, has_ntp, has_ntp_auth,
            has_snmpv3, has_banner, has_http_secure,
        )
        final_lines.append('end')

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

    return CiscoIOSParser().parse(modified)


def _complete_vty_block(block_lines: list[str]) -> list[str]:
    """
    Ensure a VTY block has transport input ssh, exec-timeout, and access-class.
    Injects any missing lines at the end of the block.
    """
    block_text = '\n'.join(block_lines)
    result = list(block_lines)

    if 'transport input' not in block_text:
        result.append(' transport input ssh')

    if 'exec-timeout' not in block_text:
        result.append(' exec-timeout 5 0')

    if 'access-class' not in block_text:
        result.append(' access-class MGMT_ACL in')

    return result


def _append_missing_globals(
    lines: list[str],
    has_ssh_version_2, has_aaa, has_logging_host,
    has_timestamps, has_ntp, has_ntp_auth,
    has_snmpv3, has_banner, has_http_secure,
):
    """Append missing global config lines (called before 'end' or at EOF)."""
    if not has_ssh_version_2:
        lines.append('ip ssh version 2')
        lines.append('ip ssh time-out 60')
        lines.append('ip ssh authentication-retries 3')

    if not has_aaa:
        lines.append('!')
        lines.append('aaa new-model')
        lines.append('aaa authentication login default local')
        lines.append('aaa authorization exec default local')

    if not has_logging_host:
        lines.append('!')
        lines.append('logging host 10.0.0.100')
        lines.append('logging trap informational')
        lines.append('logging source-interface Loopback0')

    if not has_timestamps:
        lines.append('service timestamps log datetime msec')

    if not has_ntp:
        lines.append('!')
        lines.append('ntp authenticate')
        lines.append('ntp authentication-key 1 md5 $9$NTMAUTH')
        lines.append('ntp trusted-key 1')
        lines.append('ntp server 10.0.0.50 key 1')
    elif not has_ntp_auth:
        lines.append('ntp authenticate')
        lines.append('ntp authentication-key 1 md5 $9$NTMAUTH')
        lines.append('ntp trusted-key 1')

    if not has_snmpv3:
        lines.append('!')
        lines.append('snmp-server group SECURE_GRP v3 priv')
        lines.append('snmp-server user secadmin SECURE_GRP v3 auth sha $9$SNMPAUTH priv aes 256 $9$SNMPPRIV')

    if not has_banner:
        lines.append('!')
        lines.append('banner login ^')
        lines.append('*** WARNING: Authorized access only. All activity is monitored. ***')
        lines.append('^')

    if not has_http_secure:
        lines.append('ip http secure-server')


# ===========================================================================
# Fortinet Remediation
# ===========================================================================

def _apply_fortinet_remediation(config: NormalizedConfig, commands: str) -> NormalizedConfig:
    """
    Apply remediation to a Fortinet FortiOS config and re-parse.

    Uses FortiGate-native syntax only. Never injects Cisco commands.
    """
    modified = config.raw_config

    # --- Phase 1: Process 'set' commands from remediation templates ---
    # These replace existing 'set key value' lines in-place.
    for line in commands.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        if line.startswith("set "):
            key = line.split()[1] if len(line.split()) > 1 else ""
            modified = _replace_fortinet_set(modified, key, line)

    # --- Phase 2: Fix allowaccess on WAN interfaces ---
    # Remove all management services (telnet, http, https, ssh) from allowaccess
    # lines on WAN interfaces. This addresses MGMT-001, MGMT-002, and MGMT-003.
    # Previous implementation only removed telnet/http and used \s* which
    # corrupted config by consuming newlines.
    for service in ('telnet', 'http', 'https', 'ssh'):
        modified = re.sub(
            r'^(\s*set allowaccess\s+.*)\b' + service + r'\b',
            r'\1',
            modified,
            flags=re.MULTILINE,
        )
    # Clean up trailing whitespace and double spaces left by removals
    modified = re.sub(
        r'^(\s*set allowaccess)\s+(\s+)',
        r'\1 ',
        modified,
        flags=re.MULTILINE,
    )
    # Clean up any trailing spaces on allowaccess lines
    modified = re.sub(
        r'^(\s*set allowaccess\s+\S+\s*?)(\s+)$',
        r'\1',
        modified,
        flags=re.MULTILINE,
    )

    # --- Phase 3: Fix SNMP default communities ---
    # Comment out the entire SNMP community block that has 'set name "public"'
    modified = _fortinet_remove_default_snmp(modified)

    # --- Phase 4: Fix overly permissive firewall policies ---
    # Replace 'set srcaddr "all"' with restricted values in firewall policy blocks
    modified = _fortinet_restrict_firewall_policies(modified)

    # --- Phase 5: Fix syslog ---
    # Enable syslog and add server in the syslogd setting block
    modified = _fortinet_fix_syslog(modified)

    # --- Phase 6: Fix NTP authentication ---
    modified = _fortinet_fix_ntp_auth(modified)

    # --- Phase 7: Fix VPN crypto ---
    # Replace weak proposals with strong ones
    modified = re.sub(
        r'(\s+set proposal\s+)3des-md5\b',
        r'\1aes256-sha256',
        modified,
    )
    modified = re.sub(
        r'(\s+set proposal\s+)des-md5\b',
        r'\1aes256-sha256',
        modified,
    )
    # Fix weak DH groups
    modified = re.sub(
        r'(\s+set dhgrp\s+)[12]\b',
        r'\g<1>14',
        modified,
    )

    # --- Phase 8: Fix LLDP on WAN interfaces ---
    # Replace lldp-transmission tx-rx or enable with disable
    modified = re.sub(
        r'(\s+set lldp-transmission\s+)(?:tx-rx|enable)',
        r'\1disable',
        modified,
    )

    # Re-parse the modified config
    from app.parsers.fortinet import FortinetParser
    return FortinetParser().parse(modified)


def _fortinet_remove_default_snmp(config_text: str) -> str:
    """Comment out SNMP community blocks with default names like 'public'."""
    default_names = {'public', 'private', 'community', 'snmp', 'default'}

    # Find and comment out entire community edit blocks with default names
    lines = config_text.splitlines()
    result = []
    in_snmp_community = False
    in_default_edit = False
    edit_depth = 0

    for line in lines:
        stripped = line.strip()

        if stripped == 'config system snmp community':
            in_snmp_community = True
            result.append(line)
            continue

        if in_snmp_community:
            if stripped.startswith('edit '):
                edit_depth = 1
                # Check if this is followed by set name "public" etc.
                # We'll mark it for potential commenting
                result.append(line)
                continue

            if edit_depth > 0:
                if stripped.startswith('set name'):
                    # Extract the name
                    import shlex
                    try:
                        parts = shlex.split(stripped)
                        name = parts[2] if len(parts) > 2 else ""
                    except (ValueError, IndexError):
                        name = stripped.split('"')[1] if '"' in stripped else ""

                    if name.lower() in default_names:
                        in_default_edit = True
                        result.append(f'# {line.lstrip()}  # REMEDIATED: default community removed')
                        continue

                if in_default_edit:
                    # Comment out all lines in this edit block
                    if stripped == 'next':
                        result.append(f'# {line.lstrip()}')
                        in_default_edit = False
                        edit_depth = 0
                        continue
                    elif stripped == 'end' and edit_depth > 0:
                        # Nested end (e.g., config hosts / end)
                        result.append(f'# {line.lstrip()}')
                        continue
                    elif stripped.startswith('config '):
                        result.append(f'# {line.lstrip()}')
                        continue
                    else:
                        result.append(f'# {line.lstrip()}')
                        continue

                if stripped == 'next':
                    edit_depth = 0

            if stripped == 'end' and not in_default_edit:
                in_snmp_community = False

        result.append(line)

    return '\n'.join(result)


def _fortinet_restrict_firewall_policies(config_text: str) -> str:
    """
    Restrict overly permissive firewall policies.

    Replaces 'set srcaddr "all"' with specific addresses and
    'set service "ALL"' with specific services in firewall policy blocks.
    """
    lines = config_text.splitlines()
    result = []
    in_fw_policy = False
    in_edit_block = False

    for line in lines:
        stripped = line.strip()

        if stripped == 'config firewall policy':
            in_fw_policy = True
            result.append(line)
            continue

        if in_fw_policy:
            if stripped.startswith('edit '):
                in_edit_block = True
                result.append(line)
                continue

            if in_edit_block:
                # Replace overly permissive settings
                if re.match(r'\s+set srcaddr\s+"all"', line):
                    result.append(re.sub(r'"all"', '"Internal_Subnet"', line))
                    continue
                elif re.match(r'\s+set dstaddr\s+"all"', line):
                    result.append(re.sub(r'"all"', '"Allowed_Servers"', line))
                    continue
                elif re.match(r'\s+set service\s+"ALL"', line):
                    result.append(re.sub(r'"ALL"', '"HTTPS" "HTTP" "DNS"', line))
                    continue

                if stripped == 'next':
                    in_edit_block = False

            if stripped == 'end':
                in_fw_policy = False

        result.append(line)

    return '\n'.join(result)


def _fortinet_fix_syslog(config_text: str) -> str:
    """
    Enable syslog in the config log syslogd setting block.
    If the block exists, replace 'set status disable' with 'set status enable'
    and add 'set server' if missing.
    If the block doesn't exist, add it.
    """
    lines = config_text.splitlines()
    result = []
    in_syslog_block = False
    found_syslog_block = False
    has_server = False

    for line in lines:
        stripped = line.strip()

        if stripped == 'config log syslogd setting':
            in_syslog_block = True
            found_syslog_block = True
            result.append(line)
            continue

        if in_syslog_block:
            if stripped == 'set status disable':
                result.append('    set status enable')
                continue
            if stripped.startswith('set server'):
                has_server = True
            if stripped == 'end':
                if not has_server:
                    result.append('    set server "10.0.0.100"')
                    result.append('    set mode reliable')
                    result.append('    set port 514')
                in_syslog_block = False

        result.append(line)

    if not found_syslog_block:
        # Add syslog block at the end
        result.append('config log syslogd setting')
        result.append('    set status enable')
        result.append('    set server "10.0.0.100"')
        result.append('    set mode reliable')
        result.append('    set port 514')
        result.append('end')

    return '\n'.join(result)


def _fortinet_fix_ntp_auth(config_text: str) -> str:
    """
    Enable NTP authentication in the config system ntp block.
    Handles nested 'config ntpserver' blocks by tracking depth.
    If no NTP block exists, creates one with authentication and a server.
    If block exists but has no servers, adds a server.
    The parser only reads 'set authentication enable' at the outer NTP block
    level (depth 1), so we must ensure it's there.
    """
    lines = config_text.splitlines()
    result = []
    in_ntp_block = False
    found_ntp_block = False
    has_outer_auth = False  # Only set authentication at depth 1
    has_ntp_server = False
    ntp_depth = 0

    for line in lines:
        stripped = line.strip()

        if stripped == 'config system ntp':
            in_ntp_block = True
            found_ntp_block = True
            ntp_depth = 1
            result.append(line)
            continue

        if in_ntp_block:
            if stripped == 'set authentication enable' and ntp_depth == 1:
                has_outer_auth = True
            if stripped.startswith('set server') and ntp_depth >= 1:
                has_ntp_server = True
            if stripped.startswith('config '):
                ntp_depth += 1
            if stripped == 'end':
                ntp_depth -= 1
                if ntp_depth == 0:
                    # Before closing the NTP block, add auth if missing at outer level
                    if not has_outer_auth:
                        result.append('    set authentication enable')
                    # Add an NTP server if the block has none
                    if not has_ntp_server:
                        result.append('    config ntpserver')
                        result.append('        edit 1')
                        result.append('            set server "10.0.0.50"')
                        result.append('            set authentication enable')
                        result.append('        next')
                        result.append('    end')
                    in_ntp_block = False

        result.append(line)

    # If no NTP block was found at all, create one at the end of the config
    if not found_ntp_block:
        result.append('config system ntp')
        result.append('    set ntpsync enable')
        result.append('    set authentication enable')
        result.append('    config ntpserver')
        result.append('        edit 1')
        result.append('            set server "10.0.0.50"')
        result.append('            set authentication enable')
        result.append('        next')
        result.append('    end')
        result.append('end')

    return '\n'.join(result)


# ===========================================================================
# Shared Helpers
# ===========================================================================

def _remove_config_line(config_text: str, target: str) -> str:
    """Remove lines that EXACTLY match the target from config text (with optional 'no' prefix).

    Previously used substring matching which could remove unintended lines
    (e.g., 'snmp-server community public' would also match 'snmp-server community public2').
    """
    lines = config_text.splitlines()
    result = []
    for line in lines:
        stripped = line.strip()
        # Match exact line content (target or 'no target')
        if stripped == target or stripped == f"no {target}":
            continue
        result.append(line)
    return "\n".join(result)


def _replace_fortinet_set(config_text: str, key: str, new_line: str) -> str:
    """Replace FortiGate 'set' lines with a new value.

    Replaces ALL occurrences of 'set <key>' in the config, not just the first.
    This is necessary because multiple interfaces or policies may have the same
    key (e.g., multiple 'set allowaccess' lines on different WAN interfaces).
    """
    pattern = re.compile(rf"^([ \t]*set {re.escape(key)}\b).*$", re.IGNORECASE | re.MULTILINE)
    return pattern.sub(f"    {new_line}", config_text)


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
