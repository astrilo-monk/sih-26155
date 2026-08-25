# Detection Rules Reference

This document details the exact logic planned for our 15 core security rules.

*(Status: All rules are currently planned and not yet implemented in code.)*

### SEC-001: Default Credentials Enabled
* **Severity:** Critical
* **Why it's dangerous:** Attackers can immediately gain admin access using known default passwords.
* **Detection Logic:** Check `NormalizedConfig.users` for username/password combinations like `admin/admin` or missing password definitions where default applies.
* **Coverage:** Cisco, FortiGate

### SEC-002: Weak Password Encryption
* **Severity:** High
* **Why it's dangerous:** Weak hashes (like Cisco Type 7) can be cracked in seconds using rainbow tables.
* **Detection Logic:** Check user accounts and enable passwords for weak encryption algorithms (e.g., `encryption_type == 7`).
* **Coverage:** Cisco

### SEC-003: Telnet Enabled
* **Severity:** Critical
* **Why it's dangerous:** Telnet transmits data, including passwords, in plain text.
* **Detection Logic:** Check `NormalizedConfig.management_protocols`. Fail if Telnet is present.
* **Coverage:** Cisco, FortiGate

### SEC-004: Insecure SNMP Version
* **Severity:** High
* **Why it's dangerous:** SNMP v1/v2c send community strings in plain text.
* **Detection Logic:** Check `NormalizedConfig.snmp`. Fail if version is 1 or 2c.
* **Coverage:** Cisco, FortiGate

### SEC-005: Missing ACL on VTY Lines
* **Severity:** High
* **Why it's dangerous:** Anyone on the internet could attempt to SSH/Telnet into the device.
* **Detection Logic:** Check `NormalizedConfig.management_lines` (VTY). Fail if no ACL/access-class is attached.
* **Coverage:** Cisco

### SEC-006: Open DNS Resolver
* **Severity:** Medium
* **Why it's dangerous:** Can be used in DNS amplification DDoS attacks.
* **Detection Logic:** Check if DNS server service is running and accessible from outside interfaces without restrictions.
* **Coverage:** Cisco, FortiGate

### SEC-007: Missing Password Prefix
* **Severity:** Low
* **Why it's dangerous:** Allows users to set weak passwords like 'password123'.
* **Detection Logic:** Check for global password complexity rules (e.g., `security passwords min-length`).
* **Coverage:** Cisco, FortiGate

### SEC-008: Unencrypted Traffic on HTTP
* **Severity:** Medium
* **Why it's dangerous:** Web admin traffic can be sniffed.
* **Detection Logic:** Check `NormalizedConfig.management_protocols`. Fail if HTTP is enabled and HTTPS is not exclusively forced.
* **Coverage:** Cisco, FortiGate

### SEC-009: Permissive Any-Any Rule
* **Severity:** Critical
* **Why it's dangerous:** Completely bypasses the firewall.
* **Detection Logic:** Check `NormalizedConfig.firewall_policies`. Fail if a policy exists with `source=any`, `dest=any`, `action=permit` on external interfaces.
* **Coverage:** FortiGate, Cisco (ACLs)

### SEC-010: Missing Logging
* **Severity:** Medium
* **Why it's dangerous:** Makes incident response and forensics impossible.
* **Detection Logic:** Check `NormalizedConfig.syslog_servers`. Fail if list is empty.
* **Coverage:** Cisco, FortiGate

### SEC-011: Unused Interfaces UP
* **Severity:** Low
* **Why it's dangerous:** An attacker could plug into an active but unmonitored port.
* **Detection Logic:** Find interfaces in `NormalizedConfig.interfaces` where `is_up == True` but `ip_address == null` and no specific role is assigned.
* **Coverage:** Cisco, FortiGate

### SEC-012: Weak IKE/IPSec Policies
* **Severity:** High
* **Why it's dangerous:** Allows decryption of VPN traffic.
* **Detection Logic:** Check `NormalizedConfig.vpn_configs`. Fail if using DES, 3DES, or MD5.
* **Coverage:** Cisco, FortiGate

### SEC-013: Missing BGP Authentication
* **Severity:** Medium
* **Why it's dangerous:** Route hijacking.
* **Detection Logic:** Check `NormalizedConfig.routing.bgp_peers`. Fail if `auth_type == null`.
* **Coverage:** Cisco, FortiGate

### SEC-014: SNMP Public Community
* **Severity:** High
* **Why it's dangerous:** 'public' and 'private' are universally known default SNMP strings.
* **Detection Logic:** Check SNMP config for community strings matching 'public' or 'private'.
* **Coverage:** Cisco, FortiGate

### SEC-015: NTP Unauthenticated
* **Severity:** Low
* **Why it's dangerous:** Time manipulation can break logging and certificate validation.
* **Detection Logic:** Check `NormalizedConfig.ntp`. Fail if configured but authentication is disabled.
* **Coverage:** Cisco, FortiGate
