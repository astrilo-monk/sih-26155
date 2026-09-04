# Detection Rules Reference

This document details the exact logic for our 15 core security rules, which are currently implemented in the codebase.

*(Status: All rules are fully implemented and mapped to CIS/NIST compliance frameworks.)*

### MGMT-001: Insecure Management Protocol (Telnet) Enabled
* **Severity:** Critical
* **Why it's dangerous:** Telnet transmits data, including passwords, in plain text.
* **Coverage:** Cisco, FortiGate

### MGMT-002: Insecure HTTP Management Enabled
* **Severity:** High
* **Why it's dangerous:** Web admin traffic can be sniffed if not using HTTPS.
* **Coverage:** Cisco, FortiGate

### MGMT-003: Unrestricted Management Access
* **Severity:** Critical
* **Why it's dangerous:** Anyone on the internet could attempt to SSH into the device without source IP restrictions.
* **Coverage:** Cisco, FortiGate

### MGMT-004: Weak or Default SNMP Community Strings
* **Severity:** High
* **Why it's dangerous:** 'public' and 'private' are universally known default SNMP strings, allowing attackers to read or write config.
* **Coverage:** Cisco, FortiGate

### MGMT-005: Plaintext or Weakly Encrypted Passwords
* **Severity:** Critical
* **Why it's dangerous:** Weak hashes (like Cisco Type 7) can be cracked in seconds using rainbow tables.
* **Coverage:** Cisco only

### MGMT-006: Missing or Disabled Session Timeout
* **Severity:** Medium
* **Why it's dangerous:** Idle admin sessions remain open, allowing local attackers to hijack the console.
* **Coverage:** Cisco, FortiGate

### MGMT-007: SSH Version 1 or Weak SSH Configuration
* **Severity:** High
* **Why it's dangerous:** SSHv1 has known cryptographic vulnerabilities.
* **Coverage:** Cisco, FortiGate

### MGMT-008: AAA (Authentication, Authorization, Accounting) Not Configured
* **Severity:** High
* **Why it's dangerous:** Prevents centralized credential management and auditing.
* **Coverage:** Cisco

### MGMT-009: Missing Login Banner
* **Severity:** Low
* **Why it's dangerous:** Missing legal warning banners can complicate prosecution of unauthorized access.
* **Coverage:** Cisco, FortiGate

### BOUNDARY-001: Overly Permissive Firewall/ACL Rules
* **Severity:** Critical
* **Why it's dangerous:** `any-any` permit rules completely bypass the firewall for that traffic.
* **Coverage:** Cisco, FortiGate

### BOUNDARY-002: IP Source Routing Enabled
* **Severity:** Medium
* **Why it's dangerous:** Allows an attacker to specify the return path of a packet, bypassing routing table security.
* **Coverage:** Cisco, FortiGate

### BOUNDARY-003: Discovery Protocol (CDP/LLDP) Enabled on External Interface
* **Severity:** Medium
* **Why it's dangerous:** Leaks internal network topology information to external networks.
* **Coverage:** Cisco, FortiGate

### LOG-001: No Remote Syslog Server Configured
* **Severity:** High
* **Why it's dangerous:** Makes incident response and forensics impossible if the device is compromised or wiped.
* **Coverage:** Cisco, FortiGate

### LOG-002: NTP Not Configured or Unauthenticated
* **Severity:** Medium
* **Why it's dangerous:** Time manipulation can break logging correlation and certificate validation.
* **Coverage:** Cisco, FortiGate

### CRYPTO-001: Weak VPN/IPsec Cryptographic Algorithms
* **Severity:** High
* **Why it's dangerous:** Allows decryption of VPN traffic (e.g., using DES, 3DES, or MD5).
* **Coverage:** Cisco, FortiGate
