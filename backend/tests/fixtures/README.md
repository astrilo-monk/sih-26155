# Network Configuration Fixtures

These configuration files are **synthetic test fixtures** designed for testing the AI-Driven Multi-Vendor Network Security Compliance Auditor (SIH26155). 

They are NOT real configurations from production networks. They are designed to look realistic and follow accurate vendor syntax (Cisco IOS, Fortinet FortiOS), but they contain intentional configurations for testing purposes:

- `*_vulnerable.cfg`: Contain intentional security misconfigurations, overly permissive access rules, deprecated protocols, and weak cryptography. These are used to test the auditor's ability to detect non-compliance and security flaws.
- `*_secure.cfg`: Properly hardened versions of the same network topology, demonstrating best practices. These are used to verify that the auditor does not report false positives on compliant configurations.

Do NOT deploy these files to production devices.
