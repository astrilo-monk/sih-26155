import pytest
from app.parsers.cisco_ios import CiscoIOSParser

def test_parse_extended_acl_rest():
    parser = CiscoIOSParser()

    cases = [
        ("ip any any", ("ip", "any", "any")),
        ("tcp any any eq 80", ("tcp", "any", "any")),
        ("udp host 1.1.1.1 any eq 53", ("udp", "host 1.1.1.1", "any")),
        ("icmp 192.168.1.0 0.0.0.255 host 8.8.8.8", ("icmp", "192.168.1.0 0.0.0.255", "host 8.8.8.8")),
        ("tcp any host 10.0.0.1 eq 443", ("tcp", "any", "host 10.0.0.1")),
        ("ip 10.0.0.0 0.255.255.255 172.16.0.0 0.15.255.255", ("ip", "10.0.0.0 0.255.255.255", "172.16.0.0 0.15.255.255")),
    ]

    for rest, expected in cases:
        assert parser._parse_extended_acl_rest(rest) == expected

def test_cisco_acl_parsing_and_boundary_001():
    from app.analysis.engine import analyze
    
    config = """
hostname TEST-RTR
!
ip access-list extended SECURE_ACL
 permit tcp 192.168.1.0 0.0.0.255 host 10.0.0.5 eq 443
 deny ip any any log
!
ip access-list extended VULNERABLE_ACL_1
 permit ip any any
!
access-list 100 permit tcp any any
access-list 101 permit udp any any
access-list 102 deny ip any any
"""
    parser = CiscoIOSParser()
    normalized = parser.parse(config)
    
    # Check if they are parsed correctly
    acl_secure = next(a for a in normalized.access_lists if a.name == "SECURE_ACL")
    assert acl_secure.entries[0].action == "permit"
    assert acl_secure.entries[0].protocol == "tcp"
    assert acl_secure.entries[0].source == "192.168.1.0 0.0.0.255"
    assert acl_secure.entries[0].destination == "host 10.0.0.5"
    
    assert acl_secure.entries[1].action == "deny"
    assert acl_secure.entries[1].protocol == "ip"
    assert acl_secure.entries[1].source == "any"
    assert acl_secure.entries[1].destination == "any"
    assert acl_secure.entries[1].log == True

    acl_vuln1 = next(a for a in normalized.access_lists if a.name == "VULNERABLE_ACL_1")
    assert acl_vuln1.entries[0].action == "permit"
    assert acl_vuln1.entries[0].protocol == "ip"
    assert acl_vuln1.entries[0].source == "any"
    assert acl_vuln1.entries[0].destination == "any"

    acl_100 = next(a for a in normalized.access_lists if a.name == "100")
    assert acl_100.entries[0].action == "permit"
    assert acl_100.entries[0].protocol == "tcp"
    assert acl_100.entries[0].source == "any"
    assert acl_100.entries[0].destination == "any"

    acl_101 = next(a for a in normalized.access_lists if a.name == "101")
    assert acl_101.entries[0].protocol == "udp"
    
    acl_102 = next(a for a in normalized.access_lists if a.name == "102")
    assert acl_102.entries[0].action == "deny"

    # Analyze
    result = analyze(normalized)
    
    boundary_findings = [f for f in result.findings if f.rule_id == "BOUNDARY-001"]
    
    # We should expect findings ONLY for VULNERABLE_ACL_1 (ip any any)
    # The rule BOUNDARY-001 explicitly checks for protocol == 'ip' or None.
    assert len(boundary_findings) == 1, f"Expected 1 BOUNDARY-001 finding, got {len(boundary_findings)}"
    
    evidence_lines = boundary_findings[0].evidence_lines
    assert any("permit ip any any" in line for line in evidence_lines)
    assert not any("permit tcp any any" in line for line in evidence_lines)
    assert not any("permit udp any any" in line for line in evidence_lines)
    assert not any("deny ip any any" in line for line in evidence_lines)


def test_a_comment_inside_an_acl_does_not_end_it():
    """Found by the held-out benchmark (pybatfish newyork.cfg): '! text' is a comment, so the entries after it
    still belong to the ACL; before the fix they were dropped and an any-any permit was read as absent (a PASS)."""
    parser = CiscoIOSParser()
    config = parser.parse("hostname R\n!\nip access-list extended EDGE\n! deny   ip 10.0.0.0 0.255.255.255 any\n"
                          " deny   ip host 192.0.2.1 any\n permit ip any any\n!\nline vty 0 4\n login\n")
    acl = next(a for a in config.access_lists if a.name == "EDGE")
    assert len(acl.entries) == 2 and acl.entries[-1].action == "permit"
