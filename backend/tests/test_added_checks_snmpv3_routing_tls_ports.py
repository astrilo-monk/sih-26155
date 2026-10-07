"""
MGMT-012 (SNMPv3 authPriv), BOUNDARY-005 (unused interfaces), BOUNDARY-006 (routing authentication) and
CRYPTO-003 (TLS for web management) on the two confirmed vendors: a weak configuration fails each one on the
right line, a hardened one passes, a device without the feature is N/A, and the fixes that can be safe are.
"""

import pytest

from app.models.results import Status
from app.remediation.engine import analyze_text, remediate_control

NEW = ("MGMT-012", "BOUNDARY-005", "BOUNDARY-006", "CRYPTO-003")

IOS_WEAK = """hostname R1
!
snmp-server group NETOPS v3 auth
snmp-server group SECURE v3 priv
!
ip http secure-server
ip http tls-version TLSv1.0
!
interface GigabitEthernet0/0
 description WAN uplink
 ip address 203.0.113.2 255.255.255.252
!
interface GigabitEthernet0/1
 no ip address
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 shutdown
!
interface GigabitEthernet0/3
 ip address 10.0.0.1 255.255.255.0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 Key12345
!
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
 network 10.1.0.0 0.0.0.255 area 1
 area 1 authentication
!
router bgp 65001
 neighbor 203.0.113.1 remote-as 65000
 neighbor IBGP peer-group
 neighbor IBGP password GroupKey1
 neighbor 10.0.0.2 peer-group IBGP
!
end
"""

IOS_HARD = (IOS_WEAK.replace("v3 auth\n", "v3 priv\n").replace("TLSv1.0", "TLSv1.2")
            .replace(" area 1 authentication\n", " area 1 authentication message-digest\n")
            .replace(" neighbor 203.0.113.1 remote-as 65000\n",
                     " neighbor 203.0.113.1 remote-as 65000\n neighbor 203.0.113.1 password PeerKey1\n")
            .replace(" speed auto\n", " speed auto\n shutdown\n"))

IOS_PLAIN = """hostname R2
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
!
end
"""

FORTI_WEAK = """#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config system global
    set hostname "FG1"
    set admin-https-ssl-versions tlsv1-1 tlsv1-2
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https
        set type physical
        set role wan
    next
    edit "port2"
        set vdom "root"
        set type physical
        set snmp-index 2
    next
    edit "port3"
        set vdom "root"
        set status down
        set type physical
    next
end
config system snmp user
    edit "mon"
        set security-level auth-no-priv
    next
end
config router bgp
    set as 65001
    config neighbor
        edit "203.0.113.1"
            set remote-as 65000
        next
    end
end
config router ospf
    set router-id 1.1.1.1
    config area
        edit 0.0.0.0
            set authentication text
        next
    end
end
"""

FORTI_HARD = (FORTI_WEAK.replace("auth-no-priv", "auth-priv").replace("tlsv1-1 tlsv1-2", "tlsv1-2 tlsv1-3")
              .replace("set authentication text", "set authentication md5")
              .replace("set remote-as 65000\n", "set remote-as 65000\n            set password ENC abc\n")
              .replace("set snmp-index 2\n", "set snmp-index 2\n        set status down\n"))


def _statuses(text: str) -> dict[str, list[tuple[Status, str]]]:
    result = analyze_text(text)
    return {cid: [(r.status, r.scope or "") for r in result.control(cid)] for cid in NEW}


@pytest.mark.parametrize("text", [IOS_WEAK, FORTI_WEAK], ids=["ios", "fortigate"])
def test_weak_configuration_fails_every_added_check(text):
    statuses = _statuses(text)
    for cid in NEW:
        assert any(s == Status.FAIL for s, _ in statuses[cid]), (cid, statuses[cid])


@pytest.mark.parametrize("text", [IOS_HARD, FORTI_HARD], ids=["ios", "fortigate"])
def test_hardened_configuration_passes_every_added_check(text):
    statuses = _statuses(text)
    for cid in NEW:
        assert {s for s, _ in statuses[cid]} == {Status.PASS}, (cid, statuses[cid])


def test_ios_failures_name_the_offending_scope():
    statuses = _statuses(IOS_WEAK)
    assert (Status.FAIL, "SNMPv3 group NETOPS") in statuses["MGMT-012"]
    assert (Status.FAIL, "interface GigabitEthernet0/1") in statuses["BOUNDARY-005"]
    # a shut interface, a configured one and a peer-group member with a password are not findings
    failing = {scope for s, scope in statuses["BOUNDARY-006"] if s == Status.FAIL}
    assert failing == {"neighbor 203.0.113.1", "OSPF 1 area 1"}
    assert {scope for s, scope in statuses["BOUNDARY-005"] if s == Status.FAIL} == {"interface GigabitEthernet0/1"}


def test_ospf_area_counts_its_authenticating_interfaces():
    """Area 0 has no area authentication but its only interface (10.0.0.1 in 10.0.0.0/24) uses MD5."""
    result = analyze_text(IOS_HARD)
    areas = {r.scope: r.status for r in result.control("BOUNDARY-006")}
    assert Status.FAIL not in areas.values() and Status.UNKNOWN not in areas.values()


def test_no_feature_means_not_applicable():
    statuses = _statuses(IOS_PLAIN)
    for cid in ("MGMT-012", "BOUNDARY-006", "CRYPTO-003"):
        assert {s for s, _ in statuses[cid]} == {Status.N_A}, (cid, statuses[cid])


def test_https_without_a_tls_setting_is_undecided_not_passed():
    statuses = _statuses(IOS_PLAIN.replace("!\nend", "ip http secure-server\n!\nend"))
    assert {s for s, _ in statuses["CRYPTO-003"]} == {Status.UNKNOWN}


@pytest.mark.parametrize("text", [IOS_WEAK, FORTI_WEAK], ids=["ios", "fortigate"])
@pytest.mark.parametrize("control_id", ["BOUNDARY-005", "CRYPTO-003"])
def test_safe_fixes_pass_on_rescan(text, control_id):
    outcome, after = remediate_control(text, control_id, {})
    assert outcome.status.value == "fixed", outcome.reason
    assert outcome.control_status_after == "pass"


@pytest.mark.parametrize("text", [IOS_WEAK, FORTI_WEAK], ids=["ios", "fortigate"])
@pytest.mark.parametrize("control_id", ["MGMT-012", "BOUNDARY-006"])
def test_key_dependent_fixes_go_to_manual_review(text, control_id):
    outcome, after = remediate_control(text, control_id, {})
    assert outcome.status.value == "manual_review" and after is None
