"""
Phase 1a — no raw secret reaches the AI provider.

Secret values are replaced by typed placeholders before any configuration
text is put into a prompt; the kind of secret (type7, psk, …) is kept.
"""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.interpreter import _build_prompt, interpret_lines
from app.ai.client import StructuredResponse
from app.ai.redaction import Redactor, redact_line, redact_text
from app.api.routes.scan import get_scan_store
from app.main import app
from app.models.normalized import DeviceInfo, NormalizedConfig, UnrecognizedLine, Vendor

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("line,expected", [
    ("enable password 7 0822455D0A16", "enable password 7 <SECRET:type7>"),
    ("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "enable secret 5 <SECRET:type5>"),
    ("username admin privilege 15 password 0 Cisc0!", "username admin privilege 15 password 0 <SECRET:type0>"),
    (" password vtypass", " password <SECRET:password>"),
    ("snmp-server community public RO 10", "snmp-server community <SECRET:snmp-community> RO 10"),
    ("crypto isakmp key MyPr3shared address 203.0.113.1", "crypto isakmp key <SECRET:psk> address 203.0.113.1"),
    ("    set psksecret ENC LkQ2xYz==", "    set psksecret ENC <SECRET:psk>"),
    ('    set passwd "p@ss word"', "    set passwd <SECRET:password>"),
    ('        set auth-pwd "Str0ngAuthP@ssw0rd!"', "        set auth-pwd <SECRET:password>"),
    ("tacacs-server host 10.1.1.1 key 7 104D000A0618", "tacacs-server host 10.1.1.1 key 7 <SECRET:type7>"),
    ("ntp authentication-key 1 md5 N7pKey 7", "ntp authentication-key 1 md5 <SECRET:key> 7"),
    (
        "snmp-server user ops OPS v3 auth sha AuthPass1 priv aes 128 PrivPass1",
        "snmp-server user ops OPS v3 auth sha <SECRET:password> priv aes 128 <SECRET:password>",
    ),
    ('set system root-authentication encrypted-password "$6$abc$def"',
     "set system root-authentication encrypted-password <SECRET:password>"),
    ('pre-shared-key ascii-text "$9$xyz"', "pre-shared-key ascii-text <SECRET:psk>"),
    ("password=hunter2", "password=<SECRET:password>"),
    ("enable password level 15 LvlSecret1", "enable password level 15 <SECRET:password>"),
    ("snmp-server host 192.0.2.10 version 2c HostComm1", "snmp-server host 192.0.2.10 version 2c <SECRET:snmp-community>"),
    ("enable password AsaEnable1 encrypted", "enable password <SECRET:password> encrypted"),
    ('    "password": "JsonPass1",', '    "password": "<SECRET:password>",'),
    ("<phash>$1$PanHash$xyz</phash>", "<phash><SECRET:password></phash>"),
    ("  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", "  <SECRET:key>"),
])
def test_each_secret_type_is_replaced_by_a_typed_placeholder(line, expected):
    assert redact_line(line) == expected


# (line, secret that must not survive) — realistic syntaxes across vendors
LEAK_CASES = [
    # Cisco IOS / IOS-XE
    ("enable password level 15 LvlSecret1", "LvlSecret1"),
    ("snmp-server host 192.0.2.10 version 2c HostComm1", "HostComm1"),
    ("snmp-server host 192.0.2.10 HostComm2", "HostComm2"),
    ("snmp-server host 192.0.2.10 traps version 2c HostComm3 udp-port 162", "HostComm3"),
    (" ip ospf message-digest-key 1 md5 OspfMd5Key", "OspfMd5Key"),
    ("key config-key password-encrypt MasterKey1", "MasterKey1"),
    (" wpa-psk ascii 0 WifiPsk123", "WifiPsk123"),
    (" standby 1 authentication text HsrpTxt1", "HsrpTxt1"),
    ("enable password My Spaced Secret", "Spaced Secret"),
    (" key-string 7 06575D72181B", "06575D72181B"),
    ("username bob password ab;cdSemi", "cdSemi"),
    ("crypto isakmp key 6 IsaKey6 address 0.0.0.0", "IsaKey6"),
    (" pre-shared-key address 203.0.113.5 key KeyringPsk", "KeyringPsk"),
    ("ppp chap password 7 0123ABCD", "0123ABCD"),
    # Cisco ASA
    ("enable password AsaEnable1 encrypted", "AsaEnable1"),
    ("username admin password AsaUser1 privilege 15", "AsaUser1"),
    ("snmp-server host inside 10.1.1.1 community AsaComm1 version 2c", "AsaComm1"),
    (" ikev1 pre-shared-key AsaPsk1", "AsaPsk1"),
    # NX-OS / Arista
    ("username admin password 5 $5$NxHash$abc role network-admin", "$5$NxHash$abc"),
    ("snmp-server user admin network-admin auth md5 0xabcdef priv 0x123456 localizedkey", "0x123456"),
    ('tacacs-server host 10.1.1.1 key 7 "NxTac7"', "NxTac7"),
    ("username admin secret sha512 $6$AristaHash", "$6$AristaHash"),
    # FortiOS
    ("    set passphrase ENC FortiWifi1", "FortiWifi1"),
    ("    set ppk-secret ENC FortiPpk1", "FortiPpk1"),
    ("    set sso-password ENC FortiSso1", "FortiSso1"),
    ("    set secondary-secret ENC FortiSec2", "FortiSec2"),
    ("    set password ENC SH2abcdEFGH", "SH2abcdEFGH"),
    # Juniper / VyOS
    ("set system login user a authentication plain-text-password-value PtPw1", "PtPw1"),
    ("set service user a authentication plaintext-password VyPlain1", "VyPlain1"),
    ('    authentication-key "$9$JunOspf"; ## SECRET-DATA', "$9$JunOspf"),
    ("secret JunosUnquoted;", "JunosUnquoted"),
    # Huawei / H3C
    ("local-user admin password irreversible-cipher $1a$HwHash$", "$1a$HwHash$"),
    (" password cipher %^%#HwCipher%^%#", "%^%#HwCipher%^%#"),
    ("snmp-agent community read cipher %^%#HwComm%^%#", "%^%#HwComm%^%#"),
    ("super password level 3 cipher H3cSuper1", "H3cSuper1"),
    (" password simple H3cSimple1", "H3cSimple1"),
    # MikroTik / structured formats
    ("/user add name=ops password=MtPass1 group=full", "MtPass1"),
    ('    "password": "JsonPass1",', "JsonPass1"),
    ("<phash>$1$PanHash$xyz</phash>", "$1$PanHash$xyz"),
    ("<key>PanXmlKey1</key>", "PanXmlKey1"),
    ("password: YamlPass1", "YamlPass1"),
    # PEM body, including its short padded tail
    ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIB", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIB"),
    ("  qkQyZ2Fz0Kt3==", "qkQyZ2Fz0Kt3"),
]


@pytest.mark.parametrize("line,secret", LEAK_CASES)
def test_secret_does_not_survive_redaction(line, secret):
    assert secret not in redact_line(line)


@pytest.mark.parametrize("line", [
    "service password-encryption",
    "no service password-encryption",
    "password encryption aes",
    "crypto key generate rsa modulus 2048",
    "key chain OSPF-KEYS",
    " key 1",
    "secure-shell hostkey-size minimum 3072",
    "ntp trusted-key 1",
    "ntp authenticate",
    "    set authmethod psk",
    " hash sha",
    " encryption aes256",
    "remote-console protocol telnet",
    " transport input ssh",
    "credential-policy minimum-size 15",
    "config system snmp community",
    "aaa authentication login default local",
    "audit-stream destination 10.44.60.20",
    "set deviceconfig system syslog-server 10.20.30.40",
    "interface GigabitEthernet0/1",
    " description uplink to core",
    "ip ssh version 2",
    "logging host 10.0.0.9",
    'set name "wan1"',
    "security passwords min-length 12",
])
def test_non_secret_lines_are_unchanged(line):
    assert redact_line(line) == line


def test_community_name_is_redacted_inside_an_snmp_community_block():
    scope = ("config system snmp community", "edit 1")
    assert redact_line('        set name "public"', scope) == "        set name <SECRET:snmp-community>"
    assert redact_line('        set name "wan1"', ("config system interface", 'edit "wan1"')) == '        set name "wan1"'


def test_redactor_scrubs_known_values_from_free_text():
    redactor = Redactor()
    redactor.line("snmp-server community s3cretComm RO")
    redactor.add_secret("parsedName")
    text = redactor.scrub("SNMP community 's3cretComm' (RO) and 'parsedName' are weak; the public internet is fine")
    assert "s3cretComm" not in text and "parsedName" not in text
    assert "<SECRET:redacted>" in text and "public internet" in text


def test_prose_redaction_removes_secrets_from_sentences():
    text = redact_text(
        "my snmp community string is ChatComm1, the enable password is ChatPw1. psk = ChatPsk1",
        prose=True,
    )
    for secret in ("ChatComm1", "ChatPw1", "ChatPsk1"):
        assert secret not in text


def test_redact_text_handles_multiline_blocks():
    text = redact_text("hostname R1\nenable password 7 0822455D0A16\nline vty 0 4\n password vtypass")
    assert "0822455D0A16" not in text and "vtypass" not in text
    assert text.startswith("hostname R1\n")


# ── integration: every AI entry point ────────────────────────────────────────

SECRET_CONFIG = """\
system-name EDGE-SECRETS
admin-account ops password 0 Adm1nPassw0rd
snmp community Pub1icC0mm read-only
vpn peer 203.0.113.9 pre-shared-key Sh4redK3y!
radius-server 10.1.1.5 key R4diusK3y
remote-console protocol telnet
"""
SECRETS = ["Adm1nPassw0rd", "Pub1icC0mm", "Sh4redK3y!", "R4diusK3y"]


def _sent_text(mock: MagicMock) -> str:
    return "\n".join(str(v) for call in mock.call_args_list for v in (*call.args, *call.kwargs.values()))


def _contains_token(text: str, value: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(value)}(?![\w$])", text) is not None


def test_interpreter_prompt_contains_no_raw_secret():
    lines = [
        UnrecognizedLine(raw_line=text, line_number=i + 1, vendor="unknown",
                         context_before=SECRET_CONFIG.splitlines()[max(0, i - 2):i],
                         context_after=SECRET_CONFIG.splitlines()[i + 1:i + 3])
        for i, text in enumerate(SECRET_CONFIG.splitlines())
    ]
    transport = MagicMock(return_value=StructuredResponse(data={"interpretations": []}))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        interpret_lines(lines)

    sent = _sent_text(transport)
    assert transport.call_count >= 1
    assert "<SECRET:type0>" in sent and "<SECRET:psk>" in sent
    for secret in SECRETS:
        assert secret not in sent


def test_context_lines_are_redacted_with_their_own_block_path():
    """The target sits outside the SNMP community block; its context line is inside it."""
    text = (
        "config system snmp community\n"
        "    edit 1\n"
        '        set name "CtxLeakComm"\n'
        "    end\n"
        "config system admin\n"
    )
    cfg = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config=text, raw_lines=text.splitlines())
    capture_unrecognized_lines(cfg)
    assert cfg.unrecognized_lines
    assert "CtxLeakComm" not in _build_prompt(cfg.unrecognized_lines)


def test_context_without_block_paths_is_redacted_conservatively():
    line = UnrecognizedLine(raw_line="config system admin", line_number=3, vendor="unknown",
                            context_before=['        set name "NoPathComm"', "    end"])
    assert "NoPathComm" not in _build_prompt([line])


def test_scan_api_sends_no_raw_secret_to_the_ai():
    transport = MagicMock(return_value=StructuredResponse(data={"interpretations": []}))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True), \
         patch("app.api.routes.scan.is_available", return_value=True):
        resp = TestClient(app).post("/api/scan", files=[("files", ("s.cfg", SECRET_CONFIG.encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text

    sent = _sent_text(transport)
    assert transport.call_count >= 1
    for secret in SECRETS:
        assert secret not in sent


@pytest.mark.parametrize("fixture", ["cisco_vulnerable.cfg", "fortinet_vulnerable.cfg"])
def test_explain_finding_sends_no_raw_secret(fixture):
    client = TestClient(app)
    scan = client.post("/api/scan", files=[("files", (fixture, (FIXTURES / fixture).read_bytes(), "text/plain"))]).json()
    snmp = next(f for f in scan["findings"] if f["rule_id"] == "MGMT-004")
    # Only names read from configuration lines are secrets; the FortiGate parser
    # also yields a line-less community named after a nested "edit <id>"
    communities = [
        c.name for c in get_scan_store()[scan["scan_id"]]["configs"][0].snmp.communities if c.source_lines
    ]
    assert communities

    generate = MagicMock(return_value="explanation")
    with patch("app.ai.prompts.generate", generate), \
         patch("app.api.routes.assistant.is_available", return_value=True):
        resp = client.get(f"/api/assistant/explain/{scan['scan_id']}/MGMT-004/{snmp['device_hostname']}")
    assert resp.status_code == 200 and resp.json()["ai_generated"] is True

    sent = _sent_text(generate)
    for name in communities:
        assert not _contains_token(sent, name), name


def test_chat_message_is_redacted_as_prose_and_against_known_config_secrets():
    client = TestClient(app)
    fixture = "cisco_vulnerable.cfg"
    scan = client.post("/api/scan", files=[("files", (fixture, (FIXTURES / fixture).read_bytes(), "text/plain"))]).json()
    communities = [c.name for c in get_scan_store()[scan["scan_id"]]["configs"][0].snmp.communities]

    generate = MagicMock(return_value="ok")
    message = (
        f"Is '{communities[0]}' a weak string? My enable password is ChatPw1.\n"
        "enable password 7 0822455D0A16"
    )
    with patch("app.api.routes.assistant.generate", generate), \
         patch("app.api.routes.assistant.is_available", return_value=True):
        resp = client.post("/api/assistant/chat", json={"scan_id": scan["scan_id"], "message": message})
    assert resp.status_code == 200

    sent = _sent_text(generate)
    assert "0822455D0A16" not in sent and "ChatPw1" not in sent
    assert not _contains_token(sent, communities[0])
