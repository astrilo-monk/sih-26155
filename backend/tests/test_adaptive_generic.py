"""
Generic adaptive interpretation suite.

The same pipeline must handle any configuration dialect:

    capture → learned mappings → AI (schema-constrained, per-item validated)
            → evidence + confidence decision → safe NormalizedConfig write
            → existing compliance engine

Four syntactically different dialects are exercised — flat ``set`` paths,
brace hierarchies, ``config``/``edit`` blocks and slash-path ``key=value``
commands. None of them is special-cased anywhere in the application; the
knowledge tables below only play the role of the external AI model.

Groq is never called: the transport (``request_structured``) or the
interpreter is replaced by fakes. Set ``NETAUDIT_LIVE_AI=1`` to additionally
run the live repeatability check against the real API.
"""

from __future__ import annotations

import os
import random
import re
from types import SimpleNamespace
from typing import NamedTuple, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.context import structural_paths
from app.adaptive.interpreter import (
    INTERPRETATION_RESPONSE_FORMAT,
    INTERPRETATION_SYSTEM_PROMPT,
    MAX_LINES_PER_BATCH,
    _build_prompt,
    interpret_lines,
)
from app.adaptive.mapper import line_polarity, map_interpretations
from app.adaptive.service import AdaptiveService
from app.adaptive.vendor import assess_vendor_evidence, normalize_vendor_name
from app.ai import client as ai_client
from app.ai.client import StructuredResponse
from app.ai.interpretation_schemas import (
    NORMALIZED_FIELD_ALLOWLIST,
    ConfidenceLevel,
    InterpretationResult,
    InterpretationStatus,
)
from app.api.routes.scan import get_scan_store
from app.db.mappings import LearnedMapping, MappingRepository
from app.main import app
from app.models.field_catalog import FIELD_REGISTRY, NORMALIZED_FIELD_PATHS, SETTABLE_FIELDS
from app.models.normalized import (
    AIFieldMapping,
    DeviceInfo,
    NormalizedConfig,
    UnrecognizedLine,
    Vendor,
)
from app.parsers.detector import detect_vendor


# ── Dialects ──────────────────────────────────────────────────────────────────

FLAT_SET = """\
set deviceconfig system type static
set deviceconfig system ip-address 10.10.10.1
set deviceconfig system netmask 255.255.255.0
set deviceconfig system default-gateway 10.10.10.254
set deviceconfig system update-server updates.paloaltonetworks.com

set deviceconfig system service disable-telnet no
set deviceconfig system service disable-http no
set deviceconfig system service disable-ssh no

set deviceconfig system ntp-servers primary-ntp-server ntp1.example.com
set deviceconfig system ntp-servers secondary-ntp-server ntp2.example.com

set deviceconfig system syslog-server 10.20.30.40
set deviceconfig system syslog-server 10.20.30.41

set deviceconfig setting management hostname PA-EDGE-01

set rulebase security rules Allow-Web from trust to untrust source any destination any application web-browsing service application-default action allow
set rulebase security rules Allow-SSH from untrust to trust source any destination any application ssh service application-default action allow
set rulebase security rules Allow-Telnet from untrust to trust source any destination any application telnet service application-default action allow

set deviceconfig system permitted-ip 10.10.10.0/24
"""

BRACES = """\
system {
    host-name core-sw-01;
    services {
        ssh {
            protocol-version v2;
        }
        telnet;
    }
    authentication-order radius;
    login {
        idle-timeout 15;
    }
}
"""

BLOCK_EDIT = """\
config management-plane
    https enable
    http disable
    ssh enable
    telnet disable
    idle-timeout 20
exit
config log-forwarding
    collector 198.51.100.7
exit
config clock
    ntp-server time.example.net
exit
"""

SLASH_PATH = """\
/system identity set name=edge-rtr-09
/ip service set telnet disabled=yes
/ip service set ssh disabled=no
/ip service set www-ssl disabled=no
/system logging action set remote remote=203.0.113.9
/system ntp client set enabled=yes servers=203.0.113.20
/radius add service=login address=203.0.113.30
/ip ipsec proposal set default enc-algorithms=aes-256-cbc
"""


class Answer(NamedTuple):
    field: str
    value: str
    evidence: str


# What a competent model would answer — keyed by a distinctive fragment.
# Lines with no entry are answered "unknown" (rules, objects, noise).
KNOWLEDGE = {
    "flat": [
        ("disable-telnet no", Answer("management.telnet_enabled", "true", "disable-telnet no")),
        ("disable-http no", Answer("management.http_enabled", "true", "disable-http no")),
        ("disable-ssh no", Answer("management.ssh_enabled", "true", "disable-ssh no")),
        ("primary-ntp-server", Answer("ntp.servers", "ntp1.example.com", "ntp1.example.com")),
        ("secondary-ntp-server", Answer("ntp.servers", "ntp2.example.com", "ntp2.example.com")),
        ("syslog-server 10.20.30.40", Answer("logging.remote_hosts", "10.20.30.40", "10.20.30.40")),
        ("syslog-server 10.20.30.41", Answer("logging.remote_hosts", "10.20.30.41", "10.20.30.41")),
        ("hostname PA-EDGE-01", Answer("device.hostname", "PA-EDGE-01", "hostname PA-EDGE-01")),
    ],
    "braces": [
        ("protocol-version v2", Answer("management.ssh_version", "2", "protocol-version v2")),
        ("telnet;", Answer("management.telnet_enabled", "true", "telnet")),
        ("authentication-order radius", Answer("authentication.aaa_auth_methods", "radius", "radius")),
        ("idle-timeout 15", Answer("management.admin_timeout", "15", "idle-timeout 15")),
    ],
    "block": [
        ("https enable", Answer("management.https_enabled", "true", "https enable")),
        ("http disable", Answer("management.http_enabled", "false", "http disable")),
        ("ssh enable", Answer("management.ssh_enabled", "true", "ssh enable")),
        ("telnet disable", Answer("management.telnet_enabled", "false", "telnet disable")),
        ("idle-timeout 20", Answer("management.admin_timeout", "20", "idle-timeout 20")),
        ("collector 198.51.100.7", Answer("logging.remote_hosts", "198.51.100.7", "198.51.100.7")),
        ("ntp-server time.example.net", Answer("ntp.servers", "time.example.net", "time.example.net")),
    ],
    "slash": [
        ("telnet disabled=yes", Answer("management.telnet_enabled", "false", "telnet disabled=yes")),
        ("ssh disabled=no", Answer("management.ssh_enabled", "true", "ssh disabled=no")),
        ("www-ssl disabled=no", Answer("management.https_enabled", "true", "www-ssl disabled=no")),
        ("remote=203.0.113.9", Answer("logging.remote_hosts", "203.0.113.9", "203.0.113.9")),
        ("servers=203.0.113.20", Answer("ntp.servers", "203.0.113.20", "203.0.113.20")),
        ("/radius add", Answer("authentication.aaa_auth_methods", "radius", "radius")),
    ],
}

DIALECTS = {
    "flat": (FLAT_SET, "palo_alto", {
        "ntp.servers": ["ntp1.example.com", "ntp2.example.com"],
        "logging.remote_hosts": ["10.20.30.40", "10.20.30.41"],
        "management.ssh_enabled": True,
        "management.telnet_enabled": True,
        "management.http_enabled": True,
        "device.hostname": "PA-EDGE-01",
    }),
    "braces": (BRACES, "juniper_junos", {
        "management.ssh_version": 2,
        "management.telnet_enabled": True,
        "management.admin_timeout": 15,
        "authentication.aaa_auth_methods": ["radius"],
    }),
    "block": (BLOCK_EDIT, "unknown", {
        "management.https_enabled": True,
        "management.ssh_enabled": True,
        "management.telnet_enabled": False,
        "management.admin_timeout": 20,
        "logging.remote_hosts": ["198.51.100.7"],
        "ntp.servers": ["time.example.net"],
    }),
    "slash": (SLASH_PATH, "mikrotik_routeros", {
        "management.telnet_enabled": False,
        "management.ssh_enabled": True,
        "management.https_enabled": True,
        "logging.remote_hosts": ["203.0.113.9"],
        "ntp.servers": ["203.0.113.20"],
        "authentication.aaa_auth_methods": ["radius"],
    }),
}

VENDOR_SPELLINGS = {
    "palo_alto": ["palo_alto", "Palo Alto Networks", "pan-os", "PaloAlto"],
    "juniper_junos": ["juniper", "JunOS", "Juniper Networks"],
    "mikrotik_routeros": ["mikrotik", "RouterOS", "MikroTik RouterOS"],
    "unknown": ["unknown", "generic", ""],
}


# ── Fakes ─────────────────────────────────────────────────────────────────────

_TARGET = re.compile(r"^\[TARGET line (\d+)\]\n(.*)$", re.MULTILINE)


def _lookup(dialect: str, text: str) -> Optional[Answer]:
    return next((a for needle, a in KNOWLEDGE[dialect] if needle in text), None)


def _targets(prompt: str) -> list[tuple[int, str]]:
    return [(int(n), text) for n, text in _TARGET.findall(prompt)]


def make_responder(
    dialect: str,
    vendor: str = "unknown",
    confidence: str = "high",
    rng: Optional[random.Random] = None,
    transform=None,
):
    """A fake structured transport answering like a model would."""

    def respond(**kwargs):
        items = []
        for number, text in _targets(kwargs["prompt"]):
            answer = _lookup(dialect, text)
            spelling = rng.choice(VENDOR_SPELLINGS[vendor]) if rng else vendor
            if answer is None:
                items.append(dict(
                    line_number=number, raw_line=text, likely_vendor=spelling,
                    security_concept="unknown", normalized_field="unknown",
                    extracted_value=None, value_evidence=None, confidence="low",
                    numeric_confidence=0.2, reasoning="Not a catalog field", status="unknown",
                ))
                continue
            band = (0.86, 0.98) if confidence == "high" else (0.55, 0.8)
            items.append(dict(
                line_number=number, raw_line=text, likely_vendor=spelling,
                security_concept="setting", normalized_field=answer.field,
                extracted_value=answer.value, value_evidence=answer.evidence,
                confidence=confidence,
                numeric_confidence=round(rng.uniform(*band), 2) if rng else sum(band) / 2,
                reasoning=rng.choice(["Sets it.", "Configures the setting.", f"'{text}' sets it."]) if rng
                else f"'{text}' sets {answer.field}",
                status="interpreted",
            ))
        if rng:
            rng.shuffle(items)
        if transform:
            items = transform(items)
        return StructuredResponse(data={"interpretations": items})

    return respond


def make_interpreter(dialect: str, vendor: str = "unknown", confidence=ConfidenceLevel.HIGH, numeric=0.93):
    """A fake interpret_lines for service-level tests."""

    def interpret(lines):
        results = []
        for ln in lines:
            answer = _lookup(dialect, ln.raw_line)
            if answer is None:
                results.append(InterpretationResult(
                    line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor=vendor,
                    security_concept="unknown", normalized_field="unknown", extracted_value=None,
                    confidence=ConfidenceLevel.LOW, numeric_confidence=0.2, reasoning="unknown",
                    status=InterpretationStatus.UNKNOWN,
                ))
            else:
                results.append(InterpretationResult(
                    line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor=vendor,
                    security_concept="setting", normalized_field=answer.field,
                    extracted_value=answer.value, value_evidence=answer.evidence,
                    confidence=confidence, numeric_confidence=numeric,
                    reasoning=f"{ln.raw_line.strip()} sets {answer.field}",
                    status=InterpretationStatus.INTERPRETED,
                ))
        return results

    return MagicMock(side_effect=interpret)


@pytest.fixture
def client():
    return TestClient(app)


def _scan(client, text, responder, name="device.cfg"):
    """Scan through the REAL interpreter with a fake Groq transport."""
    transport = MagicMock(side_effect=responder)
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True), \
         patch("app.api.routes.scan.is_available", return_value=True):
        resp = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    return resp.json(), transport


def _config(text: str) -> NormalizedConfig:
    cfg = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=text,
        raw_lines=text.splitlines(),
    )
    capture_unrecognized_lines(cfg)
    return cfg


def _value(cfg: NormalizedConfig, path: str):
    info = FIELD_REGISTRY[path]
    return getattr(info.get_parent(cfg), info.attr_name)


def _records(scan) -> dict[int, dict]:
    return {m["line_number"]: m for m in scan["adaptive"]["ai_mappings"]}


def _record_for(scan, fragment: str) -> dict:
    return next(m for m in scan["adaptive"]["ai_mappings"] if fragment in m["raw_line"])


def _rule_ids(scan) -> set[str]:
    return {f["rule_id"] for f in scan["findings"]}


def _lines(*texts: str) -> list[UnrecognizedLine]:
    return [UnrecognizedLine(raw_line=t, line_number=i + 1, vendor="unknown") for i, t in enumerate(texts)]


# ═══════════════════════════════════════════════════════════════════════════════
# 1 + 8 — every dialect produces structured interpretations that safely
#         populate NormalizedConfig and feed the unchanged compliance engine
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("dialect", list(DIALECTS))
def test_dialect_high_confidence_populates_normalized_config(client, dialect):
    text, vendor, expected = DIALECTS[dialect]
    assert detect_vendor(text) == Vendor.UNKNOWN

    scan, transport = _scan(client, text, make_responder(dialect, vendor=vendor))
    cfg = get_scan_store()[scan["scan_id"]]["configs"][0]

    assert transport.call_count >= 1
    for path, value in expected.items():
        assert _value(cfg, path) == value, path

    applied = [m for m in scan["adaptive"]["ai_mappings"] if m["source"] == "ai_auto_mapped"]
    assert len(applied) >= len(expected)
    assert all(m["normalized_field"] in FIELD_REGISTRY for m in applied)
    assert all(m["status"] != "ai_unavailable" for m in scan["adaptive"]["ai_mappings"])

    # The vendor is never set from AI output, whatever the evidence says
    assert scan["devices"][0]["vendor"] == "unknown"
    # Absence never fails on an unidentified vendor, and a score needs a value
    # that some rule actually evaluated (Phase 1c)
    assert "LOG-001" not in _rule_ids(scan)
    assert (scan["score"] is not None) is DIALECT_IS_ASSESSED[dialect]


# Syslog / NTP server values are evaluated by vendor-neutral rules; the braces
# dialect only yields SSH, Telnet, AAA and timeout values, which feed
# vendor-specific rules and therefore leave the config unassessed.
DIALECT_IS_ASSESSED = {"flat": True, "braces": False, "block": True, "slash": True}


def test_unsupported_structures_go_to_review_not_to_config(client):
    scan, _ = _scan(client, FLAT_SET, make_responder("flat"))
    for fragment in ("rulebase security rules", "update-server", "permitted-ip"):
        record = _record_for(scan, fragment)
        assert record["source"] in ("needs_review", "needs_training")
        assert record["normalized_field"] == "unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# Regression — the Palo Alto screenshot, stated generically
# ═══════════════════════════════════════════════════════════════════════════════

def test_regression_unknown_vendor_does_not_downgrade_valid_syslog_and_ntp(client):
    """Valid syslog/NTP syntax must not become an unusable LOW-confidence
    mapping merely because the vendor is unknown."""
    scan, _ = _scan(client, FLAT_SET, make_responder("flat", vendor="unknown"))

    for fragment in ("syslog-server", "ntp-servers"):
        records = [m for m in scan["adaptive"]["ai_mappings"] if fragment in m["raw_line"]]
        assert len(records) == 2
        for record in records:
            assert record["source"] == "ai_auto_mapped"
            assert record["confidence_tier"] == "high"
            assert record["final_value"]

    cfg = get_scan_store()[scan["scan_id"]]["configs"][0]
    assert cfg.logging.remote_hosts == ["10.20.30.40", "10.20.30.41"]
    assert cfg.ntp.servers == ["ntp1.example.com", "ntp2.example.com"]
    assert "LOG-001" not in _rule_ids(scan)

    # Naming a vendor changes nothing about the mapping decision
    named, _ = _scan(client, FLAT_SET, make_responder("flat", vendor="palo_alto"))
    decisions = lambda s: sorted((m["line_number"], m["source"], m["confidence_tier"]) for m in s["adaptive"]["ai_mappings"])
    assert decisions(named) == decisions(scan)


def test_regression_ai_outage_is_not_reported_as_low_confidence(client):
    """The observed failure: every key hit the daily quota and the Training
    tab showed LOW / 30% / "No usable suggestion" for every line."""
    quota = MagicMock(return_value=StructuredResponse(error="quota_exhausted", detail="tokens per day (TPD)"))
    scan, transport = _scan(client, FLAT_SET, quota.side_effect or (lambda **kw: quota()))

    adaptive = scan["adaptive"]
    captured = len(adaptive["unrecognized_lines"])
    assert captured > MAX_LINES_PER_BATCH                   # more than one chunk…
    assert transport.call_count == 1                        # …but no calls after the quota error
    assert adaptive["ai_unavailable_lines"] == captured
    assert any("AI interpretation was unavailable" in r for r in adaptive["provisional_reasons"])

    for record in adaptive["ai_mappings"]:
        assert record["status"] == "ai_unavailable"
        assert record["confidence"] == 0.0
        assert "LOW confidence" not in record["reason"]
        assert "quota" in record["reasoning"]

    queue = client.get(f"/api/adaptive/scans/{scan['scan_id']}/review").json()
    assert queue["pending_count"] == captured
    assert {i["interpretation_status"] for i in queue["items"]} == {"ai_unavailable"}


# ═══════════════════════════════════════════════════════════════════════════════
# 2 — controlled vocabulary from one source of truth
# ═══════════════════════════════════════════════════════════════════════════════

def test_vocabulary_derives_from_one_catalog(client):
    items = INTERPRETATION_RESPONSE_FORMAT["json_schema"]["schema"]["properties"]["interpretations"]["items"]
    assert items["properties"]["normalized_field"]["enum"] == [*SETTABLE_FIELDS, "unknown"]
    assert set(items["properties"]) == set(items["required"])

    assert NORMALIZED_FIELD_ALLOWLIST is NORMALIZED_FIELD_PATHS
    assert set(FIELD_REGISTRY) <= NORMALIZED_FIELD_PATHS
    for name in SETTABLE_FIELDS:
        assert f"- {name} [" in INTERPRETATION_SYSTEM_PROMPT
        assert FIELD_REGISTRY[name].label and FIELD_REGISTRY[name].value_rule
    assert "{field_catalog}" not in INTERPRETATION_SYSTEM_PROMPT

    fields = client.get("/api/adaptive/fields").json()
    assert [f["field"] for f in fields] == list(SETTABLE_FIELDS)
    assert all(f["label"] and f["value_rule"] for f in fields)


# ═══════════════════════════════════════════════════════════════════════════════
# 3 + 4 — invalid fields / values are rejected per line
# ═══════════════════════════════════════════════════════════════════════════════

def test_invented_field_only_affects_its_own_line(client):
    def invent(items):
        for item in items:
            if "disable-ssh" in item["raw_line"]:
                item["normalized_field"] = "security_policies[].action"
        return items

    scan, _ = _scan(client, FLAT_SET, make_responder("flat", transform=invent))
    bad = _record_for(scan, "disable-ssh")
    assert bad["normalized_field"] == "unknown"
    assert bad["source"] == "needs_review"
    assert "unsupported field" in bad["reasoning"]

    others = [m for m in scan["adaptive"]["ai_mappings"] if "syslog-server" in m["raw_line"]]
    assert all(m["source"] == "ai_auto_mapped" for m in others)
    assert all(m["status"] != "ai_unavailable" for m in scan["adaptive"]["ai_mappings"])


def test_invalid_values_are_rejected():
    cfg = _config(BLOCK_EDIT)
    lines = {ln.raw_line.strip(): ln for ln in cfg.unrecognized_lines}

    def result(raw, field, value, evidence):
        return InterpretationResult(
            line_number=lines[raw].line_number, raw_line=lines[raw].raw_line, likely_vendor="unknown",
            security_concept="x", normalized_field=field, extracted_value=value, value_evidence=evidence,
            confidence=ConfidenceLevel.HIGH, numeric_confidence=0.95, reasoning="because",
            status=InterpretationStatus.INTERPRETED,
        )

    records = map_interpretations(cfg, [
        result("idle-timeout 20", "management.admin_timeout", "twenty", "idle-timeout 20"),      # wrong type
        result("collector 198.51.100.7", "logging.remote_hosts", "10.0.0.9", "10.0.0.9"),        # not in line
        result("ssh enable", "management.ssh_version", "7", "ssh"),                              # number absent
    ])

    assert [r.source for r in records] == ["needs_review"] * 3
    assert cfg.management.admin_timeout is None
    assert cfg.logging.remote_hosts == []
    assert cfg.management.ssh_version is None
    assert records[1].confidence_tier == "medium" and "Downgraded" in records[1].reason


def test_negation_is_resolved_generically_and_contradictions_are_reviewed(client):
    assert line_polarity("set deviceconfig system service disable-ssh no") is True
    assert line_polarity("/ip service set telnet disabled=yes") is False
    assert line_polarity("no ip source-route") is False
    assert line_polarity("set https enable") is True
    assert line_polarity("secure-shell protocol-version 2") is None

    def misread(items):
        for item in items:
            if "disable-ssh" in item["raw_line"]:
                item["extracted_value"] = "false"   # literal "no" mistaken for the state
        return items

    scan, _ = _scan(client, FLAT_SET, make_responder("flat", transform=misread))
    record = _record_for(scan, "disable-ssh")
    assert record["source"] == "needs_review"
    assert record["confidence_tier"] == "medium"
    assert "Downgraded" in record["reason"]
    cfg = get_scan_store()[scan["scan_id"]]["configs"][0]
    assert record["line_number"] not in cfg.management.source_lines


# ═══════════════════════════════════════════════════════════════════════════════
# 5 — parser-established values are protected
# ═══════════════════════════════════════════════════════════════════════════════

def test_parser_values_are_never_overwritten():
    cfg = _config(BLOCK_EDIT)
    cfg.management.admin_timeout = 10          # e.g. set by a deterministic parser
    cfg.ntp.servers = ["10.1.1.1"]

    service = AdaptiveService(
        repository=MappingRepository(), interpreter=make_interpreter("block"), ai_available=lambda: True,
    )
    outcome = service.process(cfg)
    by_line = {r.raw_line.strip(): r for r in outcome.records}

    assert cfg.management.admin_timeout == 10
    assert by_line["idle-timeout 20"].source == "needs_review"
    assert "conflicts" in by_line["idle-timeout 20"].reason
    # list fields are merged, never replaced
    assert cfg.ntp.servers == ["10.1.1.1", "time.example.net"]


# ═══════════════════════════════════════════════════════════════════════════════
# 6 — vendor evidence: normalized, reported, never used to activate rules
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,expected", [
    ("Palo Alto Networks", "palo_alto"), ("pan-os", "palo_alto"), ("PaloAlto", "palo_alto"),
    ("FortiOS", "fortinet"), ("ios", "cisco_ios"), ("Cisco IOS-XE", "cisco_ios"),
    ("Juniper JunOS", "juniper_junos"), ("MikroTik RouterOS", "mikrotik_routeros"),
    ("Sangfor NGAF", "sangfor"), ("SONiC", "sonic"), ("SonicWall NSA", "sonicwall"),
    ("generic", "unknown"), ("", "unknown"), (None, "unknown"),
    ("Some New Vendor", "some_new_vendor"),
])
def test_vendor_names_normalize_consistently(name, expected):
    assert normalize_vendor_name(name) == expected


def _evidence_record(line, vendor, tier="high", status="interpreted", field="ntp.servers"):
    return AIFieldMapping(
        line_number=line, raw_line="x", normalized_field=field, extracted_value="v",
        confidence=0.9, confidence_tier=tier, reasoning="r", source="ai_auto_mapped",
        status=status, likely_vendor=vendor,
    )


def test_vendor_evidence_outcomes():
    identified = assess_vendor_evidence([_evidence_record(1, "pan-os"), _evidence_record(2, "Palo Alto")])
    assert (identified.status, identified.likely_vendor, identified.supporting_lines) == ("identified", "palo_alto", [1, 2])

    conflicting = assess_vendor_evidence([_evidence_record(1, "juniper"), _evidence_record(2, "arista")])
    assert (conflicting.status, conflicting.likely_vendor) == ("conflicting", "unknown")

    # A single line, LOW tiers, unmapped lines and learned records are not enough / not evidence
    weak = assess_vendor_evidence([
        _evidence_record(1, "juniper"),
        _evidence_record(2, "juniper", tier="low"),
        _evidence_record(3, "juniper", field="unknown"),
        _evidence_record(4, "juniper", status="learned"),
    ])
    assert (weak.status, weak.likely_vendor) == ("unknown", "unknown")


@pytest.mark.parametrize("dialect", ["flat", "braces", "slash"])
def test_vendor_evidence_is_reported_but_device_vendor_stays_unknown(client, dialect):
    text, vendor, _ = DIALECTS[dialect]
    scan, _ = _scan(client, text, make_responder(dialect, vendor=vendor, rng=random.Random(7)))
    evidence = scan["adaptive"]["vendor_evidence"]
    assert evidence["status"] == "identified"
    assert evidence["likely_vendor"] == vendor
    assert scan["devices"][0]["vendor"] == "unknown"
    assert get_scan_store()[scan["scan_id"]]["configs"][0].device.vendor == Vendor.UNKNOWN
    assert not any(r.startswith("MGMT-") for r in _rule_ids(scan))


def test_conflicting_vendor_evidence_never_creates_a_vendor(client):
    def mixed(items):
        for i, item in enumerate(items):
            item["likely_vendor"] = "juniper" if i % 2 else "fortinet"
        return items

    scan, _ = _scan(client, SLASH_PATH, make_responder("slash", transform=mixed))
    assert scan["adaptive"]["vendor_evidence"]["status"] == "conflicting"
    assert scan["devices"][0]["vendor"] == "unknown"
    assert any("conflicting" in r for r in scan["adaptive"]["provisional_reasons"])


# ═══════════════════════════════════════════════════════════════════════════════
# 7 — MEDIUM (and evidence-less HIGH) never mutate the config
# ═══════════════════════════════════════════════════════════════════════════════

def test_medium_confidence_does_not_mutate(client):
    scan, _ = _scan(client, SLASH_PATH, make_responder("slash", confidence="medium"))
    cfg = get_scan_store()[scan["scan_id"]]["configs"][0]
    assert not any(m["source"] == "ai_auto_mapped" for m in scan["adaptive"]["ai_mappings"])
    assert cfg.ntp.servers == [] and cfg.logging.remote_hosts == []
    assert cfg.management.ssh_enabled is False
    # Nothing applied: not a FAIL and not a score
    assert "LOG-001" not in _rule_ids(scan)
    assert scan["score"] is None and scan["adaptive"]["assessed"] is False


def test_high_without_cited_evidence_is_capped_at_medium(client):
    def no_evidence(items):
        for item in items:
            item["value_evidence"] = None
        return items

    scan, _ = _scan(client, FLAT_SET, make_responder("flat", transform=no_evidence))
    record = _record_for(scan, "syslog-server 10.20.30.40")
    assert record["confidence_tier"] == "medium"
    assert record["source"] == "needs_review"
    assert get_scan_store()[scan["scan_id"]]["configs"][0].logging.remote_hosts == []


# ═══════════════════════════════════════════════════════════════════════════════
# 9 + 10 + 11 — learned knowledge takes precedence over AI
# ═══════════════════════════════════════════════════════════════════════════════

def test_first_scan_admin_confirmation_second_scan_without_ai(client):
    first, transport = _scan(client, FLAT_SET, make_responder("flat", confidence="medium"))
    assert transport.call_count >= 1
    scan_id = first["scan_id"]

    queue = client.get(f"/api/adaptive/scans/{scan_id}/review").json()
    for fragment in ("syslog-server 10.20.30.40", "primary-ntp-server"):
        item = next(i for i in queue["items"] if fragment in i["raw_line"])
        resp = client.post(f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}/accept")
        assert resp.status_code == 200, resp.text

    patterns = {m.command_pattern for m in MappingRepository().list_mappings()}
    assert "set deviceconfig system syslog-server {value}" in patterns
    assert "set deviceconfig system ntp-servers primary-ntp-server {value}" in patterns

    second_text = (
        "set deviceconfig system syslog-server 10.99.0.1\n"
        "set deviceconfig system ntp-servers primary-ntp-server ntp9.example.org\n"
    )
    second, transport2 = _scan(client, second_text, make_responder("flat"))
    assert transport2.call_count == 0
    assert second["adaptive"]["ai_called"] is False
    assert {m["source"] for m in second["adaptive"]["ai_mappings"]} == {"learned_mapping"}
    cfg = get_scan_store()[second["scan_id"]]["configs"][0]
    assert cfg.logging.remote_hosts == ["10.99.0.1"]
    assert cfg.ntp.servers == ["ntp9.example.org"]
    assert "LOG-001" not in _rule_ids(second)


def test_rejected_lines_bypass_ai(client):
    first, _ = _scan(client, BLOCK_EDIT, make_responder("block", confidence="medium"))
    queue = client.get(f"/api/adaptive/scans/{first['scan_id']}/review").json()
    item = next(i for i in queue["items"] if "ntp-server" in i["raw_line"])
    assert client.post(f"/api/adaptive/scans/{first['scan_id']}/review/{item['item_id']}/reject").status_code == 200

    second, transport = _scan(client, BLOCK_EDIT, make_responder("block"))
    sent = [text for call in transport.call_args_list for _, text in _targets(call.kwargs["prompt"])]
    assert sent and not any("ntp-server" in t for t in sent)
    assert _record_for(second, "ntp-server")["source"] == "rejected"


def test_conflicting_learned_mappings_go_to_review():
    repo = MappingRepository()
    repo.save_mapping(LearnedMapping(
        concept="remote_syslog", normalized_field="logging.remote_hosts",
        command_pattern="set deviceconfig system syslog-server {value}",
        extraction_method="template_capture", confirmed=True,
    ))
    repo.save_mapping(LearnedMapping(
        concept="ntp_server", normalized_field="ntp.servers",
        command_pattern="set deviceconfig system {any} {value}",
        extraction_method="template_capture", confirmed=True,
    ))
    cfg = _config("set deviceconfig system syslog-server 10.20.30.40\n")
    interpreter = make_interpreter("flat")
    outcome = AdaptiveService(repository=repo, interpreter=interpreter, ai_available=lambda: True).process(cfg)

    assert outcome.records[0].source == "needs_review"
    assert outcome.records[0].confidence_tier == "ambiguous"
    assert interpreter.call_count == 0
    assert cfg.logging.remote_hosts == [] and cfg.ntp.servers == []


def test_ai_high_that_disagrees_with_similar_confirmed_mapping_goes_to_review():
    repo = MappingRepository()
    repo.save_mapping(LearnedMapping(
        concept="remote_syslog", normalized_field="logging.remote_hosts",
        command_pattern="set deviceconfig system syslog-server {value}",
        extraction_method="template_capture", confirmed=True,
    ))
    text = "set deviceconfig system syslog-server-backup 10.20.30.99\n"

    def interpreter_for(field):
        return MagicMock(side_effect=lambda lines: [InterpretationResult(
            line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor="unknown",
            security_concept="x", normalized_field=field, extracted_value="10.20.30.99",
            value_evidence="10.20.30.99", confidence=ConfidenceLevel.HIGH, numeric_confidence=0.95,
            reasoning="backup log host", status=InterpretationStatus.INTERPRETED,
        ) for ln in lines])

    cfg = _config(text)
    record = AdaptiveService(repository=repo, interpreter=interpreter_for("ntp.servers"),
                             ai_available=lambda: True).process(cfg).records[0]
    assert record.source == "needs_review" and "learned mapping" in record.reason
    assert cfg.ntp.servers == []

    cfg = _config(text)
    record = AdaptiveService(repository=repo, interpreter=interpreter_for("logging.remote_hosts"),
                             ai_available=lambda: True).process(cfg).records[0]
    assert record.source == "ai_auto_mapped"
    assert cfg.logging.remote_hosts == ["10.20.30.99"]


# ═══════════════════════════════════════════════════════════════════════════════
# 12 — AI failure never destroys the scan
# ═══════════════════════════════════════════════════════════════════════════════

def test_ai_outage_keeps_learned_values_and_scoring(client):
    MappingRepository().save_mapping(LearnedMapping(
        concept="remote_syslog", normalized_field="logging.remote_hosts",
        command_pattern="set deviceconfig system syslog-server {value}",
        extraction_method="template_capture", confirmed=True,
    ))
    down = lambda **kw: StructuredResponse(error="request_failed", detail="timeout")
    scan, _ = _scan(client, FLAT_SET, down)

    assert scan["score"] is not None
    assert "LOG-001" not in _rule_ids(scan)
    sources = {m["source"] for m in scan["adaptive"]["ai_mappings"]}
    assert "learned_mapping" in sources
    unavailable = [m for m in scan["adaptive"]["ai_mappings"] if m["status"] == "ai_unavailable"]
    assert unavailable and all("failed or timed out" in m["reasoning"] for m in unavailable)


def test_transport_exception_is_contained(client):
    boom = MagicMock(side_effect=RuntimeError("socket closed"))
    with patch("app.adaptive.interpreter.request_structured", boom), \
         patch("app.adaptive.interpreter.is_available", return_value=True), \
         patch("app.api.routes.scan.is_available", return_value=True):
        resp = client.post("/api/scan", files=[("files", ("d.cfg", BRACES.encode(), "text/plain"))])
    assert resp.status_code == 200
    assert {m["status"] for m in resp.json()["adaptive"]["ai_mappings"]} == {"ai_unavailable"}


def test_transient_failure_is_retried_once():
    lines = _lines("set ssh enable", "set telnet disable")
    responder = make_responder("block")
    calls = iter([StructuredResponse(error="request_failed", detail="timeout")])
    transport = MagicMock(side_effect=lambda **kw: next(calls, None) or responder(**kw))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        results = interpret_lines(lines)
    assert transport.call_count == 2
    assert [r.status for r in results] == [InterpretationStatus.INTERPRETED] * 2


def test_persistent_bad_output_splits_then_marks_unavailable():
    lines = _lines("set ssh enable", "set telnet disable", "set https enable", "set http disable")
    transport = MagicMock(return_value=StructuredResponse(error="invalid_output", detail="not json"))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        results = interpret_lines(lines)
    assert transport.call_count == 4          # retry + two halves
    assert all(r.status == InterpretationStatus.AI_UNAVAILABLE for r in results)
    assert all("unusable output" in r.reasoning for r in results)


def test_omitted_lines_are_requested_again_and_order_is_preserved():
    lines = _lines("set ssh enable", "set telnet disable", "set https enable")
    responder = make_responder("block")
    first_call = {"done": False}

    def omit_first_line_once(**kw):
        response = responder(**kw)
        if not first_call["done"]:
            first_call["done"] = True
            response.data["interpretations"] = response.data["interpretations"][1:]
        return response

    transport = MagicMock(side_effect=omit_first_line_once)
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        results = interpret_lines(lines)
    assert transport.call_count == 2
    assert [r.line_number for r in results] == [1, 2, 3]
    assert all(r.status == InterpretationStatus.INTERPRETED for r in results)


def test_results_tolerate_whitespace_and_wrong_line_numbers():
    lines = [
        UnrecognizedLine(raw_line="        set ssh enable", line_number=7, vendor="unknown"),
        UnrecognizedLine(raw_line="\tset telnet disable", line_number=8, vendor="unknown"),
    ]

    def sloppy(items):
        items[1]["line_number"] = 999            # wrong number, but the text identifies the line
        return items

    transport = MagicMock(side_effect=make_responder("block", transform=sloppy))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        results = interpret_lines(lines)
    assert [(r.line_number, r.status, r.raw_line) for r in results] == [
        (7, InterpretationStatus.INTERPRETED, "        set ssh enable"),
        (8, InterpretationStatus.INTERPRETED, "\tset telnet disable"),
    ]


def test_generation_settings_and_chunking_are_deterministic():
    lines = _lines(*[f"set ntp-server 192.0.2.{i}" for i in range(25)])
    transport = MagicMock(side_effect=lambda **kw: StructuredResponse(data={"interpretations": []}))
    with patch("app.adaptive.interpreter.request_structured", transport), \
         patch("app.adaptive.interpreter.is_available", return_value=True):
        interpret_lines(lines)

    first_requests = [c for c in transport.call_args_list if c.kwargs["prompt"].startswith("Map each")]
    sizes = [len(_targets(c.kwargs["prompt"])) for c in first_requests[:1]]
    assert sizes == [MAX_LINES_PER_BATCH]
    kwargs = transport.call_args_list[0].kwargs
    assert kwargs["temperature"] == 0.0
    assert kwargs["top_p"] == 1.0
    assert kwargs["seed"] == 42
    assert kwargs["reasoning_effort"] == "low"
    assert kwargs["response_format"] is INTERPRETATION_RESPONSE_FORMAT
    assert _build_prompt(lines[:10]) == _build_prompt(lines[:10])


# ═══════════════════════════════════════════════════════════════════════════════
# Groq client classification
# ═══════════════════════════════════════════════════════════════════════════════

def _fake_groq(monkeypatch, behaviour, keys=("k1", "k2")):
    calls = []

    def create(**kw):
        calls.append(kw)
        return behaviour(len(calls), kw)

    fake = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(ai_client, "_api_keys", list(keys))
    monkeypatch.setattr(ai_client, "_get_client", lambda index: fake)
    return calls


def _completion(content):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def test_client_reports_daily_quota_exhaustion(monkeypatch):
    def quota(n, kw):
        raise Exception("Error code: 429 - Rate limit reached on tokens per day (TPD): Limit 200000")
    calls = _fake_groq(monkeypatch, quota)
    response = ai_client.request_structured("p", {"type": "json_object"})
    assert response.quota_exhausted and not response.retryable
    assert len(calls) == 2


def test_client_rotates_keys_and_passes_generation_settings(monkeypatch):
    def first_limited(n, kw):
        if n == 1:
            raise Exception("Error code: 429 - rate_limit_exceeded tokens per minute (TPM)")
        return _completion('{"interpretations": []}')
    calls = _fake_groq(monkeypatch, first_limited)
    response = ai_client.request_structured("p", {}, top_p=1.0, reasoning_effort="low", seed=42)
    assert response.ok and response.data == {"interpretations": []}
    assert calls[1]["reasoning_effort"] == "low" and calls[1]["top_p"] == 1.0

    calls = _fake_groq(monkeypatch, lambda n, kw: _completion("{}"))
    ai_client.request_structured("p", {})
    assert "reasoning_effort" not in calls[0] and "top_p" not in calls[0]


def test_client_classifies_rate_limits_and_bad_output(monkeypatch):
    def limited(n, kw):
        raise Exception("Error code: 429 - rate_limit_exceeded tokens per minute")
    _fake_groq(monkeypatch, limited)
    assert ai_client.request_structured("p", {}).error == "rate_limited"

    _fake_groq(monkeypatch, lambda n, kw: _completion("not json"))
    bad = ai_client.request_structured("p", {})
    assert bad.error == "invalid_output" and bad.retryable
    assert ai_client.generate_structured("p", {}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# Structural context
# ═══════════════════════════════════════════════════════════════════════════════

def test_structural_paths_for_braces_blocks_and_indentation():
    braces = dict(zip(BRACES.splitlines(), structural_paths(BRACES.splitlines())))
    assert braces["            protocol-version v2;"] == ("system", "services", "ssh")
    assert braces["        telnet;"] == ("system", "services")
    assert braces["        idle-timeout 15;"] == ("system", "login")

    block = dict(zip(BLOCK_EDIT.splitlines(), structural_paths(BLOCK_EDIT.splitlines())))
    assert block["    ssh enable"] == ("config management-plane",)
    assert block["    collector 198.51.100.7"] == ("config log-forwarding",)

    edit_blocks = [
        "config system admin", "    edit admin1", "        set trusthost1 10.0.0.0/8",
        "    next", "    edit admin2", "        set accprofile read-only", "    next", "end",
        "set standalone 1",
    ]
    paths = structural_paths(edit_blocks)
    assert paths[2] == ("config system admin", "edit admin1")
    assert paths[5] == ("config system admin", "edit admin2")
    assert paths[8] == ()

    indented = ["interface uplink0", " description transit", " access-group MGMT in", "line vty 0 4", " transport input ssh"]
    paths = structural_paths(indented)
    assert paths[2] == ("interface uplink0",)
    assert paths[3] == ()
    assert paths[4] == ("line vty 0 4",)

    flat = FLAT_SET.splitlines()
    assert all(p == () for line, p in zip(flat, structural_paths(flat)) if line.strip())


def test_context_is_sent_but_results_stay_tied_to_the_target_line(client):
    scan, transport = _scan(client, BRACES, make_responder("braces"))
    prompt = transport.call_args_list[0].kwargs["prompt"]

    target = next(ln for ln in scan["adaptive"]["unrecognized_lines"] if "protocol-version" in ln["raw_line"])
    assert target["structural_path"] == ["system", "services", "ssh"]
    assert f"[TARGET line {target['line_number']}]\nprotocol-version v2;\n  block: system > services > ssh" in prompt
    assert "context before:" in prompt
    assert "do not return objects for them" in prompt
    assert _records(scan)[target["line_number"]]["normalized_field"] == "management.ssh_version"


# ═══════════════════════════════════════════════════════════════════════════════
# 13 — repeated scans are semantically stable
# ═══════════════════════════════════════════════════════════════════════════════

def _semantics(scan):
    adaptive = scan["adaptive"]
    return (
        sorted(
            (m["line_number"], m["normalized_field"], m["extracted_value"], m["source"],
             m["final_value"], m["confidence_tier"])
            for m in adaptive["ai_mappings"]
        ),
        (adaptive["vendor_evidence"]["status"], adaptive["vendor_evidence"]["likely_vendor"]),
        scan["score"],
        sorted(_rule_ids(scan)),
    )


@pytest.mark.parametrize("dialect", list(DIALECTS))
def test_repeated_scans_are_semantically_consistent(client, dialect):
    """Reasoning text, numeric confidence inside the band, vendor spelling and
    item order vary between runs; the normalized outcome must not."""
    text, vendor, _ = DIALECTS[dialect]
    outcomes = [
        _semantics(_scan(client, text, make_responder(dialect, vendor=vendor, rng=random.Random(seed)))[0])
        for seed in range(5)
    ]
    assert all(o == outcomes[0] for o in outcomes)


@pytest.mark.skipif(not os.environ.get("NETAUDIT_LIVE_AI"), reason="set NETAUDIT_LIVE_AI=1 to call the real Groq API")
@pytest.mark.parametrize("text", [FLAT_SET, SLASH_PATH], ids=["flat", "slash"])
def test_live_groq_repeatability(text):
    cfg = _config(text)
    runs = []
    for _ in range(3):
        results = interpret_lines(cfg.unrecognized_lines)
        if any(r.status == InterpretationStatus.AI_UNAVAILABLE for r in results):
            pytest.skip("Groq unavailable or quota exhausted")
        runs.append([(r.line_number, r.normalized_field, (r.extracted_value or "").lower(), r.status.value) for r in results])
    assert runs[0] == runs[1] == runs[2]
