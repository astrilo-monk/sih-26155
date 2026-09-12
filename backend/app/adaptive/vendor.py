"""
Vendor evidence from adaptive interpretations — reporting only.

``device.vendor`` is set exclusively by the deterministic detector/parsers,
because it selects vendor-specific compliance rules. What the AI believes
about a configuration's vendor is *evidence*: it is normalized, counted and
reported, but never used to activate rules.

Outcomes:

* ``identified``  — enough agreeing, validated interpretations name one vendor
* ``conflicting`` — validated interpretations name different vendors
* ``unknown``     — no usable vendor evidence
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from app.models.normalized import AIFieldMapping

UNKNOWN_VENDOR = "unknown"

EVIDENCE_IDENTIFIED = "identified"
EVIDENCE_CONFLICTING = "conflicting"
EVIDENCE_UNKNOWN = "unknown"

#: Agreeing lines required before a vendor is reported as identified.
MIN_SUPPORTING_LINES = 2

_GENERIC_NAMES = frozenset({
    "", "unknown", "generic", "none", "na", "null", "any", "other", "various",
    "multivendor", "unspecified", "notapplicable", "vendorneutral",
})

# Compact alias (lowercase, alphanumerics only) → canonical vendor slug.
# Name normalization only — no configuration syntax lives here.
_ALIASES: dict[str, tuple[str, ...]] = {
    "cisco_ios": ("cisco", "ciscoios", "ios", "iosxe", "ciscoiosxe", "catalyst", "ciscocatalyst"),
    "cisco_iosxr": ("iosxr", "ciscoiosxr"),
    "cisco_nxos": ("nxos", "cisconxos", "nexus", "cisconexus"),
    "cisco_asa": ("asa", "ciscoasa"),
    "cisco_firepower": ("firepower", "ftd", "ciscofirepower", "ciscosecurefirewall"),
    "cisco_meraki": ("meraki", "ciscomeraki"),
    "fortinet": ("fortinet", "fortigate", "fortios"),
    "palo_alto": ("paloalto", "paloaltonetworks", "panos", "pan"),
    "juniper_junos": ("juniper", "junos", "junipernetworks", "srx", "junipersrx"),
    "arista_eos": ("arista", "eos", "aristaeos", "aristanetworks"),
    "checkpoint": ("checkpoint", "gaia", "checkpointgaia"),
    "sophos": ("sophos", "sophosxg", "sfos"),
    "sonicwall": ("sonicwall", "sonicos"),
    "watchguard": ("watchguard", "fireware"),
    "barracuda": ("barracuda",),
    "hpe_aruba": ("aruba", "arubaos", "arubaoscx", "hpearuba", "procurve"),
    "hpe_comware": ("comware", "h3c", "hpecomware"),
    "huawei_vrp": ("huawei", "vrp", "huaweivrp"),
    "mikrotik_routeros": ("mikrotik", "routeros"),
    "ubiquiti": ("ubiquiti", "ubnt", "edgeos", "unifi"),
    "extreme": ("extreme", "extremenetworks", "exos", "voss"),
    "dell_os10": ("dell", "dellos", "os10", "force10", "dellemc"),
    "nokia_sros": ("nokia", "sros", "timetra"),
    "sonic": ("sonic",),
    "cumulus": ("cumulus", "cumuluslinux", "nvue"),
    "vyos": ("vyos", "vyatta"),
    "netgate_pfsense": ("pfsense", "netgate", "tnsr"),
    "allied_telesis": ("alliedtelesis", "alliedware", "awplus"),
    "dlink": ("dlink",),
    "alcatel_lucent": ("alcatel", "alcatellucent", "omniswitch", "aos"),
    "ruijie": ("ruijie",),
    "adtran": ("adtran",),
    "zyxel": ("zyxel",),
    "sangfor": ("sangfor",),
    "hillstone": ("hillstone",),
    "a10": ("a10", "a10networks"),
    "forcepoint": ("forcepoint",),
    "stormshield": ("stormshield",),
    "zscaler": ("zscaler",),
    "cato_networks": ("cato", "catonetworks"),
    "aws": ("aws", "amazonwebservices"),
    "azure": ("azure", "microsoftazure"),
    "gcp": ("gcp", "googlecloud", "googlecloudplatform"),
}

_ALIAS_TO_VENDOR: dict[str, str] = {
    alias: vendor for vendor, aliases in _ALIASES.items() for alias in aliases
}
# Prefix matching only for aliases long enough not to collide ("ios" ⊂ "fortios")
_PREFIX_ALIASES = sorted((a for a in _ALIAS_TO_VENDOR if len(a) >= 5), key=len, reverse=True)


def _compact(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def normalize_vendor_name(name: str | None) -> str:
    """
    Canonical vendor slug for a free-text vendor name.

    ``"Palo Alto Networks"``, ``"pan-os"`` and ``"PaloAlto"`` all become
    ``"palo_alto"``. Generic placeholders become ``"unknown"``. Names not in
    the alias table are slugified consistently rather than discarded.
    """
    compact = _compact(name or "")
    if compact in _GENERIC_NAMES:
        return UNKNOWN_VENDOR
    if compact in _ALIAS_TO_VENDOR:
        return _ALIAS_TO_VENDOR[compact]
    for alias in _PREFIX_ALIASES:
        if compact.startswith(alias):
            return _ALIAS_TO_VENDOR[alias]
    slug = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    return slug[:40] or UNKNOWN_VENDOR


@dataclass
class VendorEvidence:
    likely_vendor: str = UNKNOWN_VENDOR
    status: str = EVIDENCE_UNKNOWN
    supporting_lines: list[int] = field(default_factory=list)
    votes: dict[str, int] = field(default_factory=dict)


def _counts_as_evidence(record: AIFieldMapping) -> bool:
    """Only validated AI interpretations of this config are vendor evidence."""
    return (
        record.status == "interpreted"
        and record.normalized_field != "unknown"
        and record.confidence_tier in ("high", "medium", "confirmed")
    )


def assess_vendor_evidence(records: Iterable[AIFieldMapping]) -> VendorEvidence:
    """Aggregate vendor evidence; never guesses when evidence disagrees."""
    lines_by_vendor: dict[str, list[int]] = {}
    for record in records:
        if not _counts_as_evidence(record):
            continue
        vendor = normalize_vendor_name(record.likely_vendor)
        if vendor == UNKNOWN_VENDOR:
            continue
        lines_by_vendor.setdefault(vendor, []).append(record.line_number)

    votes = Counter({v: len(lines) for v, lines in lines_by_vendor.items()})
    if not votes:
        return VendorEvidence()
    if len(votes) > 1:
        return VendorEvidence(status=EVIDENCE_CONFLICTING, votes=dict(votes))

    (vendor, count), = votes.items()
    if count < MIN_SUPPORTING_LINES:
        return VendorEvidence(votes=dict(votes), supporting_lines=sorted(lines_by_vendor[vendor]))
    return VendorEvidence(
        likely_vendor=vendor,
        status=EVIDENCE_IDENTIFIED,
        supporting_lines=sorted(lines_by_vendor[vendor]),
        votes=dict(votes),
    )
