"""Seed coverage: how many of the catalog's checks shipped knowledge decides, per dialect.

    cd backend && python scripts/seed_coverage.py          # table on stdout
    cd backend && python scripts/seed_coverage.py --json   # machine-readable

Each dialect has a reference configuration in ``tests/fixtures/seed_coverage/``: a realistic file in that dialect that
states the settings the checks ask about, every line written as the vendor documents it (sources in
docs/seed-knowledge.md). The file goes through the real pipeline (vendor identification, then the generic engine with
the shipped seeds only, no AI), and a check counts as covered only when it is **decided**: PASS or FAIL from
decisive evidence (parser, confirmed, default). A heuristic suspicion or an UNKNOWN does not count.

This measures what the engine *can* decide when a setting is written down. A real configuration that leaves a
setting out still leaves that check undecided, unless a reviewed factory default covers it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
REFERENCE = BACKEND / "tests" / "fixtures" / "seed_coverage"

# file → the dialect it is written in
DIALECTS = {
    "arista.conf": "Arista EOS", "junos.conf": "Juniper Junos", "panos.conf": "Palo Alto PAN-OS",
    "nxos.conf": "Cisco NX-OS", "asa.conf": "Cisco ASA", "iosxr.conf": "Cisco IOS-XR", "huawei.conf": "Huawei VRP",
    "gaia.conf": "Check Point Gaia", "exos.conf": "Extreme Networks EXOS", "routeros.rsc": "MikroTik RouterOS",
    "aruba.conf": "HPE Aruba AOS-CX", "dell_os10.conf": "Dell OS10", "vyos.conf": "VyOS",
    "fortiswitch.conf": "Fortinet FortiSwitchOS",
}


def measure(isolate: bool = True) -> dict[str, dict]:
    """``isolate``: a throwaway database with the shipped seeds only, AI off (tests pass False and bring their own)."""
    if isolate:
        from app.cli import isolated_engine

        isolated_engine(None)

    from app.controls.catalog import CONTROLS
    from app.controls.evaluate import evaluate_controls
    from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
    from app.models.results import DECISIVE_ASSURANCE, Status
    from app.parsers.detector import identify_vendor

    out = {}
    for name, dialect in DIALECTS.items():
        text = (REFERENCE / name).read_text(encoding="utf-8")
        identification = identify_vendor(text)
        config = identification.config if identification.confirmed else NormalizedConfig(
            device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config=text, raw_lines=text.splitlines())
        decided: dict[str, str] = {}
        for r in evaluate_controls(config):
            if r.status in (Status.PASS, Status.FAIL) and r.assurance in DECISIVE_ASSURANCE:
                decided[r.control_id] = "fail" if r.status == Status.FAIL or decided.get(r.control_id) == "fail" \
                    else "pass"
        out[dialect] = {
            "file": name, "vendor_status": identification.status, "decided": sorted(decided),
            "undecided": [c for c in CONTROLS if c not in decided], "count": len(decided), "total": len(CONTROLS),
        }
    return out


def main() -> None:
    import logging
    logging.disable(logging.WARNING)
    result = measure()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        return
    for dialect, r in sorted(result.items(), key=lambda kv: -kv[1]["count"]):
        pct = round(100 * r["count"] / r["total"])
        print(f"{dialect:28} {r['count']:2}/{r['total']}  {pct:3}%  undecided: {' '.join(r['undecided'])}")


if __name__ == "__main__":
    main()
