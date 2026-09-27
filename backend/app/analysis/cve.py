"""
Known vulnerabilities for the device's OS version: context, never a finding.

Reads ``data/cve_cache.json`` (built by hand with ``scripts/build_cve_cache.py``, committed, so it works air-gapped)
and never calls the network. A match needs a platform the engine confirmed (the Cisco IOS or FortiGate parser) and
a version the uploaded file states; the version is reduced to its train (IOS ``15.2(4)M11`` → ``15.2``, IOS-XE
``17.3.4a`` → ``17.3``, FortiOS ``7.0.12`` → ``7.0``). Nothing is inferred, a missing or broken cache means "no
data", and the result never touches posture, coverage, risk, findings or remediation.
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
CACHE = Path(__file__).resolve().parents[2] / "data" / "cve_cache.json"
CAVEAT = ("Matched on the stated software version: a specific build may already carry the fix. This is context, "
          "not an assessment.")
_TRAIN = re.compile(r"^(\d+)\.(\d+)")


@lru_cache(maxsize=1)
def _cache() -> Optional[dict]:
    try:
        data = json.loads(CACHE.read_text(encoding="utf-8"))
        return data if isinstance(data.get("trains"), dict) else None
    except (OSError, ValueError, AttributeError) as e:
        logger.warning("CVE cache unavailable: %s", e)
        return None


def _platform(vendor: str, version: str) -> Optional[str]:
    if vendor == "cisco_ios":
        # IOS-XE numbers its releases from 16 (Denali); classic IOS stops at 15
        return "cisco_ios_xe" if int(version.split(".")[0]) >= 16 else "cisco_ios"
    if vendor == "fortinet":
        return "fortios"
    return None


def known_cves(vendor: str, os_version: Optional[str]) -> Optional[dict]:
    """The cached CVE context for this platform and stated version, or None (no version, no cache, no entry)."""
    m = _TRAIN.match((os_version or "").strip())
    cache = _cache()
    if not m or cache is None:
        return None
    platform = _platform(vendor, m.group(0))
    entry = cache["trains"].get(f"{platform} {m.group(0)}") if platform else None
    if not entry:
        return None
    return {"platform": platform, "train": m.group(0), "critical": entry["critical"], "high": entry["high"],
            "top": entry["top"], "cache_date": cache.get("generated"), "source": cache.get("source"),
            "caveat": CAVEAT}


if __name__ == "__main__":
    assert _platform("cisco_ios", "15.2") == "cisco_ios" and _platform("cisco_ios", "17.3") == "cisco_ios_xe"
    assert _platform("unknown", "10.1") is None and known_cves("cisco_ios", None) is None
    assert known_cves("cisco_ios", "unknown") is None
    print("ok")
