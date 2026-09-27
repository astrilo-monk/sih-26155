"""Build the offline CVE context: ``backend/data/cve_cache.json``. Run by hand, needs internet.

    python backend/scripts/build_cve_cache.py

For each OS train (Cisco IOS ``15.2``, IOS-XE ``17.3``, FortiOS ``7.0`` …) asks the NVD CVE API 2.0 for the CVEs
whose configurations cover that train (``virtualMatchString`` with a version range from the train up to the next
one), CVSS v3 critical and high only, and keeps the totals and the five highest-scoring. The scan path only reads
the file (``app/analysis/cve.py``): no network call is ever made while scanning.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "cve_cache.json"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TOP = 5
PAUSE = 6.5  # NVD allows 5 requests per 30 seconds without an API key

PLATFORMS = {
    "cisco_ios": ("cpe:2.3:o:cisco:ios", ["12.2", "12.4", *(f"15.{n}" for n in range(10))]),
    "cisco_ios_xe": ("cpe:2.3:o:cisco:ios_xe", [*(f"16.{n}" for n in range(3, 13)), *(f"17.{n}" for n in range(1, 16))]),
    "fortios": ("cpe:2.3:o:fortinet:fortios", ["5.6", "6.0", "6.2", "6.4", "7.0", "7.2", "7.4", "7.6"]),
}


def _next(train: str) -> str:
    major, minor = train.split(".")
    return f"{major}.{int(minor) + 1}"


def _query(cpe: str, train: str, severity: str) -> dict:
    params = {"virtualMatchString": cpe, "versionStart": train, "versionStartType": "including",
              "versionEnd": _next(train), "versionEndType": "excluding", "cvssV3Severity": severity,
              "resultsPerPage": 2000}
    url = f"{API}?{urllib.parse.urlencode(params)}"
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                return json.load(response)
        except OSError as e:  # rate limit (403/429) or a transient failure: wait and retry
            print(f"  retry {attempt + 1} for {train} {severity}: {e}", file=sys.stderr)
            time.sleep(PAUSE * (attempt + 2))
    raise RuntimeError(f"NVD did not answer for {cpe} {train} {severity}")


def _cve(item: dict) -> dict:
    cve = item["cve"]
    metric = next(m for key in ("cvssMetricV31", "cvssMetricV30") for m in cve.get("metrics", {}).get(key, []))
    summary = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
    return {"id": cve["id"], "score": metric["cvssData"]["baseScore"], "severity": metric["cvssData"]["baseSeverity"],
            "published": cve["published"][:10], "summary": summary[:240] + ("…" if len(summary) > 240 else ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"}


def main() -> int:
    trains: dict[str, dict] = {}
    for platform, (cpe, versions) in PLATFORMS.items():
        for train in versions:
            found, totals = {}, {}
            for severity in ("CRITICAL", "HIGH"):
                data = _query(cpe, train, severity)
                totals[severity.lower()] = data.get("totalResults", 0)
                for item in data.get("vulnerabilities", []):
                    try:
                        entry = _cve(item)
                    except StopIteration:  # no CVSS v3 metric: outside the filter
                        continue
                    found[entry["id"]] = entry
                time.sleep(PAUSE)
            top = sorted(found.values(), key=lambda c: (-c["score"], c["id"]))[:TOP]
            trains[f"{platform} {train}"] = {"critical": totals["critical"], "high": totals["high"], "top": top}
            print(f"{platform} {train}: {totals['critical']} critical, {totals['high']} high")
    OUT.write_text(json.dumps({
        "generated": date.today().isoformat(),
        "source": "NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)",
        "filter": f"virtualMatchString per platform with versions from the train up to the next one; "
                  f"CVSS v3 CRITICAL and HIGH; the {TOP} highest base scores per train",
        "platforms": {p: cpe for p, (cpe, _) in PLATFORMS.items()},
        "trains": trains,
    }, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
