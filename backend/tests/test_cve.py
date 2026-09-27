"""CVE context by OS version (``app/analysis/cve.py``): read-only, offline, and never part of any verdict."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis import cve
from app.api.routes.scan import run_scan

ROOT = Path(__file__).resolve().parents[2]
CACHE = {"generated": "2026-09-28", "source": "NVD CVE API 2.0", "filter": "test",
         "trains": {"cisco_ios 15.2": {"critical": 1, "high": 2, "top": [
             {"id": "CVE-2017-12240", "score": 9.8, "severity": "CRITICAL", "published": "2017-09-29",
              "summary": "DHCP relay", "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-12240"}]},
             "cisco_ios_xe 16.4": {"critical": 0, "high": 1, "top": []},
             "cisco_ios_xe 16.9": {"critical": 2, "high": 5, "top": []},
             "fortios 7.0": {"critical": 3, "high": 4, "top": []}}}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    def write(content):
        path = tmp_path / "cve_cache.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        monkeypatch.setattr(cve, "CACHE", path)
        cve._cache.cache_clear()
    yield write
    cve._cache.cache_clear()


def test_a_stated_version_is_matched_on_its_train(cache):
    cache(CACHE)
    found = cve.known_cves("cisco_ios", "15.2(4)M11")
    assert (found["platform"], found["train"], found["top"][0]["id"]) == ("cisco_ios", "15.2", "CVE-2017-12240")
    assert cve.known_cves("cisco_ios", "16.4")["platform"] == "cisco_ios_xe"
    assert cve.known_cves("fortinet", "7.0.12 build0523")["critical"] == 3
    assert "context, not an assessment" in found["caveat"]


@pytest.mark.parametrize("vendor, version", [
    ("cisco_ios", None), ("cisco_ios", "unknown"), ("cisco_ios", "12.1"),  # no version, or a train not cached
    ("unknown", "15.2"),  # an unconfirmed platform is never matched, whatever it states
])
def test_nothing_is_inferred(cache, vendor, version):
    cache(CACHE)
    assert cve.known_cves(vendor, version) is None


@pytest.mark.parametrize("content", ["{not json", json.dumps({"no": "trains"}), json.dumps([1, 2])])
def test_a_broken_cache_means_no_data(cache, content):
    cache(content)
    assert cve.known_cves("cisco_ios", "15.2") is None


def _scan(text: str) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return run_scan([("r.cfg", text)]).model_dump(mode="json")


def _without_context(scan: dict) -> dict:
    return {k: ([{**d, "known_cves": None} for d in v] if k == "devices" else v)
            for k, v in scan.items() if k not in ("scan_id", "timestamp")}


def test_scores_and_findings_are_identical_with_and_without_the_cache(seeded_adaptive_db, cache):
    text = (ROOT / "demo-sih" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")  # states version 16.9
    cache(CACHE)
    with_cache = _scan(text)
    cache("{broken")
    without = _scan(text)
    assert with_cache["devices"][0]["known_cves"] and without["devices"][0]["known_cves"] is None
    assert _without_context(with_cache) == _without_context(without)


def test_the_report_shows_it_with_the_caveat(seeded_adaptive_db, cache):
    from app.reporting.report import identification_block

    cache(CACHE)
    scan = run_scan([("r.cfg", "version 15.2\nhostname R1\n!\nline vty 0 4\n login\n")])
    text = " ".join(str(b[1]) for b in identification_block(scan, 0))
    assert "CVE-2017-12240" in text and "context, not an assessment" in text and "2026-09-28" in text
