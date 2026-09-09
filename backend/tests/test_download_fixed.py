"""Tests for fixed-configuration download formats and contents."""

import io
import asyncio
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.analysis.engine import analyze, analyze_multiple
from app.api.routes.remediation import download_fixed_configs
from app.api.routes.scan import get_scan_store
from app.api.schemas import DownloadFixedRequest
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser


FIXTURES = Path(__file__).parent / "fixtures"


def _parse(path: Path):
    text = path.read_text(encoding="utf-8")
    parser = CiscoIOSParser() if "cisco" in path.name else FortinetParser()
    return parser.parse(text)


@pytest.fixture(autouse=True)
def clear_scan_store():
    store = get_scan_store()
    store.clear()
    yield
    store.clear()


def test_single_fixed_config_is_readable_cfg():
    config = _parse(FIXTURES / "cisco_vulnerable.cfg")
    scan_id = "single-download-test"
    get_scan_store()[scan_id] = {"result": analyze(config), "configs": [config]}

    response = asyncio.run(download_fixed_configs(DownloadFixedRequest(scan_id=scan_id)))

    assert response.media_type == "text/plain"
    assert response.headers["content-disposition"] == (
        'attachment; filename="CORP-RTR-01_fixed.cfg"'
    )
    body = response.body.decode("utf-8")
    assert "hostname CORP-RTR-01" in body
    assert "ip http secure-server" in body
    assert "ip http server" not in body


def test_multiple_fixed_configs_are_cfg_files_in_zip():
    configs = [
        _parse(FIXTURES / "cisco_vulnerable.cfg"),
        _parse(FIXTURES / "fortinet_vulnerable.cfg"),
    ]
    scan_id = "multi-download-test"
    get_scan_store()[scan_id] = {
        "result": analyze_multiple(configs),
        "configs": configs,
    }

    response = asyncio.run(download_fixed_configs(DownloadFixedRequest(scan_id=scan_id)))

    assert response.media_type == "application/zip"
    assert response.headers["content-disposition"] == (
        'attachment; filename="NetAuditAI_Fixed_Configs.zip"'
    )
    with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
        names = archive.namelist()
        contents = {
            name: archive.read(name).decode("utf-8") for name in names
        }

    assert all(name.endswith("_fixed.cfg") for name in names)
    assert "ip http secure-server" in contents["CORP-RTR-01_fixed.cfg"]
    assert "ip http server" not in contents["CORP-RTR-01_fixed.cfg"]
    assert all(text.strip() for text in contents.values())