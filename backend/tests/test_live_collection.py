"""
Live collection (``app.collect`` and the ``/api/collect`` route).

No test opens a connection. Netmiko ships in requirements.txt and NAPALM is an optional upgrade that
may be absent, so the drivers are stubbed and what is asserted is everything around them: which driver is
chosen, that a collected configuration reaches the ordinary scan pipeline unchanged, that a device
that cannot be reached does not deny an audit of the ones that can, and that credentials do not
escape the request.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import config as app_config
from app.api.routes import scan as scan_route
from app.collect import PLATFORMS, CollectionError, Target, collect, platform_choices
from app.main import app

# Enough Cisco IOS for the detector to confirm the vendor and the engine to decide controls
IOS_CONFIG = """hostname EDGE-01
service password-encryption
enable secret 5 $1$abc$xyz
no ip http server
ip ssh version 2
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
end
"""

JUNOS_CONFIG = """system {
    host-name CORE-01;
    authentication-order tacplus;
    services {
        ssh;
    }
}
"""


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_config.settings, "live_collection_enabled", True)
    return TestClient(app)


def _target(**kw):
    return Target(**{"host": "10.0.0.1", "platform": "cisco_ios",
                     "username": "admin", "password": "s3cret", **kw})


def _body(host="10.0.0.1", platform="cisco_ios", **kw):
    return {"host": host, "platform": platform, "username": "admin", "password": "s3cret", **kw}


# -- choosing a driver -------------------------------------------------------------------------

def test_auto_prefers_napalm_where_the_platform_has_a_driver():
    """NAPALM asks the device for its configuration; Netmiko types a command at it. Prefer asking."""
    from app.collect.collector import _chosen_method

    with patch("app.collect.collector.available_methods", return_value=("napalm", "netmiko")):
        assert _chosen_method(_target()) == "napalm"
        # FortiGate has no NAPALM driver, so auto falls back without being asked to
        assert _chosen_method(_target(platform="fortinet")) == "netmiko"


def test_a_platform_without_a_napalm_driver_cannot_be_forced_onto_napalm():
    from app.collect.collector import _chosen_method

    with patch("app.collect.collector.available_methods", return_value=("napalm", "netmiko")):
        with pytest.raises(CollectionError, match="no driver for"):
            _chosen_method(_target(platform="fortinet", method="napalm"))


def test_a_broken_install_is_a_message_an_operator_can_act_on_not_a_crash():
    """Netmiko is a normal dependency now, so its absence means the install is incomplete."""
    with patch("app.collect.collector.available_methods", return_value=()):
        with pytest.raises(CollectionError, match=r"pip install -r requirements\.txt"):
            collect(_target())


def test_asking_for_napalm_without_it_points_at_the_optional_requirements():
    with patch("app.collect.collector.available_methods", return_value=("netmiko",)):
        with pytest.raises(CollectionError, match="requirements-live.txt"):
            collect(_target(method="napalm"))


def test_an_unknown_platform_names_the_ones_that_exist():
    with pytest.raises(CollectionError, match="Unknown platform"):
        _target(platform="nonesuch").spec


def test_every_platform_names_a_netmiko_driver_and_a_command():
    """Netmiko is the fallback for every platform, so none may be left without a way to be read."""
    for key, spec in PLATFORMS.items():
        assert spec.netmiko and spec.command, key
        assert spec.label, key


# -- credentials do not escape -----------------------------------------------------------------

def test_a_target_never_prints_its_credentials():
    """A dataclass repr is the likeliest way for a password to reach a log file or a traceback."""
    target = _target(enable="en4ble")
    assert "s3cret" not in repr(target) and "en4ble" not in repr(target)
    assert "10.0.0.1" in repr(target)


def test_a_driver_failure_is_summarized_rather_than_re_raised():
    """Driver exceptions quote the session, which can include the password prompt. Only the type survives."""
    with patch("app.collect.collector.available_methods", return_value=("netmiko",)), \
         patch("app.collect.collector._collect_netmiko",
               side_effect=ValueError("auth failed for admin/s3cret")):
        with pytest.raises(CollectionError) as excinfo:
            collect(_target(method="netmiko"))
    assert "s3cret" not in str(excinfo.value)
    assert "ValueError" in str(excinfo.value) and "10.0.0.1" in str(excinfo.value)


def test_a_collected_scan_stores_no_credential(client):
    """The scan store outlives the request and is archived; a credential must not be in it."""
    with patch("app.api.routes.collect.collect", return_value=IOS_CONFIG):
        resp = client.post("/api/collect", json={"targets": [_body()]})
    assert resp.status_code == 200, resp.text
    entry = scan_route.get_scan_store()[resp.json()["scan"]["scan_id"]]
    assert "s3cret" not in repr(entry)
    assert "s3cret" not in resp.text


# -- collected configurations take the ordinary scan path --------------------------------------

def test_a_collected_config_is_scanned_exactly_like_an_uploaded_one(client):
    """Same text, same verdicts: nothing downstream may treat a collected config differently."""
    with patch("app.api.routes.collect.collect", return_value=IOS_CONFIG):
        collected = client.post("/api/collect", json={"targets": [_body()]}).json()["scan"]
    uploaded = client.post(
        "/api/scan", files=[("files", ("device.cfg", IOS_CONFIG.encode(), "text/plain"))]
    ).json()

    assert collected["devices"][0]["vendor"] == uploaded["devices"][0]["vendor"] == "cisco_ios"
    verdicts = lambda s: {r["control_id"]: r["status"] for r in s["results"]}
    assert verdicts(collected) == verdicts(uploaded)
    assert collected["posture"] == uploaded["posture"]


def test_an_unconfirmed_vendor_is_collected_and_read_generically(client, seeded_adaptive_db):
    """The engine is vendor-agnostic, so collection is not limited to the three parsers."""
    with patch("app.api.routes.collect.collect", return_value=JUNOS_CONFIG):
        resp = client.post("/api/collect", json={"targets": [_body(platform="juniper_junos")]})
    scan = resp.json()["scan"]
    assert scan["devices"][0]["hostname"] == "CORE-01"
    assert any(r["status"] in ("pass", "fail") for r in scan["results"])


def test_the_chosen_framework_reaches_a_collected_scan(client):
    with patch("app.api.routes.collect.collect", return_value=IOS_CONFIG):
        resp = client.post("/api/collect", json={"targets": [_body()], "framework": "CIS"})
    assert resp.json()["scan"]["framework"] == "CIS"


def test_a_collected_scan_rejects_an_unknown_framework(client):
    with patch("app.api.routes.collect.collect", return_value=IOS_CONFIG):
        resp = client.post("/api/collect", json={"targets": [_body()], "framework": "SOX"})
    assert resp.status_code == 422


# -- partial success ---------------------------------------------------------------------------

def test_one_unreachable_device_does_not_deny_an_audit_of_the_others(client):
    """The normal case on a real network. The reachable devices are scanned and the rest reported."""
    def one_fails(target):
        if target.host == "10.0.0.2":
            raise CollectionError("Could not collect from 10.0.0.2 over netmiko: TimeoutError")
        return IOS_CONFIG

    with patch("app.api.routes.collect.collect", side_effect=one_fails):
        resp = client.post("/api/collect", json={
            "targets": [_body("10.0.0.1"), _body("10.0.0.2"), _body("10.0.0.3")]})
    body = resp.json()
    assert resp.status_code == 200, resp.text
    assert body["collected"] == ["10.0.0.1", "10.0.0.3"]
    assert [f["host"] for f in body["failures"]] == ["10.0.0.2"]
    assert len(body["scan"]["devices"]) == 2


def test_every_device_failing_is_an_error_because_there_is_nothing_to_audit(client):
    with patch("app.api.routes.collect.collect", side_effect=CollectionError("unreachable")):
        resp = client.post("/api/collect", json={"targets": [_body()]})
    assert resp.status_code == 502
    assert resp.json()["detail"]["errors"] == {"10.0.0.1": "unreachable"}


def test_a_device_answering_with_an_enormous_configuration_is_refused(client):
    """The size limit guards the pipeline, not the upload form: a device can answer with just as much."""
    with patch("app.api.routes.collect.collect", return_value="! padding\n" * 300_000):
        resp = client.post("/api/collect", json={"targets": [_body()]})
    assert resp.status_code == 413


def test_an_empty_configuration_is_reported_as_a_privilege_problem():
    """A device that answers with nothing usually means the account cannot read the config."""
    with patch("app.collect.collector.available_methods", return_value=("netmiko",)), \
         patch("app.collect.collector._collect_netmiko", return_value="   \n"):
        with pytest.raises(CollectionError, match="empty configuration"):
            collect(_target(method="netmiko"))


# -- the feature is off unless asked for -------------------------------------------------------

def test_collection_can_be_switched_off(monkeypatch):
    """On a backend others can reach, an endpoint that SSHes to any host it is given is a pivot."""
    monkeypatch.setattr(app_config.settings, "live_collection_enabled", False)
    resp = TestClient(app).post("/api/collect", json={"targets": [_body()]})
    assert resp.status_code == 403
    assert "LIVE_COLLECTION_ENABLED" in resp.json()["detail"]


def test_the_default_configuration_has_collection_on():
    """It is a deliverable the workflow asks for, and Netmiko ships in requirements.txt."""
    assert app_config.Settings(_env_file=None).live_collection_enabled is True


def test_every_platform_is_collectable_with_what_requirements_txt_installs():
    """Netmiko is not optional any more, so no platform may need an extra install to be reachable."""
    with patch("app.collect.collector.available_methods", return_value=("netmiko",)):
        assert all(p["available"] for p in platform_choices())


def test_capabilities_answers_even_when_collection_is_off(monkeypatch):
    """'Collection is disabled here' is what the form needs to know, not an error."""
    monkeypatch.setattr(app_config.settings, "live_collection_enabled", False)
    body = TestClient(app).get("/api/collect/capabilities").json()
    assert body["enabled"] is False
    assert {p["platform"] for p in body["platforms"]} == set(PLATFORMS)


def test_capabilities_reports_which_platforms_are_reachable_with_what_is_installed():
    with patch("app.collect.collector.available_methods", return_value=("napalm",)):
        choices = {p["platform"]: p for p in platform_choices()}
    # NAPALM alone reaches the platforms it has drivers for, and no others
    assert choices["cisco_ios"]["methods"] == ["napalm"] and choices["cisco_ios"]["available"]
    assert choices["fortinet"]["methods"] == [] and not choices["fortinet"]["available"]
