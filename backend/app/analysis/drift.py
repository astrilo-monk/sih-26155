"""
Changes since the last audit: one device's scan against its most recent earlier scan.

Both sides are archived scan responses (app.db.scans): redacted, never the configuration. Only decided verdicts
count, the same rule as scoring. A check that moves from a decided FAIL to undecided is reported as "no longer
decided", never as fixed: the engine lost its evidence, it did not see the problem go away.
"""

from __future__ import annotations

from app.analysis.attack_paths import DECISIVE


def _verdicts(response: dict, index: int) -> dict[str, dict]:
    return {r["control_id"]: r for r in response.get("results", []) if r["config_index"] == index}


def _decided(result: dict | None, status: str) -> bool:
    return bool(result) and result["status"] == status and result.get("assurance") in DECISIVE


def _brief(result: dict) -> dict:
    return {"control_id": result["control_id"], "title": result["title"], "severity": result["severity"]}


def device_drift(old: dict, old_index: int, new: dict, new_index: int) -> dict:
    """What changed on one device between two scans (``old`` earlier than ``new``)."""
    before, after = _verdicts(old, old_index), _verdicts(new, new_index)
    fixed, new_problems, undecided = [], [], []
    for cid in sorted(before.keys() | after.keys()):
        was, now = before.get(cid), after.get(cid)
        if _decided(was, "fail") and _decided(now, "pass"):
            fixed.append(_brief(now))
        elif _decided(now, "fail") and not _decided(was, "fail"):
            new_problems.append(_brief(now))
        elif _decided(was, "fail") and not _decided(now, "fail"):
            undecided.append(_brief(was))
    paths = lambda r, i: {p["path_id"]: p["title"] for p in r.get("attack_paths", []) if p["config_index"] == i}
    old_paths, new_paths = paths(old, old_index), paths(new, new_index)
    device = lambda r, i: r["devices"][i] if i < len(r.get("devices", [])) else {}
    was_dev, now_dev = device(old, old_index), device(new, new_index)
    return {
        "config_index": new_index,
        "hostname": now_dev.get("hostname"),
        "previous_scan_id": old["scan_id"],
        "previous_at": old["timestamp"],
        "posture": [was_dev.get("posture"), now_dev.get("posture")],
        "risk": [(was_dev.get("risk") or {}).get("level"), (now_dev.get("risk") or {}).get("level")],
        "fixed": fixed,
        "new_problems": new_problems,
        "no_longer_decided": undecided,
        "paths_closed": [t for p, t in old_paths.items() if p not in new_paths],
        "paths_opened": [t for p, t in new_paths.items() if p not in old_paths],
    }


def scan_drift(new: dict, earlier: list[dict]) -> list[dict]:
    """For each device in ``new``, the drift against the most recent scan in ``earlier`` (newest first) that holds
    the same hostname and vendor. Devices seen for the first time are left out."""
    out = []
    for i, dev in enumerate(new.get("devices", [])):
        key = (dev.get("hostname"), dev.get("vendor"))
        for old in earlier:
            match = next((j for j, d in enumerate(old.get("devices", []))
                          if (d.get("hostname"), d.get("vendor")) == key), None)
            if match is not None:
                out.append(device_drift(old, match, new, i))
                break
    return out
