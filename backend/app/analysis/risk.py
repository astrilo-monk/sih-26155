"""
Contextual risk: how dangerous this device's problems are where it sits, not only how many it has.

Posture answers "how compliant is the configuration". Risk adds what an auditor weighs next: the worst confirmed
problem, whether the device faces an untrusted network, whether its problems chain into an attack path, and how
much the asset matters. The formula is fixed, documented and shown with its reasons:

    points = worst severity (critical 60, high 45, medium 25, low 10, none 0)
           + 20 when the device faces an untrusted network (a decided MGMT-010 FAIL, or stated at upload)
           + 10 per potential attack path, at most 20
    risk   = min(100, round(points × criticality)), criticality low 0.8, medium 1.0 (default), high 1.15, critical 1.3
    level  = low < 25 ≤ medium < 50 ≤ high < 75 ≤ critical

Only decided FAILs count, like posture: a suspected problem never raises risk.
"""

from __future__ import annotations

from typing import Optional

DECISIVE = {"parser", "confirmed", "default"}
SEVERITY_POINTS = {"critical": 60, "high": 45, "medium": 25, "low": 10}
CRITICALITY = {"low": 0.8, "medium": 1.0, "high": 1.15, "critical": 1.3}
FORMULA = ("worst severity (critical 60, high 45, medium 25, low 10) + 20 if it faces an untrusted network "
           "+ 10 per attack path (max 20), times asset criticality (low 0.8, medium 1.0, high 1.15, critical 1.3)")


def device_risk(results: list[dict], paths: list[dict], criticality: Optional[str] = None,
                internet_facing: bool = False) -> dict:
    """Risk of one device from its (redacted) results and attack paths, as the scan response carries them."""
    failing = [r for r in results if r["status"] == "fail" and r.get("assurance") in DECISIVE]
    reasons, points = [], 0
    worst = max(failing, key=lambda r: SEVERITY_POINTS.get(r["severity"], 0), default=None)
    if worst:
        points += SEVERITY_POINTS.get(worst["severity"], 0)
        reasons.append(f"Worst confirmed problem is {worst['severity']}: {worst['title']}")
    if any(r["control_id"] == "MGMT-010" for r in failing):
        points += 20
        reasons.append("Management is reachable from an untrusted interface")
    elif internet_facing:
        points += 20
        reasons.append("Marked as facing the internet at upload")
    if paths:
        points += min(20, 10 * len(paths))
        reasons.append(f"{len(paths)} potential attack path{'s' if len(paths) != 1 else ''}")
    factor = CRITICALITY.get(criticality or "medium", 1.0)
    if criticality:
        reasons.append(f"Asset criticality {criticality} (×{factor:g})")
    score = min(100, round(points * factor))
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {"score": score, "level": level, "reasons": reasons or ["No confirmed problem"], "formula": FORMULA}
