"""
Potential attack paths: how an attacker could chain this device's failed checks.

A finding list says what is wrong; a path says what it adds up to. Each chain in ``CHAINS`` is a fixed,
reviewed sequence of steps, and a step is open when any of its checks is a **decided** FAIL on the device.
A chain is reported only when every step is open, with the lines behind each step, so a path is never a
guess: it is the conjunction of findings the engine already proved. Heuristic and AI verdicts never open a
step. A path is a *potential* one: the engine reads configuration, it does not test exploitability.

``break_with`` is the cheapest way to close the path: the step with the fewest failing checks, since fixing
every check of one step breaks the whole chain.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.controls.catalog import CONTROLS

DECISIVE = {"parser", "confirmed", "default"}


@dataclass(frozen=True)
class Step:
    title: str
    how: str
    controls: tuple[str, ...]


@dataclass(frozen=True)
class Chain:
    path_id: str
    title: str
    outcome: str
    severity: str
    steps: tuple[Step, ...]


_REACH = Step("Reach the login", "The device's management services accept connections from any address, or from the "
                                 "internet side", ("MGMT-010", "MGMT-003"))
_UNSEEN = Step("Stay unseen", "Logs stay on the device, where an attacker with access can clear them", ("LOG-001",))

CHAINS: tuple[Chain, ...] = (
    Chain("remote-takeover", "Remote takeover through the management plane",
          "Full administrative control of the device", "critical", (
              _REACH,
              Step("Capture the password", "The login travels in cleartext (Telnet, HTTP) or over SSH version 1, so "
                                           "anyone on the path can read it", ("MGMT-001", "MGMT-002", "MGMT-007")),
              Step("Log in as an administrator", "A default account name, no lockout or no central AAA means a "
                                                 "captured or guessed login is all it takes",
                   ("AUTH-003", "AUTH-001", "MGMT-008")),
          )),
    Chain("password-guessing", "Unlimited password guessing that leaves no trace",
          "An administrator password found by brute force, with no record kept off the device", "high", (
              _REACH,
              Step("Guess without limit", "No lockout after failed logins, a weak password policy, or a default "
                                          "account name to aim at", ("AUTH-001", "AUTH-002", "AUTH-003")),
              _UNSEEN,
          )),
    Chain("snmp-exposure", "Configuration read or changed over SNMP",
          "Device configuration and state exposed, or changed through a read-write community", "high", (
              Step("Guess the community", "A default community string such as 'public' or 'private'", ("MGMT-004",)),
              Step("Speak SNMPv1/v2c", "The community travels in cleartext and there is no per-user login",
                   ("MGMT-011",)),
              _UNSEEN,
          )),
    Chain("perimeter-bypass", "Traffic steered through an open perimeter",
          "Hosts behind the device reachable from outside, along a route the sender chooses", "high", (
              Step("Pass the filter", "A rule permits any source to any destination", ("BOUNDARY-001",)),
              Step("Steer the traffic", "IP source routing, ICMP redirects or proxy-ARP let a sender influence the "
                                        "route", ("BOUNDARY-002", "BOUNDARY-004")),
          )),
)


def attack_paths(results: list[dict]) -> list[dict]:
    """The potential attack paths of one device, from its control results as the scan response carries them
    (already redacted): ``control_id``, ``status``, ``assurance`` and ``evidence`` {line_numbers, lines}."""
    failing: dict[str, list[dict]] = {}
    for r in results:
        if r["status"] == "fail" and r.get("assurance") in DECISIVE:
            failing.setdefault(r["control_id"], []).append(r)

    paths = []
    for chain in CHAINS:
        open_steps = [[c for c in step.controls if c in failing] for step in chain.steps]
        if not all(open_steps):
            continue
        cheapest = min(range(len(chain.steps)), key=lambda i: len(open_steps[i]))
        paths.append({
            "path_id": chain.path_id,
            "title": chain.title,
            "outcome": chain.outcome,
            "severity": chain.severity,
            "steps": [{
                "title": step.title,
                "how": step.how,
                "controls": [{"control_id": c, "title": CONTROLS[c].title, "lines": _lines(failing[c])}
                             for c in controls],
            } for step, controls in zip(chain.steps, open_steps)],
            "break_with": open_steps[cheapest],
            "break_step": chain.steps[cheapest].title,
        })
    return sorted(paths, key=lambda p: (p["severity"] != "critical", p["path_id"]))


def _lines(results: list[dict], limit: int = 3) -> list[dict]:
    seen = {}
    for r in results:
        for n, text in zip(r["evidence"]["line_numbers"], r["evidence"]["lines"]):
            seen.setdefault(n, text.strip())
    return [{"number": n, "text": t} for n, t in sorted(seen.items())[:limit]]
