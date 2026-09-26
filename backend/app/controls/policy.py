"""
Organisation policy: an organisation's own baseline on top of the frameworks.

A policy can only **tighten** the default thresholds (a shorter idle timeout, fewer login attempts, a longer
minimum password) and name the approved NTP and syslog servers. Loosening is refused: a result that says PASS must
still mean the framework requirement is met.

The active policy is a context variable, set where a scan is created (``run_scan``) and where an action on a stored
scan starts (``live_scan``), so every evaluation of that scan (teaching, remediation re-checks) uses the same policy
without passing it through every call.
"""

from __future__ import annotations

import ipaddress
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass

FIELDS = ("name", "idle_timeout_minutes", "login_attempts", "password_min_length", "ntp_servers", "syslog_servers")


@dataclass(frozen=True)
class Policy:
    # None = the built-in defaults, not an organisation policy
    name: str | None = None
    idle_timeout_minutes: int = 15
    login_attempts: int = 10
    password_min_length: int = 8
    # empty = any server is acceptable
    ntp_servers: tuple[str, ...] = ()
    syslog_servers: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {k: list(v) if isinstance(v, tuple) else v for k, v in asdict(self).items()}

    def says(self) -> str:
        """Suffix for a reason that used a policy value."""
        return f" (organisation policy '{self.name}')" if self.name else ""


DEFAULT = Policy()
_active: ContextVar[Policy] = ContextVar("policy", default=DEFAULT)


def current() -> Policy:
    return _active.get()


def activate(policy: Policy | None):
    """Make ``policy`` the active one; returns the token ``_active.reset`` takes to undo it."""
    return _active.set(policy or DEFAULT)


@contextmanager
def using(policy: Policy | None):
    token = activate(policy)
    try:
        yield
    finally:
        _active.reset(token)


def _servers(value, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value) or len(value) > 20:
        raise ValueError(f"'{field}' must be a list of up to 20 server addresses or names")
    for v in value:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            if not all(c.isalnum() or c in ".-" for c in v.strip()):
                raise ValueError(f"'{field}': '{v}' is not an address or host name") from None
    return tuple(v.strip() for v in value)


def _bound(data: dict, field: str, lo: int, hi: int) -> int:
    value = data.get(field, getattr(DEFAULT, field))
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise ValueError(f"'{field}' must be a whole number from {lo} to {hi}: a policy can only tighten the default "
                         f"({getattr(DEFAULT, field)})")
    return value


def parse(data) -> Policy:
    """A validated policy from its JSON object; ValueError says what is wrong."""
    if not isinstance(data, dict):
        raise ValueError("The policy must be a JSON object")
    unknown = sorted(set(data) - set(FIELDS))
    if unknown:
        raise ValueError(f"Unknown policy field(s): {', '.join(unknown)}. Known: {', '.join(FIELDS)}")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise ValueError("'name' is required: up to 80 characters naming the policy")
    return Policy(
        name=name.strip(),
        idle_timeout_minutes=_bound(data, "idle_timeout_minutes", 1, DEFAULT.idle_timeout_minutes),
        login_attempts=_bound(data, "login_attempts", 1, DEFAULT.login_attempts),
        password_min_length=_bound(data, "password_min_length", DEFAULT.password_min_length, 128),
        ntp_servers=_servers(data.get("ntp_servers", []), "ntp_servers"),
        syslog_servers=_servers(data.get("syslog_servers", []), "syslog_servers"),
    )
