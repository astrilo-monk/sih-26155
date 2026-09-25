"""
Vendor defaults: what a confirmed platform does when the configuration is silent.

Used only for confirmed vendor profiles, only when no fact at all was found for
a control, and only for documented defaults. A default we are not sure of
across releases is left out; the control then stays NOT_CONFIGURED / UNKNOWN.

Deliberately absent (the control keeps its Phase 0 behaviour):

* Cisco IOS ``ip source-route`` (enabled by default) and ``ip ssh version``
  (1.99 compatibility on older releases): applying them would add FAILs
  that differ by release.
* Cisco IOS ``exec-timeout`` (10 minutes): CIS 1.2.7 / 1.2.8 require it to be
  set explicitly, and a missing timeout keeps failing.
* Cisco IOS ``ip http server`` and VTY ``transport input``: differ by
  platform and release.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.facts.predicates import (
    ADMIN_ACCOUNT, IDLE_TIMEOUT, LOGIN_BANNER, LOGIN_MAX_ATTEMPTS, MGMT_WEAK_CRYPTO, NOT_SET, SNMP_COMMUNITY,
    SOURCE_ROUTING, SSH_VERSION, SecurityFact,
)
from app.models.normalized import Vendor
from app.models.results import Assurance

# (vendor, predicate) → (value, unit, documented default)
DEFAULTS: dict[tuple[Vendor, str], tuple[Any, str | None, str]] = {
    (Vendor.FORTINET, IDLE_TIMEOUT): (5, "min", "FortiOS default 'set admintimeout 5'"),
    (Vendor.FORTINET, SSH_VERSION): (2, None, "FortiOS default 'set admin-ssh-v1 disable'"),
    (Vendor.FORTINET, LOGIN_BANNER): (False, None, "FortiOS default 'set pre-login-banner disable'"),
    (Vendor.FORTINET, SOURCE_ROUTING): (False, None, "FortiOS default 'set ip-src-routing disable'"),
    # No community configured: SNMPv1/v2c cannot be reached with a community string at all
    (Vendor.CISCO_IOS, SNMP_COMMUNITY): (NOT_SET, None, "IOS default: no 'snmp-server community' is configured"),
    (Vendor.FORTINET, SNMP_COMMUNITY): (NOT_SET, None, "FortiOS default: no 'config system snmp community' entry"),
    (Vendor.FORTINET, LOGIN_MAX_ATTEMPTS): (3, None, "FortiOS default 'set admin-lockout-threshold 3'"),
    # a configuration without a 'config system admin' section still has the account every FortiGate ships with
    (Vendor.FORTINET, ADMIN_ACCOUNT): ("admin", None, "FortiOS ships with the 'admin' account"),
    (Vendor.FORTINET, MGMT_WEAK_CRYPTO): (False, None, "FortiOS default 'set strong-crypto enable'"),
}


def default_facts(vendor: Vendor, predicates: Iterable[str]) -> list[SecurityFact]:
    facts = []
    for predicate in predicates:
        if (vendor, predicate) in DEFAULTS:
            value, unit, source = DEFAULTS[(vendor, predicate)]
            facts.append(SecurityFact(predicate, value, Assurance.DEFAULT, unit=unit, provenance=source))
    return facts
