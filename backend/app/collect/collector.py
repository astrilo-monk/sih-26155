"""
Pull a running configuration off a live device over SSH.

The problem statement suggests Netmiko/NAPALM as a way to get configurations from devices rather
than asking an operator to paste a file. This module is only that fetch step: it returns the same
configuration text an upload would have carried, and the caller hands it to the ordinary scan
pipeline. Nothing downstream can tell where the text came from, so live collection inherits vendor
identification, secret redaction and the AI rules unchanged -a collected config is never treated as
more trusted, and never as less redacted, than an uploaded one.

Two drivers, because they answer different questions:

  * NAPALM asks the device for its configuration (``get_config``) and knows, per platform, how to do
    that. It is vendor-agnostic in the same way this engine is, so it is preferred where it has a
    driver.
  * Netmiko runs the command an operator would type. It reaches far more platforms, at the cost of
    naming that command here.

Netmiko ships in requirements.txt and reads every platform in the table below, so collection works
on a normal install. NAPALM is the optional upgrade (requirements-live.txt). Neither is imported
until a collection actually runs, so a backend missing one still starts, serves and scans -the
feature reports what it cannot do instead of breaking the install.

Credentials are arguments, never state: this module opens the session, reads the configuration and
closes it. It stores nothing, returns nothing but the configuration text, and never logs a Target
(whose repr is overridden), so a password cannot reach a log file through an exception trace.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field, replace


class CollectionError(RuntimeError):
    """A device could not be reached, authenticated against, or read.

    Carries an operator-facing message only: the cause is summarized without echoing credentials.
    """


@dataclass(frozen=True)
class Platform:
    """How to ask one platform for its full configuration."""

    label: str
    # Netmiko device_type
    netmiko: str
    # The command whose output is the configuration
    command: str
    # Commands sent first whose output is discarded (paging, output format)
    setup: tuple[str, ...] = ()
    # NAPALM driver, where one exists for this platform
    napalm: str = ""


# Platforms a device can be collected from. The engine itself is vendor-agnostic -only three vendors
# have deterministic parsers, and everything else is read generically -so this list is deliberately
# wider than the parser set: a Junos or MikroTik device is worth collecting even though its verdicts
# come from recognizers and heuristics rather than a parser.
PLATFORMS: dict[str, Platform] = {
    "cisco_ios": Platform("Cisco IOS / IOS-XE", "cisco_ios", "show running-config", napalm="ios"),
    "cisco_nxos": Platform("Cisco NX-OS", "cisco_nxos", "show running-config", napalm="nxos_ssh"),
    "cisco_xr": Platform("Cisco IOS-XR", "cisco_xr", "show running-config", napalm="iosxr"),
    "arista_eos": Platform("Arista EOS", "arista_eos", "show running-config", napalm="eos"),
    "juniper_junos": Platform("Juniper Junos", "juniper_junos", "show configuration", napalm="junos"),
    "fortinet": Platform("Fortinet FortiGate", "fortinet", "show full-configuration"),
    # PAN-OS prints XML unless the session is switched to the `set` syntax the parser reads
    "paloalto_panos": Platform("Palo Alto PAN-OS", "paloalto_panos", "show config running",
                               setup=("set cli config-output-format set",)),
    "aruba_aoscx": Platform("HPE Aruba AOS-CX", "aruba_aoscx", "show running-config"),
    "huawei_vrp": Platform("Huawei VRP", "huawei", "display current-configuration"),
    "checkpoint_gaia": Platform("Check Point Gaia", "checkpoint_gaia", "show configuration"),
    "extreme_exos": Platform("Extreme EXOS", "extreme_exos", "show configuration"),
    "mikrotik_routeros": Platform("MikroTik RouterOS", "mikrotik_routeros", "/export"),
}

# Collection methods, in the order ``auto`` prefers them
METHODS = ("napalm", "netmiko")

# What to run when one is missing. Netmiko is a normal dependency; NAPALM is the optional upgrade.
INSTALL = {
    "netmiko": "pip install -r requirements.txt",
    "napalm": "pip install -r requirements-live.txt",
}


@dataclass(frozen=True)
class Target:
    """One device to collect from. Credentials live here for the length of one request and no longer."""

    host: str
    platform: str
    username: str = ""
    password: str = field(default="", repr=False)
    port: int = 22
    # Privileged-mode secret, where the platform needs one to print its configuration
    enable: str = field(default="", repr=False)
    # "auto", "napalm" or "netmiko"
    method: str = "auto"
    timeout: int = 30

    def __repr__(self) -> str:
        # Overridden wholesale: a dataclass repr is the likeliest way for a credential to reach a log
        return f"Target(host={self.host!r}, platform={self.platform!r}, method={self.method!r})"

    @property
    def spec(self) -> Platform:
        try:
            return PLATFORMS[self.platform]
        except KeyError:
            raise CollectionError(
                f"Unknown platform '{self.platform}': choose one of {', '.join(sorted(PLATFORMS))}"
            ) from None


def _installed(module: str) -> bool:
    from importlib.util import find_spec

    try:
        return find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def available_methods() -> tuple[str, ...]:
    """The collection libraries installed here, so the UI can say what is possible before it is tried."""
    return tuple(m for m in METHODS if _installed(m))


def _chosen_method(target: Target) -> str:
    """The driver to use, or a CollectionError explaining what to install.

    ``auto`` prefers NAPALM where the platform has a driver and the library is present, because it
    asks the device for its configuration rather than typing a command at it.
    """
    spec, available = target.spec, available_methods()
    if not available:
        raise CollectionError(
            "Live collection needs Netmiko or NAPALM, and neither is installed. Netmiko is a normal "
            f"dependency, so this install is incomplete: {INSTALL['netmiko']}"
        )
    if target.method == "auto":
        if spec.napalm and "napalm" in available:
            return "napalm"
        if "netmiko" in available:
            return "netmiko"
        raise CollectionError(
            f"{spec.label} has no NAPALM driver and Netmiko is not installed. "
            f"Install it with: {INSTALL['netmiko']}"
        )
    if target.method not in METHODS:
        raise CollectionError(f"Unknown method '{target.method}': choose auto, napalm or netmiko")
    if target.method not in available:
        raise CollectionError(f"{target.method} is not installed. Install it with: "
                              f"{INSTALL[target.method]}")
    if target.method == "napalm" and not spec.napalm:
        raise CollectionError(f"NAPALM has no driver for {spec.label} -collect it with Netmiko instead")
    return target.method


def _reachable_addresses(host: str) -> list:
    """Every address the host resolves to, so the check cannot be dodged by naming one."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise CollectionError(f"'{host}' does not resolve") from None
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _vetted_address(host: str, policy: str) -> str:
    """The address to actually connect to: resolved once here, checked, and returned as a literal.

    Live collection takes a hostname from a request and opens a connection to it, which is
    server-side request forgery unless something bounds where it may go: on a reachable backend it
    would otherwise reach any address the server can, including ones a client cannot.

    ``is_private`` alone is not that bound. Python counts link-local as private, so 169.254.169.254
    -the cloud metadata endpoint, and the first address anyone tries -would pass. It is excluded by
    name, along with multicast and reserved space.

    Checking the name and then handing the *name* to the driver would not be a bound either: the
    driver resolves it a second time, and a DNS answer that changes between the two lookups (a short
    TTL under the caller's control) passes the check and connects somewhere else. So every address
    the name resolves to is checked, and the driver is given a vetted literal it cannot re-resolve.
    """
    if policy == "any":
        return host
    addresses = _reachable_addresses(host)
    for address in addresses:
        private = (address.is_private or address.is_loopback) and not (
            address.is_link_local or address.is_multicast or address.is_reserved)
        if not private:
            raise CollectionError(
                f"'{host}' resolves to {address}, which is outside the private network live collection "
                "is limited to. Set LIVE_COLLECTION_NETWORKS=any to allow it."
            )
    return str(addresses[0])


def _collect_napalm(target: Target) -> str:
    import napalm

    driver = napalm.get_network_driver(target.spec.napalm)
    device = driver(
        hostname=target.host,
        username=target.username,
        password=target.password,
        timeout=target.timeout,
        optional_args={"port": target.port, "secret": target.enable},
    )
    device.open()
    try:
        config = device.get_config(retrieve="running")
    finally:
        device.close()
    # Some drivers answer with the startup or candidate config when the running one is empty
    return config.get("running") or config.get("startup") or ""


def _collect_netmiko(target: Target) -> str:
    from netmiko import ConnectHandler

    spec = target.spec
    connection = ConnectHandler(
        device_type=spec.netmiko,
        host=target.host,
        username=target.username,
        password=target.password,
        port=target.port,
        secret=target.enable,
        conn_timeout=target.timeout,
    )
    try:
        if target.enable:
            connection.enable()
        for command in spec.setup:
            connection.send_command(command)
        # A full configuration takes longer than the default read window on a busy device
        return connection.send_command(spec.command, read_timeout=max(target.timeout, 60))
    finally:
        connection.disconnect()


def collect(target: Target) -> str:
    """The device's running configuration as text, ready to scan.

    Raises ``CollectionError`` with an operator-facing message for every failure -unreachable host,
    rejected credentials, a command the platform did not accept. The underlying exception is summarized
    rather than re-raised, because driver exceptions quote the session (and sometimes the password
    prompt) in their message.
    """
    from app import config as app_config

    method = _chosen_method(target)
    named = target.host.strip()
    if not named:
        raise CollectionError("No host given")
    # Guarded here, not in the route: every caller reaches a device through this function. The driver
    # is handed the vetted address rather than the name, so it cannot resolve to somewhere else.
    # ``named`` stays the operator's spelling, because that is what they recognize in a message.
    target = replace(target, host=_vetted_address(named, app_config.settings.live_collection_networks))

    collector = _collect_napalm if method == "napalm" else _collect_netmiko
    try:
        config = collector(target)
    except CollectionError:
        raise
    except Exception as e:
        raise CollectionError(
            f"Could not collect from {named} over {method}: {type(e).__name__}"
        ) from None

    if not config.strip():
        raise CollectionError(
            f"{named} returned an empty configuration. The account may lack the privilege to "
            f"read it -'{target.spec.command}' printed nothing."
        )
    return config


def platform_choices() -> list[dict]:
    """Every platform with the driver it would actually use here, for the collection form."""
    available = available_methods()
    choices = []
    for key, spec in sorted(PLATFORMS.items(), key=lambda kv: kv[1].label):
        methods = [m for m in available if m == "netmiko" or spec.napalm]
        choices.append({
            "platform": key,
            "label": spec.label,
            "command": spec.command,
            "napalm_driver": spec.napalm or None,
            "methods": methods,
            "available": bool(methods),
        })
    return choices
