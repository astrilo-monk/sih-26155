"""
Normalized field catalog — the single source of truth for adaptive mapping.

Every consumer of "which NormalizedConfig fields may an unrecognized line
map to" derives from this module:

* the AI response schema enum and the AI system prompt   (interpreter)
* the Pydantic field allowlist                            (interpretation_schemas)
* value conversion and validation                         (mapper)
* learned-mapping validation                              (db.mappings)
* the Review & Recognizers field picker                           (/api/adaptive/fields)

``FIELD_REGISTRY`` lists the scalar fields an adaptive value can be written
to, with a human label and value rules. ``NORMALIZED_FIELD_PATHS`` is the
complete vocabulary of the model (including container fields such as
``interfaces[].name``) and is derived by introspecting ``NormalizedConfig``,
so it can never drift from the dataclasses.
"""

from __future__ import annotations

import dataclasses
import typing
from dataclasses import dataclass
from typing import Any, Callable, Optional

from app.models.normalized import ConsoleLine, NormalizedConfig


# ── Type converters ───────────────────────────────────────────────────────────

_TRUE_VALUES = frozenset({"true", "enabled", "yes", "1", "on"})
_FALSE_VALUES = frozenset({"false", "disabled", "no", "0", "off"})


def convert_bool(value: Optional[str]) -> Optional[bool]:
    """Convert a string to ``bool``.  Returns ``None`` if ambiguous."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in _TRUE_VALUES:
        return True
    if v in _FALSE_VALUES:
        return False
    return None


def convert_int(value: Optional[str]) -> Optional[int]:
    """Convert a string to ``int``.  Handles prefixes like ``v2``.
    Returns ``None`` if the value is not a valid integer."""
    if value is None:
        return None
    v = value.strip()
    if v.lower().startswith("v"):
        v = v[1:]
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def convert_str(value: Optional[str]) -> Optional[str]:
    """Convert a string to ``str`` (stripped)."""
    if value is None:
        return None
    return value.strip()


def convert_list_str(value: Optional[str]) -> list[str]:
    """Convert a string to ``list[str]``.  Splits on commas."""
    if value is None:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


# ── Field metadata ────────────────────────────────────────────────────────────

TYPE_BOOL = "bool"
TYPE_INT = "int"
TYPE_STR = "str"
TYPE_OPTIONAL_BOOL = "optional_bool"
TYPE_OPTIONAL_INT = "optional_int"
TYPE_OPTIONAL_STR = "optional_str"
TYPE_LIST_STR = "list_str"

BOOL_TYPES = frozenset({TYPE_BOOL, TYPE_OPTIONAL_BOOL})
INT_TYPES = frozenset({TYPE_INT, TYPE_OPTIONAL_INT})
STR_TYPES = frozenset({TYPE_STR, TYPE_OPTIONAL_STR})

_VALUE_RULES = {
    TYPE_BOOL: 'resulting state as "true" or "false"',
    TYPE_OPTIONAL_BOOL: 'resulting state as "true" or "false"',
    TYPE_INT: "whole number, digits only",
    TYPE_OPTIONAL_INT: "whole number, digits only",
    TYPE_STR: "text exactly as written, without quotes",
    TYPE_OPTIONAL_STR: "text exactly as written, without quotes",
    TYPE_LIST_STR: "the one item this line adds, exactly as written",
}


@dataclass
class FieldTypeInfo:
    """Metadata for a settable scalar field in :class:`NormalizedConfig`."""
    type_category: str
    convert: Callable[[Optional[str]], Optional[Any]]
    get_parent: Callable[[NormalizedConfig], Any]
    attr_name: str
    label: str = ""
    description: str = ""

    @property
    def value_rule(self) -> str:
        return _VALUE_RULES.get(self.type_category, "")


_CONVERTERS = {
    TYPE_BOOL: convert_bool,
    TYPE_OPTIONAL_BOOL: convert_bool,
    TYPE_INT: convert_int,
    TYPE_OPTIONAL_INT: convert_int,
    TYPE_STR: convert_str,
    TYPE_OPTIONAL_STR: convert_str,
    TYPE_LIST_STR: convert_list_str,
}


def _ensure_console(config: NormalizedConfig) -> ConsoleLine:
    """Return ``config.management.console``, creating one if it is ``None``."""
    if config.management.console is None:
        config.management.console = ConsoleLine()
    return config.management.console


_PARENTS: dict[str, Callable[[NormalizedConfig], Any]] = {
    "device": lambda cfg: cfg.device,
    "management": lambda cfg: cfg.management,
    "management.console": _ensure_console,
    "authentication": lambda cfg: cfg.authentication,
    "snmp": lambda cfg: cfg.snmp,
    "logging": lambda cfg: cfg.logging,
    "ntp": lambda cfg: cfg.ntp,
    "vpn": lambda cfg: cfg.vpn,
    "banners": lambda cfg: cfg.banners,
    "services": lambda cfg: cfg.services,
}


def _field(path: str, type_category: str, label: str, description: str) -> tuple[str, FieldTypeInfo]:
    parent, attr = path.rsplit(".", 1)
    return path, FieldTypeInfo(
        type_category=type_category,
        convert=_CONVERTERS[type_category],
        get_parent=_PARENTS[parent],
        attr_name=attr,
        label=label,
        description=description,
    )


#: Registry of all scalar (directly settable) fields.
#: Container fields (those with ``[]`` in the path) are intentionally absent —
#: they need additional context and are routed to review/training.
FIELD_REGISTRY: dict[str, FieldTypeInfo] = dict([
    # DeviceInfo
    _field("device.hostname", TYPE_STR, "Device hostname",
           "Name the device identifies itself with"),
    _field("device.os_version", TYPE_OPTIONAL_STR, "OS / firmware version",
           "Operating system or firmware version string"),

    # ManagementAccess
    _field("management.ssh_enabled", TYPE_BOOL, "SSH management enabled",
           "Whether SSH access to the device's management plane is enabled"),
    _field("management.ssh_version", TYPE_OPTIONAL_INT, "SSH protocol version",
           "SSH protocol version allowed (1 or 2)"),
    _field("management.ssh_timeout", TYPE_OPTIONAL_INT, "SSH negotiation timeout",
           "SSH authentication/negotiation timeout in seconds"),
    _field("management.ssh_retries", TYPE_OPTIONAL_INT, "SSH authentication retries",
           "Maximum SSH authentication attempts"),
    _field("management.telnet_enabled", TYPE_BOOL, "Telnet management enabled",
           "Whether Telnet access to the management plane is enabled"),
    _field("management.http_enabled", TYPE_BOOL, "HTTP management enabled",
           "Whether unencrypted HTTP web management is enabled"),
    _field("management.https_enabled", TYPE_BOOL, "HTTPS management enabled",
           "Whether HTTPS web management is enabled"),
    _field("management.admin_timeout", TYPE_OPTIONAL_INT, "Admin session idle timeout",
           "Idle timeout for administrative sessions, in minutes"),

    # ConsoleLine
    _field("management.console.exec_timeout_minutes", TYPE_OPTIONAL_INT, "Console idle timeout (minutes)",
           "Console session idle timeout, minutes part"),
    _field("management.console.exec_timeout_seconds", TYPE_OPTIONAL_INT, "Console idle timeout (seconds)",
           "Console session idle timeout, seconds part"),
    _field("management.console.login_method", TYPE_OPTIONAL_STR, "Console login method",
           "How console logins are authenticated (e.g. local, aaa, password)"),
    _field("management.console.password_type", TYPE_OPTIONAL_STR, "Console password storage",
           "How the console password is stored (plaintext, hashed, encrypted)"),

    # Authentication
    _field("authentication.aaa_enabled", TYPE_BOOL, "Central AAA enabled",
           "Whether centralized authentication (AAA/RADIUS/TACACS+/LDAP) is enabled"),
    _field("authentication.aaa_auth_methods", TYPE_LIST_STR, "Authentication method",
           "An authentication method or server group in use (e.g. radius, tacacs+, local)"),
    _field("authentication.password_encryption_service", TYPE_BOOL, "Stored password encryption",
           "Whether passwords in the configuration are stored encrypted"),
    _field("authentication.enable_password_type", TYPE_OPTIONAL_STR, "Privileged password storage",
           "How the privileged/enable password is stored"),

    # SnmpConfig
    _field("snmp.enabled", TYPE_BOOL, "SNMP enabled",
           "Whether the SNMP agent is enabled"),
    _field("snmp.v3_configured", TYPE_BOOL, "SNMPv3 configured",
           "Whether SNMPv3 (authenticated/encrypted) is configured"),

    # LoggingConfig
    _field("logging.buffered", TYPE_BOOL, "Local log buffer enabled",
           "Whether logs are kept in a local buffer"),
    _field("logging.buffer_size", TYPE_OPTIONAL_INT, "Local log buffer size",
           "Size of the local log buffer"),
    _field("logging.remote_hosts", TYPE_LIST_STR, "Remote syslog server",
           "A remote syslog/log collector host or IP address"),
    _field("logging.trap_level", TYPE_OPTIONAL_STR, "Remote logging severity",
           "Minimum severity sent to remote log servers"),
    _field("logging.timestamps_enabled", TYPE_BOOL, "Log timestamps enabled",
           "Whether log messages carry timestamps"),
    _field("logging.timestamps_msec", TYPE_BOOL, "Millisecond log timestamps",
           "Whether log timestamps include milliseconds"),

    # NtpConfig
    _field("ntp.servers", TYPE_LIST_STR, "NTP server",
           "A time synchronization (NTP) server host or IP address"),
    _field("ntp.authentication_enabled", TYPE_BOOL, "NTP authentication enabled",
           "Whether NTP messages are authenticated"),

    # VpnConfig
    _field("vpn.ssl_min_tls_version", TYPE_OPTIONAL_STR, "Minimum TLS version",
           "Lowest TLS version accepted for SSL VPN / management TLS (e.g. tls1.2)"),

    # BannerConfig
    _field("banners.login_banner", TYPE_OPTIONAL_STR, "Login banner",
           "Text shown before login"),
    _field("banners.motd_banner", TYPE_OPTIONAL_STR, "MOTD banner",
           "Message-of-the-day text"),
    _field("banners.pre_login_banner_enabled", TYPE_OPTIONAL_BOOL, "Pre-login banner enabled",
           "Whether a pre-login disclaimer banner is enabled"),

    # ServiceConfig
    _field("services.ip_source_route", TYPE_OPTIONAL_BOOL, "IP source routing",
           "Whether IP source-routed packets are accepted"),
    _field("services.cdp_globally_enabled", TYPE_OPTIONAL_BOOL, "CDP enabled globally",
           "Whether Cisco Discovery Protocol is enabled device-wide"),
    _field("services.lldp_globally_enabled", TYPE_OPTIONAL_BOOL, "LLDP enabled globally",
           "Whether LLDP neighbor discovery is enabled device-wide"),
    _field("services.password_encryption", TYPE_BOOL, "Password encryption service",
           "Whether the device's password-obfuscation service is enabled"),
])


# ── Model vocabulary (derived by introspection) ──────────────────────────────

# Bookkeeping attributes that are not configuration semantics
_NON_SEMANTIC_ATTRS = frozenset({
    "source_lines", "raw_config", "raw_lines", "unrecognized_lines", "ai_mappings",
})


def _dataclass_type(tp: Any) -> Optional[type]:
    """Return the dataclass inside ``tp`` (unwrapping Optional), if any."""
    if dataclasses.is_dataclass(tp):
        return tp
    for arg in typing.get_args(tp):
        if arg is not type(None) and dataclasses.is_dataclass(arg):
            return arg
    return None


def _walk(cls: type, prefix: str) -> list[str]:
    paths = []
    hints = typing.get_type_hints(cls)
    for f in dataclasses.fields(cls):
        if f.name in _NON_SEMANTIC_ATTRS:
            continue
        tp = hints[f.name]
        path = f"{prefix}{f.name}"
        if typing.get_origin(tp) is list:
            (item,) = typing.get_args(tp)
            if dataclasses.is_dataclass(item):
                paths.extend(_walk(item, f"{path}[]."))
                continue
            paths.append(path)
            continue
        nested = _dataclass_type(tp)
        if nested is not None:
            paths.extend(_walk(nested, f"{path}."))
        else:
            paths.append(path)
    return paths


def model_field_paths() -> frozenset[str]:
    """Every semantic field path of ``NormalizedConfig``."""
    return frozenset(_walk(NormalizedConfig, ""))


#: Full normalized vocabulary (scalar + container field paths).
NORMALIZED_FIELD_PATHS: frozenset[str] = model_field_paths()

#: Fields an adaptive interpretation may be written to, in stable order.
SETTABLE_FIELDS: tuple[str, ...] = tuple(sorted(FIELD_REGISTRY))

assert set(SETTABLE_FIELDS) <= NORMALIZED_FIELD_PATHS, "FIELD_REGISTRY names a field NormalizedConfig lacks"
