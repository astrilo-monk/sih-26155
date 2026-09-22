"""
MappingRepository -persistence boundary for learned adaptive mappings.

Conceptual model:

* CONCEPT  -what the configuration means (``session_timeout``)
* PATTERN  -how some vendor expresses it (``admin idle-timeout {value}``)
* MAPPING  -the confirmed link between a pattern and a normalized field
* RECOGNIZER (Phase 6) -a mapping that answers a security predicate directly
  (``remote-console protocol {enum:protocol}`` → Telnet allowed); see ``app.facts.recognizers``

Vendor is optional metadata, never part of a mapping's identity.

Safety rules enforced here:

* patterns are safe templates (see ``app.adaptive.matcher``), never raw regex
* only an administrator can confirm, update or disable a confirmed mapping
* saving a mapping whose pattern (and scope) is identical to an active confirmed mapping
  raises ``MappingConflictError`` instead of silently overwriting it
* recognizers pass the gates of ``validate_recognizer``: two keywords besides stopwords, counting
  the scope template, stated polarity, a unit for durations, a value that matches the example line
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.adaptive.mapper import FIELD_REGISTRY, TYPE_LIST_STR
from app.adaptive.matcher import (
    EXTRACTION_CONSTANT,
    EXTRACTION_RECOGNIZER,
    EXTRACTION_TEMPLATE_CAPTURE,
    LearnedMappingMatcher,
    MappingMatch,
    PatternError,
    SimilarMapping,
    match_pattern,
    normalize_line,
    validate_pattern,
)
from app.ai.redaction import Redactor, redact_line
from app.db.database import _database_url, get_connection
from app.facts.predicates import FIELD_PREDICATES
from app.facts.recognizers import RecognizerError, validate_recognizer


ADMIN_ACTOR = "admin"

EDITABLE_FIELDS = frozenset({
    "concept",
    "normalized_field",
    "vendor",
    "command_pattern",
    "extraction_method",
    "constant_value",
    "example_line",
    "active",
    "scope_template",
    "negatives",
})

_COLUMNS = (
    "concept", "normalized_field", "vendor", "command_pattern", "extraction_method", "expected_value_type",
    "constant_value", "confidence", "confirmed", "active", "example_line", "predicate", "subject",
    "scope_template", "dialect_fingerprint", "negatives", "source",
)

SOURCE_RUNTIME = "runtime"
SOURCE_SEED = "seed"


class MappingValidationError(ValueError):
    """The mapping is malformed (bad field, type, or pattern)."""


class MappingConflictError(Exception):
    """An active confirmed mapping already owns this pattern."""

    def __init__(self, existing: "LearnedMapping"):
        self.existing = existing
        super().__init__(
            f"Confirmed mapping #{existing.id} already uses pattern "
            f"'{existing.command_pattern}' (→ {existing.normalized_field or existing.predicate}). "
            "Edit or disable it explicitly instead."
        )


class MappingPermissionError(PermissionError):
    """A non-administrator tried to confirm or modify a confirmed mapping."""


class MappingNotFoundError(LookupError):
    pass


@dataclass
class LearnedMapping:
    concept: str
    normalized_field: str
    command_pattern: str
    extraction_method: str
    expected_value_type: str = ""
    vendor: Optional[str] = None
    constant_value: Optional[str] = None
    confidence: float = 1.0
    confirmed: bool = False
    active: bool = True
    example_line: Optional[str] = None
    id: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""
    # Phase 6: the security fact the mapping answers (derived from the field for field mappings)
    predicate: Optional[str] = None
    subject: Optional[str] = None
    scope_template: Optional[str] = None
    dialect_fingerprint: Optional[str] = None
    # Normalized lines the recognizer must never match
    negatives: list[str] = field(default_factory=list)
    # "runtime" = learned from an administrator, "seed" = shipped knowledge (app.facts.seed)
    source: str = SOURCE_RUNTIME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_mapping(row) -> LearnedMapping:
    predicate, subject, _, _ = FIELD_PREDICATES.get(row["normalized_field"], (None, None, None, None))
    return LearnedMapping(
        id=row["id"],
        concept=row["concept"],
        normalized_field=row["normalized_field"],
        vendor=row["vendor"],
        command_pattern=row["command_pattern"],
        extraction_method=row["extraction_method"],
        expected_value_type=row["expected_value_type"],
        constant_value=row["constant_value"],
        confidence=row["confidence"],
        confirmed=bool(row["confirmed"]),
        active=bool(row["active"]),
        example_line=row["example_line"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        predicate=row["predicate"] or predicate,
        subject=row["subject"] or subject,
        scope_template=row["scope_template"],
        dialect_fingerprint=row["dialect_fingerprint"],
        negatives=json.loads(row["negatives"] or "[]"),
        source=row["source"] or SOURCE_RUNTIME,
    )


def _values(mapping: LearnedMapping) -> tuple:
    row = dataclasses.asdict(mapping)
    row.update(confidence=float(mapping.confidence), confirmed=int(mapping.confirmed), active=int(mapping.active),
               negatives=json.dumps(mapping.negatives))
    return tuple(row[column] for column in _COLUMNS)


def _validate_recognizer(mapping: LearnedMapping) -> LearnedMapping:
    mapping.normalized_field = ""
    mapping.expected_value_type = EXTRACTION_RECOGNIZER
    mapping.command_pattern = " ".join((mapping.command_pattern or "").split())
    mapping.scope_template = " ".join((mapping.scope_template or "").split()) or None
    mapping.negatives = sorted({normalize_line(n) for n in mapping.negatives if n.strip()})
    try:
        validate_recognizer(mapping)
    except RecognizerError as e:
        raise MappingValidationError(str(e)) from e
    return mapping


def rejection_key(raw_line: str) -> str:
    """Key of a reviewed-but-unmapped line. Built from the redacted line, so a secret is never stored or compared."""
    return normalize_line(redact_line(raw_line))


_SLOT_TOKEN = re.compile(r"^\{[a-z]+(?::[\w-]+)?\}$")


def _holds_secret(text: str) -> bool:
    """True when redaction would remove a value. A value that is only template slots (``secret {enum:type}
    {any}``) or an existing placeholder (``<SECRET:type0>``) holds no secret, so a recognizer can read how a
    password is stored without ever storing one."""
    redactor = Redactor()
    if redactor.line(text) == text:
        return False
    return any(not all(_SLOT_TOKEN.match(t) for t in value.split()) for value in redactor.secrets)


def _refuse_secrets(mapping: LearnedMapping) -> None:
    texts = [mapping.example_line, mapping.command_pattern, mapping.scope_template, mapping.constant_value,
             *mapping.negatives]
    if any(text and _holds_secret(text) for text in texts):
        raise MappingValidationError(
            "This line holds a secret (password, key or community string): it cannot be stored as a mapping "
            "or recognizer"
        )


def validate_mapping(mapping: LearnedMapping) -> LearnedMapping:
    """Validate a mapping in place (field, value type, pattern, example)."""
    if not (mapping.concept or "").strip():
        raise MappingValidationError("Concept must not be empty")
    mapping.concept = mapping.concept.strip()
    mapping.vendor = (mapping.vendor or "").strip() or None
    if not 0.0 <= float(mapping.confidence) <= 1.0:
        raise MappingValidationError("Confidence must be between 0.0 and 1.0")
    # the mapping store is persistent: configuration secrets never go into it
    _refuse_secrets(mapping)

    if mapping.extraction_method == EXTRACTION_RECOGNIZER:
        return _validate_recognizer(mapping)

    field_info = FIELD_REGISTRY.get(mapping.normalized_field)
    if field_info is None:
        raise MappingValidationError(
            f"'{mapping.normalized_field}' is not a settable NormalizedConfig field"
        )
    mapping.expected_value_type = field_info.type_category
    mapping.predicate, mapping.subject, _, _ = FIELD_PREDICATES.get(mapping.normalized_field, (None, None, None, None))

    try:
        validate_pattern(mapping.command_pattern, mapping.extraction_method)
    except PatternError as e:
        raise MappingValidationError(str(e)) from e
    mapping.command_pattern = " ".join(mapping.command_pattern.split())

    def _converts(value: Optional[str]) -> bool:
        converted = field_info.convert(value)
        if field_info.type_category == TYPE_LIST_STR:
            return bool(converted)
        return converted is not None

    if mapping.extraction_method == EXTRACTION_CONSTANT:
        if mapping.constant_value is None or not _converts(mapping.constant_value):
            raise MappingValidationError(
                f"Constant value '{mapping.constant_value}' is not a valid "
                f"'{field_info.type_category}' for {mapping.normalized_field}"
            )
    else:
        mapping.constant_value = None

    if mapping.example_line:
        matched, captured = match_pattern(
            mapping.command_pattern, mapping.extraction_method, mapping.example_line
        )
        if not matched:
            raise MappingValidationError("Command pattern does not match its example line")
        if mapping.extraction_method == EXTRACTION_TEMPLATE_CAPTURE and not _converts(captured):
            raise MappingValidationError(
                f"Pattern captures '{captured}', which is not a valid "
                f"'{field_info.type_category}' for {mapping.normalized_field}"
            )

    return mapping


# Postgres reads, per database URL: a scan reads the store several times and every round trip to a hosted
# database costs a few hundred milliseconds. Every write below goes through this module and clears it.
# ponytail: per-process cache, correct for one backend instance; with several instances a write on one leaves the
# others stale until they restart -move to LISTEN/NOTIFY or a short TTL before scaling out.
_PG_READS: dict[tuple, Any] = {}


class MappingRepository:
    """Store of learned mappings and rejected lines (SQLite, or Postgres when DATABASE_URL is set)."""

    def __init__(self, db_path: Path | str | None = None):
        self._db_path = db_path

    def _conn(self):
        return get_connection(self._db_path)

    def _cached(self, key: str, read):
        url = _database_url(self._db_path)
        if not url:
            return read()
        if (url, key) not in _PG_READS:
            _PG_READS[(url, key)] = read()
        return _PG_READS[(url, key)]

    @staticmethod
    def _written() -> None:
        _PG_READS.clear()

    # ── mappings ────────────────────────────────────────────────────────────

    def save_mapping(self, mapping: LearnedMapping, actor: str = ADMIN_ACTOR) -> LearnedMapping:
        if mapping.confirmed and actor != ADMIN_ACTOR:
            raise MappingPermissionError("Only an administrator can confirm a mapping")

        mapping = validate_mapping(dataclasses.replace(mapping, id=None, negatives=list(mapping.negatives)))

        with self._conn() as conn:
            self._raise_on_conflict(conn, mapping)
            now = _now()
            row = conn.execute(
                f"INSERT INTO learned_mappings ({', '.join(_COLUMNS)}, created_at, updated_at) "
                f"VALUES ({', '.join('?' * len(_COLUMNS))}, ?, ?) RETURNING id",
                (*_values(mapping), now, now),
            ).fetchone()
        # after the commit: a read in between would otherwise cache the old list
        self._written()
        return dataclasses.replace(mapping, id=row["id"], created_at=now, updated_at=now)

    def get_mapping(self, mapping_id: int) -> LearnedMapping:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM learned_mappings WHERE id = ?", (mapping_id,)).fetchone()
        if row is None:
            raise MappingNotFoundError(f"Mapping #{mapping_id} not found")
        return _row_to_mapping(row)

    def list_mappings(self, include_inactive: bool = False) -> list[LearnedMapping]:
        query = "SELECT * FROM learned_mappings"
        if not include_inactive:
            query += " WHERE active = 1"

        def read():
            with self._conn() as conn:
                return conn.execute(query + " ORDER BY id").fetchall()
        # fresh objects each call: callers may change a mapping without writing it
        return [_row_to_mapping(r) for r in self._cached(query, read)]

    def find_matching_mappings(self, raw_line: str) -> list[MappingMatch]:
        """Confirmed, active mappings whose pattern matches the line exactly."""
        return LearnedMappingMatcher(self).match_line(raw_line).matches

    def find_similar_mappings(self, raw_line: str) -> list[SimilarMapping]:
        """Confirmed mappings that resemble the line (candidate concepts/patterns)."""
        return LearnedMappingMatcher(self).match_line(raw_line).candidates

    def update_mapping(self, mapping_id: int, changes: dict[str, Any], actor: str) -> LearnedMapping:
        existing = self.get_mapping(mapping_id)
        if existing.confirmed and actor != ADMIN_ACTOR:
            raise MappingPermissionError("Confirmed mappings can only be changed by an administrator")

        unknown = set(changes) - EDITABLE_FIELDS
        if unknown:
            raise MappingValidationError(f"Fields cannot be edited: {sorted(unknown)}")

        updated = validate_mapping(dataclasses.replace(existing, **changes))

        with self._conn() as conn:
            if updated.active and updated.confirmed:
                self._raise_on_conflict(conn, updated, exclude_id=mapping_id)
            now = _now()
            conn.execute(
                f"UPDATE learned_mappings SET {', '.join(f'{c} = ?' for c in _COLUMNS)}, updated_at = ? WHERE id = ?",
                (*_values(updated), now, mapping_id),
            )
        self._written()
        return dataclasses.replace(updated, updated_at=now)

    def disable_mapping(self, mapping_id: int, actor: str) -> LearnedMapping:
        return self.update_mapping(mapping_id, {"active": False}, actor=actor)

    def _raise_on_conflict(self, conn, mapping: LearnedMapping, exclude_id: Optional[int] = None) -> None:
        rows = conn.execute(
            "SELECT * FROM learned_mappings WHERE active = 1 AND confirmed = 1"
        ).fetchall()
        key = (normalize_line(mapping.command_pattern), normalize_line(mapping.scope_template or ""))
        for row in rows:
            if row["id"] != exclude_id and (
                normalize_line(row["command_pattern"]), normalize_line(row["scope_template"] or "")
            ) == key:
                raise MappingConflictError(_row_to_mapping(row))

    # ── reviewed-but-unmapped lines ─────────────────────────────────────────

    def record_rejection(self, raw_line: str, vendor: Optional[str] = None, reason: Optional[str] = None) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO rejected_lines (line_key, raw_line, vendor, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (line_key) DO NOTHING
                """,
                (rejection_key(raw_line), redact_line(raw_line).strip(), vendor, reason, _now()),
            )
        self._written()

    def rejected_line_keys(self) -> set[str]:
        """Keys to compare with ``rejection_key(line)``."""
        def read():
            with self._conn() as conn:
                return conn.execute("SELECT line_key FROM rejected_lines").fetchall()
        return {r["line_key"] for r in self._cached("rejected_lines", read)}

    def is_rejected(self, raw_line: str) -> bool:
        return rejection_key(raw_line) in self.rejected_line_keys()
