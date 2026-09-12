"""
MappingRepository — persistence boundary for learned adaptive mappings.

Conceptual model:

* CONCEPT  — what the configuration means (``session_timeout``)
* PATTERN  — how some vendor expresses it (``admin idle-timeout {value}``)
* MAPPING  — the confirmed link between a pattern and a normalized field

Vendor is optional metadata, never part of a mapping's identity.

Safety rules enforced here:

* patterns are safe templates (see ``app.adaptive.matcher``), never raw regex
* only an administrator can confirm, update or disable a confirmed mapping
* saving a mapping whose pattern is identical to an active confirmed mapping
  raises ``MappingConflictError`` instead of silently overwriting it
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.adaptive.mapper import FIELD_REGISTRY, TYPE_LIST_STR
from app.adaptive.matcher import (
    EXTRACTION_CONSTANT,
    EXTRACTION_TEMPLATE_CAPTURE,
    LearnedMappingMatcher,
    MappingMatch,
    PatternError,
    SimilarMapping,
    match_pattern,
    normalize_line,
    validate_pattern,
)
from app.db.database import get_connection


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
})


class MappingValidationError(ValueError):
    """The mapping is malformed (bad field, type, or pattern)."""


class MappingConflictError(Exception):
    """An active confirmed mapping already owns this pattern."""

    def __init__(self, existing: "LearnedMapping"):
        self.existing = existing
        super().__init__(
            f"Confirmed mapping #{existing.id} already uses pattern "
            f"'{existing.command_pattern}' (→ {existing.normalized_field}). "
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_mapping(row) -> LearnedMapping:
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
    )


def validate_mapping(mapping: LearnedMapping) -> LearnedMapping:
    """Validate a mapping in place (field, value type, pattern, example)."""
    field_info = FIELD_REGISTRY.get(mapping.normalized_field)
    if field_info is None:
        raise MappingValidationError(
            f"'{mapping.normalized_field}' is not a settable NormalizedConfig field"
        )
    mapping.expected_value_type = field_info.type_category

    if not (mapping.concept or "").strip():
        raise MappingValidationError("Concept must not be empty")
    mapping.concept = mapping.concept.strip()
    mapping.vendor = (mapping.vendor or "").strip() or None

    if not 0.0 <= float(mapping.confidence) <= 1.0:
        raise MappingValidationError("Confidence must be between 0.0 and 1.0")

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


class MappingRepository:
    """SQLite-backed store of learned mappings and rejected lines."""

    def __init__(self, db_path: Path | str | None = None):
        self._db_path = db_path

    def _conn(self):
        return get_connection(self._db_path)

    # ── mappings ────────────────────────────────────────────────────────────

    def save_mapping(self, mapping: LearnedMapping, actor: str = ADMIN_ACTOR) -> LearnedMapping:
        if mapping.confirmed and actor != ADMIN_ACTOR:
            raise MappingPermissionError("Only an administrator can confirm a mapping")

        mapping = validate_mapping(dataclasses.replace(mapping, id=None))

        with self._conn() as conn:
            self._raise_on_conflict(conn, mapping)
            now = _now()
            cur = conn.execute(
                """
                INSERT INTO learned_mappings (
                    concept, normalized_field, vendor, command_pattern,
                    extraction_method, expected_value_type, constant_value,
                    confidence, confirmed, active, example_line, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping.concept, mapping.normalized_field, mapping.vendor,
                    mapping.command_pattern, mapping.extraction_method,
                    mapping.expected_value_type, mapping.constant_value,
                    float(mapping.confidence), int(mapping.confirmed), int(mapping.active),
                    mapping.example_line, now, now,
                ),
            )
            return dataclasses.replace(mapping, id=cur.lastrowid, created_at=now, updated_at=now)

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
        with self._conn() as conn:
            rows = conn.execute(query + " ORDER BY id").fetchall()
        return [_row_to_mapping(r) for r in rows]

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
                """
                UPDATE learned_mappings SET
                    concept = ?, normalized_field = ?, vendor = ?, command_pattern = ?,
                    extraction_method = ?, expected_value_type = ?, constant_value = ?,
                    active = ?, example_line = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    updated.concept, updated.normalized_field, updated.vendor,
                    updated.command_pattern, updated.extraction_method,
                    updated.expected_value_type, updated.constant_value,
                    int(updated.active), updated.example_line, now, mapping_id,
                ),
            )
        return dataclasses.replace(updated, updated_at=now)

    def disable_mapping(self, mapping_id: int, actor: str) -> LearnedMapping:
        return self.update_mapping(mapping_id, {"active": False}, actor=actor)

    def _raise_on_conflict(self, conn, mapping: LearnedMapping, exclude_id: Optional[int] = None) -> None:
        rows = conn.execute(
            "SELECT * FROM learned_mappings WHERE active = 1 AND confirmed = 1"
        ).fetchall()
        key = normalize_line(mapping.command_pattern)
        for row in rows:
            if row["id"] != exclude_id and normalize_line(row["command_pattern"]) == key:
                raise MappingConflictError(_row_to_mapping(row))

    # ── reviewed-but-unmapped lines ─────────────────────────────────────────

    def record_rejection(self, raw_line: str, vendor: Optional[str] = None, reason: Optional[str] = None) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO rejected_lines (line_key, raw_line, vendor, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (normalize_line(raw_line), raw_line.strip(), vendor, reason, _now()),
            )

    def rejected_line_keys(self) -> set[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT line_key FROM rejected_lines").fetchall()
        return {r["line_key"] for r in rows}

    def is_rejected(self, raw_line: str) -> bool:
        return normalize_line(raw_line) in self.rejected_line_keys()
