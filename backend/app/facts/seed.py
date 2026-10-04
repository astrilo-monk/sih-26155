"""
Shipped seed knowledge.

    fresh deployment → empty SQLite → seed recognizers loaded → an unfamiliar dialect already
    answers several controls → the administrator only has to teach what is left

Seed recognizers are ordinary recognizers (``app.facts.recognizers``): the same templates, the same
safety gates, the same decisive CONFIRMED facts. The only difference is provenance -they were
shipped in ``backend/data/seed_recognizers.json`` instead of confirmed by an administrator -which
is recorded in the ``source`` column so the two can be told apart and audited separately.

This is not training and not a second learning system: nothing is inferred, generalized or written
back here. The file is version-controlled, reviewed like code, and loaded as-is.

Loading is deterministic and idempotent:

* a seed entry whose template (and scope) is already stored is skipped, active or not -so a seed
  an administrator disabled stays disabled, and a second load changes nothing
* an entry that collides with an administrator's confirmed mapping is skipped, never overwritten
* an entry that fails ``validate_recognizer`` (or holds a secret) is skipped with a warning, so one
  bad line can never stop a deployment from starting
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from app.adaptive.matcher import EXTRACTION_RECOGNIZER, normalize_line

logger = logging.getLogger(__name__)

SEED_FILE = Path(__file__).resolve().parents[2] / "data" / "seed_recognizers.json"


def read_seed_file(path: Path | str | None = None) -> list[dict]:
    """The shipped entries, or an empty list when the file is missing or malformed."""
    file = Path(path) if path is not None else SEED_FILE
    try:
        return json.loads(file.read_text(encoding="utf-8"))["recognizers"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.warning("Seed knowledge unavailable (%s): %s", file, e)
        return []


def load_seed_recognizers(db_path: Path | str | None = None, seed_file: Path | str | None = None) -> int:
    """Store any shipped recognizer the database does not have yet. Returns how many were added."""
    from app.db.mappings import (  # imported here: the store imports this package for its gates
        SOURCE_SEED, LearnedMapping, MappingConflictError, MappingRepository, MappingValidationError,
    )

    entries = read_seed_file(seed_file)
    if not entries:
        return 0

    repository = MappingRepository(db_path)
    try:
        stored = {_key(m.command_pattern, m.scope_template) for m in repository.list_mappings(include_inactive=True)}
    except Exception as e:  # a store failure must never stop the scanner from starting
        logger.warning("Seed knowledge not loaded -mapping store unavailable: %s", e)
        return 0

    added = 0
    for entry in entries:
        mapping = LearnedMapping(
            concept=entry.get("concept", ""),
            normalized_field="",
            command_pattern=entry.get("command_pattern", ""),
            extraction_method=EXTRACTION_RECOGNIZER,
            vendor=entry.get("vendor"),
            constant_value=entry.get("constant_value"),
            confirmed=True,
            example_line=entry.get("example_line"),
            predicate=entry.get("predicate"),
            subject=entry.get("subject"),
            scope_template=entry.get("scope_template"),
            dialect_fingerprint=entry.get("dialect_fingerprint"),
            negatives=list(entry.get("negatives", [])),
            source=SOURCE_SEED,
        )
        if _key(mapping.command_pattern, mapping.scope_template) in stored:
            continue
        try:
            repository.save_mapping(mapping)
        except (MappingValidationError, MappingConflictError) as e:
            logger.warning("Seed recognizer '%s' skipped: %s", mapping.command_pattern, e)
            continue
        added += 1

    if added:
        logger.info("Loaded %d seed recognizer(s)", added)
    return added


def _key(command_pattern: str, scope_template: Optional[str]) -> tuple[str, str]:
    return normalize_line(command_pattern or ""), normalize_line(scope_template or "")
