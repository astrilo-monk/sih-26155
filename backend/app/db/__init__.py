"""
Persistence layer.

Currently holds the Adaptive Knowledge Layer: administrator-confirmed
syntax-to-concept mappings and rejected lines, stored in SQLite.
Parsers and the AI client never touch this package directly.
"""

from app.db.database import get_connection, init_db
from app.db.mappings import (
    LearnedMapping,
    MappingRepository,
    MappingConflictError,
    MappingValidationError,
    MappingPermissionError,
    MappingNotFoundError,
)

__all__ = [
    "get_connection",
    "init_db",
    "LearnedMapping",
    "MappingRepository",
    "MappingConflictError",
    "MappingValidationError",
    "MappingPermissionError",
    "MappingNotFoundError",
]
