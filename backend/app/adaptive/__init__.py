"""
Adaptive Parsing Package.

Provides vendor-agnostic configuration parsing capabilities:
- Security relevance filtering (Phase 1)
- Unrecognized line capture (Phase 1)
- AI interpretation (Phase 2)
- Confidence validation + safe normalization (Phase 3)
- Learned mappings (Phase 5)
"""

from app.adaptive.relevance import is_security_relevant, filter_security_relevant, get_context_lines
from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.interpreter import interpret_lines, interpret_config
from app.adaptive.mapper import (
    ConfidenceTier,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    determine_tier,
    InterpretationValidator,
    ConfidenceDecision,
    make_confidence_decision,
    AdaptiveMapper,
    map_interpretations,
    ValidationResult,
    FIELD_REGISTRY,
    FieldTypeInfo,
)

__all__ = [
    # Phase 1
    "is_security_relevant",
    "filter_security_relevant",
    "get_context_lines",
    "capture_unrecognized_lines",
    # Phase 2
    "interpret_lines",
    "interpret_config",
    # Phase 3
    "ConfidenceTier",
    "HIGH_THRESHOLD",
    "MEDIUM_THRESHOLD",
    "determine_tier",
    "InterpretationValidator",
    "ConfidenceDecision",
    "make_confidence_decision",
    "AdaptiveMapper",
    "map_interpretations",
    "ValidationResult",
    "FIELD_REGISTRY",
    "FieldTypeInfo",
]