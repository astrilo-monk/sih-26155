"""
Pydantic schemas for AI interpretation results.

These models validate structured output from the Groq AI interpreter.
They enforce controlled values for confidence/status and reject
invented normalized fields via an explicit allowlist.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.field_catalog import NORMALIZED_FIELD_PATHS


# ---------------------------------------------------------------------------
# Normalized field allowlist
#
# Derived from NormalizedConfig by app.models.field_catalog (single source of
# truth). The AI MUST NOT invent fields; a line that cannot safely map to an
# existing field uses normalized_field = "unknown".
# ---------------------------------------------------------------------------

NORMALIZED_FIELD_ALLOWLIST: frozenset[str] = NORMALIZED_FIELD_PATHS


class ConfidenceLevel(str, Enum):
    """Controlled confidence values for AI interpretation."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Default numeric scores assigned to each string confidence level when the
# AI does not provide an explicit ``numeric_confidence`` value.
_CONFIDENCE_NUMERIC_DEFAULTS: dict[ConfidenceLevel, float] = {
    ConfidenceLevel.HIGH: 0.90,
    ConfidenceLevel.MEDIUM: 0.70,
    ConfidenceLevel.LOW: 0.30,
}


def confidence_to_numeric(level: ConfidenceLevel) -> float:
    """Map a string ``ConfidenceLevel`` to a numeric score in [0, 1]."""
    return _CONFIDENCE_NUMERIC_DEFAULTS[level]


class InterpretationStatus(str, Enum):
    """Status of an AI interpretation attempt."""
    INTERPRETED = "interpreted"
    UNKNOWN = "unknown"
    AI_UNAVAILABLE = "ai_unavailable"


class InterpretationResult(BaseModel):
    """
    A single interpreted configuration line.

    The AI is an interpreter ONLY. It determines semantic meaning,
    never compliance decisions.
    """
    line_number: int = Field(..., description="1-indexed line number in the original config")
    raw_line: str = Field(..., description="The original configuration line text")
    likely_vendor: str = Field(
        ...,
        description="Vendor or vendor family the line likely belongs to",
    )
    security_concept: str = Field(
        ...,
        description="Vendor-independent security concept (e.g. ssh_host_key_minimum)",
    )
    normalized_field: str = Field(
        ...,
        description="Existing normalized field path this maps to, or 'unknown'",
    )
    extracted_value: Optional[str] = Field(
        default=None,
        description="Value extracted from the line, if any",
    )
    value_evidence: Optional[str] = Field(
        default=None,
        description="Exact substring of the line that proves the extracted value",
    )
    confidence: ConfidenceLevel = Field(
        ...,
        description="How confident the AI is in this interpretation",
    )
    numeric_confidence: Optional[float] = Field(
        default=None,
        description="Numeric confidence score in [0, 1]; derived from confidence if absent",
        ge=0.0,
        le=1.0,
    )
    reasoning: str = Field(
        ...,
        description="Concise explanation of the interpretation",
    )
    status: InterpretationStatus = Field(
        ...,
        description="Interpretation status",
    )

    @property
    def effective_confidence(self) -> float:
        """Numeric confidence: use explicit value if present, else derive from string level."""
        if self.numeric_confidence is not None:
            return self.numeric_confidence
        return confidence_to_numeric(self.confidence)

    @field_validator("normalized_field")
    @classmethod
    def validate_normalized_field(cls, v: str) -> str:
        """Reject invented normalized fields not in the allowlist."""
        from app.ai.interpretation_schemas import NORMALIZED_FIELD_ALLOWLIST
        if v == "unknown":
            return v
        if v not in NORMALIZED_FIELD_ALLOWLIST:
            raise ValueError(
                f"Invented normalized field: {v}. "
                f"Must be one of: {sorted(NORMALIZED_FIELD_ALLOWLIST)} or 'unknown'"
            )
        return v

    @field_validator("numeric_confidence")
    @classmethod
    def validate_numeric_confidence(cls, v):
        """Ensure numeric_confidence is in [0, 1] when provided."""
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError("numeric_confidence must be between 0.0 and 1.0")
        return v


class BatchedInterpretationResponse(BaseModel):
    """
    Response from a batched Groq interpretation request.

    Contains exactly one result per input line.
    """
    interpretations: list[InterpretationResult] = Field(
        ...,
        description="One interpretation result per input line",
    )