"""
Adaptive Parsing Package.

Provides vendor-agnostic configuration parsing capabilities:
- Security relevance filtering
- Unrecognized line capture
- AI interpretation (Phase 2)
- Confidence validation (Phase 3)
- Learned mappings (Phase 5)
"""

from app.adaptive.relevance import is_security_relevant, filter_security_relevant, get_context_lines
from app.adaptive.capture import capture_unrecognized_lines

__all__ = [
    "is_security_relevant",
    "filter_security_relevant",
    "get_context_lines",
    "capture_unrecognized_lines",
]