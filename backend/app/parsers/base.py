"""
Base parser interface.

Every vendor parser inherits from this and implements the parse() method.
The parse method takes raw config text and returns a NormalizedConfig.
"""

from abc import ABC, abstractmethod
from app.models.normalized import NormalizedConfig


class BaseParser(ABC):
    """
    All vendor parsers follow the same contract:
    take raw config text in, return a NormalizedConfig out.
    """

    @abstractmethod
    def parse(self, raw_config: str) -> NormalizedConfig:
        """Parse raw configuration text into the normalized model."""
        ...

    @staticmethod
    def _index_lines(raw_config: str) -> list[str]:
        """Split config into lines for evidence referencing."""
        return raw_config.splitlines()

    @staticmethod
    def _is_any_address(addr: str) -> bool:
        """Check if an address represents 'any' (0.0.0.0, any, all, etc.)."""
        normalized = addr.strip().lower()
        return normalized in ("any", "all", "0.0.0.0", "0.0.0.0/0", "0.0.0.0 0.0.0.0")
