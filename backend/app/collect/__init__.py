"""Live collection: pull running configurations off devices instead of uploading files."""

from app.collect.collector import (
    PLATFORMS,
    CollectionError,
    Platform,
    Target,
    available_methods,
    collect,
    platform_choices,
)

__all__ = [
    "PLATFORMS",
    "CollectionError",
    "Platform",
    "Target",
    "available_methods",
    "collect",
    "platform_choices",
]
