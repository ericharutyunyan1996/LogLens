"""Offline knowledge base: explains Windows events, error codes and well-known error messages.

The built-in knowledge (``default_kb()``) can be combined with the user's own entries from a
:class:`UserKnowledgeStore` via ``KnowledgeBase.combined(default_kb(), store.all())`` — user entries take precedence.
"""

from __future__ import annotations

from functools import cache

from .knowledge import (
    ORIGIN_AI,
    ORIGIN_BUILTIN,
    ORIGIN_IMPORTED,
    ORIGIN_LABELS,
    ORIGIN_USER,
    USER_ORIGINS,
    Finding,
    KBEntry,
    KnowledgeBase,
    normalize_provider,
)
from .signatures import Signature, pattern_for, signature_of
from .user_store import (
    DuplicateEntryError,
    EntryNotFoundError,
    ImportResult,
    InvalidEntryError,
    KnowledgePackError,
    KnowledgeStoreError,
    UnknownSignature,
    UserKnowledgeStore,
    compile_pattern,
    entry_from_dict,
    entry_from_explanation,
    pack_text,
    unique_entry_id,
    validate_entry,
)

__all__ = [
    "ORIGIN_AI",
    "ORIGIN_BUILTIN",
    "ORIGIN_IMPORTED",
    "ORIGIN_LABELS",
    "ORIGIN_USER",
    "USER_ORIGINS",
    "DuplicateEntryError",
    "EntryNotFoundError",
    "Finding",
    "ImportResult",
    "InvalidEntryError",
    "KBEntry",
    "KnowledgeBase",
    "KnowledgePackError",
    "KnowledgeStoreError",
    "Signature",
    "UnknownSignature",
    "UserKnowledgeStore",
    "compile_pattern",
    "default_kb",
    "entry_from_dict",
    "entry_from_explanation",
    "normalize_provider",
    "pack_text",
    "pattern_for",
    "signature_of",
    "unique_entry_id",
    "validate_entry",
]


@cache
def default_kb() -> KnowledgeBase:
    """The built-in knowledge base, loaded once per process."""
    return KnowledgeBase.builtin()
