"""Shared types for payload formatters.

A *payload* is a machine-readable fragment embedded in a log line or record — JSON, XML, a URL query string,
a JWT, key=value pairs, SQL, … Each formatter finds its payloads in a text and returns :class:`Section` objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Section:
    """A formatted view of one payload.

    ``start``/``end`` locate the payload in the analysed text. Derived sections (e.g. a JSON document found inside a
    JSON string value) are not located in the text and use ``start == end == -1``.
    """

    kind: str
    body: str
    start: int = -1
    end: int = -1

    @property
    def located(self) -> bool:
        return self.start >= 0

    def overlaps(self, other: Section) -> bool:
        return self.located and other.located and self.start < other.end and other.start < self.end


class PayloadFormatter(Protocol):
    """Finds and formats one kind of payload."""

    kind: str

    def find(self, text: str) -> list[Section]:
        """All payloads of this kind in ``text``, located sections first, derived sections after."""
        ...
