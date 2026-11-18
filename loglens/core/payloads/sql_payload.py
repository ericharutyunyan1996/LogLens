"""SQL statements: break long one-line queries into clauses."""

from __future__ import annotations

import re

from .base import Section

# A statement needs a verb *and* its companion clause, so prose like "select a file from the list" rarely matches
# (both words must be upper-case, as SQL in logs almost always is).
_STATEMENT = re.compile(
    r"\b(?:SELECT\b.+?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.+?\bSET\b|DELETE\s+FROM\b|MERGE\s+INTO\b|EXEC(?:UTE)?\s+\w)"
    r".*?(?=;|$)",
)
# Break before a clause keyword — but never between a join qualifier and JOIN ("INNER JOIN" stays together).
_CLAUSES = re.compile(
    r"(?<!\bLEFT)(?<!\bRIGHT)(?<!\bINNER)(?<!\bFULL)(?<!\bCROSS)(?<!\bOUTER)"
    r"\s+(?=\b(?:FROM|WHERE|GROUP BY|ORDER BY|HAVING|UNION(?: ALL)?|VALUES|SET|(?:LEFT |RIGHT |INNER |FULL |CROSS )?"
    r"(?:OUTER )?JOIN|ON|LIMIT|OFFSET|RETURNING|OUTPUT)\b)"
)
_LOGIC = re.compile(r"\s+(?=\b(?:AND|OR)\b)")
_QUOTED = re.compile(r"'(?:[^']|'')*'")


def format_sql(sql: str) -> str:
    """Clause-per-line layout; string literals are protected from re-formatting."""
    literals: list[str] = []

    def stash(m: re.Match[str]) -> str:
        literals.append(m.group(0))
        return f"\x00{len(literals) - 1}\x00"

    body = _QUOTED.sub(stash, sql.strip())
    body = _CLAUSES.sub("\n", body)
    body = _LOGIC.sub("\n    ", body)
    return re.sub(r"\x00(\d+)\x00", lambda m: literals[int(m.group(1))], body)


class SqlFormatter:
    kind = "SQL"

    def find(self, text: str) -> list[Section]:
        out: list[Section] = []
        for m in _STATEMENT.finditer(text):
            statement = m.group(0)
            if len(statement) < 20:
                continue
            out.append(Section(self.kind, format_sql(statement), m.start(), m.end()))
        return out
