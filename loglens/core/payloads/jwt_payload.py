"""JSON Web Tokens: decode header and claims for debugging (the signature is NOT verified)."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime

from .base import Section
from .json_payload import dumps

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_TIME_CLAIMS = ("exp", "iat", "nbf", "auth_time")


def _b64url_json(part: str) -> dict | None:
    try:
        value = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (binascii.Error, ValueError):
        return None
    return value if isinstance(value, dict) else None


class JwtFormatter:
    kind = "JWT"

    def find(self, text: str) -> list[Section]:
        out: list[Section] = []
        for m in _JWT.finditer(text):
            header_part, claims_part, _signature = m.group(0).split(".")
            header, claims = _b64url_json(header_part), _b64url_json(claims_part)
            if header is None or claims is None:
                continue
            lines = ["header:", dumps(header), "", "claims:", dumps(claims)]
            times = [
                f"  {k} = {datetime.fromtimestamp(claims[k], UTC).isoformat()}"
                for k in _TIME_CLAIMS
                if isinstance(claims.get(k), (int, float))
            ]
            if times:
                lines += ["", "times (UTC):", *times]
            lines += ["", "signature not verified — decoded for reading only"]
            out.append(Section(self.kind, "\n".join(lines), m.start(), m.end()))
        return out
