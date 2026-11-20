"""What state an AI provider is in, as shown next to "Test connection" — and the one place secrets are scrubbed.

``ProviderStatus`` is the outcome of validation or of a real request. ``scrub`` removes API keys, tokens and private
keys from any text that is about to be shown or logged: SDK and HTTP errors sometimes echo request details.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from ..secrets import mask


class ProviderStatus(StrEnum):
    NOT_CONFIGURED = "not_configured"  # nothing entered yet (no key / project / model …)
    INCOMPLETE = "incomplete"  # some required fields are missing or malformed
    NOT_TESTED = "not_tested"  # complete, but never verified with the current settings
    CONNECTED = "connected"  # a real request succeeded
    AUTH_FAILED = "auth_failed"  # credentials rejected
    PERMISSION_DENIED = "permission_denied"  # authenticated, but not allowed to use the model / API
    MODEL_UNAVAILABLE = "model_unavailable"  # the configured model does not exist / is not installed
    PROVIDER_UNAVAILABLE = "provider_unavailable"  # cannot be reached, or the service is down / overloaded
    TIMED_OUT = "timed_out"
    QUOTA_EXCEEDED = "quota_exceeded"
    ERROR = "error"  # anything else; the message says what


STATUS_LABELS: dict[ProviderStatus, str] = {
    ProviderStatus.NOT_CONFIGURED: "Not configured",
    ProviderStatus.INCOMPLETE: "Configuration incomplete",
    ProviderStatus.NOT_TESTED: "Not tested",
    ProviderStatus.CONNECTED: "Connected",
    ProviderStatus.AUTH_FAILED: "Authentication failed",
    ProviderStatus.PERMISSION_DENIED: "Permission denied",
    ProviderStatus.MODEL_UNAVAILABLE: "Model unavailable",
    ProviderStatus.PROVIDER_UNAVAILABLE: "Provider unavailable",
    ProviderStatus.TIMED_OUT: "Request timed out",
    ProviderStatus.QUOTA_EXCEEDED: "Quota exceeded",
    ProviderStatus.ERROR: "Request failed",
}


@dataclass(frozen=True, slots=True)
class TestResult:
    """Outcome of validating / testing a provider with the settings as they are now."""

    __test__ = False  # not a pytest test class, whatever its name suggests

    status: ProviderStatus
    message: str
    model: str = ""  # the model that answered (only when connected)
    compatibility_needed: bool = False

    @property
    def ok(self) -> bool:
        return self.status is ProviderStatus.CONNECTED

    @property
    def label(self) -> str:
        return STATUS_LABELS[self.status]


_SECRET_SHAPES = re.compile(
    r"sk-ant-[A-Za-z0-9_-]{8,}"  # Anthropic keys
    r"|sk-[A-Za-z0-9_-]{20,}"  # OpenAI-style keys
    r"|AIza[0-9A-Za-z_-]{30,}"  # Google API keys
    r"|ya29\.[0-9A-Za-z_.-]{20,}"  # Google OAuth access tokens
    r"|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{16,}"  # Authorization headers
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"  # service-account / PEM keys
    r'|"private_key(?:_id)?"\s*:\s*"[^"]*"'  # service-account JSON
)


def scrub(text: str) -> str:
    """``text`` with API keys, tokens and private keys replaced by ``[hidden]`` (safe to show, log or copy)."""
    return mask(_SECRET_SHAPES.sub("[hidden]", text), replacement="[hidden]")
