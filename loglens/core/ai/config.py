"""AI assistant settings (persisted in settings.json; secrets live in the OS credential store, never here)."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit


class Provider(StrEnum):
    API_KEY = "api_key"  # Anthropic API key stored in Windows Credential Manager
    ENVIRONMENT = "environment"  # ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / `ant auth login` profile
    BEDROCK = "bedrock"  # Claude on Amazon Bedrock (AWS credentials from the environment)
    VERTEX = "vertex"  # Claude on Google Vertex AI (gcloud application-default credentials)
    FOUNDRY = "foundry"  # Claude on Microsoft Foundry (resource name + API key)
    LOCAL = "local"  # a model server on this computer (Ollama, LM Studio, llama.cpp, …) — nothing leaves the machine


PROVIDER_LABELS: dict[Provider, str] = {
    Provider.API_KEY: "Anthropic API key (stored in Windows Credential Manager)",
    Provider.ENVIRONMENT: "Environment / Anthropic CLI profile (ANTHROPIC_API_KEY or `ant auth login`)",
    Provider.BEDROCK: "Amazon Bedrock (AWS credentials)",
    Provider.VERTEX: "Google Vertex AI (gcloud credentials)",
    Provider.FOUNDRY: "Microsoft Foundry (resource + API key)",
    Provider.LOCAL: "Local model on this computer (Ollama, LM Studio, llama.cpp…)",
}
LOCAL_API_OLLAMA = "ollama"
LOCAL_API_OPENAI = "openai"  # OpenAI-compatible chat API (LM Studio, llama.cpp llama-server, LocalAI, vLLM)
LOCAL_APIS = {LOCAL_API_OLLAMA: "Ollama", LOCAL_API_OPENAI: "OpenAI-compatible (LM Studio, llama.cpp, …)"}
DEFAULT_LOCAL_URLS = {LOCAL_API_OLLAMA: "http://localhost:11434", LOCAL_API_OPENAI: "http://localhost:1234"}
PROVIDERS_NEEDING_KEY = {Provider.API_KEY, Provider.FOUNDRY}

DEFAULT_MODEL = "claude-opus-5-5"
SUGGESTED_MODELS = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5")
EFFORTS = ("low", "medium", "high")


class Redact(StrEnum):
    """Categories of values replaced by placeholders before anything is sent."""

    SECRETS = "secrets"  # passwords, API keys, tokens, JWTs, credentials in URLs — always on (see redaction_set)
    EMAILS = "emails"
    IP_ADDRESSES = "ip_addresses"
    # User names: C:\\Users\\<name>, \\\\server\\c$\\Users\\<name>, /home/<name>, DOMAIN\\<name>, user '<name>'
    USER_PATHS = "user_paths"
    HOSTNAMES = "hostnames"  # fully-qualified domain names
    GUIDS = "guids"


DEFAULT_REDACTIONS = (Redact.SECRETS, Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS)
ALWAYS_REDACTED = frozenset({Redact.SECRETS})  # can't be switched off: the UI promises secrets never leave


def is_loopback_url(url: str) -> bool:
    """Whether ``url`` is an http(s) address on this computer: ``localhost``, 127.0.0.0/8 or ``::1``."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "https"} or not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:  # a host name: only "localhost" is known to stay on this computer
        return False


@dataclass
class AIConfig:
    enabled: bool = False
    provider: Provider = Provider.API_KEY
    model: str = DEFAULT_MODEL
    effort: str = "medium"
    context_before: int = 30
    context_after: int = 10
    preview_before_send: bool = True
    compatibility_mode: bool = False  # older request format, for AI gateways/proxies that need it
    redactions: list[str] = field(default_factory=lambda: [r.value for r in DEFAULT_REDACTIONS])
    aws_region: str = "us-east-1"
    gcp_project: str = ""
    gcp_region: str = "global"
    foundry_resource: str = ""
    local_api: str = LOCAL_API_OLLAMA
    local_url: str = DEFAULT_LOCAL_URLS[LOCAL_API_OLLAMA]
    local_model: str = ""
    # Explicit opt-in to send log excerpts to a "local" model server that is NOT on this computer (another host on the
    # network). Off by default: the local provider then only talks to localhost / 127.0.0.0/8 / ::1.
    local_allow_remote: bool = False

    @property
    def is_local(self) -> bool:
        return self.provider is Provider.LOCAL

    @property
    def local_url_is_loopback(self) -> bool:
        """Whether the local model server address is on this computer."""
        return is_loopback_url(self.local_url)

    @property
    def model_label(self) -> str:
        """The model requests go to, as shown to the user."""
        if not self.is_local:
            return self.model
        where = "on this computer" if self.local_url_is_loopback else f"at {self.local_url}"
        return f"{self.local_model or 'a local model'} ({where})"

    @property
    def needs_api_key(self) -> bool:
        return self.provider in PROVIDERS_NEEDING_KEY

    def redaction_set(self) -> set[Redact]:
        """The enabled categories; secrets are always included, whatever the stored list says."""
        valid = {r.value for r in Redact}
        return {Redact(r) for r in self.redactions if r in valid} | ALWAYS_REDACTED

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["provider"] = self.provider.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AIConfig:
        if not data:
            return cls()
        known = {f.name for f in fields(cls)}
        values = {k: v for k, v in data.items() if k in known}
        try:
            values["provider"] = Provider(values.get("provider", Provider.API_KEY))
        except ValueError:
            values["provider"] = Provider.API_KEY
        if values.get("effort") not in EFFORTS:
            values["effort"] = "medium"
        if values.get("local_api") not in LOCAL_APIS:
            values["local_api"] = LOCAL_API_OLLAMA
        redactions = values.get("redactions")
        if not isinstance(redactions, list):  # missing or corrupted: fall back to the safe defaults
            redactions = [r.value for r in DEFAULT_REDACTIONS]
        values["redactions"] = [r for r in redactions if isinstance(r, str)]  # unknown names are ignored later
        values["local_allow_remote"] = values.get("local_allow_remote") is True  # only an explicit true opts in
        return cls(**values)
