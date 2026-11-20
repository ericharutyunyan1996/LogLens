"""Provider-specific validation that needs no network: is everything required filled in, and does it look right?

``preflight`` runs before any request ("Test connection" and every explain), so a missing project id, a malformed
region or an absent key is reported as such instead of surfacing as an SDK stack trace. ``credential_problem`` adds the
checks that look at the machine's credentials (still without contacting the provider).
"""

from __future__ import annotations

import re

from .config import AIConfig, Provider
from .status import ProviderStatus, TestResult

GCP_PROJECT = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$"
)  # 6–30 chars: letters, digits, hyphens; starts with a letter
GCP_REGION = re.compile(r"^(?:global|[a-z]+-[a-z]+\d+|us|eu|asia)$")
AWS_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
AZURE_RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{1,62}$")  # a DNS label: it becomes <name>.services.ai.azure.com
ANTHROPIC_KEY_PREFIX = "sk-ant-"


def _incomplete(message: str) -> TestResult:
    return TestResult(ProviderStatus.INCOMPLETE, message)


def preflight(config: AIConfig, api_key: str | None) -> TestResult | None:  # noqa: PLR0911 - one return per provider
    """The first problem with the settings themselves, or None when they are complete and plausible."""
    match config.provider:
        case Provider.API_KEY:
            return _check_api_key(config, api_key)
        case Provider.ENVIRONMENT:
            return None  # credentials come from the environment / an `ant` profile: only a real request tells
        case Provider.BEDROCK:
            return _check_bedrock(config)
        case Provider.VERTEX:
            return _check_vertex(config)
        case Provider.FOUNDRY:
            return _check_foundry(config, api_key)
        case Provider.LOCAL:
            return _check_local(config)
    return None  # pragma: no cover


def _check_model(config: AIConfig) -> TestResult | None:
    if not config.model.strip():
        return _incomplete("Choose a model in AI settings.")
    if re.search(r"\s", config.model.strip()):
        return _incomplete(f"The model name {config.model!r} contains spaces: copy the exact model id.")
    return None


def _check_api_key(config: AIConfig, api_key: str | None) -> TestResult | None:
    if not (api_key or "").strip():
        return TestResult(ProviderStatus.NOT_CONFIGURED, "No API key yet: paste your key and click Save key.")
    return _check_model(config)


def key_warning(config: AIConfig, api_key: str | None) -> str:
    """A hint (not an error) when a direct Anthropic key does not look like one: gateways use their own tokens."""
    key = (api_key or "").strip()
    if config.provider is Provider.API_KEY and key and not key.startswith(ANTHROPIC_KEY_PREFIX):
        return f" The key does not start with {ANTHROPIC_KEY_PREFIX} (fine for a company gateway; otherwise check it)."
    return ""


def _check_bedrock(config: AIConfig) -> TestResult | None:
    if not AWS_REGION.match(config.aws_region.strip()):
        return _incomplete(f"The AWS region {config.aws_region!r} is not valid: use a region such as us-east-1.")
    return _check_model(config)


def _check_vertex(config: AIConfig) -> TestResult | None:
    project = config.gcp_project.strip()
    if not project:
        return TestResult(ProviderStatus.NOT_CONFIGURED, "Enter the Google Cloud project ID.")
    if not GCP_PROJECT.match(project):
        return _incomplete(
            f"The project ID {project!r} is not valid: 6–30 lowercase letters, digits or hyphens, starting with "
            "a letter "
            "(use the project ID, not the project name or number)."
        )
    region = (config.gcp_region or "global").strip()
    if not GCP_REGION.match(region):
        return _incomplete(f"The Vertex AI region {region!r} is not valid: use global, us-east5, europe-west1, …")
    return _check_model(config)


def _check_foundry(config: AIConfig, api_key: str | None) -> TestResult | None:
    resource = config.foundry_resource.strip()
    if not resource:
        return TestResult(ProviderStatus.NOT_CONFIGURED, "Enter the Microsoft Foundry resource name.")
    if not AZURE_RESOURCE.match(resource):
        return _incomplete(f"The resource name {resource!r} is not valid: letters, digits and hyphens only.")
    if not (api_key or "").strip():
        return _incomplete("No Foundry API key yet: paste your key and click Save key.")
    return _check_model(config)


def _check_local(config: AIConfig) -> TestResult | None:
    if not config.local_model.strip():
        return TestResult(
            ProviderStatus.NOT_CONFIGURED, "Choose a local model (click Refresh to list the installed ones)."
        )
    if not config.local_url.strip().lower().startswith(("http://", "https://")):
        return _incomplete(f"The model server address must start with http:// or https:// (got {config.local_url!r}).")
    return None


def credential_problem(config: AIConfig) -> TestResult | None:
    """Platform credentials missing on this machine (looked up locally, nothing is sent). None when found / unknown."""
    if config.provider is Provider.VERTEX:
        return _vertex_credentials()
    if config.provider is Provider.BEDROCK:
        return _bedrock_credentials()
    return None


def _vertex_credentials() -> TestResult | None:
    try:
        import google.auth  # noqa: PLC0415 - optional dependency
        from google.auth.exceptions import DefaultCredentialsError  # noqa: PLC0415
    except ImportError:
        return None  # missing_dependency() already tells how to install it
    try:
        google.auth.default()
    except DefaultCredentialsError:
        return TestResult(
            ProviderStatus.NOT_CONFIGURED,
            "No Google Cloud credentials found on this computer. Run: gcloud auth application-default login "
            "(or set GOOGLE_APPLICATION_CREDENTIALS to a service-account file).",
        )
    except Exception:  # noqa: BLE001 - e.g. a metadata-server timeout: the real request will explain it better
        return None
    return None


def _bedrock_credentials() -> TestResult | None:
    try:
        import boto3  # type: ignore[import-untyped]  # noqa: PLC0415 - optional dependency
    except ImportError:
        return None
    if boto3.Session().get_credentials() is None:
        return TestResult(
            ProviderStatus.NOT_CONFIGURED,
            "No AWS credentials found on this computer (environment variables, ~/.aws/credentials or an SSO profile).",
        )
    return None
