"""Claude provider (official ``anthropic`` SDK, imported lazily — the app works without it installed).

Request shape (Claude API docs): structured JSON output via ``output_config.format``, effort via
``output_config.effort`` (thinking is adaptive by default on current models, so no ``thinking`` parameter), a cached
static system prompt, and — where the platform supports it — server-side refusal fallbacks
(``fallbacks="default"`` with the ``server-side-fallback-2026-07-01`` beta).
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from .config import AIConfig, Provider
from .explain import EXPLANATION_SCHEMA, SYSTEM_PROMPT, ExplainRequest, Explanation
from .status import ProviderStatus, scrub
from .validation import credential_problem, preflight

API_KEY_SECRET = "anthropic-api-key"
FOUNDRY_KEY_SECRET = "foundry-api-key"
# Everything LogLens ever stores in the Windows Credential Manager (name -> what it is, for the user).
# Cloud identities (Google Vertex, AWS Bedrock) are NOT stored by LogLens: they stay with gcloud / AWS.
SECRET_LABELS = {API_KEY_SECRET: "Anthropic API key", FOUNDRY_KEY_SECRET: "Microsoft Foundry API key"}
MAX_TOKENS = 16_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Server-side fallbacks exist on the Claude API (direct / env profile) for these models; not on Bedrock, Vertex or
# Foundry, and never for Haiku (a fallback list there is an error).
FALLBACK_PROVIDERS = {Provider.API_KEY, Provider.ENVIRONMENT}
FALLBACK_MODEL_PREFIXES = ("claude-opus-5", "claude-sonnet-5-5", "claude-fable-5")


class AIError(Exception):
    """A user-presentable failure (bad key, network, refusal, …). The message never contains secrets (scrubbed here,
    once, for every raise) and ``status`` says which kind of failure it is."""

    def __init__(self, message: str, status: ProviderStatus = ProviderStatus.ERROR) -> None:
        super().__init__(scrub(message))
        self.status = status


def supports_fallbacks(config: AIConfig) -> bool:
    return config.provider in FALLBACK_PROVIDERS and config.model.startswith(FALLBACK_MODEL_PREFIXES)


def model_id(config: AIConfig) -> str:
    if config.provider is Provider.BEDROCK and not config.model.startswith("anthropic."):
        return f"anthropic.{config.model}"
    return config.model


# Cloud platforms need optional SDK extras: module that must be importable -> pip extra to install.
PROVIDER_EXTRAS: dict[Provider, tuple[str, str]] = {
    Provider.BEDROCK: ("boto3", "bedrock"),
    Provider.VERTEX: ("google.auth", "vertex"),
}


def missing_dependency(provider: Provider) -> str | None:
    """Install hint if the provider's optional packages are missing, else None."""
    if provider is Provider.LOCAL:
        return None  # plain HTTP to a server on this computer
    if importlib.util.find_spec("anthropic") is None:
        return 'The AI assistant needs the Anthropic SDK: pip install "anthropic>=2.8"'
    required = PROVIDER_EXTRAS.get(provider)
    if required is None:
        return None
    module, extra = required
    try:
        found = importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:  # parent package (e.g. "google") missing
        found = False
    return None if found else f'This provider needs extra packages: pip install "anthropic[{extra}]"'


def make_client(config: AIConfig, api_key: str | None) -> Any:
    """SDK client for the configured platform (uses the platform's own credential resolution)."""
    hint = missing_dependency(config.provider)
    if hint:
        raise AIError(hint, ProviderStatus.INCOMPLETE)
    problem = preflight(config, api_key) or credential_problem(config)
    if problem is not None:
        raise AIError(problem.message, problem.status)
    import anthropic  # noqa: PLC0415 - optional dependency, loaded on first use

    try:
        match config.provider:
            case Provider.API_KEY:
                return anthropic.Anthropic(api_key=api_key)
            case Provider.ENVIRONMENT:
                return anthropic.Anthropic()  # ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile
            case Provider.BEDROCK:
                return anthropic.AnthropicBedrockMantle(aws_region=config.aws_region)
            case Provider.VERTEX:
                if not config.gcp_project:
                    raise AIError("Enter the Google Cloud project ID in AI settings.")
                return anthropic.AnthropicVertex(project_id=config.gcp_project, region=config.gcp_region or "global")
            case Provider.FOUNDRY:
                if not config.foundry_resource:
                    raise AIError("Enter the Microsoft Foundry resource name in AI settings.")
                return anthropic.AnthropicFoundry(api_key=api_key, resource=config.foundry_resource)
    except AIError:
        raise
    except Exception as exc:  # SDK/platform credential setup errors: show them as they are, not as "unexpected"
        raise AIError(f"Could not set up the {config.provider.value} client: {exc}") from exc
    raise AIError(f"Unknown provider {config.provider}")


# Older request format for AI gateways/proxies that only translate the classic Vertex/Claude API version
# (the SDK sends API version 2026-10-21 by default; some corporate gateways reject it).
LEGACY_HEADER_VERSION = "2023-06-01"
LEGACY_VERTEX_BODY_VERSION = "vertex-2023-10-16"


class _VersionRejectedError(Exception):
    """The endpoint (typically a gateway) rejected the request's API-version format."""


def _version_overrides(config: AIConfig, compatibility: bool) -> dict[str, Any]:
    if not compatibility:
        return {}
    headers = {"extra_headers": {"anthropic-version": LEGACY_HEADER_VERSION}}
    if config.provider is Provider.VERTEX:
        # Vertex carries the version in the body (the SDK only sets it if absent); gateways that forward Vertex-style
        # requests to the Claude API also need the classic header — send both, as Claude Code does.
        return headers | {"extra_body": {"anthropic_version": LEGACY_VERTEX_BODY_VERSION}}
    return headers


def _create(client: Any, config: AIConfig, compatibility: bool, **kwargs: Any) -> Any:
    kwargs |= _version_overrides(config, compatibility)
    if supports_fallbacks(config):
        return client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
    return client.messages.create(**kwargs)


_QUOTA_WORDS = ("quota", "resource_exhausted", "credit balance", "billing", "usage limit", "spend limit")
_VERTEX_API_OFF = ("service_disabled", "has not been used in project", "is disabled", "api has not been enabled")


def _quota_like(text: str) -> bool:
    low = text.lower()
    return any(word in low for word in _QUOTA_WORDS)


def _auth_failed(config: AIConfig | None) -> AIError:
    match config.provider if config is not None else None:
        case Provider.VERTEX:
            text = (
                "Authentication failed: Google Cloud rejected the credentials. "
                "Run: gcloud auth application-default login"
            )
        case Provider.BEDROCK:
            text = "Authentication failed: AWS rejected the credentials (expired token, wrong profile or region)."
        case Provider.FOUNDRY:
            text = f"Authentication failed: the Foundry API key was rejected for resource {config.foundry_resource}."  # type: ignore[union-attr]
        case _:
            text = "Authentication failed: the API key was rejected. Check that it is correct, active and complete."
    return AIError(text, ProviderStatus.AUTH_FAILED)


def _permission_denied(config: AIConfig | None, detail: str) -> AIError:
    low = detail.lower()
    model = config.model if config is not None else "this model"
    match config.provider if config is not None else None:
        case Provider.VERTEX if any(word in low for word in _VERTEX_API_OFF):
            text = (
                f"Permission denied: the Vertex AI API is not enabled for project {config.gcp_project}. "  # type: ignore[union-attr]
                "Enable aiplatform.googleapis.com in the Google Cloud console, then try again."
            )
        case Provider.VERTEX:
            text = (
                "Authorization failed: the configured Google Cloud identity does not have permission to access this "
                f"Vertex AI model in project {config.gcp_project}. Give it the 'Vertex AI User' role "  # type: ignore[union-attr]
                "(roles/aiplatform.user) and make sure the Claude model is enabled for the project in Model Garden."
            )
        case Provider.BEDROCK:
            text = (
                f"Authorization failed: the AWS identity may not invoke {model}. Enable model access for it in the "
                "Bedrock console and allow bedrock:InvokeModel for this identity."
            )
        case _:
            text = f"Authorization failed: these credentials are not allowed to use {model}."
    return AIError(text, ProviderStatus.PERMISSION_DENIED)


def _model_unavailable(config: AIConfig | None) -> AIError:
    model = config.model if config is not None else "the model"
    where = ""
    if config is not None and config.provider is Provider.VERTEX:
        where = f" in region {config.gcp_region or 'global'} (not every model is offered in every region)"
    elif config is not None and config.provider is Provider.BEDROCK:
        where = f" in region {config.aws_region}"
    return AIError(
        f"Model unavailable: '{model}' was not found for this provider{where}. Check the model name.",
        ProviderStatus.MODEL_UNAVAILABLE,
    )


def _call(action: Callable[[], Any], config: AIConfig | None = None) -> Any:
    """Run an SDK call, translating SDK errors into short, actionable messages (most specific first)."""
    import anthropic  # noqa: PLC0415

    try:
        return action()
    except anthropic.AuthenticationError as exc:
        raise _auth_failed(config) from exc
    except anthropic.PermissionDeniedError as exc:
        raise _permission_denied(config, str(exc)) from exc
    except anthropic.NotFoundError as exc:
        raise _model_unavailable(config) from exc
    except anthropic.RateLimitError as exc:
        if _quota_like(str(exc)):
            raise AIError(
                "API quota exceeded: the provider rejected the request because the configured quota was exhausted. "
                "Check the plan, billing and quota of this account / project.",
                ProviderStatus.QUOTA_EXCEEDED,
            ) from exc
        retry = exc.response.headers.get("retry-after", "a few")
        raise AIError(f"Rate limited: try again in {retry} seconds.", ProviderStatus.QUOTA_EXCEEDED) from exc
    except anthropic.BadRequestError as exc:
        message = str(exc.message)
        if "anthropic-version" in message or "anthropic_version" in message:
            raise _VersionRejectedError(message) from exc
        if _quota_like(message):
            raise AIError(f"API quota exceeded: {message}", ProviderStatus.QUOTA_EXCEEDED) from exc
        if "model" in message.lower() and any(
            w in message.lower() for w in ("not found", "invalid", "unknown", "not supported")
        ):
            raise _model_unavailable(config) from exc
        raise AIError(f"Request rejected: {message}") from exc
    except anthropic.APITimeoutError as exc:  # before APIConnectionError: it is a subclass
        raise AIError(
            "Request timed out: the provider did not answer in time. Try again, or use fewer context lines.",
            ProviderStatus.TIMED_OUT,
        ) from exc
    except anthropic.APIStatusError as exc:
        if exc.status_code >= 500:
            raise AIError(
                f"Provider unavailable (HTTP {exc.status_code}): the service is down or overloaded. Try again later.",
                ProviderStatus.PROVIDER_UNAVAILABLE,
            ) from exc
        raise AIError(f"Request failed (HTTP {exc.status_code}): {exc.message}") from exc
    except anthropic.APIConnectionError as exc:
        raise AIError(
            "Provider unavailable: cannot reach the service. Check the internet connection, VPN / proxy settings and "
            "the endpoint.",
            ProviderStatus.PROVIDER_UNAVAILABLE,
        ) from exc


def _text(response: Any) -> str:
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        raise AIError(f"The model declined this request{f' ({category})' if category else ''}.")
    if response.stop_reason == "max_tokens":
        raise AIError("The answer was cut off (too long). Try fewer context lines.")
    for block in response.content:
        if getattr(block, "type", "") == "text":
            return str(block.text)
    raise AIError("The model returned no text.")


class ClaudeProvider:
    """Explains log lines with Claude. ``client`` can be injected (tests); otherwise built from the config."""

    def __init__(self, config: AIConfig, api_key: str | None = None, client: Any = None) -> None:
        self.config = config
        self.compatibility_used = config.compatibility_mode
        self._client = client if client is not None else make_client(config, api_key)

    def _request(self, **kwargs: Any) -> Any:
        """Send; if the endpoint rejects the API-version format, retry once in compatibility mode."""
        try:
            return _call(lambda: _create(self._client, self.config, self.compatibility_used, **kwargs), self.config)
        except _VersionRejectedError as exc:
            if self.compatibility_used:
                raise AIError(f"Request rejected: {exc}") from exc
        self.compatibility_used = True
        try:
            return _call(lambda: _create(self._client, self.config, True, **kwargs), self.config)
        except _VersionRejectedError as exc:
            raise AIError(f"Request rejected (also in compatibility mode): {exc}") from exc

    def explain(
        self, request: ExplainRequest, progress: Callable[[str], None] | None = None, cancel: object = None
    ) -> Explanation:
        """``progress`` gets phase messages; the request itself can't be interrupted (``cancel`` is unused)."""
        if progress is not None:
            progress(f"Sent to {model_id(self.config)} — waiting for the answer…")
        response = self._request(
            model=model_id(self.config),
            max_tokens=MAX_TOKENS,
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": request.user_text}],
            output_config={
                "effort": self.config.effort,
                "format": {"type": "json_schema", "schema": EXPLANATION_SCHEMA},
            },
        )
        valid = range(request.first_line + 1, request.last_line + 2)  # 1-based numbers shown to the model
        try:
            explanation = Explanation.from_json(_text(response), valid)
        except ValueError as exc:
            raise AIError("The model's answer could not be read.") from exc
        served_by = str(getattr(response, "model", "") or self.config.model)
        notes = [f"Answered by fallback model {served_by}."] if served_by != model_id(self.config) else []
        if self.compatibility_used and not self.config.compatibility_mode:
            notes.append("Your AI gateway needed compatibility mode — LogLens turned it on.")
        usage = getattr(response, "usage", None)
        return replace(
            explanation,
            model=served_by,
            notes=tuple(notes),
            compatibility_used=self.compatibility_used,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )

    def test_connection(self) -> str:
        """Tiny request to verify credentials and model; returns the model that answered."""
        response = self._request(
            model=model_id(self.config),
            max_tokens=64,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
            output_config={"effort": "low"},
        )
        _text(response)
        return str(getattr(response, "model", "") or self.config.model)
