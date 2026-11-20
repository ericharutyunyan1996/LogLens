"""AI providers: validation, status mapping, actionable errors, provider switching, secret scrubbing.

Everything here is MOCKED (fake SDK clients / servers) except ``test_real_ollama_*`` at the bottom, which talks to a
real local Ollama and is skipped when none is running. No real credentials are used or needed.
"""

from __future__ import annotations

import json
import urllib.request
from types import SimpleNamespace
from typing import Any

import anthropic
import pytest

try:  # the SDK's HTTP client is httpx, or httpx2 in newer releases
    import httpx2 as httpx
except ImportError:  # pragma: no cover
    import httpx  # type: ignore[no-redef]

from loglens.core.ai import claude
from loglens.core.ai.claude import AIError, ClaudeProvider, make_client
from loglens.core.ai.config import LOCAL_API_OLLAMA, AIConfig, Provider
from loglens.core.ai.explain import ExplainRequest
from loglens.core.ai.local import LocalProvider
from loglens.core.ai.providers import make_provider
from loglens.core.ai.status import ProviderStatus, scrub
from loglens.core.ai.validation import key_warning, preflight

REQUEST = ExplainRequest("app.log", (2,), "L3|>> login failed", {}, 0, 4)
URL = httpx.Request("POST", "https://api.example.test/v1/messages")


def api_error(cls: type[anthropic.APIStatusError], status: int, text: str, headers: dict[str, str] | None = None):
    response = httpx.Response(status, request=URL, headers=headers or {}, json={"error": {"message": text}})
    return cls(text, response=response, body={"error": {"message": text}})


def failing_client(error: Exception) -> Any:
    def create(**_kwargs: Any) -> Any:
        raise error

    return SimpleNamespace(
        messages=SimpleNamespace(create=create), beta=SimpleNamespace(messages=SimpleNamespace(create=create))
    )


def ok_client(model: str = "m") -> Any:
    reply = SimpleNamespace(
        stop_reason="end_turn", content=[SimpleNamespace(type="text", text="OK")], model=model, usage=None
    )
    return SimpleNamespace(
        messages=SimpleNamespace(create=lambda **_k: reply),
        beta=SimpleNamespace(messages=SimpleNamespace(create=lambda **_k: reply)),
    )


VERTEX = AIConfig(
    provider=Provider.VERTEX, model="claude-opus-5-5", gcp_project="my-project-123", gcp_region="us-east5"
)
DIRECT = AIConfig(provider=Provider.API_KEY, model="claude-opus-5-5")
BEDROCK = AIConfig(provider=Provider.BEDROCK, model="claude-opus-5-5", aws_region="us-east-1")
FOUNDRY = AIConfig(provider=Provider.FOUNDRY, model="claude-opus-5-5", foundry_resource="my-resource")


def connection_error(config: AIConfig, error: Exception) -> AIError:
    with pytest.raises(AIError) as raised:
        ClaudeProvider(config, "sk-ant-api03-" + "x" * 30, client=failing_client(error)).test_connection()
    return raised.value


# ---- errors → status + actionable message -------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("config", "error", "status", "needles"),
    [
        (
            DIRECT,
            api_error(anthropic.AuthenticationError, 401, "invalid x-api-key"),
            ProviderStatus.AUTH_FAILED,
            ["API key was rejected"],
        ),
        (
            VERTEX,
            api_error(anthropic.AuthenticationError, 401, "bad token"),
            ProviderStatus.AUTH_FAILED,
            ["gcloud auth application-default login"],
        ),
        (
            BEDROCK,
            api_error(anthropic.AuthenticationError, 403, "expired"),
            ProviderStatus.AUTH_FAILED,
            ["AWS rejected"],
        ),
        (FOUNDRY, api_error(anthropic.AuthenticationError, 401, "no"), ProviderStatus.AUTH_FAILED, ["my-resource"]),
        (
            VERTEX,
            api_error(
                anthropic.PermissionDeniedError, 403, "Permission 'aiplatform.endpoints.predict' denied on resource"
            ),
            ProviderStatus.PERMISSION_DENIED,
            ["does not have permission", "my-project-123", "roles/aiplatform.user", "Model Garden"],
        ),
        (
            VERTEX,
            api_error(
                anthropic.PermissionDeniedError, 403, "SERVICE_DISABLED: Vertex AI API has not been used in project"
            ),
            ProviderStatus.PERMISSION_DENIED,
            ["not enabled", "aiplatform.googleapis.com"],
        ),
        (
            BEDROCK,
            api_error(anthropic.PermissionDeniedError, 403, "AccessDenied"),
            ProviderStatus.PERMISSION_DENIED,
            ["bedrock:InvokeModel"],
        ),
        (
            DIRECT,
            api_error(anthropic.PermissionDeniedError, 403, "no"),
            ProviderStatus.PERMISSION_DENIED,
            ["not allowed to use claude-opus-5-5"],
        ),
        (
            VERTEX,
            api_error(anthropic.NotFoundError, 404, "model not found"),
            ProviderStatus.MODEL_UNAVAILABLE,
            ["claude-opus-5-5", "us-east5"],
        ),
        (
            DIRECT,
            api_error(anthropic.RateLimitError, 429, "RESOURCE_EXHAUSTED: quota exceeded for this project"),
            ProviderStatus.QUOTA_EXCEEDED,
            ["API quota exceeded", "quota was exhausted"],
        ),
        (
            DIRECT,
            api_error(anthropic.RateLimitError, 429, "slow down", {"retry-after": "7"}),
            ProviderStatus.QUOTA_EXCEEDED,
            ["Rate limited", "7 seconds"],
        ),
        (
            DIRECT,
            api_error(anthropic.BadRequestError, 400, "Your credit balance is too low"),
            ProviderStatus.QUOTA_EXCEEDED,
            ["quota exceeded"],
        ),
        (
            VERTEX,
            api_error(anthropic.BadRequestError, 400, "Unknown model name 'claude-x'"),
            ProviderStatus.MODEL_UNAVAILABLE,
            ["Model unavailable"],
        ),
        (
            DIRECT,
            api_error(anthropic.InternalServerError, 503, "overloaded"),
            ProviderStatus.PROVIDER_UNAVAILABLE,
            ["HTTP 503"],
        ),
        (DIRECT, anthropic.APITimeoutError(request=URL), ProviderStatus.TIMED_OUT, ["timed out"]),
        (
            DIRECT,
            anthropic.APIConnectionError(message="boom", request=URL),
            ProviderStatus.PROVIDER_UNAVAILABLE,
            ["cannot reach"],
        ),
    ],
)
def test_sdk_errors_become_a_status_and_an_actionable_message(config, error, status, needles) -> None:
    err = connection_error(config, error)
    assert err.status is status
    for needle in needles:
        assert needle.lower() in str(err).lower(), (needle, str(err))


def test_a_successful_request_is_connected_and_reports_the_model() -> None:
    assert (
        ClaudeProvider(DIRECT, "sk-ant-api03-" + "x" * 30, client=ok_client("claude-opus-5-5")).test_connection()
        == "claude-opus-5-5"
    )


def test_selected_model_is_the_one_requested() -> None:
    seen: dict[str, Any] = {}

    def create(**kwargs: Any) -> Any:
        seen.update(kwargs)
        return SimpleNamespace(
            stop_reason="end_turn", content=[SimpleNamespace(type="text", text="OK")], model=kwargs["model"], usage=None
        )

    client = SimpleNamespace(
        messages=SimpleNamespace(create=create), beta=SimpleNamespace(messages=SimpleNamespace(create=create))
    )
    ClaudeProvider(
        AIConfig(provider=Provider.VERTEX, model="claude-sonnet-5-5", gcp_project="my-project-123"), None, client=client
    ).test_connection()
    assert seen["model"] == "claude-sonnet-5-5"
    ClaudeProvider(BEDROCK, None, client=client).test_connection()
    assert seen["model"] == "anthropic.claude-opus-5-5"  # Bedrock's id form


# ---- secrets never reach messages ----------------------------------------------------------------------------------------
# Built from pieces on purpose: a literal that looks like a real key would trip secret scanners (and GitHub push protection)
FAKE_SECRETS = [
    "sk-" + "ant-" + "api03-" + "AbCdEfGhIjKlMnOpQrStUv" + "WxYz0123456789",
    "AI" + "za" + "SyA1234567890abcdef" + "ghijklmnopqrstuvw",
    "ya" + "29." + "a0AfH6SMBx12345678" + "90abcdefghijklmn",
    "Bear" + "er " + "eyJhbGciOiJSUzI1NiJ9" + ".abcdefghijklmnop.qrstuvwxyz012345",
    '{"private' + '_key": "-----BEGIN ' + "PRIVATE KEY-----" + "\nMIIEvQIBADANBgkq\n-----END " + 'PRIVATE KEY-----\n"}',
]


@pytest.mark.parametrize("secret", FAKE_SECRETS)
def test_secrets_are_removed_from_every_error_message(secret: str) -> None:
    assert secret not in scrub(f"request failed: {secret} was rejected")
    assert secret not in str(AIError(f"upstream said: {secret}"))
    err = connection_error(DIRECT, api_error(anthropic.BadRequestError, 400, f"bad request with {secret}"))
    assert secret not in str(err)


# ---- validation (no network) ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("config", "key", "status"),
    [
        (DIRECT, None, ProviderStatus.NOT_CONFIGURED),
        (DIRECT, "  ", ProviderStatus.NOT_CONFIGURED),
        (AIConfig(provider=Provider.API_KEY, model=""), "sk-ant-x", ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.API_KEY, model="two words"), "sk-ant-x", ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.VERTEX, gcp_project=""), None, ProviderStatus.NOT_CONFIGURED),
        (AIConfig(provider=Provider.VERTEX, gcp_project="Bad Project"), None, ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.VERTEX, gcp_project="1234567"), None, ProviderStatus.INCOMPLETE),
        (
            AIConfig(provider=Provider.VERTEX, gcp_project="my-project-123", gcp_region="mars"),
            None,
            ProviderStatus.INCOMPLETE,
        ),
        (AIConfig(provider=Provider.BEDROCK, aws_region="useast1"), None, ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.FOUNDRY, foundry_resource=""), "k", ProviderStatus.NOT_CONFIGURED),
        (AIConfig(provider=Provider.FOUNDRY, foundry_resource="bad name!"), "k", ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.FOUNDRY, foundry_resource="res"), None, ProviderStatus.INCOMPLETE),
        (AIConfig(provider=Provider.LOCAL, local_model=""), None, ProviderStatus.NOT_CONFIGURED),
        (
            AIConfig(provider=Provider.LOCAL, local_model="m", local_url="localhost:11434"),
            None,
            ProviderStatus.INCOMPLETE,
        ),
    ],
)
def test_incomplete_or_malformed_settings_are_reported_before_any_request(config, key, status) -> None:
    result = preflight(config, key)
    assert result is not None and result.status is status and result.message


@pytest.mark.parametrize(
    ("config", "key"),
    [
        (DIRECT, "sk-ant-api03-" + "x" * 20),
        (DIRECT, "company-gateway-token"),  # not an Anthropic-shaped key, but allowed (gateways)
        (VERTEX, None),
        (AIConfig(provider=Provider.VERTEX, gcp_project="my-project-123"), None),  # region defaults to global
        (BEDROCK, None),
        (FOUNDRY, "k"),
        (AIConfig(provider=Provider.LOCAL, local_model="qwen2.5:7b"), None),
        (AIConfig(provider=Provider.ENVIRONMENT, model="claude-opus-5-5"), None),
    ],
)
def test_complete_settings_pass_validation(config, key) -> None:
    assert preflight(config, key) is None


def test_a_gateway_token_gets_a_hint_not_an_error() -> None:
    assert "sk-ant-" in key_warning(DIRECT, "company-gateway-token")
    assert key_warning(DIRECT, "sk-ant-api03-abc") == ""


def test_clients_are_not_built_for_incomplete_settings() -> None:
    with pytest.raises(AIError) as raised:
        make_client(AIConfig(provider=Provider.VERTEX, gcp_project="Not A Project"), None)
    assert raised.value.status is ProviderStatus.INCOMPLETE
    with pytest.raises(AIError) as raised:
        make_client(DIRECT, None)
    assert raised.value.status is ProviderStatus.NOT_CONFIGURED


# ---- provider switching: the selected provider is the one used, nothing falls back silently -------------------------
def test_each_provider_builds_its_own_client(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[tuple[str, dict[str, Any]]] = []

    def fake(name: str):
        def factory(*_args: Any, **kwargs: Any) -> Any:
            built.append((name, kwargs))
            return SimpleNamespace(name=name)

        return factory

    for name in ("Anthropic", "AnthropicBedrockMantle", "AnthropicVertex", "AnthropicFoundry"):
        monkeypatch.setattr(anthropic, name, fake(name))
    monkeypatch.setattr(claude, "credential_problem", lambda _config: None)  # no cloud credentials on this machine
    for config, key, name in [
        (DIRECT, "sk-ant-api03-" + "x" * 20, "Anthropic"),
        (AIConfig(provider=Provider.ENVIRONMENT, model="claude-opus-5-5"), None, "Anthropic"),
        (BEDROCK, None, "AnthropicBedrockMantle"),
        (VERTEX, None, "AnthropicVertex"),
        (FOUNDRY, "k", "AnthropicFoundry"),
    ]:
        built.clear()
        assert make_client(config, key).name == name
        assert [b[0] for b in built] == [name]  # exactly that class, no other provider touched
    assert built[0][1] == {"api_key": "k", "resource": "my-resource"}
    built.clear()
    make_client(VERTEX, None)
    assert built == [("AnthropicVertex", {"project_id": "my-project-123", "region": "us-east5"})]


def test_local_provider_is_chosen_for_local_and_never_for_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    local = make_provider(AIConfig(provider=Provider.LOCAL, local_model="m"), None)
    assert isinstance(local, LocalProvider)
    monkeypatch.setattr(claude, "make_client", lambda *_a, **_k: ok_client())
    assert isinstance(make_provider(DIRECT, "sk-ant-api03-" + "x" * 20), ClaudeProvider)


def test_a_failing_provider_fails_visibly_instead_of_falling_back(qapp, wait_for) -> None:
    from loglens.services.ai_service import AIService

    asked: list[Provider] = []

    class Broken:
        compatibility_used = False

        def explain(self, *_a: Any, **_k: Any) -> Any:
            raise AIError("Permission denied: nope", ProviderStatus.PERMISSION_DENIED)

        def test_connection(self) -> str:
            raise AIError("Permission denied: nope", ProviderStatus.PERMISSION_DENIED)

    def factory(config: AIConfig, _key: str | None) -> Any:
        asked.append(config.provider)
        return Broken()

    service = AIService(factory=factory)
    failures: list[str] = []
    results: list[Any] = []
    service.failed.connect(failures.append)
    service.testResult.connect(results.append)
    service.explain(VERTEX, REQUEST)
    wait_for(lambda: failures)
    service.test_connection(VERTEX)
    wait_for(lambda: results)
    assert asked == [Provider.VERTEX, Provider.VERTEX]  # only the selected provider was ever asked
    assert "Permission denied" in failures[0]
    assert results[0].status is ProviderStatus.PERMISSION_DENIED and not results[0].ok


# ---- local provider: statuses over a real socket ------------------------------------------------------------------------------
def test_local_server_down_and_timeout_have_their_own_statuses() -> None:
    down = AIConfig(provider=Provider.LOCAL, local_model="m", local_url="http://127.0.0.1:9")
    with pytest.raises(AIError) as raised:
        LocalProvider(down).test_connection()
    assert raised.value.status is ProviderStatus.PROVIDER_UNAVAILABLE and "ollama serve" in str(raised.value)
    assert raised.value.status is not ProviderStatus.TIMED_OUT


def test_remote_local_server_needs_explicit_permission() -> None:
    config = AIConfig(provider=Provider.LOCAL, local_model="m", local_url="http://10.1.2.3:11434")
    with pytest.raises(AIError, match="not on this computer"):
        LocalProvider(config)


# ---- REAL integration: a locally running Ollama (skipped when there is none) ------------------------------------------------
def _ollama_has(model: str) -> bool:
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2) as response:
            return any(
                m["name"].startswith(model.split(":", maxsplit=1)[0]) for m in json.load(response).get("models", [])
            )
    except OSError:
        return False


MODEL = "qwen2.5:7b"
needs_ollama = pytest.mark.skipif(not _ollama_has(MODEL), reason=f"no local Ollama with {MODEL}")


@needs_ollama
def test_real_ollama_connection_test_runs_a_real_inference() -> None:
    config = AIConfig(provider=Provider.LOCAL, local_api=LOCAL_API_OLLAMA, local_model=MODEL)
    assert LocalProvider(config).test_connection() == f"{MODEL} (local)"


@needs_ollama
def test_real_ollama_explains_a_line_and_wrong_model_is_reported() -> None:
    config = AIConfig(provider=Provider.LOCAL, local_api=LOCAL_API_OLLAMA, local_model=MODEL)
    answer = LocalProvider(config).explain(REQUEST)
    assert answer.summary and answer.model == f"{MODEL} (local)"
    with pytest.raises(AIError) as raised:
        LocalProvider(AIConfig(provider=Provider.LOCAL, local_model="does-not-exist:1b")).test_connection()
    assert raised.value.status is ProviderStatus.MODEL_UNAVAILABLE and "not installed" in str(raised.value)
