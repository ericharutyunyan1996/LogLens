"""AI assistant core: redaction, request building, provider request shape and answer handling (no network)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from loglens.core.ai import claude, credentials
from loglens.core.ai.claude import AIError, ClaudeProvider, supports_fallbacks
from loglens.core.ai.config import AIConfig, Provider, Redact
from loglens.core.ai.explain import EXPLANATION_SCHEMA, Explanation, build_request
from loglens.core.ai.redaction import Redactor

ANSWER = {
    "summary": "The payment gateway timed out.",
    "severity": "error",
    "is_likely_noise": False,
    "what_happened": "A POST to the gateway took 30 s and was aborted.",
    "probable_causes": [
        {"cause": "Gateway overloaded", "likelihood": "high", "evidence_lines": [11, 12, 999]},
    ],
    "next_steps": ["Check gateway latency", "Raise the timeout"],
    "missing_information": "",
    "confidence": "medium",
}


# ---- redaction ------------------------------------------------------------------------------------------------------
def test_redaction_categories_and_consistent_placeholders() -> None:
    text = (
        "user alice@example.com from 10.1.2.3 then 10.1.2.3 again; password=hunter2 "
        "Authorization: Bearer abcdefghijklmnop123 url https://bob:s3cret@host.example.com/x "
        r"path C:\Users\erik.smith\AppData\x.log token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    )
    result = Redactor([Redact.SECRETS, Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS]).redact(text)
    out = result.text
    for secret in (
        "alice@example.com",
        "10.1.2.3",
        "hunter2",
        "abcdefghijklmnop123",
        "bob:s3cret",
        "erik.smith",
        "eyJhbGciOiJIUzI1NiJ9",
    ):
        assert secret not in out, secret
    assert out.count("<IP_1>") == 2  # same value → same placeholder
    assert "password=<SECRET_1>" in out and r"C:\Users\<USER_1>\AppData" in out
    assert result.counts["IP"] == 2 and result.total >= 7


def test_redaction_respects_disabled_categories() -> None:
    text = "host 10.0.0.1 id 6f1c2e7a-0d3b-4c1e-9a55-000000000001 mail a@b.io"
    out = Redactor([Redact.EMAILS]).redact(text).text
    assert "10.0.0.1" in out and "6f1c2e7a" in out and "<EMAIL_1>" in out


# ---- request building -----------------------------------------------------------------------------------------------
def test_build_request_numbers_marks_and_redacts() -> None:
    lines = [(9, "INFO start"), (10, "ERROR timeout calling 10.0.0.7"), (11, "INFO retry")]
    request = build_request("app.log", lines, [10], Redactor([Redact.IP_ADDRESSES]), note="happens nightly")
    assert "Log file: app.log" in request.user_text and "Note from the user: happens nightly" in request.user_text
    assert "L11|>> ERROR timeout calling <IP_1>" in request.user_text and "L10| INFO start" in request.user_text
    assert request.focus_lines == (10,) and request.redaction_counts == {"IP": 1}
    assert (request.first_line, request.last_line) == (9, 11)


def test_explanation_drops_citations_outside_excerpt() -> None:
    explanation = Explanation.from_json(json.dumps(ANSWER), valid_lines=range(10, 13))
    assert explanation.probable_causes[0].evidence_lines == (11, 12)
    assert explanation.next_steps == ("Check gateway latency", "Raise the timeout")


def test_schema_is_strict() -> None:
    assert EXPLANATION_SCHEMA["additionalProperties"] is False
    assert set(EXPLANATION_SCHEMA["required"]) == set(EXPLANATION_SCHEMA["properties"])


# ---- provider -------------------------------------------------------------------------------------------------------
@dataclass
class FakeMessages:
    response: Any
    calls: list[dict[str, Any]] = field(default_factory=list)

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.response


def fake_client(answer: dict[str, Any] | None = None, stop_reason: str = "end_turn", model: str = "claude-opus-5-5"):
    response = SimpleNamespace(
        stop_reason=stop_reason,
        stop_details=SimpleNamespace(category="cyber") if stop_reason == "refusal" else None,
        content=[SimpleNamespace(type="text", text=json.dumps(answer or ANSWER))],
        model=model,
        usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
    )
    messages, beta_messages = FakeMessages(response), FakeMessages(response)
    return SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=beta_messages))


def _request() -> Any:
    return build_request("a.log", [(10, "ERROR x"), (11, "y"), (12, "z")], [10], Redactor([]))


def test_explain_request_shape_with_fallbacks_on_claude_api() -> None:
    client = fake_client()
    config = AIConfig(enabled=True, provider=Provider.API_KEY, model="claude-opus-5-5", effort="high")
    explanation = ClaudeProvider(config, client=client).explain(_request())
    call = client.beta.messages.calls[0]
    assert call["model"] == "claude-opus-5-5" and call["fallbacks"] == "default"
    assert call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["output_config"]["effort"] == "high"
    assert call["output_config"]["format"]["schema"] is EXPLANATION_SCHEMA
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "thinking" not in call and "temperature" not in call
    assert explanation.summary.startswith("The payment") and explanation.input_tokens == 1200
    assert explanation.probable_causes[0].evidence_lines == (11, 12)  # 999 is outside the excerpt
    assert explanation.notes == ()


def test_no_fallbacks_for_haiku_or_cloud_platforms() -> None:
    assert not supports_fallbacks(AIConfig(provider=Provider.API_KEY, model="claude-haiku-5-5"))
    assert not supports_fallbacks(AIConfig(provider=Provider.BEDROCK, model="claude-opus-5-5"))
    client = fake_client()
    config = AIConfig(provider=Provider.BEDROCK, model="claude-opus-5-5")
    ClaudeProvider(config, client=client).explain(_request())
    assert client.beta.messages.calls == []
    assert client.messages.calls[0]["model"] == "anthropic.claude-opus-5-5"
    assert "fallbacks" not in client.messages.calls[0]


def test_fallback_model_is_reported() -> None:
    client = fake_client(model="claude-opus-4-8")
    result = ClaudeProvider(AIConfig(), client=client).explain(_request())
    assert result.model == "claude-opus-4-8" and "fallback" in result.notes[0]


def test_refusal_and_truncation_are_errors() -> None:
    with pytest.raises(AIError, match=r"declined.*cyber"):
        ClaudeProvider(AIConfig(), client=fake_client(stop_reason="refusal")).explain(_request())
    with pytest.raises(AIError, match="cut off"):
        ClaudeProvider(AIConfig(), client=fake_client(stop_reason="max_tokens")).explain(_request())


def test_missing_key_is_a_friendly_error() -> None:
    with pytest.raises(AIError, match="No API key"):
        claude.make_client(AIConfig(provider=Provider.API_KEY), api_key=None)


# ---- config & credentials -------------------------------------------------------------------------------------------
def test_config_roundtrip_and_bad_values() -> None:
    config = AIConfig(enabled=True, provider=Provider.VERTEX, gcp_project="p1", effort="low")
    assert AIConfig.from_dict(config.to_dict()) == config
    broken = AIConfig.from_dict({"provider": "nope", "effort": "max", "unknown": 1})
    assert broken.provider is Provider.API_KEY and broken.effort == "medium"
    assert AIConfig.from_dict(None) == AIConfig()


def test_credentials_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict[str, str] = {}

    class FakeCred:
        CRED_TYPE_GENERIC = 1
        CRED_PERSIST_LOCAL_MACHINE = 2

        @staticmethod
        def CredWrite(cred: dict[str, Any], _flags: int) -> None:  # noqa: N802 - mirrors pywin32
            store[cred["TargetName"]] = cred["CredentialBlob"]

        @staticmethod
        def CredRead(target: str, _type: int, _flags: int) -> dict[str, Any]:  # noqa: N802
            if target not in store:
                raise credentials.pywintypes.error(1168, "CredRead", "not found")
            return {"CredentialBlob": store[target].encode("utf-16-le")}

        @staticmethod
        def CredDelete(target: str, _type: int, _flags: int) -> None:  # noqa: N802
            store.pop(target, None)

    monkeypatch.setattr(credentials, "win32cred", FakeCred)
    assert credentials.load_secret("k") is None
    credentials.save_secret("k", "sk-ant-123")
    assert credentials.load_secret("k") == "sk-ant-123" and "LogLens/k" in store
    credentials.delete_secret("k")
    assert credentials.load_secret("k") is None


# ---- gateway compatibility -------------------------------------------------------------------------------------------
class GatewayMessages(FakeMessages):
    """Rejects the new API-version format like some company gateways; accepts the classic one."""

    def create(self, **kwargs: Any) -> Any:
        import anthropic
        import httpx2

        self.calls.append(kwargs)
        if (kwargs.get("extra_headers") or {}).get("anthropic-version") != "2023-06-01":
            response = httpx2.Response(400, request=httpx2.Request("POST", "https://gateway.example/v1/messages"))
            raise anthropic.BadRequestError("anthropic-version: header is required", response=response, body=None)
        return self.response


def test_gateway_needing_classic_format_is_retried_once() -> None:
    client = fake_client()
    client.messages = GatewayMessages(client.messages.response)
    config = AIConfig(provider=Provider.VERTEX, gcp_project="p")
    provider = ClaudeProvider(config, client=client)
    result = provider.explain(_request())
    assert len(client.messages.calls) == 2 and provider.compatibility_used and result.compatibility_used
    retry = client.messages.calls[1]
    assert retry["extra_headers"] == {"anthropic-version": "2023-06-01"}
    assert retry["extra_body"] == {"anthropic_version": "vertex-2023-10-16"}
    assert "compatibility mode" in result.notes[0]
    # once known, compatibility mode is used straight away (no failed first attempt)
    client.messages.calls.clear()
    ClaudeProvider(AIConfig(provider=Provider.VERTEX, compatibility_mode=True), client=client).test_connection()
    assert len(client.messages.calls) == 1
