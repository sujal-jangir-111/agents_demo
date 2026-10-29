import json
import os
from typing import Callable, List

import httpx
import pytest

from common.asi1_client import ASI1Client, LLMError, parse_json_object, truncate
from common.models import PatchDraftResult

URL = "https://asi.test/v1/chat/completions"
KEY = "test-key-123"


def completion(text: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": text}}]})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    sleeps: List[float] = []

    async def fake(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("common.http_retry._sleep", fake)
    return sleeps


def make(handler: Callable[[httpx.Request], httpx.Response], key: str = KEY):
    seen: List[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(wrapped))
    return ASI1Client(http, api_key=key, model="asi1-mini", base_url=URL), seen, http


# ------------------------------------------------------------------ parsing helpers

def test_parse_json_object_variants():
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('```\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('Sure! Here you go: {"a": {"b": 2}} hope it helps') == {"a": {"b": 2}}


@pytest.mark.parametrize("bad", ["not json", "[1, 2]", "", "{broken"])
def test_parse_json_object_rejects(bad):
    with pytest.raises(ValueError):
        parse_json_object(bad)


def test_truncate():
    assert truncate("short", 100) == "short"
    out = truncate("x" * 500, 100)
    assert len(out) == 100 and out.endswith("[truncated]")


# ------------------------------------------------------------------ chat

async def test_chat_request_shape_and_auth():
    client, seen, http = make(lambda r: completion("hello"))
    async with http:
        assert await client.chat("be brief", "hi") == "hello"
    req = seen[0]
    body = json.loads(req.content)
    assert str(req.url) == URL and req.headers["Authorization"] == f"Bearer {KEY}"
    assert body["model"] == "asi1-mini" and body["temperature"] == 0.2
    assert body["messages"] == [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]


async def test_secrets_are_masked_before_sending():
    client, seen, http = make(lambda r: completion("ok"))
    async with http:
        await client.chat("sys", 'STRIPE = "sk_test_51SENTINELDEMOxxxxxxxx" and AKIAIOSFODNN7EXAMPLE')
    sent = seen[0].content.decode()
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in sent and "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "sk_tes****" in sent and "AKIAIO****" in sent


async def test_missing_api_key_never_sends():
    client, seen, http = make(lambda r: completion("x"), key="")
    async with http:
        with pytest.raises(LLMError, match="ASI1_API_KEY"):
            await client.chat("s", "u")
    assert seen == []


async def test_retries_5xx_with_backoff_then_succeeds(no_sleep):
    replies = iter([httpx.Response(503), httpx.Response(500), completion("finally")])
    client, seen, http = make(lambda r: next(replies))
    async with http:
        assert await client.chat("s", "u") == "finally"
    assert len(seen) == 3 and no_sleep == [0.5, 1.0]


async def test_timeout_exhausts_retries(no_sleep):
    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)

    client, seen, http = make(boom)
    async with http:
        with pytest.raises(LLMError, match="3 attempts.*ReadTimeout"):
            await client.chat("s", "u")
    assert len(seen) == 3 and no_sleep == [0.5, 1.0]


async def test_4xx_not_retried_and_key_not_leaked():
    client, seen, http = make(lambda r: httpx.Response(401, json={"error": f"bad key {KEY}"}))
    async with http:
        with pytest.raises(LLMError) as exc:
            await client.chat("s", "u")
    assert "HTTP 401" in str(exc.value) and KEY not in str(exc.value) and len(seen) == 1


@pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": [{"message": {}}]}, {"choices": [{"message": {"content": "  "}}]}])
async def test_malformed_completion_raises(payload):
    client, _, http = make(lambda r: httpx.Response(200, json=payload))
    async with http:
        with pytest.raises(LLMError):
            await client.chat("s", "u")


# ------------------------------------------------------------------ JSON mode

async def test_chat_json_strips_fences():
    client, seen, http = make(lambda r: completion('```json\n{"patched_code": "x = 1", "explanation": "e"}\n```'))
    async with http:
        out = await client.chat_json("sys", "user", '{"patched_code": str, "explanation": str}')
    assert out == {"patched_code": "x = 1", "explanation": "e"}
    system = json.loads(seen[0].content)["messages"][0]["content"]
    assert "ONLY a single JSON object" in system and '"patched_code"' in system


async def test_chat_json_retries_once_on_parse_failure():
    replies = iter([completion("I think the answer is..."), completion('{"ok": true}')])
    client, seen, http = make(lambda r: next(replies))
    async with http:
        assert await client.chat_json("s", "u", "{}") == {"ok": True}
    retry_prompt = json.loads(seen[1].content)["messages"][1]["content"]
    assert "previous reply was invalid" in retry_prompt


async def test_chat_json_gives_up_after_second_failure():
    client, seen, http = make(lambda r: completion("still not json"))
    async with http:
        with pytest.raises(LLMError, match="valid JSON after 2 attempts"):
            await client.chat_json("s", "u", "{}")
    assert len(seen) == 2


async def test_chat_model_validates_into_uagents_model():
    att = {
        "incident_id": "inc-1", "approved": True, "attestation_hash": "h", "target_file": "app.py",
        "patched_code_content": "x", "updated_requirements_txt": "y", "unified_diff": "z",
    }
    good = {"incident_id": "inc-1", "attestation": att, "rollback_available": True, "attempts": 2}
    client, _, http = make(lambda r: completion(json.dumps(good)))
    async with http:
        result = await client.chat_model(PatchDraftResult, "s", "u")
    assert isinstance(result, PatchDraftResult) and result.attempts == 2 and result.attestation.approved


async def test_chat_model_retries_on_validation_error_then_fails():
    client, seen, http = make(lambda r: completion('{"incident_id": "inc-1"}'))
    async with http:
        with pytest.raises(LLMError, match="2 attempts"):
            await client.chat_model(PatchDraftResult, "s", "u")
    assert len(seen) == 2


async def test_chat_model_default_schema_hint_lists_fields():
    client, seen, http = make(lambda r: completion("{}"))
    async with http:
        with pytest.raises(LLMError):
            await client.chat_model(PatchDraftResult, "s", "u")
    system = json.loads(seen[0].content)["messages"][0]["content"]
    assert "rollback_available" in system and "attempts" in system


# ------------------------------------------------------------------ live (opt-in)

@pytest.mark.integration
async def test_live_asi1_json_roundtrip():
    key = os.getenv("ASI1_API_KEY")
    if not key:
        pytest.skip("ASI1_API_KEY not set")
    async with httpx.AsyncClient() as http:
        out = await ASI1Client(http, api_key=key).chat_json("You are a test.", 'Return {"ok": true}', '{"ok": bool}')
    assert isinstance(out, dict)
