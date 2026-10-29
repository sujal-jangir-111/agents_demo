"""Async ASI:One chat-completions wrapper (OpenAI-compatible) with a JSON-mode helper.

Safety: every prompt is passed through `mask_secrets` before leaving the process, and
callers should truncate large inputs with `truncate` (CLAUDE.md §9.4, §14).
"""
import json
import re
from typing import Any, Callable, Dict, Optional, Type, TypeVar

import httpx
from pydantic import ValidationError

from common.config import get_settings
from common.http_retry import send_with_retry
from common.sast_rules import mask_secrets

TIMEOUT_SECONDS = 30.0
TEMPERATURE = 0.2

T = TypeVar("T")


class LLMError(Exception):
    """ASI:One could not be reached, rejected the request, or returned unusable output."""


def truncate(text: str, limit: int, marker: str = "\n...[truncated]") -> str:
    """Cap text at `limit` characters (marker included)."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(marker))] + marker


_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?```$", re.DOTALL)


def parse_json_object(raw: str) -> Dict[str, Any]:
    """Strip ``` fences and parse a JSON object; falls back to the outermost {...} span."""
    text = raw.strip()
    fenced = _FENCE_RE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


class ASI1Client:
    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        cfg = get_settings()
        self._client = client
        self._api_key = cfg.asi1_api_key if api_key is None else api_key
        self.model = model or cfg.asi1_model
        self._url = base_url or cfg.asi1_base_url

    async def chat(self, system: str, user: str, temperature: float = TEMPERATURE) -> str:
        """One chat completion; returns the assistant text."""
        if not self._api_key:
            raise LLMError("ASI1_API_KEY is not configured")
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": mask_secrets(system)},
                {"role": "user", "content": mask_secrets(user)},
            ],
        }
        resp = await send_with_retry(
            self._client, "POST", self._url, error_cls=LLMError, label="ASI:One request",
            json=payload, headers={"Authorization": f"Bearer {self._api_key}"}, timeout=TIMEOUT_SECONDS,
        )
        if resp.status_code >= 400:
            raise LLMError(f"ASI:One request failed: HTTP {resp.status_code}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("ASI:One returned an unexpected response shape") from exc
        if not isinstance(content, str) or not content.strip():
            raise LLMError("ASI:One returned an empty completion")
        return content

    async def _json_call(
        self, system: str, user: str, schema_hint: str, build: Callable[[Dict[str, Any]], T]
    ) -> T:
        """Ask for JSON only; on a parse/validation failure retry once with the error, then raise."""
        json_system = (
            f"{system}\n\nRespond with ONLY a single JSON object matching this shape. "
            f"No prose, no markdown fences.\n{schema_hint}"
        )
        prompt = user
        error = ""
        for attempt in range(2):
            raw = await self.chat(json_system, prompt)
            try:
                return build(parse_json_object(raw))
            except (ValueError, ValidationError) as exc:  # JSONDecodeError is a ValueError
                error = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
                prompt = f"{user}\n\nYour previous reply was invalid ({error}). Reply with ONLY valid JSON."
        raise LLMError(f"ASI:One did not return valid JSON after 2 attempts ({error})")

    async def chat_json(self, system: str, user: str, schema_hint: str) -> Dict[str, Any]:
        """JSON-object completion (fences stripped, one parse retry, then LLMError)."""
        return await self._json_call(system, user, schema_hint, lambda d: d)

    async def chat_model(
        self, model_cls: Type[T], system: str, user: str, schema_hint: Optional[str] = None
    ) -> T:
        """Like chat_json but validates into a pydantic/uagents Model (e.g. PatchDraftResult)."""
        if schema_hint is None:
            # uagents Models return the schema as a JSON string; plain pydantic returns a dict
            schema = model_cls.model_json_schema()  # type: ignore[attr-defined]
            schema = json.loads(schema) if isinstance(schema, str) else schema
            schema_hint = json.dumps(schema, separators=(",", ":"))
        hint = schema_hint
        return await self._json_call(system, user, hint, lambda d: model_cls.model_validate(d))  # type: ignore[attr-defined]
