"""Host-LLM adapter that calls a local Ollama server (OpenAI-compatible chat).

This lets Sedna's semantic extraction run on free local models (qwen3.6,
gpt-oss, deepseek-v4-flash) instead of the expensive codex CLI (gpt-5.5) or
the out-of-credits OpenRouter fallback. Local models are free (no token
billing) at the cost of a smaller/faster model — which is why the schema was
relaxed (multi-line command templates) and orphan execution examples are
dropped instead of failing the whole bundle.

The adapter speaks the same ``complete_structured(**kwargs)`` surface the
Hermes PluginLlm exposes, so it drops in as the ``host`` passed to
``HadesLlmAdapter`` without touching Sedna's semantic pipeline.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_DEFAULT_BASE_URL = os.environ.get("SEDNA_OLLAMA_URL", "http://127.0.0.1:11434")
_DEFAULT_MODEL = os.environ.get("SEDNA_OLLAMA_MODEL", "qwen3.6:latest")
_DEFAULT_TIMEOUT = float(os.environ.get("SEDNA_OLLAMA_TIMEOUT", "300"))
# Optional API key for remote Ollama Cloud (OpenAI-compatible endpoint).
_DEFAULT_API_KEY = os.environ.get("SEDNA_OLLAMA_API_KEY", "") or None


class OllamaHostError(RuntimeError):
    """A transport-level failure talking to the local Ollama server."""


@dataclass(slots=True)
class OllamaResult:
    """Structural subset of the host result consumed by Sedna's adapter.

    Mirrors ``CodexCliResult``: ``parsed`` (dict or None), ``provider``,
    ``model``, ``agent_id``, ``usage`` (``input_tokens``/``output_tokens``),
    ``audit``.
    """

    parsed: object | None
    provider: str
    model: str
    agent_id: str
    usage: object
    audit: Mapping[str, str]


@dataclass(slots=True)
class OllamaUsage:
    input_tokens: int
    output_tokens: int


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (4 chars/token) when Ollama omits usage counts."""
    return max(1, len(text) // 4)


class OllamaHost:
    """A ``complete_structured`` host backed by a local Ollama chat endpoint.

    Uses Ollama's ``format=json`` to force JSON output, then parses the
    ``content`` field. The ``instructions`` and input text blocks are combined
    into a single user message.
    """

    def __init__(
        self,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        model: str = _DEFAULT_MODEL,
        timeout: float = _DEFAULT_TIMEOUT,
        api_key: str | None = None,
        api_mode: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._api_key = api_key if api_key is not None else _DEFAULT_API_KEY
        # "native" = Ollama's /api/chat endpoint (local). "openai" =
        # OpenAI-compatible /v1/chat/completions (Ollama Cloud, remote).
        # Auto-detect: a base_url containing "ollama.com" or "://api" is remote
        # OpenAI-compatible; otherwise assume the native local endpoint.
        if api_mode is None:
            lower = base_url.lower()
            self._api_mode = "openai" if ("ollama.com" in lower or "/v1" in lower) else "native"
        else:
            self._api_mode = api_mode

    # This host can consume a real JSON Schema as structured output. The
    # HadesLlmAdapter gates on this to hand us the schema instead of forcing us
    # to reverse-engineer it from the prompt text.
    accepts_schema = True

    def complete_structured(
        self,
        *,
        instructions: str,
        input: Sequence[Mapping[str, object]],
        json_schema: Mapping[str, object] | None = None,
        json_mode: bool = False,
        schema_name: str = "",
        system_prompt: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
        agent_id: str | None = None,
        profile: str | None = None,
        purpose: str | None = None,
    ) -> OllamaResult:
        del json_mode, schema_name, provider, agent_id, profile, max_tokens
        eff_model = model or self._model
        # Local models are slow; the upstream HadesLlmAdapter passes a 120s
        # timeout which qwen/gpt-oss routinely exceed on large payloads. Use our
        # own generous timeout as a lower bound, never let the caller shrink it.
        eff_timeout = max(timeout or 0.0, self._timeout)

        # Build the user message from instructions + input text blocks.
        blocks = [instructions]
        for block in input or ():
            if isinstance(block, Mapping):
                text = block.get("text")
                if isinstance(text, str):
                    blocks.append(text)
        user_content = "\n\n".join(blocks)

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_content})

        # Structured output: when a real JSON Schema is supplied (our adapter
        # passes it because accepts_schema=True), constrain the sampler to it
        # instead of a bare "json" hint. This is what lets otherwise weak
        # models (deepseek-v4-flash, gpt-oss) emit schema-conformant JSON.
        if isinstance(json_schema, Mapping):
            schema_dict = dict(json_schema)
            schema_dict.setdefault("additionalProperties", False)
            if self._api_mode == "openai":
                response_format = {
                    "type": "json_schema",
                    "json_schema": {"name": "response", "schema": schema_dict},
                }
            else:
                response_format = schema_dict
        else:
            response_format = None

        # Build payload depending on endpoint mode.
        if self._api_mode == "openai":
            payload: dict[str, Any] = {
                "model": eff_model,
                "messages": messages,
                "stream": False,
                "temperature": temperature if temperature is not None else 0,
            }
            if response_format is not None:
                payload["response_format"] = response_format
            else:
                payload["response_format"] = {"type": "json_object"}
            url = f"{self._base_url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
        else:
            payload = {
                "model": eff_model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature if temperature is not None else 0},
            }
            # Native Ollama /api/chat accepts the schema object directly in
            # "format" (structured output); a plain "json" is the loose fallback.
            payload["format"] = response_format if response_format is not None else "json"
            url = f"{self._base_url}/api/chat"
            headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=eff_timeout) as resp:
                body = json.load(resp)
        except Exception as err:
            raise OllamaHostError(f"ollama request failed: {err}") from err

        # Extract content depending on endpoint mode.
        if self._api_mode == "openai":
            content = (body.get("choices") or [{}])[0].get("message", {}).get("content")
            usage_raw = body.get("usage") or {}
            prompt_tok = usage_raw.get("prompt_tokens")
            comp_tok = usage_raw.get("completion_tokens")
        else:
            content = (body.get("message") or {}).get("content")
            prompt_tok = body.get("prompt_eval_count")
            comp_tok = body.get("eval_count")

        parsed: object | None = None
        if isinstance(content, str) and content.strip():
            try:
                parsed = json.loads(content)
            except ValueError:
                # Try to extract the last JSON object (defensive).
                parsed = _last_json_object(content)

        usage = OllamaUsage(
            input_tokens=int(prompt_tok)
            if prompt_tok is not None
            else _estimate_tokens(user_content),
            output_tokens=int(comp_tok)
            if comp_tok is not None
            else _estimate_tokens(content or ""),
        )
        return OllamaResult(
            parsed=parsed,
            provider="ollama" + ("-cloud" if self._api_mode == "openai" else ""),
            model=eff_model,
            agent_id="ollama-cloud" if self._api_mode == "openai" else "ollama-local",
            usage=usage,
            audit={"host": "ollama", "api_mode": self._api_mode, "purpose": purpose or ""},
        )


def _last_json_object(raw: str) -> object | None:
    """Best-effort extraction of the last balanced JSON object in raw text."""
    for end in range(len(raw), -1, -1):
        if end == 0:
            break
        if raw[end - 1] == "}":
            depth = 0
            for i in range(end - 1, -1, -1):
                ch = raw[i]
                if ch == "}":
                    depth += 1
                elif ch == "{":
                    depth -= 1
                    if depth == 0:
                        candidate = raw[i:end]
                        try:
                            return json.loads(candidate)
                        except (ValueError, json.JSONDecodeError):
                            break
    return None


__all__ = ["OllamaHost", "OllamaHostError", "OllamaResult", "OllamaUsage"]
