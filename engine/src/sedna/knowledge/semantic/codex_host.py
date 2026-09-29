"""Host-LLM adapter that invokes the local ``codex`` CLI via subprocess.

This bypasses the host (Hermes) LLM routing entirely for Sedna's semantic
extraction. Rationale: Sedna's host-owned ``ctx.llm`` routes through Hermes'
auxiliary client, whose fallback chain tries ``openrouter`` first — which on
this machine is out of credits (HTTP 402, ``limit_source: openrouter_credits``)
and rejects every extraction request. The user's local ``codex`` CLI is
authenticated (OAuth/ChatGPT) and produces deterministic JSON when given an
``--output-schema``.

The adapter speaks the same ``complete_structured(**kwargs)`` surface the
Hermes PluginLlm exposes, so it drops in as the ``host`` passed to
``HadesLlmAdapter`` without touching Sedna's semantic pipeline.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_DEFAULT_MODEL = os.environ.get("SEDNA_CODEX_MODEL", "gpt-5.5")
_DEFAULT_BINARY = os.environ.get("SEDNA_CODEX_BIN", "codex")


class CodexCliError(RuntimeError):
    """A transport-level failure from the local Codex CLI."""


@dataclass(slots=True)
class CodexCliResult:
    """Structural subset of the host result consumed by Sedna's adapter.

    Mirrors ``agent.plugin_llm.PluginLlmStructuredResult``'s consumed fields:
    ``parsed`` (dict or None), ``provider``, ``model``, ``agent_id``,
    ``usage`` (with ``input_tokens`` / ``output_tokens``), ``audit``.
    """

    parsed: object | None
    provider: str
    model: str
    agent_id: str
    usage: object
    audit: Mapping[str, str]


@dataclass(slots=True)
class CodexUsage:
    input_tokens: int
    output_tokens: int


class CodexCliHost:
    """A ``complete_structured`` host backed by the local ``codex`` CLI.

    The prompt is built from ``instructions`` + the text blocks in ``input``,
    and the response is constrained to the JSON schema via Codex's
    ``--output-schema`` (which enforces structured output deterministically).
    ``json_mode``/``json_schema`` are honoured; the CLI's own schema file is
    written to a temporary file.
    """

    def __init__(
        self,
        *,
        binary: str = _DEFAULT_BINARY,
        model: str = _DEFAULT_MODEL,
        timeout: float = 600.0,
    ) -> None:
        self._binary = binary
        self._model = model
        self._timeout = timeout

    # -- public structured surface -----------------------------------------

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
    ) -> CodexCliResult:
        del provider, temperature, max_tokens, agent_id, profile
        prompt = self._build_prompt(instructions, input, system_prompt)
        eff_model = model or self._model

        # Codex's --output-schema requires a real JSON Schema with properties.
        # Only pass it when a concrete schema is supplied; with bare json_mode
        # (json_schema=None) Codex rejects an empty object schema, so omit the
        # flag and rely on the prompt to force JSON + robust extraction.
        schema = self._schema_for_save(json_schema, schema_name) if json_schema else None

        with tempfile.TemporaryDirectory(prefix="sedna-codex-") as tmp:
            schema_path = None
            if schema is not None:
                schema_path = os.path.join(tmp, "response_schema.json")
                with open(schema_path, "w", encoding="utf-8") as fh:
                    json.dump(schema, fh, ensure_ascii=False)
            raw, events = self._run_codex(prompt, schema_path, eff_model)
        parsed = self._extract_parsed(events, raw)
        usage = self._extract_usage(events)
        return CodexCliResult(
            parsed=parsed,
            provider="codex-cli",
            model=eff_model,
            agent_id="codex-cli-local",
            usage=usage,
            audit={"host": "codex-cli", "purpose": purpose or ""},
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _build_prompt(
        instructions: str,
        inputs: Sequence[Mapping[str, object]],
        system_prompt: str | None,
    ) -> str:
        parts: list[str] = []
        if system_prompt:
            parts.append(system_prompt)
        if instructions:
            parts.append(instructions)
        text_blocks = []
        for block in inputs:
            if not isinstance(block, Mapping):
                continue
            if (
                block.get("type") == "text"
                and isinstance(block.get("text"), str)
                or isinstance(block.get("text"), str)
            ):
                text_blocks.append(block["text"])
        if text_blocks:
            parts.append("\n\n--- INPUT ---\n\n" + "\n\n".join(text_blocks))
        return "\n\n".join(parts).strip()

    @staticmethod
    def _schema_for_save(
        json_schema: Mapping[str, object] | None, schema_name: str
    ) -> dict[str, object]:
        if json_schema is None:
            return {
                "type": "object",
                "additionalProperties": False,
            }
        out = dict(json_schema)
        # Codex requires additionalProperties to be present and false.
        out.setdefault("additionalProperties", False)
        return out

    def _run_codex(
        self,
        prompt: str,
        schema_path: str | None,
        model: str,
    ) -> tuple[str, list[dict[str, object]]]:
        binary = shutil.which(self._binary) or self._binary
        if not binary:
            raise CodexCliError(f"codex CLI not found: {self._binary!r}")
        cmd = [
            binary,
            "exec",
            "--skip-git-repo-check",
            "--json",
            "--model",
            model,
        ]
        if schema_path:
            cmd += ["--output-schema", schema_path]
        # The prompt is delivered on stdin, never in argv. A planner prompt on a
        # real settled engagement measured 208_114 characters, and passing it as
        # an argument made the OS refuse the spawn with
        # "[Errno 7] Argument list too long" (E2BIG) — which the planner adapter
        # then relabelled `transport_failure` and surfaced as `gap
        # llm_unavailable`, so a frontier could never be proposed. `codex exec`
        # reads instructions from stdin when the prompt is given as "-".
        cmd += ["-"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                input=prompt,
                timeout=self._timeout,
                cwd=os.path.dirname(binary) if os.path.dirname(binary) else None,
            )
        except subprocess.TimeoutExpired as err:
            raise CodexCliError(f"codex exec timed out after {self._timeout}s") from err
        except OSError as err:
            raise CodexCliError(f"codex exec failed to start: {err}") from err
        raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
        events = self._parse_events(proc.stdout or "")
        return raw, events

    @staticmethod
    def _parse_events(stdout: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except (ValueError, json.JSONDecodeError):
                continue
        return events

    @staticmethod
    def _extract_parsed(events: list[dict[str, Any]], raw: str) -> object | None:
        # The answer is the agent message itself. Every other event in the stream
        # (thread.started, turn.started, turn.completed with usage counters) is
        # bookkeeping and must never be returned as the model's output.
        for ev in events:
            if ev.get("type") == "item.completed":
                item = ev.get("item", {})
                if item.get("type") != "agent_message":
                    continue
                text = item.get("text")
                if not isinstance(text, str):
                    continue
                stripped = text.strip()
                try:
                    return json.loads(stripped)
                except (ValueError, json.JSONDecodeError):
                    # The message is not pure JSON. Extract the object FROM THIS
                    # MESSAGE only; never fall back to a global last-object scan,
                    # which returned the turn.completed usage event instead of the
                    # answer and made a correct draft look malformed.
                    embedded = _first_json_object(stripped)
                    if embedded is not None:
                        return embedded
                    continue
        # No agent message produced a usable object: surface an error event.
        for ev in events:
            if ev.get("type") in ("error", "turn.failed"):
                msg = ev.get("message") or ev.get("error")
                raise CodexCliError(f"codex exec failed: {json.dumps(msg)[:500]}")
        return None

    @staticmethod
    def _extract_usage(events: list[dict[str, Any]]) -> CodexCliUsage:
        for ev in events:
            if ev.get("type") == "turn.completed":
                u = ev.get("usage") or {}
                return CodexUsage(
                    input_tokens=int(u.get("input_tokens", 0)),
                    output_tokens=int(u.get("output_tokens", 0)),
                )
        return CodexUsage(input_tokens=0, output_tokens=0)


def _first_json_object(raw: str) -> object | None:
    """Extract the first balanced JSON object embedded in a single message.

    Scans FORWARD, deliberately: a backwards scan returns the LAST object, which
    on a real stream was the turn.completed usage event rather than the model's
    answer. Only ever applied to one agent message's text, never to the whole
    stdout+stderr stream.
    """
    length = len(raw)
    index = 0
    while index < length:
        if raw[index] != "{":
            index += 1
            continue
        depth = 0
        in_string = False
        escaped = False
        for position in range(index, length):
            character = raw[position]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    candidate = raw[index : position + 1]
                    try:
                        return json.loads(candidate)
                    except (ValueError, json.JSONDecodeError):
                        break
        index += 1
    return None


__all__ = ["CodexCliHost", "CodexCliError", "CodexCliResult", "CodexCliUsage"]
