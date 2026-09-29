"""Promotion-only JSON boundary for the host-owned structured LLM facade."""

from __future__ import annotations

import json
from contextlib import suppress
from types import MappingProxyType
from typing import Literal, TypeAlias, TypeVar

from pydantic import BaseModel

from sedna.engagement.promotion.models import (
    MAX_PROMOTION_DRAFT_BYTES,
    MAX_PROMOTION_INPUT_BYTES,
    PromotionCriticVerdict,
    PromotionDraft,
    PromotionInput,
    _PromotionModel,
)
from sedna.knowledge.semantic.llm import (
    HostStructuredLlm,
    StructuredResult,
    StructuredUsage,
)

PromotionPurpose = Literal[
    "sedna.promotion.extract",
    "sedna.promotion.critic",
    "sedna.promotion.repair",
]
PromotionLlmReasonCode = Literal[
    "transport_failure",
    "missing_parsed_response",
    "invalid_structured_response",
    "request_too_large",
]
ModelT = TypeVar("ModelT", bound=_PromotionModel)
MAX_PROMOTION_CRITIC_BYTES = 512 * 1024
MAX_PROMOTION_LLM_REQUEST_BYTES = (
    MAX_PROMOTION_INPUT_BYTES + MAX_PROMOTION_DRAFT_BYTES + MAX_PROMOTION_CRITIC_BYTES + 64 * 1024
)


class SafePromotionExtractRequest(_PromotionModel):
    source: PromotionInput


class SafePromotionCriticRequest(_PromotionModel):
    source: PromotionInput
    draft: PromotionDraft


class SafePromotionRepairRequest(_PromotionModel):
    source: PromotionInput
    draft: PromotionDraft
    critic: PromotionCriticVerdict


PromotionLlmRequest: TypeAlias = (
    SafePromotionExtractRequest | SafePromotionCriticRequest | SafePromotionRepairRequest
)
_CONTRACTS: dict[str, tuple[type[_PromotionModel], type[_PromotionModel]]] = {
    "sedna.promotion.extract": (SafePromotionExtractRequest, PromotionDraft),
    "sedna.promotion.critic": (SafePromotionCriticRequest, PromotionCriticVerdict),
    "sedna.promotion.repair": (SafePromotionRepairRequest, PromotionDraft),
}


class PromotionLlmError(RuntimeError):
    """Closed response-free failure at the promotion LLM boundary."""

    def __init__(self, reason_code: PromotionLlmReasonCode) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class PromotionLlmAdapter:
    """Send only closed promotion envelopes through the structured host API."""

    def __init__(
        self,
        host: HostStructuredLlm,
        *,
        max_tokens: int = 8_000,
        timeout: float = 120.0,
    ) -> None:
        self._host = host
        self._max_tokens = max_tokens
        self._timeout = timeout

    def complete(
        self,
        model_type: type[ModelT],
        *,
        instructions: str,
        payload: PromotionLlmRequest,
        purpose: PromotionPurpose,
    ) -> StructuredResult[ModelT]:
        contract = _CONTRACTS.get(purpose)
        if contract is None or type(payload) is not contract[0] or model_type is not contract[1]:
            raise TypeError("promotion purpose, payload, and response model must match")
        serialized: str | None = None
        try:
            payload_data = payload.model_dump(mode="python", warnings="error")
            validated = type(payload).model_validate(payload_data)
            serialized = _canonical_json(validated.model_dump(mode="json", warnings="error"))
        except Exception:
            pass
        if serialized is None:
            raise TypeError("payload must be a safe promotion request")
        if len(serialized.encode("utf-8")) > MAX_PROMOTION_LLM_REQUEST_BYTES:
            raise PromotionLlmError("request_too_large")

        schema = _canonical_json(model_type.model_json_schema())
        host_result = None
        host_parsed = None
        host_usage = None
        provider = None
        model = None
        agent_id = None
        host_result_complete = False
        with suppress(Exception):
            host_result = self._host.complete_structured(
                instructions=(
                    f"{instructions}\n\nReturn one JSON object matching this schema "
                    f"exactly:\n{schema}"
                ),
                input=[{"type": "text", "text": serialized}],
                json_schema=None,
                json_mode=True,
                schema_name=model_type.__name__,
                temperature=0,
                max_tokens=self._max_tokens,
                timeout=self._timeout,
                purpose=purpose,
            )
            host_parsed = getattr(host_result, "parsed", None)
            host_usage = host_result.usage
            provider = host_result.provider
            model = host_result.model
            agent_id = host_result.agent_id
            host_result_complete = True
        host_result = None
        if not host_result_complete:
            host_parsed = None
            host_usage = None
            provider = None
            model = None
            agent_id = None
            raise PromotionLlmError("transport_failure")

        if host_parsed is None:
            raise PromotionLlmError("missing_parsed_response")
        parsed: ModelT | None = None
        try:
            response_data = (
                host_parsed.model_dump(mode="json", warnings="error")
                if isinstance(host_parsed, BaseModel)
                else host_parsed
            )
            response_json = _canonical_json(response_data)
            if (
                model_type is PromotionCriticVerdict
                and len(response_json.encode("utf-8")) > MAX_PROMOTION_CRITIC_BYTES
            ):
                raise ValueError("critic response exceeds its bound")
            parsed = model_type.model_validate_json(response_json)
        except Exception:
            pass
        if parsed is None:
            raise PromotionLlmError("invalid_structured_response")

        usage: StructuredUsage | None = None
        with suppress(Exception):
            usage = StructuredUsage.model_validate(host_usage)
            if not all(isinstance(item, str) and item for item in (provider, model, agent_id)):
                raise ValueError("invalid host attribution")
        if usage is None or provider is None or model is None or agent_id is None:
            raise PromotionLlmError("transport_failure")
        return StructuredResult(
            parsed=parsed,
            provider=provider,
            model=model,
            agent_id=agent_id,
            usage=usage,
            audit=MappingProxyType({"purpose": purpose}),
        )


__all__ = [
    "MAX_PROMOTION_CRITIC_BYTES",
    "MAX_PROMOTION_LLM_REQUEST_BYTES",
    "PromotionLlmAdapter",
    "PromotionLlmError",
    "PromotionLlmRequest",
    "PromotionPurpose",
    "SafePromotionCriticRequest",
    "SafePromotionExtractRequest",
    "SafePromotionRepairRequest",
]
