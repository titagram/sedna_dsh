"""Bounded symbolization for case-promotion material."""

from __future__ import annotations

import html
import json
import re
from urllib.parse import quote, unquote

from pydantic import BaseModel

from sedna.engagement.promotion.models import (
    PromotionEvidenceItem,
    PromotionInput,
    PromotionSecretInventory,
)

_MAX_DECODE_INPUT_CHARS = 65_536
_MAX_DECODE_ROUNDS = 8
_MAX_DECODE_WORK_CHARS = 262_144
_HTB_FLAG_RE = re.compile(r"HTB\{[^}]*\}", re.IGNORECASE)
_HTB_OPEN_RE = re.compile(r"HTB\{", re.IGNORECASE)


def _canonical_json(value: object) -> str:
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json", warnings="error")
    else:
        payload = value
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _recursively_decode(value: str) -> tuple[str, bool]:
    if len(value) > _MAX_DECODE_INPUT_CHARS:
        return value, False
    current = value
    work = len(value)
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = html.unescape(unquote(current))
        work += len(decoded)
        if work > _MAX_DECODE_WORK_CHARS:
            return current, False
        if decoded == current:
            return current, True
        current = decoded
    return current, html.unescape(unquote(current)) == current


def _replacement_table(inventory: PromotionSecretInventory) -> dict[str, str]:
    table: dict[str, str] = {}
    groups = (
        ("FLAG", inventory.flags),
        ("CREDENTIAL", inventory.credentials),
        ("TARGET", inventory.target_identifiers),
        ("CHALLENGE", inventory.challenge_identifiers),
    )
    claimed: set[str] = set()
    for prefix, values in groups:
        unique = sorted(set(values), key=lambda item: (item.casefold(), item))
        index = 0
        for private in unique:
            folded = private.casefold()
            if folded in claimed:
                continue
            claimed.add(folded)
            index += 1
            table[private] = f"<{prefix}_{index}>"
    return table


def _encoded_variants(value: str) -> tuple[str, ...]:
    variants = {
        value,
        quote(value),
        quote(value, safe=""),
        quote(quote(value, safe=""), safe=""),
        html.escape(value),
    }
    return tuple(sorted(variants, key=lambda item: (-len(item), item)))


def assert_promotion_safe(value: object, inventory: PromotionSecretInventory) -> None:
    serialized = value if isinstance(value, str) else _canonical_json(value)
    decoded, stable = _recursively_decode(serialized)
    if not stable:
        raise ValueError("promotion material encoding exceeds its decode budget")
    candidates = (serialized, decoded)
    private_values = (
        inventory.flags
        + inventory.credentials
        + inventory.target_identifiers
        + inventory.challenge_identifiers
    )
    if any(
        private.casefold() in candidate.casefold()
        for private in private_values
        for candidate in candidates
    ):
        raise ValueError("promotion material contains private value")
    if any(
        _HTB_FLAG_RE.search(candidate) or _HTB_OPEN_RE.search(candidate) for candidate in candidates
    ):
        raise ValueError("promotion material contains raw flag")


def assert_semantic_promotion_safe(value: object, inventory: PromotionSecretInventory) -> None:
    """Apply the final recursive leak scan to the complete semantic boundary."""

    assert_promotion_safe(value, inventory)


def symbolize_text(value: str, inventory: PromotionSecretInventory) -> str:
    safe = value
    replacements = _replacement_table(inventory)
    for private, symbol in sorted(
        replacements.items(), key=lambda item: (-len(item[0]), item[0].casefold())
    ):
        for variant in _encoded_variants(private):
            safe = re.sub(re.escape(variant), symbol, safe, flags=re.IGNORECASE)
    decoded, stable = _recursively_decode(safe)
    if not stable:
        raise ValueError("promotion material encoding exceeds its decode budget")
    if decoded != safe:
        safe = decoded
        for private, symbol in sorted(
            replacements.items(), key=lambda item: (-len(item[0]), item[0].casefold())
        ):
            safe = re.sub(re.escape(private), symbol, safe, flags=re.IGNORECASE)
    safe = _HTB_FLAG_RE.sub("<FLAG_REDACTED>", safe)
    safe = _HTB_OPEN_RE.sub("<FLAG_REDACTED>", safe)
    assert_promotion_safe(safe, inventory)
    return safe


def symbolize_evidence(
    item: PromotionEvidenceItem,
    inventory: PromotionSecretInventory,
) -> PromotionEvidenceItem:
    safe = item.model_copy(update={"summary": symbolize_text(item.summary, inventory)})
    return PromotionEvidenceItem.model_validate(safe.model_dump(mode="python"))


def symbolize_promotion_input(
    value: PromotionInput,
    inventory: PromotionSecretInventory,
) -> PromotionInput:
    safe = PromotionInput(
        engagement_id=value.engagement_id,
        verified_revision=value.verified_revision,
        verification_event_id=value.verification_event_id,
        display_name=symbolize_text(value.display_name, inventory),
        objective=symbolize_text(value.objective, inventory),
        context=tuple(symbolize_evidence(item, inventory) for item in value.context),
        decisions=tuple(symbolize_evidence(item, inventory) for item in value.decisions),
        outcomes=tuple(symbolize_evidence(item, inventory) for item in value.outcomes),
        alternatives=tuple(symbolize_evidence(item, inventory) for item in value.alternatives),
    )
    assert_promotion_safe(safe, inventory)
    return safe
