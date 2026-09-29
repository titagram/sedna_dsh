"""Deterministic, private-safe Markdown rendering for verified case promotion."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from uuid import NAMESPACE_URL, UUID, uuid5

from markdown_it import MarkdownIt

from sedna.engagement.models import JournalRevision, PromotionSourceId
from sedna.engagement.promotion.models import (
    PromotionClaim,
    PromotionDraft,
    PromotionInput,
    PromotionProvenanceMap,
    PromotionProvenanceSpan,
    PromotionSecretInventory,
    PromotionStepDraft,
    RenderedPromotionSource,
)
from sedna.engagement.promotion.sanitize import assert_promotion_safe

PROMOTION_RENDERER_VERSION = "1"
_SYMBOL = re.compile(r"<[A-Z]+(?:_[A-Z0-9]+)*>")
_MARKDOWN_PUNCTUATION = re.compile(r"([\\`*{}\[\]()#+.!_|>-])")
_UNIVERSAL_NEWLINE = re.compile(r"\r\n|\r|\n")


def promotion_source_id(engagement_id: UUID) -> str:
    """Return the content-independent journal-promotion source identity."""
    return f"source-{uuid5(NAMESPACE_URL, f'sedna:journal-promotion:{engagement_id}')}"


def promotion_source_relative_path(engagement_id: UUID, promotion_revision: int) -> str:
    """Derive the closed source path grammar from trusted identity fields."""
    return f"engagements/{engagement_id}/promotion/sources/promotion-v{promotion_revision}.md"


def promotion_provenance_relative_path(engagement_id: UUID, promotion_revision: int) -> str:
    """Derive the closed provenance path grammar from trusted identity fields."""
    return (
        f"engagements/{engagement_id}/promotion/sources/"
        f"promotion-v{promotion_revision}.provenance.json"
    )


@dataclass(frozen=True, slots=True, repr=False)
class PromotionRenderIdentity:
    engagement_id: UUID
    attempt_id: UUID
    verification_event_id: UUID
    verified_revision: JournalRevision
    source_id: PromotionSourceId
    promotion_revision: int

    def __post_init__(self) -> None:
        if type(self.engagement_id) is not UUID or type(self.attempt_id) is not UUID:
            raise TypeError("promotion render identity requires UUID values")
        if type(self.verification_event_id) is not UUID:
            raise TypeError("promotion render identity requires a verification UUID")
        if not isinstance(self.verified_revision, JournalRevision):
            raise TypeError("promotion render identity requires a journal revision")
        if type(self.promotion_revision) is not int or self.promotion_revision < 1:
            raise ValueError("promotion revision must be a positive integer")
        if self.source_id != promotion_source_id(self.engagement_id):
            raise ValueError("promotion source identity does not match engagement")


class _LineAccumulator:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.spans: list[PromotionProvenanceSpan] = []

    def structural(self, line: str = "") -> None:
        self.lines.append(line)

    def strategic(
        self,
        lines: tuple[str, ...],
        *,
        event_ids: tuple[UUID, ...],
        evidence_ids: tuple[str, ...],
    ) -> None:
        start = len(self.lines) + 1
        self.lines.extend(lines)
        self.spans.append(
            PromotionProvenanceSpan(
                start_line=start,
                end_line=len(self.lines),
                event_ids=event_ids,
                evidence_ids=evidence_ids,
            )
        )


def _escape_prose(value: str) -> tuple[str, ...]:
    placeholders: dict[str, str] = {}

    def reserve(match: re.Match[str]) -> str:
        key = f"\x00{len(placeholders)}\x00"
        placeholders[key] = match.group()
        return key

    reserved = _SYMBOL.sub(reserve, value)
    escaped = html.escape(reserved, quote=True)
    escaped = _MARKDOWN_PUNCTUATION.sub(r"\\\1", escaped)
    for key, symbol in placeholders.items():
        escaped = escaped.replace(key, f"\\{symbol}")
    return tuple(_UNIVERSAL_NEWLINE.split(escaped))


def _command_fence(value: str) -> tuple[str, ...]:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return (fence + "text", *_UNIVERSAL_NEWLINE.split(value), fence)


def _append_claim(accumulator: _LineAccumulator, claim: PromotionClaim) -> None:
    accumulator.strategic(
        _escape_prose(claim.text),
        event_ids=claim.event_ids,
        evidence_ids=claim.evidence_ids,
    )
    accumulator.structural()


def _append_step_scalar(
    accumulator: _LineAccumulator,
    value: str,
    step: PromotionStepDraft,
    *,
    command: bool = False,
) -> None:
    lines = _command_fence(value) if command else _escape_prose(value)
    accumulator.strategic(lines, event_ids=step.event_ids, evidence_ids=step.evidence_ids)
    accumulator.structural()


def _validate_structure(markdown: str, expected_headings: tuple[tuple[int, str], ...]) -> None:
    tokens = MarkdownIt("commonmark", {"html": False}).parse(markdown)
    headings: list[tuple[int, str]] = []
    for index, token in enumerate(tokens):
        nested = (token, *(token.children or ()))
        if any(item.type in {"html_block", "html_inline", "link_open", "image"} for item in nested):
            raise ValueError("rendered promotion source contains forbidden Markdown structure")
        if token.type == "heading_open":
            inline = tokens[index + 1]
            text = "".join(child.content for child in (inline.children or ()))
            headings.append((int(token.tag[1:]), text))
    if tuple(headings) != expected_headings:
        raise ValueError("rendered promotion source heading structure is invalid")


def render_promotion_source(
    draft: PromotionDraft,
    *,
    context: PromotionInput,
    inventory: PromotionSecretInventory,
    identity: PromotionRenderIdentity,
) -> RenderedPromotionSource:
    """Render one immutable Markdown source and its exact canonical line map."""
    draft = PromotionDraft.model_validate_json(draft.model_dump_json(warnings="error"))
    context = PromotionInput.model_validate_json(context.model_dump_json(warnings="error"))
    if context.engagement_id != identity.engagement_id:
        raise ValueError("promotion context does not match render identity")
    if context.verified_revision != identity.verified_revision:
        raise ValueError("verified revision does not match render identity")
    if context.verification_event_id != identity.verification_event_id:
        raise ValueError("verification event does not match render identity")

    accumulator = _LineAccumulator()
    title = " ".join(_escape_prose(draft.title))
    expected_title = " ".join(_UNIVERSAL_NEWLINE.split(draft.title)).strip()
    expected_headings: list[tuple[int, str]] = [(1, expected_title)]
    accumulator.structural(f"# {title}")
    accumulator.structural()

    sections = (
        ("Starting Access", (draft.starting_access,)),
        ("Applicability", draft.applicability),
    )
    for heading, claims in sections:
        accumulator.structural(f"## {heading}")
        accumulator.structural()
        expected_headings.append((2, heading))
        for claim in claims:
            _append_claim(accumulator, claim)

    accumulator.structural("## Steps")
    accumulator.structural()
    expected_headings.append((2, "Steps"))
    for step in draft.steps:
        heading = f"Step {step.ordinal}"
        accumulator.structural(f"### {heading}")
        accumulator.structural()
        expected_headings.append((3, heading))
        for value in (
            step.state_before,
            *step.observations,
            *step.hypotheses,
            step.selected_strategy,
        ):
            _append_step_scalar(accumulator, value, step)
        for command in step.command_examples:
            _append_step_scalar(accumulator, command, step, command=True)
        for value in (
            step.outcome,
            *step.negative_evidence,
            *step.retry_conditions,
            step.state_after,
        ):
            _append_step_scalar(accumulator, value, step)

    remaining = (
        ("Alternate Paths", draft.alternate_paths),
        ("Transferable Properties", draft.transferable_properties),
        ("Non-transferable Properties", draft.non_transferable_properties),
        ("Generalizability Basis", (draft.generalizability_basis,)),
        ("Verified Outcome", (draft.verified_outcome,)),
    )
    for heading, claims in remaining:
        accumulator.structural(f"## {heading}")
        accumulator.structural()
        expected_headings.append((2, heading))
        for claim in claims:
            _append_claim(accumulator, claim)

    markdown = "\n".join(accumulator.lines[:-1]) + "\n"
    _validate_structure(markdown, tuple(expected_headings))
    assert_promotion_safe(markdown, inventory)
    source_digest = sha256(markdown.encode("utf-8")).hexdigest()
    source_path = promotion_source_relative_path(
        identity.engagement_id, identity.promotion_revision
    )
    provenance = PromotionProvenanceMap(
        engagement_id=identity.engagement_id,
        attempt_id=identity.attempt_id,
        promotion_revision=identity.promotion_revision,
        verified_revision=identity.verified_revision,
        verification_event_id=identity.verification_event_id,
        source_id=identity.source_id,
        source_relative_path=source_path,
        source_sha256=source_digest,
        spans=tuple(accumulator.spans),
    )
    provenance_bytes = json.dumps(
        provenance.model_dump(mode="json", warnings="error"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert_promotion_safe(provenance_bytes.decode("utf-8"), inventory)
    return RenderedPromotionSource(
        source_id=identity.source_id,
        promotion_revision=identity.promotion_revision,
        title=draft.title,
        source_relative_path=source_path,
        markdown=markdown,
        source_sha256=source_digest,
        provenance_relative_path=promotion_provenance_relative_path(
            identity.engagement_id, identity.promotion_revision
        ),
        provenance=provenance,
        provenance_sha256=sha256(provenance_bytes).hexdigest(),
    )
