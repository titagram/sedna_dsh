"""Strict bounded contracts for verified case promotion."""

from __future__ import annotations

import json
import re
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Annotated, Literal, Self, TypeVar
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from sedna.engagement.models import (
    ConfinedRelativePath,
    EvidenceId,
    JournalRevision,
    PromotionAttemptState,
    PromotionSourceId,
    Sha256Hex,
)

PROMOTION_DRAFT_SCHEMA_VERSION = "1.0.0"
PROMOTION_SOURCE_SCHEMA_VERSION = "1.0.0"
PROMOTION_PROVENANCE_SCHEMA_VERSION = "1.0.0"
PROMOTION_COMPILER_VERSION = "1"
MAX_PROMOTION_INPUT_BYTES = 512 * 1024
MAX_PROMOTION_DRAFT_BYTES = 512 * 1024
MAX_PROMOTION_SOURCE_BYTES = 1024 * 1024
MAX_PROMOTION_PROVENANCE_BYTES = 8 * 1024 * 1024
MAX_PROMOTION_PROVENANCE_SPANS = 4_096
MAX_PROMOTION_PROVENANCE_EVENT_IDS = 16_384
MAX_PROMOTION_PROVENANCE_EVIDENCE_IDS = 16_384
MAX_PROMOTION_SPAN_EVENT_IDS = 256
MAX_PROMOTION_SPAN_EVIDENCE_IDS = 256
MAX_PROMOTION_PRIVATE_VALUES = 512
MAX_PROMOTION_PRIVATE_VALUE_BYTES = 16 * 1024
MAX_PROMOTION_PRIVATE_BYTES = 512 * 1024
PromotionText = Annotated[str, Field(min_length=1, max_length=16_384)]

_SYMBOL_RE = re.compile(r"<([A-Z]+(?:_[A-Z0-9]+)*)>")


def _canonical_size(value: BaseModel) -> int:
    return len(
        json.dumps(
            value.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


_T = TypeVar("_T")


def _require_sorted_unique(values: tuple[_T, ...], field_name: str) -> tuple[_T, ...]:
    if len(values) != len(set(values)) or values != tuple(sorted(values, key=str)):
        raise ValueError(f"{field_name} must be sorted and unique")
    return values


class _PromotionModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
        strict=True,
    )

    @field_validator("*", mode="after")
    @classmethod
    def reject_empty_symbolic_tokens(cls, value: object) -> object:
        def visit(item: object) -> None:
            if isinstance(item, str):
                for match in re.finditer(r"<[^>]*>", item):
                    inner = match.group()[1:-1]
                    looks_symbolic = not inner or re.fullmatch(r"[A-Z][A-Z0-9_-]*", inner)
                    if looks_symbolic and _SYMBOL_RE.fullmatch(match.group()) is None:
                        raise ValueError("promotion text contains an invalid symbolic token")
            elif isinstance(item, tuple):
                for nested in item:
                    visit(nested)

        visit(value)
        return value


@dataclass(frozen=True, slots=True, repr=False)
class PromotionSecretInventory:
    flags: tuple[str, ...] = ()
    credentials: tuple[str, ...] = ()
    target_identifiers: tuple[str, ...] = ()
    challenge_identifiers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        groups = (
            self.flags,
            self.credentials,
            self.target_identifiers,
            self.challenge_identifiers,
        )
        values = tuple(item for group in groups for item in group)
        if len(values) > MAX_PROMOTION_PRIVATE_VALUES:
            raise ValueError("private value inventory exceeds its count bound")
        total = 0
        for value in values:
            if not isinstance(value, str) or not value:
                raise ValueError("private value must be a non-empty string")
            size: int | None = None
            with suppress(UnicodeEncodeError):
                size = len(value.encode("utf-8"))
            if size is None:
                raise ValueError("private value must be valid UTF-8")
            if size > MAX_PROMOTION_PRIVATE_VALUE_BYTES:
                raise ValueError("private value exceeds its per-value bound")
            total += size
        if total > MAX_PROMOTION_PRIVATE_BYTES:
            raise ValueError("private value inventory exceeds its byte bound")


class PromotionEvidenceItem(_PromotionModel):
    summary: PromotionText
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=64)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)

    @field_validator("event_ids", "evidence_ids")
    @classmethod
    def validate_ids(cls, value: tuple[object, ...], info) -> tuple[object, ...]:
        return _require_sorted_unique(value, info.field_name)


class PromotionInput(_PromotionModel):
    engagement_id: UUID
    verified_revision: JournalRevision
    verification_event_id: UUID
    display_name: PromotionText
    objective: PromotionText
    context: tuple[PromotionEvidenceItem, ...] = Field(max_length=128)
    decisions: tuple[PromotionEvidenceItem, ...] = Field(max_length=256)
    outcomes: tuple[PromotionEvidenceItem, ...] = Field(max_length=256)
    alternatives: tuple[PromotionEvidenceItem, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def enforce_input_size(self) -> Self:
        if _canonical_size(self) > MAX_PROMOTION_INPUT_BYTES:
            raise ValueError("promotion input exceeds its byte bound")
        return self


class PromotionStepDraft(_PromotionModel):
    ordinal: StrictInt = Field(ge=1, le=512)
    state_before: PromotionText
    observations: tuple[PromotionText, ...] = Field(max_length=64)
    hypotheses: tuple[PromotionText, ...] = Field(max_length=64)
    selected_strategy: PromotionText
    command_examples: tuple[PromotionText, ...] = Field(default=(), max_length=16)
    outcome: PromotionText
    negative_evidence: tuple[PromotionText, ...] = Field(default=(), max_length=64)
    retry_conditions: tuple[PromotionText, ...] = Field(default=(), max_length=64)
    state_after: PromotionText
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=128)

    @field_validator("event_ids", "evidence_ids")
    @classmethod
    def validate_ids(cls, value: tuple[object, ...], info) -> tuple[object, ...]:
        return _require_sorted_unique(value, info.field_name)


class PromotionClaim(_PromotionModel):
    text: PromotionText
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=128)

    @field_validator("event_ids", "evidence_ids")
    @classmethod
    def validate_ids(cls, value: tuple[object, ...], info) -> tuple[object, ...]:
        return _require_sorted_unique(value, info.field_name)


class PromotionClaimRequest(_PromotionModel):
    """Data-only request; repository authority supplies attempt identity and ordinals."""

    verified_revision: JournalRevision
    verification_event_id: UUID
    compiler_version: str = Field(min_length=1, max_length=64)
    extractor_prompt_version: str = Field(min_length=1, max_length=64)
    critic_prompt_version: str = Field(min_length=1, max_length=64)
    repair_prompt_version: str = Field(min_length=1, max_length=64)
    renderer_version: str = Field(min_length=1, max_length=64)
    semantic_compiler_version: str = Field(min_length=1, max_length=64)
    semantic_prompt_versions: tuple[str, ...] = Field(min_length=1, max_length=8)


@dataclass(frozen=True, slots=True, repr=False)
class PromotionClaimOwnership:
    attempt_id: UUID
    claim_event_id: UUID
    _issuer_token: object


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class PromotionSemanticReceipt:
    attempt_id: UUID
    promotion_revision: int
    source_id: str
    foundation_manifest_sha256: str
    artifact_ids: tuple[str, ...]
    _issuer_token: object
    operation_nonce: object = field(default_factory=object)


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class PromotionIndexPendingReceipt:
    attempt_id: UUID
    promotion_revision: int
    source_id: str
    expected_canonical_revision: str
    _issuer_token: object
    operation_nonce: object = field(default_factory=object)


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class PromotionIndexFailureReceipt:
    attempt_id: UUID
    promotion_revision: int
    retry_count: int
    reason_code: Literal["index_rebuild_failed", "index_unavailable"]
    _issuer_token: object
    operation_nonce: object = field(default_factory=object)


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class PromotionPublicationReceipt:
    attempt_id: UUID
    promotion_revision: int
    source_id: str
    case_ids: tuple[str, ...]
    _issuer_token: object
    operation_nonce: object = field(default_factory=object)


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class PromotionCleanupReceipt:
    attempt_id: UUID
    promotion_revision: int
    source_id: str
    canonical_revision: str
    _issuer_token: object
    operation_nonce: object = field(default_factory=object)


@dataclass(frozen=True, slots=True)
class PromotionClaimResult:
    disposition: Literal["created", "resumed", "existing", "retry_exhausted"]
    attempt: PromotionAttemptState | None
    claim_event_id: UUID | None
    revision: JournalRevision
    ownership: PromotionClaimOwnership | None

    def __post_init__(self) -> None:
        owned = self.disposition in {"created", "resumed"}
        exhausted = self.disposition == "retry_exhausted"
        if exhausted != (self.attempt is None and self.claim_event_id is None):
            raise ValueError("promotion claim result has an invalid exhausted shape")
        if owned != (self.ownership is not None):
            raise ValueError("only a created or fresh-runtime resumed claim transfers ownership")
        if self.ownership is not None and (
            self.attempt is None
            or self.claim_event_id is None
            or self.ownership.attempt_id != self.attempt.attempt_id
            or self.ownership.claim_event_id != self.claim_event_id
        ):
            raise ValueError("promotion claim ownership does not match its claim")


class PromotionDraft(_PromotionModel):
    schema_version: Literal["1.0.0"]
    title: PromotionText
    starting_access: PromotionClaim
    applicability: tuple[PromotionClaim, ...] = Field(min_length=1, max_length=64)
    steps: tuple[PromotionStepDraft, ...] = Field(min_length=1, max_length=512)
    alternate_paths: tuple[PromotionClaim, ...] = Field(default=(), max_length=128)
    transferable_properties: tuple[PromotionClaim, ...] = Field(min_length=1, max_length=128)
    non_transferable_properties: tuple[PromotionClaim, ...] = Field(min_length=1, max_length=128)
    generalizability: Literal["none", "low", "medium", "high"]
    generalizability_basis: PromotionClaim
    verified_outcome: PromotionClaim

    @model_validator(mode="after")
    def validate_draft(self) -> Self:
        ordinals = tuple(item.ordinal for item in self.steps)
        if ordinals != tuple(range(1, len(ordinals) + 1)):
            raise ValueError("promotion step ordinals must be consecutive and unique")
        if _canonical_size(self) > MAX_PROMOTION_DRAFT_BYTES:
            raise ValueError("promotion draft exceeds its byte bound")
        return self


class PromotionProvenanceSpan(_PromotionModel):
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=MAX_PROMOTION_SPAN_EVENT_IDS)
    evidence_ids: tuple[EvidenceId, ...] = Field(
        default=(), max_length=MAX_PROMOTION_SPAN_EVIDENCE_IDS
    )

    @field_validator("event_ids", "evidence_ids")
    @classmethod
    def validate_ids(cls, value: tuple[object, ...], info) -> tuple[object, ...]:
        return _require_sorted_unique(value, info.field_name)

    @model_validator(mode="after")
    def validate_lines(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("provenance span lines must be ordered")
        return self


class PromotionProvenanceMap(_PromotionModel):
    schema_version: Literal["1.0.0"] = PROMOTION_PROVENANCE_SCHEMA_VERSION
    engagement_id: UUID
    attempt_id: UUID
    promotion_revision: StrictInt = Field(ge=1)
    verified_revision: JournalRevision
    verification_event_id: UUID
    source_id: PromotionSourceId
    source_relative_path: ConfinedRelativePath
    source_sha256: Sha256Hex
    spans: tuple[PromotionProvenanceSpan, ...] = Field(
        min_length=1, max_length=MAX_PROMOTION_PROVENANCE_SPANS
    )

    @model_validator(mode="after")
    def validate_map(self) -> Self:
        previous_end = 0
        event_count = 0
        evidence_count = 0
        for span in self.spans:
            if span.start_line <= previous_end:
                raise ValueError("provenance spans must be ordered and non-overlapping")
            previous_end = span.end_line
            event_count += len(span.event_ids)
            evidence_count += len(span.evidence_ids)
        if event_count > MAX_PROMOTION_PROVENANCE_EVENT_IDS:
            raise ValueError("provenance event IDs exceed their cumulative bound")
        if evidence_count > MAX_PROMOTION_PROVENANCE_EVIDENCE_IDS:
            raise ValueError("provenance evidence IDs exceed their cumulative bound")
        if _canonical_size(self) > MAX_PROMOTION_PROVENANCE_BYTES:
            raise ValueError("promotion provenance exceeds its byte bound")
        return self


class RenderedPromotionSource(_PromotionModel):
    source_id: PromotionSourceId
    source_namespace: Literal["journal-promotion"] = "journal-promotion"
    promotion_revision: StrictInt = Field(ge=1)
    title: PromotionText
    source_relative_path: ConfinedRelativePath
    markdown: str
    source_sha256: Sha256Hex
    provenance_relative_path: ConfinedRelativePath
    provenance: PromotionProvenanceMap
    provenance_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_rendered_source(self) -> Self:
        markdown_bytes = self.markdown.encode("utf-8")
        if not markdown_bytes or len(markdown_bytes) > MAX_PROMOTION_SOURCE_BYTES:
            raise ValueError("promotion source exceeds its byte bound")
        if sha256(markdown_bytes).hexdigest() != self.source_sha256:
            raise ValueError("promotion source digest does not match its bytes")
        if self.provenance.source_sha256 != self.source_sha256:
            raise ValueError("promotion source digest does not match provenance")
        if self.provenance.source_id != self.source_id:
            raise ValueError("promotion source identity does not match provenance")
        if self.provenance.promotion_revision != self.promotion_revision:
            raise ValueError("promotion revision does not match provenance")
        if self.provenance.source_relative_path != self.source_relative_path:
            raise ValueError("promotion source path does not match provenance")
        line_count = len(self.markdown.splitlines())
        if any(span.end_line > line_count for span in self.provenance.spans):
            raise ValueError("promotion provenance exceeds physical Markdown lines")
        engagement_id = self.provenance.engagement_id
        expected_source_id = (
            f"source-{uuid5(NAMESPACE_URL, f'sedna:journal-promotion:{engagement_id}')}"
        )
        expected_stem = (
            f"engagements/{engagement_id}/promotion/sources/promotion-v{self.promotion_revision}"
        )
        if self.source_id != expected_source_id:
            raise ValueError("promotion source identity does not match engagement")
        if self.source_relative_path != expected_stem + ".md":
            raise ValueError("promotion source path does not match its closed grammar")
        if self.provenance_relative_path != expected_stem + ".provenance.json":
            raise ValueError("promotion provenance path does not match its closed grammar")
        canonical = json.dumps(
            self.provenance.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if sha256(canonical).hexdigest() != self.provenance_sha256:
            raise ValueError("promotion provenance digest does not match its bytes")
        return self


class CommittedPromotionSource(RenderedPromotionSource):
    committed_revision: JournalRevision


class PromotionCriticFinding(_PromotionModel):
    code: Literal[
        "unsupported_claim",
        "invalid_provenance",
        "secret_leak",
        "target_leak",
        "overgeneralization",
        "lost_negative_evidence",
        "missing_retry_condition",
        "missing_applicability",
        "command_presented_as_guaranteed",
    ]
    message: PromotionText
    step_ordinals: tuple[StrictInt, ...] = Field(default=(), max_length=512)

    @field_validator("step_ordinals")
    @classmethod
    def validate_ordinals(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(item < 1 or item > 512 for item in value):
            raise ValueError("critic step ordinal is out of range")
        return _require_sorted_unique(value, "step_ordinals")


class PromotionCriticVerdict(_PromotionModel):
    accepted: bool
    findings: tuple[PromotionCriticFinding, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def validate_acceptance(self) -> Self:
        if self.accepted != (not self.findings):
            raise ValueError("accepted must be true exactly when findings are empty")
        return self


class PromotionCompilationResult(_PromotionModel):
    disposition: Literal["verified", "quarantined", "failed"]
    draft: PromotionDraft | None = None
    critic: PromotionCriticVerdict | None = None
    repair_count: StrictInt = Field(ge=0, le=1)
    failure_code: (
        Literal[
            "transport_failure",
            "invalid_structured_response",
            "invalid_provenance",
            "unsafe_material",
            "critic_rejected",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.disposition == "verified":
            valid = self.draft is not None and self.critic is not None and self.critic.accepted
            valid = valid and self.failure_code is None
        elif self.disposition == "quarantined":
            valid = (
                self.draft is None
                and self.critic is not None
                and not self.critic.accepted
                and self.failure_code == "critic_rejected"
            )
        else:
            valid = self.draft is None and self.failure_code is not None
        if not valid:
            raise ValueError("disposition has an invalid result shape")
        return self


@dataclass(frozen=True, slots=True, repr=False)
class PromotionResult:
    """Closed, private-safe outcome of one promotion invocation."""

    disposition: Literal[
        "promoted",
        "unchanged",
        "in_progress",
        "retrying",
        "retry_exhausted",
        "quarantined",
        "failed",
        "revoked",
    ]
    attempt_id: UUID | None = None
    promotion_revision: int | None = None
    source_id: str | None = None
    case_ids: tuple[str, ...] = ()
    journal_revision: JournalRevision | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.attempt_id is not None and type(self.attempt_id) is not UUID:
            raise TypeError("promotion result attempt_id must be a UUID")
        if self.promotion_revision is not None and (
            type(self.promotion_revision) is not int or self.promotion_revision < 1
        ):
            raise ValueError("promotion result revision must be a positive integer")
        if not isinstance(self.case_ids, tuple) or any(
            type(item) is not str for item in self.case_ids
        ):
            raise TypeError("promotion result case_ids must be a tuple of strings")
