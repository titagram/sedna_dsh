"""Strict, dependency-neutral contracts for versioned engagement state."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

from sedna.knowledge.retrieval import AuthorizationScope, AuthorizationState, TargetKind

if TYPE_CHECKING:
    from sedna.engagement.reporting.models import ReportRef

ENGAGEMENT_MANIFEST_SCHEMA_VERSION = "sedna.engagement-manifest.v1"
EVENT_ENVELOPE_SCHEMA_VERSION = "sedna.journal-event.v1"
ENGAGEMENT_STATE_PROJECTION_SCHEMA_VERSION = "sedna.engagement-state.v1"
LANE_POLICY_VERSION = "sedna.execution-lane.v1"
CORRELATION_POLICY_VERSION = "sedna.tool-correlation.v1"
MAX_JOURNAL_EVENT_BYTES = 65_536
MAX_JOURNAL_BATCH_EVENTS = 512
MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_JOURNAL_EVENTS = 100_000
MAX_REPORT_REVISIONS = 1_024
MAX_ENGAGEMENTS = 10_000
MAX_ENGAGEMENT_DIRECTORY_ENTRIES = 11_000
MAX_EVIDENCE_OBJECTS = 110_000
MAX_EVIDENCE_DIRECTORY_ENTRIES = 120_000
MAX_EVIDENCE_ITEM_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_ENGAGEMENT_BYTES = 4 * 1024 * 1024 * 1024
MAX_JOURNAL_HEAD_BYTES = 16 * 1024
MAX_CREATE_INTENT_BYTES = (
    4 * ((MAX_MANIFEST_BYTES + 2 * (MAX_JOURNAL_EVENT_BYTES + 1) + 2) // 3) + 128 * 1024
)
MAX_PENDING_APPEND_BYTES = (
    4 * ((MAX_JOURNAL_BATCH_EVENTS * (MAX_JOURNAL_EVENT_BYTES + 1) + 2) // 3) + 128 * 1024
)
MAX_TAIL_RECOVERY_INTENT_BYTES = 256 * 1024
MAX_CAPTURE_INTENT_BYTES = 64 * 1024
MAX_RECOVERABLE_TAIL_BYTES = MAX_JOURNAL_EVENT_BYTES
MAX_DERIVED_PROJECTION_BYTES = 64 * 1024 * 1024
MAX_TOOL_NAME_CHARS = 256
MAX_HOST_CORRELATION_ID_CHARS = 512
MAX_TOOL_CALL_ORDINAL = 65_535
MAX_API_CALL_COUNT = 1_000_000
MAX_TOOL_DURATION_MS = 86_400_000
MAX_REQUIRED_PROOFS = 64
MAX_SCOPE_EVENT_BYTES = 60 * 1024
MAX_IN_FLIGHT_CALLS = 512
MAX_SETTLEMENT_PENDING_RANGES = 2_147_483_647
MAX_HOST_RESULT_BYTES = 256 * 1024
MAX_PUBLIC_INVENTORY_ITEMS = 64
MAX_HEALTH_ENTRIES_PER_STORE = 512
MAX_HEALTH_ENTRIES_TOTAL = 4_096
MAX_HEALTH_OCCURRENCES = 2_147_483_647
MAX_STRATEGY_ARCHIVE_RECORDS = 100_000
MAX_STRATEGY_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_STRATEGY_ARCHIVE_PAGE = 256
MAX_STRATEGY_ARCHIVE_RECORD_BYTES = 64 * 1024


class PromotionSagaInProgressError(ValueError):
    """A foreign writer attempted to mutate an engagement during promotion."""

    code = "promotion_saga_in_progress"
    retryable = True


class HostKind(StrEnum):
    HADES = "hades"
    HERMES = "hermes"
    OTHER = "other"


class EngagementStatus(StrEnum):
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED_UNVERIFIED = "closed_unverified"
    CLOSED_VERIFIED = "closed_verified"
    ABANDONED = "abandoned"


class ExecutionLaneKey(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    host_kind: HostKind
    session_id: Annotated[str, Field(min_length=1, max_length=512)]
    task_id: Annotated[str, Field(min_length=1, max_length=512)]

    @classmethod
    def from_host(
        cls,
        *,
        host_kind: HostKind,
        session_id: str,
        task_id: str | None,
    ) -> ExecutionLaneKey:
        clean_session = session_id.strip()
        if not clean_session:
            raise ValueError("session_id is required")
        clean_task = (task_id or "").strip() or f"root:{clean_session}"
        return cls(host_kind=host_kind, session_id=clean_session, task_id=clean_task)

    @field_validator("session_id", "task_id")
    @classmethod
    def reject_surrounding_whitespace(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("lane identifiers cannot contain surrounding whitespace")
        return value

    @property
    def stable_key(self) -> str:
        payload = f"{self.host_kind.value}\0{self.session_id}\0{self.task_id}".encode()
        return f"lane-{sha256(payload).hexdigest()[:32]}"


class ScopeReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    reference_id: Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")]
    kind: Literal["exact_target", "cidr", "hostname", "url_origin", "generic_id"]
    value: Annotated[str, Field(min_length=1, max_length=2048)]


EvidenceId: TypeAlias = Annotated[str, Field(pattern=r"^evidence-sha256-[0-9a-f]{64}$")]
Sha256Hex: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PendingSubjectCursor: TypeAlias = Annotated[str, Field(pattern=r"^pending-[0-9a-f]{64}$")]
PromotionSourceId: TypeAlias = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._:-]*$")
]
PromotionArtifactId: TypeAlias = Annotated[
    str, Field(min_length=1, max_length=256, pattern=r"^[a-z0-9][a-z0-9._:-]*$")
]
PromotionCaseId = PromotionArtifactId


def validate_confined_relative_path(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("confined relative path must be a string")
    if (
        not value
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "\\" in value
    ):
        raise ValueError("invalid confined relative path")
    if value.startswith("/") or value != unicodedata.normalize("NFC", value):
        raise ValueError("invalid confined relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid confined relative path")
    if re.match(r"^[A-Za-z]:", parts[0]):
        raise ValueError("invalid confined relative path")
    if PurePosixPath(value).as_posix() != value:
        raise ValueError("invalid confined relative path")
    return value


ConfinedRelativePath: TypeAlias = Annotated[
    str,
    BeforeValidator(validate_confined_relative_path),
    Field(min_length=1, max_length=4096),
]


class ProofRequirement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    kind: Literal["flag", "access", "custom"]
    description: Annotated[str, Field(min_length=1, max_length=512)]

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("description is required")
        return normalized


class CaptureLimitation(StrEnum):
    PROVIDER_OR_HOST_SECRET_REDACTED = "provider_or_host_secret_redacted_before_persistence"
    HOST_REPORTED_TRUNCATION = "host_reported_truncation"
    EXTERNAL_ARTIFACT_NOT_CAPTURED = "external_artifact_not_captured"


SettlementSafeCode: TypeAlias = Literal[
    "evidence_budget_exhausted",
    "interpretation_incomplete",
    "interpretation_failed",
    "journal_unavailable",
    "journal_corrupt",
    "settlement_unavailable",
]


class JournalRevision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    sequence: StrictInt = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    event_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def _validate_archive_json(
    value: object, *, depth: int = 0, nodes: list[int] | None = None
) -> None:
    """Keep archive payloads data-only and small before they reach durable storage."""
    if depth > 16:
        raise ValueError("strategy archive payload is too deeply nested")
    current_nodes = nodes if nodes is not None else [0]
    current_nodes[0] += 1
    if current_nodes[0] > 4096:
        raise ValueError("strategy archive payload has too many values")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("strategy archive payload contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > 8192:
            raise ValueError("strategy archive payload string exceeds its bound")
        return
    if isinstance(value, list):
        for item in value:
            _validate_archive_json(item, depth=depth + 1, nodes=current_nodes)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise ValueError("strategy archive payload has an invalid key")
            _validate_archive_json(item, depth=depth + 1, nodes=current_nodes)
        return
    raise ValueError("strategy archive payload must contain only JSON data")


class StrategyArchiveRecordDraft(BaseModel):
    """A planning-owned, data-only cold strategy record.

    M6A deliberately treats ``payload`` as bounded opaque JSON: it stores no planning model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    entry_id: UUID
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _payload_is_bounded_json(self) -> Self:
        _validate_archive_json(self.payload)
        encoded = json.dumps(
            self.payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > MAX_STRATEGY_ARCHIVE_RECORD_BYTES:
            raise ValueError("strategy archive record exceeds its byte bound")
        return self


class StrategyArchiveProjectionEnvelope(BaseModel):
    """Header line for the fixed-name M6A strategy archive projection."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_id: Annotated[str, Field(min_length=1, max_length=128)]
    archive_revision: StrictInt = Field(ge=1)
    authoritative_journal_revision: JournalRevision
    entry_count: StrictInt = Field(ge=0, le=MAX_STRATEGY_ARCHIVE_RECORDS)
    entries_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    byte_size: StrictInt = Field(ge=1, le=MAX_STRATEGY_ARCHIVE_BYTES)


class StrategyArchivePage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    envelope: StrategyArchiveProjectionEnvelope
    records: Annotated[
        tuple[StrategyArchiveRecordDraft, ...], Field(max_length=MAX_STRATEGY_ARCHIVE_PAGE)
    ] = ()
    next_after_entry_id: UUID | None = None
    complete: bool
    omitted_entries_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None

    @model_validator(mode="after")
    def _page_cursor_is_consistent(self) -> Self:
        if self.complete != (self.next_after_entry_id is None):
            raise ValueError("strategy archive page cursor is inconsistent")
        if (
            self.records
            and self.next_after_entry_id is not None
            and self.next_after_entry_id != self.records[-1].entry_id
        ):
            raise ValueError("strategy archive next cursor must identify the final record")
        if self.complete != (self.omitted_entries_sha256 is None):
            raise ValueError("strategy archive omitted digest is inconsistent")
        return self


class StrategyArchiveCommitResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    envelope: StrategyArchiveProjectionEnvelope
    file_name: Literal["strategy-archive.jsonl"] = "strategy-archive.jsonl"


def scope_references(scope: AuthorizationScope) -> tuple[ScopeReference, ...]:
    """Expand an already-normalized authorization into stable sorted references."""

    expanded: list[tuple[str, str]] = []
    for target in scope.exact_targets:
        if target.kind is TargetKind.INVALID or target.normalized is None:
            raise ValueError("scope contains an invalid exact target")
        expanded.append(("exact_target", target.normalized))
    expanded.extend(("cidr", value) for value in scope.cidrs)
    expanded.extend(("hostname", value) for value in scope.hostnames)
    expanded.extend(("url_origin", value) for value in scope.url_origins)
    expanded.extend(("generic_id", value) for value in scope.generic_ids)
    references: list[ScopeReference] = []
    for kind, value in sorted(expanded):
        digest = sha256((kind + "\0" + value).encode()).hexdigest()[:32]
        references.append(
            ScopeReference(
                reference_id=f"scope-{digest}",
                kind=kind,
                value=value,
            )
        )
    return tuple(references)


class HostIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    kind: HostKind
    adapter_version: Annotated[str, Field(min_length=1, max_length=128)]


class EngagementManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal[ENGAGEMENT_MANIFEST_SCHEMA_VERSION] = ENGAGEMENT_MANIFEST_SCHEMA_VERSION
    engagement_id: UUID
    display_name: Annotated[str, Field(min_length=1, max_length=256)]
    initial_objective: Annotated[str, Field(min_length=1, max_length=8192)]
    initial_scope: AuthorizationScope
    required_proofs: tuple[ProofRequirement, ...] = Field(
        default=(), max_length=MAX_REQUIRED_PROOFS
    )
    created_at: datetime
    created_by_host: HostIdentity

    @field_validator("display_name", "initial_objective", mode="before")
    @classmethod
    def normalize_display_text(cls, value: Any) -> Any:
        if isinstance(value, str):
            return " ".join(value.split())
        return value

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("created_at must be UTC-aware")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> EngagementManifest:
        if self.initial_scope.state is not AuthorizationState.AUTHORIZED:
            raise ValueError("initial_scope must be authorized")
        if not scope_references(self.initial_scope):
            raise ValueError("initial_scope must contain a target")
        proof_ids = [item.proof_id for item in self.required_proofs]
        if len(set(proof_ids)) != len(proof_ids):
            raise ValueError("required proof_id values must be unique")
        return self


class EvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    evidence_id: EvidenceId
    sha256: Sha256Hex
    size: StrictInt = Field(ge=0, le=MAX_EVIDENCE_ITEM_BYTES)
    media_type: Annotated[str, Field(min_length=1, max_length=256)]
    representation: Annotated[str, Field(min_length=1, max_length=128)]
    relative_path: ConfinedRelativePath
    capture_limitations: tuple[CaptureLimitation, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def validate_reference(self) -> EvidenceReference:
        if self.evidence_id != f"evidence-sha256-{self.sha256}":
            raise ValueError("evidence_id must contain the content digest")
        if len(set(self.capture_limitations)) != len(self.capture_limitations):
            raise ValueError("capture_limitations must be unique")
        ordered = tuple(sorted(self.capture_limitations, key=lambda item: item.value))
        object.__setattr__(self, "capture_limitations", ordered)
        return self


class EvidenceSlice(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    evidence_id: EvidenceId
    offset: StrictInt = Field(ge=0)
    data: bytes
    complete: bool


class HostAdaptedCommandRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    origin: Literal["host_adapted"] = "host_adapted"
    command_template: Annotated[str, Field(min_length=1, max_length=8192)]
    placeholder_names: tuple[Annotated[str, Field(min_length=1, max_length=64)], ...] = Field(
        default=(), max_length=32
    )
    adaptation_note: Annotated[str | None, Field(min_length=1, max_length=2048)] = None
    requires_validation: Literal[True] = True

    @model_validator(mode="after")
    def validate_record(self) -> HostAdaptedCommandRecord:
        if len(set(self.placeholder_names)) != len(self.placeholder_names):
            raise ValueError("placeholder_names must be unique")
        if len(self.model_dump_json().encode("utf-8")) > 16 * 1024:
            raise ValueError("host-adapted command record exceeds 16 KiB")
        return self


class ActiveDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    lane: ExecutionLaneKey
    decision_id: Annotated[str, Field(min_length=1, max_length=512)]
    proposal_id: UUID | None = None
    strategy: Annotated[str, Field(min_length=1, max_length=8192)]
    rationale: Annotated[str, Field(min_length=1, max_length=8192)]
    host_adapted_command: HostAdaptedCommandRecord | None = None


class ClosureBarrier(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    event_id: UUID
    terminal_watermark: StrictInt = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    in_flight_call_ids: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(
        default=(), max_length=MAX_IN_FLIGHT_CALLS
    )
    origin: Literal["manual", "proof_settlement"] = "manual"

    @model_validator(mode="after")
    def validate_calls(self) -> ClosureBarrier:
        if tuple(sorted(set(self.in_flight_call_ids))) != self.in_flight_call_ids:
            raise ValueError("in_flight_call_ids must be sorted and unique")
        return self


class LaneBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    lane: ExecutionLaneKey
    engagement_id: UUID


class PromotionAttemptState(BaseModel):
    """Replay-derived progress for one bounded publication attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    attempt_id: UUID
    attempt_ordinal: Annotated[StrictInt, Field(ge=1)]
    promotion_revision: Annotated[StrictInt, Field(ge=1)]
    idempotency_key: Sha256Hex
    verified_revision: JournalRevision | None = None
    verification_event_id: UUID | None = None
    claim_event_id: UUID | None = None
    claim_expires_at: datetime | None = None
    stage: Literal[
        "requested",
        "candidate_ready",
        "source_committed",
        "semantic_committed",
        "index_pending",
        "retry_failed",
        "promoted",
        "terminated",
        "cancellation_requested",
        "revocation_requested",
        "revoked",
        "superseded",
    ]
    source_id: PromotionSourceId | None = None
    candidate_relative_path: ConfinedRelativePath | None = None
    candidate_sha256: Sha256Hex | None = None
    repair_count: Annotated[StrictInt, Field(ge=0, le=1)] = 0
    artifact_ids: tuple[PromotionArtifactId, ...] = ()
    case_ids: tuple[PromotionCaseId, ...] = ()
    index_retry_count: Annotated[StrictInt, Field(ge=0, le=3)] = 0
    disposition: Literal["promoted", "quarantined", "failed", "abandoned", "cancelled"] | None = (
        None
    )
    reason_code: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    cancellation_request_event_id: UUID | None = None
    revocation_request_event_id: UUID | None = None
    cleanup_event_id: UUID | None = None
    cleanup_canonical_revision: Sha256Hex | None = None
    replacement_attempt_id: UUID | None = None

    @model_validator(mode="after")
    def _validate_task6_stage_ownership(self) -> Self:
        if self.stage == "cancellation_requested" and self.cancellation_request_event_id is None:
            raise ValueError("cancellation request event is required")
        if self.stage in {"revocation_requested", "revoked"} and (
            self.revocation_request_event_id is None or self.source_id is None or not self.case_ids
        ):
            raise ValueError("revocation request fields are required")
        if self.stage == "revoked" and (
            self.cleanup_event_id is None
            or self.cleanup_canonical_revision is None
            or self.disposition != "cancelled"
        ):
            raise ValueError("revoked cleanup fields are required")
        if self.stage == "superseded" and self.replacement_attempt_id is None:
            raise ValueError("superseded replacement attempt is required")
        return self


class PromotionPublicationLineage(BaseModel):
    """Latest successful canonical publication retained by bounded replay."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    attempt_id: UUID
    promotion_revision: Annotated[StrictInt, Field(ge=1)]
    source_id: PromotionSourceId
    case_ids: tuple[PromotionArtifactId, ...] = Field(min_length=1, max_length=4096)


class PromotionState(BaseModel):
    """Bounded durable replay result for promotion publication."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    active_attempt: PromotionAttemptState | None = None
    recent_terminal_attempts: tuple[PromotionAttemptState, ...] = Field(default=(), max_length=64)
    folded_terminal_count: Annotated[StrictInt, Field(ge=0)] = 0
    folded_terminal_sha256: Sha256Hex | None = None
    latest_successful_publication: PromotionPublicationLineage | None = None

    @model_validator(mode="after")
    def _validate_fold(self) -> Self:
        if (self.folded_terminal_count == 0) != (self.folded_terminal_sha256 is None):
            raise ValueError("folded promotion count and digest must be present together")
        if any(item.disposition is None for item in self.recent_terminal_attempts):
            raise ValueError("recent promotion attempts must be terminal")
        if self.active_attempt is not None and self.active_attempt.disposition is not None:
            raise ValueError("active promotion attempt cannot be terminal")
        return self

    @property
    def attempts(self) -> tuple[PromotionAttemptState, ...]:
        if self.active_attempt is None:
            return self.recent_terminal_attempts
        return (*self.recent_terminal_attempts, self.active_attempt)

    @property
    def promoted_source_ids(self) -> tuple[PromotionSourceId, ...]:
        if self.latest_successful_publication is None:
            return ()
        return (self.latest_successful_publication.source_id,)

    @property
    def promoted_case_ids(self) -> tuple[PromotionArtifactId, ...]:
        if self.latest_successful_publication is None:
            return ()
        return self.latest_successful_publication.case_ids


class EngagementState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    revision: JournalRevision
    status: EngagementStatus
    scope_references: tuple[ScopeReference, ...]
    bound_lanes: tuple[LaneBinding, ...] = ()
    active_decisions: tuple[ActiveDecision, ...] = ()
    reports: tuple[ReportRef, ...] = Field(default=(), max_length=MAX_REPORT_REVISIONS)
    active_report: ReportRef | None = None
    promotion: PromotionState = Field(default_factory=PromotionState)
    in_flight_call_ids: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(
        default=(), max_length=MAX_IN_FLIGHT_CALLS
    )
    closure: ClosureBarrier | None = None
    closure_ready: bool = False
    projection_version: Literal[ENGAGEMENT_STATE_PROJECTION_SCHEMA_VERSION] = (
        ENGAGEMENT_STATE_PROJECTION_SCHEMA_VERSION
    )
    journal_healthy: bool = True

    @model_validator(mode="after")
    def validate_state(self) -> EngagementState:
        if tuple(sorted(set(self.in_flight_call_ids))) != self.in_flight_call_ids:
            raise ValueError("in_flight_call_ids must be sorted and unique")
        if self.closure_ready and self.closure is None:
            raise ValueError("closure_ready requires a closure barrier")
        return self


class OrphanEvidencePage(BaseModel):
    """A frozen bounded page of orphan evidence names/digests."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    names: tuple[str, ...] = Field(max_length=256)
    total_count: StrictInt = Field(ge=0, le=MAX_EVIDENCE_OBJECTS)
    next_after_name: str | None = None
    summary: tuple[tuple[Sha256Hex, StrictInt], ...] = ()
