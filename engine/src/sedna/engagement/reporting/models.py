"""Immutable private operational report contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Literal, Self
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sedna.engagement.models import (
    MAX_REPORT_REVISIONS,
    CaptureLimitation,
    ConfinedRelativePath,
    EvidenceId,
    JournalRevision,
    Sha256Hex,
)

if TYPE_CHECKING:
    from sedna.engagement.events import EngagementSnapshot

REPORT_SCHEMA_VERSION = "1.0.0"
REPORT_RENDERER_VERSION = "1"
BoundedPrivateString = Annotated[str, Field(min_length=1, max_length=262_144)]
MAX_REPORT_INLINE_TEXT_BYTES = 65_536
InlineReportText = Annotated[str, Field(min_length=1, max_length=MAX_REPORT_INLINE_TEXT_BYTES)]
MAX_REPORT_JSON_BYTES = 8 * 1024 * 1024
MAX_REPORT_MARKDOWN_BYTES = 16 * 1024 * 1024
MAX_REPORT_TRANSACTION_BYTES = 256 * 1024


class _ReportModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    @model_validator(mode="after")
    def require_unique_references(self) -> Self:
        for field_name in ("event_ids", "evidence_ids"):
            values = getattr(self, field_name, ())
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
        return self


class ReportEvidenceRef(_ReportModel):
    attachment_event_id: UUID
    event_sequence: int = Field(ge=1)
    evidence_id: EvidenceId
    relative_path: ConfinedRelativePath
    sha256: Sha256Hex
    media_type: Annotated[str, Field(min_length=1, max_length=255)]
    representation: Literal["host_text", "host_bytes", "canonical_host_json"]
    capture_limitations: tuple[CaptureLimitation, ...] = Field(default=(), max_length=8)
    size_bytes: int = Field(ge=0, le=1_073_741_824)
    host_truncated: bool = False


class ReportCapturedOutput(_ReportModel):
    disposition: Literal["inline", "evidence", "absent"]
    inline_text: InlineReportText | None = None
    evidence: ReportEvidenceRef | None = None
    absence_reason: (
        Literal[
            "host_returned_no_result",
            "blocked",
            "cancelled",
            "error",
            "timed_out",
            "abandoned",
            "capture_failed",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def require_exact_capture(self) -> Self:
        if self.disposition == "inline" and (
            self.inline_text is None or self.evidence is not None or self.absence_reason is not None
        ):
            raise ValueError("inline output has an invalid shape")
        if self.disposition == "evidence" and (
            self.evidence is None or self.inline_text is not None or self.absence_reason is not None
        ):
            raise ValueError("evidence output has an invalid shape")
        if self.disposition == "absent" and (
            self.absence_reason is None or self.inline_text is not None or self.evidence is not None
        ):
            raise ValueError("absent output has an invalid shape")
        return self


class ReportSession(_ReportModel):
    session_id: Annotated[str, Field(min_length=1, max_length=512)]
    started_at: datetime
    ended_at: datetime | None = None
    objective: BoundedPrivateString | None = None
    event_ids: tuple[UUID, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def require_chronology(self) -> Self:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("session end precedes start")
        return self


class ReportObservation(_ReportModel):
    summary: BoundedPrivateString
    confidence: float = Field(ge=0.0, le=1.0)
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=128)


class ReportHypothesis(_ReportModel):
    statement: BoundedPrivateString
    status: Literal["open", "supported", "weakened", "rejected"]
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportDecision(_ReportModel):
    strategy: BoundedPrivateString
    rationale: BoundedPrivateString
    score: int | None = Field(default=None, ge=0, le=100)
    proposal_id: UUID | None = None
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportFrontierChange(_ReportModel):
    strategy_key: Annotated[str, Field(min_length=1, max_length=512)]
    previous_score: int | None = Field(default=None, ge=0, le=100)
    score: int = Field(ge=0, le=100)
    reason: BoundedPrivateString
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportToolExecution(_ReportModel):
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    tool_name: Annotated[str, Field(min_length=1, max_length=512)]
    suggested_commands: tuple[BoundedPrivateString, ...] = Field(default=(), max_length=64)
    executed_command: BoundedPrivateString | None = None
    outcome: Annotated[str, Field(min_length=1, max_length=128)]
    output: ReportCapturedOutput
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportSecret(_ReportModel):
    kind: Literal["flag", "credential", "token", "other"]
    label: Annotated[str, Field(min_length=1, max_length=512)]
    value: BoundedPrivateString
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportSource(_ReportModel):
    locator: Annotated[str, Field(min_length=1, max_length=4096)]
    query: BoundedPrivateString | None = None
    assessment: BoundedPrivateString
    event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)


class ReportCompletion(_ReportModel):
    objective_satisfied: bool
    final_access: tuple[BoundedPrivateString, ...] = Field(default=(), max_length=256)
    unresolved_issues: tuple[BoundedPrivateString, ...] = Field(default=(), max_length=1024)


class ReportOverflowSummary(_ReportModel):
    section: Literal[
        "sessions",
        "timeline",
        "observations",
        "hypotheses",
        "decisions",
        "frontier_changes",
        "tool_executions",
        "failed_attempts",
        "secrets",
        "sources",
    ]
    omitted_count: int = Field(ge=1)
    first_omitted_sequence: int = Field(ge=1)
    last_omitted_sequence: int = Field(ge=1)
    omitted_event_digest: Sha256Hex


class OperationalReport(_ReportModel):
    schema_version: Literal["1.0.0"] = REPORT_SCHEMA_VERSION
    report_id: UUID
    report_revision: int = Field(ge=1, le=MAX_REPORT_REVISIONS)
    engagement_id: UUID
    display_name: Annotated[str, Field(min_length=1, max_length=256)]
    journal_revision: JournalRevision
    generated_at: datetime
    lifecycle_status: Literal["closed_unverified", "closed_verified"]
    objective: BoundedPrivateString
    scope: tuple[BoundedPrivateString, ...] = Field(min_length=1, max_length=256)
    sessions: tuple[ReportSession, ...] = Field(default=(), max_length=1024)
    timeline: tuple[ReportObservation, ...] = Field(default=(), max_length=8192)
    observations: tuple[ReportObservation, ...] = Field(default=(), max_length=4096)
    hypotheses: tuple[ReportHypothesis, ...] = Field(default=(), max_length=2048)
    decisions: tuple[ReportDecision, ...] = Field(default=(), max_length=4096)
    frontier_changes: tuple[ReportFrontierChange, ...] = Field(default=(), max_length=4096)
    tool_executions: tuple[ReportToolExecution, ...] = Field(default=(), max_length=8192)
    failed_attempts: tuple[ReportToolExecution, ...] = Field(default=(), max_length=8192)
    secrets: tuple[ReportSecret, ...] = Field(default=(), max_length=1024)
    sources: tuple[ReportSource, ...] = Field(default=(), max_length=2048)
    overflow: tuple[ReportOverflowSummary, ...] = Field(default=(), max_length=10)
    completion: ReportCompletion

    @field_validator("generated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("generated_at must be UTC-aware")
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        expected = uuid5(self.engagement_id, f"report:{self.report_revision}")
        if self.report_id != expected:
            raise ValueError("report_id must derive from engagement_id and report_revision")
        call_ids = tuple(item.call_id for item in (*self.tool_executions, *self.failed_attempts))
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("report call_id values must be unique")
        return self


class ReportRef(_ReportModel):
    report_id: UUID
    report_revision: int = Field(ge=1, le=MAX_REPORT_REVISIONS)
    json_relative_path: ConfinedRelativePath
    json_sha256: Sha256Hex
    markdown_relative_path: ConfinedRelativePath
    markdown_sha256: Sha256Hex
    renderer_version: Literal["1"]
    journal_revision: JournalRevision


class ReportCommitResult(_ReportModel):
    report: ReportRef
    snapshot: EngagementSnapshot


__all__ = [
    "BoundedPrivateString",
    "InlineReportText",
    "MAX_REPORT_INLINE_TEXT_BYTES",
    "MAX_REPORT_JSON_BYTES",
    "MAX_REPORT_MARKDOWN_BYTES",
    "MAX_REPORT_REVISIONS",
    "MAX_REPORT_TRANSACTION_BYTES",
    "REPORT_RENDERER_VERSION",
    "REPORT_SCHEMA_VERSION",
    "OperationalReport",
    "ReportCapturedOutput",
    "ReportCommitResult",
    "ReportCompletion",
    "ReportDecision",
    "ReportEvidenceRef",
    "ReportFrontierChange",
    "ReportHypothesis",
    "ReportObservation",
    "ReportOverflowSummary",
    "ReportRef",
    "ReportSecret",
    "ReportSession",
    "ReportSource",
    "ReportToolExecution",
]
