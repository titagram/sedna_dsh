"""Closed payloads and versioned event envelopes for engagement journals."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Annotated, Any, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    TypeAdapter,
    field_validator,
    model_validator,
)

from sedna.engagement.models import (
    CORRELATION_POLICY_VERSION,
    ENGAGEMENT_STATE_PROJECTION_SCHEMA_VERSION,
    EVENT_ENVELOPE_SCHEMA_VERSION,
    MAX_API_CALL_COUNT,
    MAX_EVIDENCE_ITEM_BYTES,
    MAX_HOST_CORRELATION_ID_CHARS,
    MAX_IN_FLIGHT_CALLS,
    MAX_JOURNAL_BATCH_EVENTS,
    MAX_JOURNAL_EVENT_BYTES,
    MAX_JOURNAL_EVENTS,
    MAX_SETTLEMENT_PENDING_RANGES,
    MAX_TOOL_CALL_ORDINAL,
    MAX_TOOL_DURATION_MS,
    MAX_TOOL_NAME_CHARS,
    ConfinedRelativePath,
    EngagementManifest,
    EngagementState,
    EvidenceId,
    EvidenceReference,
    ExecutionLaneKey,
    HostAdaptedCommandRecord,
    JournalRevision,
    PendingSubjectCursor,
    PromotionArtifactId,
    PromotionCaseId,
    PromotionSourceId,
    ScopeReference,
    SettlementSafeCode,
    Sha256Hex,
    scope_references,
)
from sedna.engagement.normalization import NormalizationFailure, SanitizedHostValue
from sedna.knowledge.retrieval import AuthorizationScope, AuthorizationState

if TYPE_CHECKING:
    from sedna.engagement.reporting.models import ReportRef

CONTROL_TOOL_POLICY_VERSION = "sedna.control-tools.v1"
CONTROL_TOOL_NAMES = frozenset(
    {
        "sedna_manage_engagement",
        "sedna_plan_next",
        "sedna_record_decision",
        "sedna_add_source",
        "sedna_learn_local",
        "sedna_retrieve_knowledge",
        "sedna_get_knowledge_artifact",
        "sedna_knowledge_maintenance",
    }
)

CorrelationReason: TypeAlias = Literal[
    "missing_stable_identity",
    "normalization_failed",
]


class CorrelationKind(StrEnum):
    TOOL_CALL_ID = "tool_call_id"
    API_ATTEMPT = "api_attempt"
    UNCERTAIN = "uncertain"


def _bounded_identity(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if len(value) > MAX_HOST_CORRELATION_ID_CHARS:
        raise ValueError(f"{field_name} exceeds its bound")
    normalized = value.strip()
    if not normalized:
        return None
    return normalized


def _bounded_strict_int(
    value: int | None,
    *,
    field_name: str,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{field_name} must be an in-range integer")
    return value


class ToolCorrelation(BaseModel):
    """A bounded correlation decision derived only from sanitized host metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    policy_version: Literal[CORRELATION_POLICY_VERSION] = CORRELATION_POLICY_VERSION
    kind: CorrelationKind
    lane_key: Annotated[str | None, Field(pattern=r"^lane-[0-9a-f]{32}$")] = None
    host_tool_call_id_sha256: Sha256Hex | None = None
    turn_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    api_request_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    api_call_count: StrictInt | None = Field(default=None, ge=0, le=MAX_API_CALL_COUNT)
    tool_call_ordinal: StrictInt | None = Field(default=None, ge=0, le=MAX_TOOL_CALL_ORDINAL)
    tool_name_sha256: Sha256Hex | None = None
    sanitized_argument_sha256: Sha256Hex | None = None
    stable_key: Annotated[str | None, Field(pattern=r"^correlation-[0-9a-f]{64}$")] = None
    deduplication_allowed: bool
    reason: CorrelationReason | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> ToolCorrelation:
        stable = self.kind in {CorrelationKind.TOOL_CALL_ID, CorrelationKind.API_ATTEMPT}
        if stable:
            if not self.deduplication_allowed or self.reason is not None or self.stable_key is None:
                raise ValueError("stable correlation has an invalid shape")
        elif self.deduplication_allowed or self.reason is None or self.stable_key is not None:
            raise ValueError("uncertain correlation has an invalid shape")
        return self

    @property
    def call_id(self) -> str | None:
        if self.stable_key is None:
            return None
        return f"call-{sha256(self.stable_key.encode()).hexdigest()}"

    @classmethod
    def uncertain(cls, reason: CorrelationReason) -> ToolCorrelation:
        return cls(
            kind=CorrelationKind.UNCERTAIN,
            deduplication_allowed=False,
            reason=reason,
        )

    @classmethod
    def from_hook(
        cls,
        *,
        lane: ExecutionLaneKey,
        tool_name: str,
        sanitized_arguments: SanitizedHostValue | NormalizationFailure,
        tool_call_id: str | None = None,
        turn_id: str | None = None,
        api_request_id: str | None = None,
        api_call_count: int | None = None,
        tool_call_ordinal: int | None = None,
    ) -> ToolCorrelation:
        if not isinstance(tool_name, str):
            raise ValueError("tool_name is required")
        if len(tool_name) > MAX_TOOL_NAME_CHARS:
            raise ValueError("tool_name is required and bounded")
        normalized_tool_name = tool_name.strip()
        if not normalized_tool_name:
            raise ValueError("tool_name is required and bounded")
        host_tool_call_id = _bounded_identity(tool_call_id, "tool_call_id")
        normalized_turn = _bounded_identity(turn_id, "turn_id")
        normalized_request = _bounded_identity(api_request_id, "api_request_id")
        normalized_count = _bounded_strict_int(
            api_call_count,
            field_name="api_call_count",
            maximum=MAX_API_CALL_COUNT,
        )
        normalized_ordinal = _bounded_strict_int(
            tool_call_ordinal,
            field_name="tool_call_ordinal",
            maximum=MAX_TOOL_CALL_ORDINAL,
        )
        if not isinstance(sanitized_arguments, (SanitizedHostValue, NormalizationFailure)):
            raise TypeError("sanitized_arguments must be a bounded normalized host value")
        if (
            isinstance(sanitized_arguments, SanitizedHostValue)
            and not sanitized_arguments.has_valid_integrity()
        ):
            sanitized_arguments = NormalizationFailure(reason_code="serialization_failed")

        tool_digest = sha256(normalized_tool_name.encode()).hexdigest()
        argument_digest = (
            sanitized_arguments.canonical_digest
            if isinstance(sanitized_arguments, SanitizedHostValue)
            else None
        )
        common: dict[str, Any] = {
            "lane_key": lane.stable_key,
            "turn_id": normalized_turn,
            "api_request_id": normalized_request,
            "api_call_count": normalized_count,
            "tool_call_ordinal": normalized_ordinal,
            "tool_name_sha256": tool_digest,
            "sanitized_argument_sha256": argument_digest,
        }
        if host_tool_call_id is not None:
            host_digest = sha256(host_tool_call_id.encode()).hexdigest()
            material = f"tool-call-id\0{lane.stable_key}\0{host_tool_call_id}".encode()
            return cls(
                kind=CorrelationKind.TOOL_CALL_ID,
                host_tool_call_id_sha256=host_digest,
                stable_key=f"correlation-{sha256(material).hexdigest()}",
                deduplication_allowed=True,
                **common,
            )
        if argument_digest is None:
            return cls.uncertain("normalization_failed")
        if (
            normalized_turn is not None
            and normalized_request is not None
            and normalized_count is not None
            and normalized_ordinal is not None
        ):
            material = "\0".join(
                (
                    "api-attempt",
                    lane.stable_key,
                    normalized_turn,
                    normalized_request,
                    str(normalized_count),
                    str(normalized_ordinal),
                    normalized_tool_name,
                    argument_digest,
                )
            ).encode()
            return cls(
                kind=CorrelationKind.API_ATTEMPT,
                stable_key=f"correlation-{sha256(material).hexdigest()}",
                deduplication_allowed=True,
                **common,
            )
        return cls(
            kind=CorrelationKind.UNCERTAIN,
            deduplication_allowed=False,
            reason="missing_stable_identity",
            **common,
        )


class SystemCorrelation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    kind: Literal["system"] = "system"
    source: Literal[
        "recovery",
        "proof_settlement",
        "lifecycle",
        "planning",
        "reporting",
        "promotion",
    ]
    operation_id: UUID


class _Payload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")


class EngagementOpenedPayload(_Payload):
    kind: Literal["engagement_opened"] = "engagement_opened"
    scope_references: tuple[ScopeReference, ...]


class EngagementResumedPayload(_Payload):
    kind: Literal["engagement_resumed"] = "engagement_resumed"
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class LaneBoundPayload(_Payload):
    kind: Literal["lane_bound"] = "lane_bound"
    lane: ExecutionLaneKey
    binding_reason: Annotated[str, Field(min_length=1, max_length=2048)]


class LaneUnboundPayload(_Payload):
    kind: Literal["lane_unbound"] = "lane_unbound"
    lane: ExecutionLaneKey
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class ChildLaneLinkedPayload(_Payload):
    kind: Literal["child_lane_linked"] = "child_lane_linked"
    parent_session_id: Annotated[str, Field(min_length=1, max_length=512)]
    child_session_id: Annotated[str, Field(min_length=1, max_length=512)]
    child_subagent_id: Annotated[str, Field(min_length=1, max_length=512)]


class SessionStartedPayload(_Payload):
    kind: Literal["session_started"] = "session_started"
    model: Annotated[str, Field(min_length=1, max_length=512)]
    platform: Annotated[str, Field(min_length=1, max_length=512)]


class SessionCheckpointedPayload(_Payload):
    kind: Literal["session_checkpointed"] = "session_checkpointed"
    completed: bool
    interrupted: bool
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class SessionFinalizedPayload(_Payload):
    kind: Literal["session_finalized"] = "session_finalized"
    reason: Annotated[str, Field(min_length=1, max_length=2048)]
    settlement_status: Literal[
        "not_configured", "complete", "incomplete", "failed", "unavailable"
    ] = "not_configured"
    pending_range_count: StrictInt = Field(default=0, ge=0, le=MAX_SETTLEMENT_PENDING_RANGES)
    next_pending_offset: StrictInt | None = Field(default=None, ge=0, le=MAX_EVIDENCE_ITEM_BYTES)
    next_pending_subject: PendingSubjectCursor | None = None
    pending_inventory_sha256: Sha256Hex | None = None
    safe_code: SettlementSafeCode | None = None

    @model_validator(mode="after")
    def validate_settlement(self) -> SessionFinalizedPayload:
        empty = (
            self.pending_range_count == 0
            and self.next_pending_offset is None
            and self.next_pending_subject is None
            and self.pending_inventory_sha256 is None
        )
        if self.settlement_status in {"not_configured", "complete"}:
            if not empty or self.safe_code is not None:
                raise ValueError("completed settlement must have an empty pending shape")
        elif self.settlement_status == "incomplete":
            if (
                self.pending_range_count <= 0
                or self.pending_inventory_sha256 is None
                or self.safe_code not in {"evidence_budget_exhausted", "interpretation_incomplete"}
            ):
                raise ValueError("incomplete settlement requires bounded pending inventory")
        elif self.settlement_status == "failed":
            if self.safe_code != "interpretation_failed":
                raise ValueError("failed settlement requires interpretation_failed")
            if not empty and (
                self.pending_range_count <= 0 or self.pending_inventory_sha256 is None
            ):
                raise ValueError("failed settlement has an invalid pending shape")
        elif not empty or self.safe_code not in {
            "journal_unavailable",
            "journal_corrupt",
            "settlement_unavailable",
        }:
            raise ValueError("unavailable settlement has an invalid closed shape")
        return self


class ObjectiveChangedPayload(_Payload):
    kind: Literal["objective_changed"] = "objective_changed"
    objective: Annotated[str, Field(min_length=1, max_length=8192)]
    authorization_basis: Annotated[str, Field(min_length=1, max_length=2048)]


class ScopeChangedPayload(_Payload):
    kind: Literal["scope_changed"] = "scope_changed"
    scope: AuthorizationScope
    scope_references: tuple[ScopeReference, ...]
    authorization_basis: Annotated[str, Field(min_length=1, max_length=2048)]

    @model_validator(mode="after")
    def validate_scope(self) -> ScopeChangedPayload:
        if self.scope.state is not AuthorizationState.AUTHORIZED:
            raise ValueError("changed scope must be authorized")
        if self.scope_references != scope_references(self.scope):
            raise ValueError("scope_references must exactly describe scope")
        return self


class DecisionRecordedPayload(_Payload):
    kind: Literal["decision_recorded"] = "decision_recorded"
    decision_id: Annotated[str, Field(min_length=1, max_length=512)]
    proposal_id: UUID | None = None
    strategy: Annotated[str, Field(min_length=1, max_length=8192)]
    rationale: Annotated[str, Field(min_length=1, max_length=8192)]
    host_adapted_command: HostAdaptedCommandRecord | None = None


class AgentDeviationRecordedPayload(_Payload):
    kind: Literal["agent_deviation_recorded"] = "agent_deviation_recorded"
    decision_id: Annotated[str, Field(min_length=1, max_length=512)]
    strategy: Annotated[str, Field(min_length=1, max_length=8192)]
    rationale: Annotated[str, Field(min_length=1, max_length=8192)]


class _EvidencePairPayload(_Payload):
    evidence_id: EvidenceId | None = None
    evidence_attachment_event_id: UUID | None = None

    @model_validator(mode="after")
    def validate_evidence_pair(self) -> _EvidencePairPayload:
        if (self.evidence_id is None) != (self.evidence_attachment_event_id is None):
            raise ValueError("evidence and attachment event IDs must be supplied together")
        return self


class ToolCallStartedPayload(_Payload):
    kind: Literal["tool_call_started"] = "tool_call_started"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    tool_name: Annotated[str, Field(min_length=1, max_length=MAX_TOOL_NAME_CHARS)]
    correlation: ToolCorrelation
    safe_arguments: dict[str, Any]
    argument_evidence_id: EvidenceId | None = None
    argument_attachment_event_id: UUID | None = None
    decision_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None

    @model_validator(mode="after")
    def validate_argument_pair(self) -> ToolCallStartedPayload:
        if (self.argument_evidence_id is None) != (self.argument_attachment_event_id is None):
            raise ValueError("argument evidence and attachment event IDs must be supplied together")
        try:
            encoded = json.dumps(
                self.safe_arguments,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("safe_arguments must be canonical JSON") from exc
        if len(encoded) > MAX_JOURNAL_EVENT_BYTES:
            raise ValueError("safe_arguments exceed the journal event byte bound")
        return self


class ToolCallCompletedPayload(_EvidencePairPayload):
    kind: Literal["tool_call_completed"] = "tool_call_completed"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    correlation: ToolCorrelation
    technical_status: Literal["returned", "blocked", "cancelled", "error", "unknown"]
    duration_ms: StrictInt = Field(ge=0, le=MAX_TOOL_DURATION_MS)
    error_type: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    possible_terminal_evidence: bool = False


class ToolCallTerminatedPayload(_Payload):
    kind: Literal["tool_call_terminated"] = "tool_call_terminated"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    resolution: Literal["timed_out", "abandoned"]
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class EvidenceAttachedPayload(_Payload):
    kind: Literal["evidence_attached"] = "evidence_attached"
    evidence: EvidenceReference


class EvidenceCaptureFailedPayload(_Payload):
    kind: Literal["evidence_capture_failed"] = "evidence_capture_failed"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    capture_role: Literal["arguments", "result"]
    reason_code: Literal[
        "item_quota_exceeded",
        "engagement_quota_exceeded",
        "evidence_object_limit_exceeded",
        "normalization_limit_exceeded",
        "unsupported_value",
        "serialization_failed",
        "external_artifact_unavailable",
    ]
    observed_size: StrictInt | None = Field(default=None, ge=0, le=MAX_EVIDENCE_ITEM_BYTES)
    observed_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def validate_observation(self) -> EvidenceCaptureFailedPayload:
        if (self.observed_size is None) != (self.observed_sha256 is None):
            raise ValueError("observed size and digest must be supplied together")
        quota_reasons = {
            "item_quota_exceeded",
            "engagement_quota_exceeded",
            "evidence_object_limit_exceeded",
        }
        if self.reason_code in quota_reasons and self.observed_size is None:
            raise ValueError("quota failures require a safe observed size and digest")
        if self.reason_code not in quota_reasons and self.observed_size is not None:
            raise ValueError("this failure cannot retain observed material")
        return self


class UnmatchedToolCompletionPayload(_EvidencePairPayload):
    kind: Literal["unmatched_tool_completion"] = "unmatched_tool_completion"
    correlation: ToolCorrelation
    technical_status: Literal["returned", "blocked", "cancelled", "error", "unknown"]
    duration_ms: StrictInt = Field(ge=0, le=MAX_TOOL_DURATION_MS)
    reason_code: Annotated[str, Field(min_length=1, max_length=512)]


class UnplannedActionPayload(_Payload):
    kind: Literal["unplanned_action"] = "unplanned_action"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class ControlToolInvokedPayload(_Payload):
    kind: Literal["control_tool_invoked"] = "control_tool_invoked"
    control_tool: Annotated[str, Field(min_length=1, max_length=MAX_TOOL_NAME_CHARS)]
    policy_version: Literal[CONTROL_TOOL_POLICY_VERSION] = CONTROL_TOOL_POLICY_VERSION
    correlation: ToolCorrelation

    @field_validator("control_tool")
    @classmethod
    def require_control_tool(cls, value: str) -> str:
        if value not in CONTROL_TOOL_NAMES:
            raise ValueError("control_tool is not in the versioned allowlist")
        return value


class ClosureRequestedPayload(_Payload):
    kind: Literal["closure_requested"] = "closure_requested"
    terminal_watermark: StrictInt = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    in_flight_call_ids: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(
        default=(), max_length=MAX_IN_FLIGHT_CALLS
    )
    reason: Annotated[str, Field(min_length=1, max_length=2048)]
    origin: Literal["manual", "proof_settlement"] = "manual"

    @model_validator(mode="after")
    def normalize_calls(self) -> ClosureRequestedPayload:
        if len(set(self.in_flight_call_ids)) != len(self.in_flight_call_ids):
            raise ValueError("in_flight_call_ids must be unique")
        object.__setattr__(self, "in_flight_call_ids", tuple(sorted(self.in_flight_call_ids)))
        return self


class ClosureCancelledPayload(_Payload):
    kind: Literal["closure_cancelled"] = "closure_cancelled"
    closure_event_id: UUID
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class EngagementReopenedPayload(_Payload):
    kind: Literal["engagement_reopened"] = "engagement_reopened"
    reason: Annotated[str, Field(min_length=1, max_length=2048)]
    prior_status: Literal["closing", "closed_unverified", "closed_verified", "abandoned"] | None = (
        None
    )
    proof_revalidation: Literal["retain_rejections", "invalidate_all"] | None = None

    @model_validator(mode="after")
    def validate_versioned_fields(self) -> EngagementReopenedPayload:
        if (self.prior_status is None) != (self.proof_revalidation is None):
            raise ValueError("reopen lifecycle fields must be both present or both absent")
        return self


class EngagementVerifiedPayload(_Payload):
    kind: Literal["engagement_verified"] = "engagement_verified"
    report_id: UUID
    report_revision: int = Field(ge=1)
    verification_kind: Literal["platform", "user"]
    verification_reference: Annotated[str, Field(min_length=1, max_length=2048)]


class FlagRejectedPayload(_Payload):
    kind: Literal["flag_rejected"] = "flag_rejected"
    flag_event_id: UUID
    rejected_value_sha256: Sha256Hex
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class EngagementAbandonedPayload(_Payload):
    kind: Literal["engagement_abandoned"] = "engagement_abandoned"
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


class SourceSuggestedPayload(_Payload):
    kind: Literal["source_suggested"] = "source_suggested"
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    locator: Annotated[str, Field(min_length=1, max_length=4096)]


class RecoveryWarningPayload(_Payload):
    kind: Literal["recovery_warning"] = "recovery_warning"
    reason_code: Annotated[str, Field(min_length=1, max_length=512)]
    evidence_id: EvidenceId


class UncertainCorrelationPayload(_Payload):
    kind: Literal["uncertain_correlation"] = "uncertain_correlation"
    call_id: Annotated[str, Field(min_length=1, max_length=512)]
    reason_code: CorrelationReason


class UserNotePayload(_Payload):
    kind: Literal["user_note"] = "user_note"
    note: Annotated[str, Field(min_length=1, max_length=8192)]


PrivateText: TypeAlias = Annotated[str, Field(min_length=1, max_length=4096)]
ConditionText: TypeAlias = Annotated[str, Field(min_length=1, max_length=512)]
MediaType: TypeAlias = Annotated[str, Field(min_length=1, max_length=255)]
StableRef: TypeAlias = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$",
    ),
]
Confidence: TypeAlias = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]


class JournalCorrectionRecordedPayload(_Payload):
    """Append-only correction of a prior journal claim/event."""

    kind: Literal["journal_correction_recorded"] = "journal_correction_recorded"
    correction_id: UUID
    target_event_id: UUID
    target_claim_ref: StableRef | None = None
    correction_kind: Literal["retraction", "clarification", "supersession"]
    reason_code: Literal[
        "evidence_reassessment",
        "provenance_error",
        "scope_change",
        "operator_review",
        "duplicate_claim",
    ]


class _EventRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    @model_validator(mode="after")
    def normalize_bounded_tuples(self) -> _EventRecord:
        for name in type(self).model_fields:
            value = getattr(self, name)
            if not isinstance(value, tuple):
                continue
            keyed = tuple(
                (
                    json.dumps(item.model_dump(mode="json"), sort_keys=True)
                    if isinstance(item, BaseModel)
                    else str(item),
                    item,
                )
                for item in value
            )
            keys = tuple(key for key, _ in keyed)
            if len(keys) != len(set(keys)):
                raise ValueError(f"{name} must be unique")
            object.__setattr__(self, name, tuple(item for _, item in sorted(keyed)))
        return self


class _PlanningEventPayload(_Payload):
    @model_validator(mode="after")
    def validate_planning_payload_size(self) -> _PlanningEventPayload:
        encoded = json.dumps(
            self.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > 64 * 1024:
            raise ValueError("canonical planning payload exceeds 64 KiB")
        return self


class EvidenceSliceEventRef(_EventRecord):
    evidence_id: EvidenceId
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(gt=0)]
    sha256: Sha256Hex
    media_type: MediaType

    @model_validator(mode="after")
    def validate_range(self) -> EvidenceSliceEventRef:
        if not 0 < self.end - self.start <= 32 * 1024:
            raise ValueError("evidence slice range exceeds its bound")
        return self


class TextFactEventRecord(_EventRecord):
    record_kind: Literal["text_fact"] = "text_fact"
    subject: ConditionText
    value: PrivateText
    polarity: Literal["observed", "not_observed"] = "observed"


class FacetObservationEventRecord(_EventRecord):
    record_kind: Literal["facet"] = "facet"
    dimension: Literal[
        "os_family",
        "os_version",
        "cpu_architecture",
        "execution_environment",
        "service",
        "port",
        "protocol",
        "technology",
        "network_position",
        "security_control",
        "custom",
    ]
    key: ConditionText
    value: Annotated[str, Field(min_length=1, max_length=2048)]
    relation: Literal["observed", "compatible", "incompatible", "unknown"]


class AccessStateDeltaEventRecord(_EventRecord):
    record_kind: Literal["access_state_delta"] = "access_state_delta"
    scope_reference_id: Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")]
    access_kind: Literal[
        "network_reachability",
        "service_access",
        "authenticated_session",
        "shell",
        "user",
        "administrator",
        "root",
        "custom",
    ]
    transition: Literal["gained", "lost", "confirmed", "denied", "unknown"]
    principal_label: ConditionText | None = None
    service_ref: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    privilege_label: ConditionText | None = None


class PrivateValueEventRecord(_EventRecord):
    evidence_slice: EvidenceSliceEventRef
    value_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_value_digest(self) -> PrivateValueEventRecord:
        if self.value_sha256 != self.evidence_slice.sha256:
            raise ValueError("private value digest must match its evidence slice")
        return self


class SecretReferenceEventRecord(_EventRecord):
    record_kind: Literal["secret_reference"] = "secret_reference"
    secret_ref_id: Annotated[str, Field(min_length=1, max_length=512)]
    secret_kind: Literal[
        "username",
        "password",
        "token",
        "hash",
        "private_key",
        "cookie",
        "flag_candidate",
        "other",
    ]
    label: ConditionText
    value: PrivateValueEventRecord
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...],
        Field(max_length=8),
    ] = ()
    service_ref: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    username_ref: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    origin: Literal["engagement_evidence"] = "engagement_evidence"

    @field_validator("scope_reference_ids")
    @classmethod
    def normalize_scope_reference_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("scope_reference_ids must be unique")
        return tuple(sorted(value))


class IncompatibilityObservationEventRecord(_EventRecord):
    record_kind: Literal["incompatibility"] = "incompatibility"
    subject_ref: StableRef
    reason: Annotated[str, Field(min_length=1, max_length=2048)]
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...],
        Field(max_length=8),
    ] = ()
    event_refs: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()

    @field_validator("scope_reference_ids", "event_refs", "knowledge_refs")
    @classmethod
    def normalize_unique_tuple(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("references must be unique")
        return tuple(sorted(value, key=str))


ExtractedObservationEventRecord: TypeAlias = Annotated[
    TextFactEventRecord
    | FacetObservationEventRecord
    | AccessStateDeltaEventRecord
    | SecretReferenceEventRecord
    | IncompatibilityObservationEventRecord,
    Field(discriminator="record_kind"),
]


class ObservationExtractedEventPayload(_PlanningEventPayload):
    kind: Literal["observation_extracted"] = "observation_extracted"
    summary: PrivateText
    observation: ExtractedObservationEventRecord
    confidence: Confidence
    evidence_slices: Annotated[
        tuple[EvidenceSliceEventRef, ...], Field(min_length=1, max_length=64)
    ]
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...],
        Field(max_length=16),
    ] = ()
    interpretation_input_digest: Sha256Hex

    @field_validator("scope_reference_ids")
    @classmethod
    def normalize_scope_reference_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("scope_reference_ids must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_nested_references(self) -> ObservationExtractedEventPayload:
        if (
            isinstance(self.observation, AccessStateDeltaEventRecord)
            and self.observation.scope_reference_id not in self.scope_reference_ids
        ):
            raise ValueError("nested scope must occur in scope_reference_ids")
        if isinstance(self.observation, SecretReferenceEventRecord):
            if not set(self.observation.scope_reference_ids).issubset(self.scope_reference_ids):
                raise ValueError("nested scopes must occur in scope_reference_ids")
            if self.observation.value.evidence_slice not in self.evidence_slices:
                raise ValueError("private value slice must occur in evidence_slices")
        if isinstance(self.observation, IncompatibilityObservationEventRecord) and not set(
            self.observation.scope_reference_ids
        ).issubset(self.scope_reference_ids):
            raise ValueError("nested scopes must occur in scope_reference_ids")
        return self


class HypothesisFormedEventPayload(_PlanningEventPayload):
    kind: Literal["hypothesis_formed"] = "hypothesis_formed"
    statement: PrivateText
    confidence: Confidence
    supporting_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    contradicting_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...],
        Field(max_length=16),
    ] = ()
    interpretation_input_digest: Sha256Hex

    @field_validator("supporting_event_ids", "contradicting_event_ids", "scope_reference_ids")
    @classmethod
    def normalize_unique_tuple(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("references must be unique")
        return tuple(sorted(value, key=str))

    @model_validator(mode="after")
    def validate_event_sets(self) -> HypothesisFormedEventPayload:
        if set(self.supporting_event_ids) & set(self.contradicting_event_ids):
            raise ValueError("supporting and contradicting event ids must be disjoint")
        return self


class MissingInformationIdentifiedEventPayload(_PlanningEventPayload):
    kind: Literal["missing_information_identified"] = "missing_information_identified"
    question: Annotated[str, Field(min_length=1, max_length=2048)]
    reason: PrivateText
    importance: Annotated[int, Field(ge=0, le=100)]
    related_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...],
        Field(max_length=16),
    ] = ()
    interpretation_input_digest: Sha256Hex

    @field_validator("related_event_ids", "scope_reference_ids")
    @classmethod
    def normalize_unique_tuple(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("references must be unique")
        return tuple(sorted(value, key=str))


class OutcomeAssessedEventPayload(_PlanningEventPayload):
    kind: Literal["outcome_assessed"] = "outcome_assessed"
    attachment_event_id: UUID
    terminal_tool_event_id: UUID
    decision_id: UUID | None = None
    tool_call_ids: Annotated[tuple[StableRef, ...], Field(min_length=1, max_length=32)]
    category: Literal[
        "progress",
        "partial_progress",
        "no_effect",
        "negative_evidence",
        "incompatible",
        "execution_error",
        "ambiguous",
    ]
    summary: PrivateText
    strategic_impact: PrivateText
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=64)] = ()
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]
    interpretation_input_digest: Sha256Hex

    @field_validator("tool_call_ids", "evidence_ids", "source_event_ids")
    @classmethod
    def normalize_unique_tuple(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("references must be unique")
        return tuple(sorted(value, key=str))


class PlanningCallMetadataEventRecord(_EventRecord):
    purpose: Literal["observe", "plan", "critic", "repair"]
    provider: Annotated[str, Field(min_length=1, max_length=256)]
    model: Annotated[str, Field(min_length=1, max_length=256)]
    agent_id: Annotated[str, Field(min_length=1, max_length=256)]
    prompt_id: StableRef
    prompt_version: StableRef
    response_schema_version: StableRef
    input_digest: Sha256Hex
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    elapsed_ms: Annotated[int, Field(ge=0)]


class RetryPredicateEventRecord(_EventRecord):
    predicate_id: StableRef
    kind: Literal[
        "fact_present",
        "fact_changed",
        "prerequisite_satisfied",
        "evidence_category_present",
        "credential_available",
        "state_revision_after",
    ]
    subject_ref: StableRef
    expected_symbolic_value: StableRef | None = None
    expected_value_digest: Sha256Hex | None = None
    minimum_material_revision: JournalRevision | None = None
    description: ConditionText

    @model_validator(mode="after")
    def validate_kind_fields(self) -> RetryPredicateEventRecord:
        required = {
            "fact_changed": self.expected_value_digest is not None,
            "evidence_category_present": self.expected_symbolic_value is not None,
            "state_revision_after": self.minimum_material_revision is not None,
        }
        if self.kind in required and not required[self.kind]:
            raise ValueError("retry predicate required field is missing")
        if self.kind == "credential_available" and any(
            value is not None
            for value in (
                self.expected_symbolic_value,
                self.expected_value_digest,
                self.minimum_material_revision,
            )
        ):
            raise ValueError("credential predicate carries only a symbolic subject")
        return self


class StrategyApplicabilityEventRecord(_EventRecord):
    dimension: Literal[
        "os_family",
        "os_version",
        "cpu_architecture",
        "execution_environment",
        "service",
        "access_state",
        "network_position",
        "custom",
    ]
    relation: Literal["required", "compatible", "incompatible", "unknown"]
    value: ConditionText
    event_refs: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def require_grounding(self) -> StrategyApplicabilityEventRecord:
        if self.relation != "unknown" and not (self.event_refs or self.knowledge_refs):
            raise ValueError("non-unknown applicability requires grounding")
        return self


OutcomeValue: TypeAlias = Literal[
    "progress",
    "partial_progress",
    "no_effect",
    "negative_evidence",
    "incompatible",
    "execution_error",
    "ambiguous",
]
StrategyStatusValue: TypeAlias = Literal[
    "available",
    "deferred",
    "blocked",
    "exhausted",
    "completed",
    "archived",
    "superseded",
]
ReconciliationOperationValue: TypeAlias = Literal[
    "retain",
    "update",
    "merge",
    "split",
    "supersede",
    "complete",
    "block",
    "archive",
    "reactivate",
]


class AttemptOutcomeCountEventRecord(_EventRecord):
    category: OutcomeValue
    count: Annotated[int, Field(ge=0)]


class AttemptAggregateEventRecord(_EventRecord):
    total_count: Annotated[int, Field(ge=0)]
    recent_attempt_ids: Annotated[tuple[UUID, ...], Field(max_length=8)] = ()
    outcome_counts: Annotated[tuple[AttemptOutcomeCountEventRecord, ...], Field(max_length=7)] = ()
    first_material_revision: JournalRevision | None = None
    last_material_revision: JournalRevision | None = None
    history_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_counts(self) -> AttemptAggregateEventRecord:
        if sum(item.count for item in self.outcome_counts) != self.total_count:
            raise ValueError("outcome counts must equal total_count")
        has_revisions = (
            self.first_material_revision is not None and self.last_material_revision is not None
        )
        if (self.total_count > 0) != has_revisions:
            raise ValueError("attempt revisions must match total_count")
        return self


class CommandPlaceholderEventRecord(_EventRecord):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    kind: Literal[
        "target",
        "port",
        "username",
        "credential_ref",
        "source_case_credential",
        "wordlist",
        "path",
        "value",
    ]
    binding_policy: Literal["authorized_scope", "host_supplied", "never_auto_bind"]
    role: ConditionText


class CommandBindingEventRecord(_EventRecord):
    placeholder_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    source: Literal[
        "scope_reference",
        "secret_reference",
        "host_supplied",
        "unresolved_source_case",
    ]
    reference_id: StableRef | None = None

    @model_validator(mode="after")
    def validate_reference(self) -> CommandBindingEventRecord:
        if self.source == "unresolved_source_case" and self.reference_id is not None:
            raise ValueError("unresolved source-case binding cannot carry a reference")
        if self.source != "unresolved_source_case" and self.reference_id is None:
            raise ValueError("resolved command binding requires a reference")
        if self.source == "scope_reference" and (
            self.reference_id is None or not self.reference_id.startswith("scope-")
        ):
            raise ValueError("scope binding requires a scope reference")
        return self


class CommandSuggestionEventRecord(_EventRecord):
    command_id: UUID
    origin: Literal["source_example", "model_generated", "host_adapted"]
    capability_hint: StableRef
    purpose: ConditionText
    command_template: Annotated[str, Field(min_length=1, max_length=8192)]
    placeholders: Annotated[tuple[CommandPlaceholderEventRecord, ...], Field(max_length=32)] = ()
    bindings: Annotated[tuple[CommandBindingEventRecord, ...], Field(max_length=32)] = ()
    rendered_preview: Annotated[str, Field(min_length=1, max_length=8192)]
    source_example_id: StableRef | None = None
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()
    requires_validation: Literal[True] = True
    validation_note: ConditionText

    @model_validator(mode="after")
    def validate_command_shape(self) -> CommandSuggestionEventRecord:
        names = {item.name for item in self.placeholders}
        binding_names = {item.placeholder_name for item in self.bindings}
        if names != binding_names:
            raise ValueError("command placeholders and bindings must have exact coverage")
        if (self.origin == "source_example") != (self.source_example_id is not None):
            raise ValueError("source example identity must match command origin")
        if any(item.kind == "source_case_credential" for item in self.placeholders):
            source_case_names = {
                item.name for item in self.placeholders if item.kind == "source_case_credential"
            }
            for binding in self.bindings:
                if (
                    binding.placeholder_name in source_case_names
                    and binding.source != "unresolved_source_case"
                ):
                    raise ValueError("source-case credentials cannot be bound")
        return self


class ExecutionVariantEventRecord(_EventRecord):
    record_kind: Literal["execution_variant"] = "execution_variant"
    variant_id: UUID
    family_id: UUID
    stable_key: StableRef
    title: Annotated[str, Field(min_length=1, max_length=2048)]
    strategic_intent: Annotated[str, Field(min_length=1, max_length=2048)]
    rationale: Annotated[str, Field(min_length=1, max_length=2048)]
    score: Annotated[int, Field(ge=0, le=100)]
    confidence: Confidence
    status: StrategyStatusValue
    prerequisites: Annotated[tuple[ConditionText, ...], Field(max_length=16)] = ()
    applicability: Annotated[
        tuple[StrategyApplicabilityEventRecord, ...], Field(max_length=16)
    ] = ()
    retry_predicates: Annotated[tuple[RetryPredicateEventRecord, ...], Field(max_length=16)] = ()
    attempts: AttemptAggregateEventRecord
    evidence_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=32)] = ()
    supersedes_variant_ids: Annotated[tuple[UUID, ...], Field(max_length=16)] = ()
    last_material_revision: JournalRevision


class StrategyFamilyEventRecord(_EventRecord):
    record_kind: Literal["strategy_family"] = "strategy_family"
    family_id: UUID
    stable_key: StableRef
    title: Annotated[str, Field(min_length=1, max_length=2048)]
    strategic_intent: Annotated[str, Field(min_length=1, max_length=2048)]
    rationale: Annotated[str, Field(min_length=1, max_length=2048)]
    score: Annotated[int, Field(ge=0, le=100)]
    confidence: Confidence
    status: StrategyStatusValue
    prerequisites: Annotated[tuple[ConditionText, ...], Field(max_length=16)] = ()
    applicability: Annotated[
        tuple[StrategyApplicabilityEventRecord, ...], Field(max_length=16)
    ] = ()
    retry_predicates: Annotated[tuple[RetryPredicateEventRecord, ...], Field(max_length=16)] = ()
    variant_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    evidence_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=32)] = ()
    supersedes_family_ids: Annotated[tuple[UUID, ...], Field(max_length=8)] = ()
    last_material_revision: JournalRevision


class StrategyTombstoneEventRecord(_EventRecord):
    record_kind: Literal["strategy_tombstone"] = "strategy_tombstone"
    entity_kind: Literal["family", "variant"]
    entity_id: UUID
    replacement_ids: Annotated[tuple[UUID, ...], Field(max_length=16)] = ()
    reason: Annotated[str, Field(min_length=1, max_length=2048)]


StrategyResultSnapshot: TypeAlias = Annotated[
    StrategyFamilyEventRecord | ExecutionVariantEventRecord | StrategyTombstoneEventRecord,
    Field(discriminator="record_kind"),
]


class FrontierProposalEventRecord(_EventRecord):
    proposal_id: UUID
    rank: Annotated[int, Field(ge=1, le=8)]
    family_id: UUID | None = None
    variant_id: UUID | None = None
    title: Annotated[str, Field(min_length=1, max_length=2048)]
    strategic_intent: Annotated[str, Field(min_length=1, max_length=2048)]
    rationale: Annotated[str, Field(min_length=1, max_length=2048)]
    score: Annotated[int, Field(ge=0, le=100)]
    confidence: Confidence
    prerequisites: Annotated[tuple[ConditionText, ...], Field(max_length=16)] = ()
    expected_information_gain: Annotated[str, Field(min_length=1, max_length=2048)]
    expected_evidence: Annotated[tuple[ConditionText, ...], Field(max_length=16)] = ()
    stop_conditions: Annotated[tuple[ConditionText, ...], Field(max_length=16)] = ()
    event_refs: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()
    scope_reference_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^scope-[0-9a-f]{32}$")], ...], Field(max_length=8)
    ] = ()
    commands: Annotated[tuple[CommandSuggestionEventRecord, ...], Field(max_length=1)] = ()

    @model_validator(mode="after")
    def validate_ancestry_and_commands(self) -> FrontierProposalEventRecord:
        if self.variant_id is not None and self.family_id is None:
            raise ValueError("variant proposal requires family ancestry")
        if any(command.origin == "host_adapted" for command in self.commands):
            raise ValueError("planner frontier cannot persist host-adapted commands")
        return self


class ArchivedStrategyEventRecord(_EventRecord):
    archive_entry_id: UUID
    snapshot: Annotated[
        StrategyFamilyEventRecord | ExecutionVariantEventRecord, Field(discriminator="record_kind")
    ]
    archive_reason: Annotated[str, Field(min_length=1, max_length=2048)]
    retry_predicates: Annotated[tuple[RetryPredicateEventRecord, ...], Field(max_length=16)] = ()
    archive_summary: PrivateText
    archived_at_material_revision: JournalRevision
    source_reconciliation_event_id: UUID
    archive_entry_digest: Sha256Hex


class StrategyReconciliationEventOperation(_EventRecord):
    operation_id: UUID
    operation: ReconciliationOperationValue
    family_id: UUID
    variant_id: UUID | None = None
    related_family_ids: Annotated[tuple[UUID, ...], Field(max_length=8)] = ()
    related_variant_ids: Annotated[tuple[UUID, ...], Field(max_length=16)] = ()
    reason: Annotated[str, Field(min_length=1, max_length=2048)]
    evidence_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    knowledge_refs: Annotated[tuple[StableRef, ...], Field(max_length=32)] = ()

    @model_validator(mode="after")
    def validate_grounding(self) -> StrategyReconciliationEventOperation:
        if self.operation != "retain" and not (self.evidence_event_ids or self.knowledge_refs):
            raise ValueError("semantic reconciliation change requires grounding")
        return self


class ObjectiveProofObservedEventPayload(_PlanningEventPayload):
    kind: Literal["objective_proof_observed"] = "objective_proof_observed"
    proof_requirement_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    assessment_generation: Annotated[int, Field(ge=1)]
    assessment: Literal["supported", "contradicted"]
    candidate_value: PrivateValueEventRecord
    confidence: Confidence
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    interpretation_input_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_candidate_evidence(self) -> ObjectiveProofObservedEventPayload:
        if self.candidate_value.evidence_slice.evidence_id not in self.evidence_ids:
            raise ValueError("candidate evidence slice must occur in evidence_ids")
        return self


class InterpretationSucceededEventPayload(_PlanningEventPayload):
    kind: Literal["interpretation_succeeded"] = "interpretation_succeeded"
    interpretation_id: UUID
    attachment_event_id: UUID
    terminal_tool_event_id: UUID | None = None
    evidence_id: EvidenceId
    covered_slices: Annotated[tuple[EvidenceSliceEventRef, ...], Field(max_length=64)]
    emitted_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)]
    call_metadata: PlanningCallMetadataEventRecord
    call_input_digest: Sha256Hex
    call_output_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_slice_evidence(self) -> InterpretationSucceededEventPayload:
        if any(item.evidence_id != self.evidence_id for item in self.covered_slices):
            raise ValueError("covered slices must use evidence_id")
        return self


class InterpretationFailedEventPayload(_PlanningEventPayload):
    kind: Literal["interpretation_failed"] = "interpretation_failed"
    interpretation_id: UUID
    attachment_event_id: UUID
    terminal_tool_event_id: UUID | None = None
    evidence_id: EvidenceId
    attempted_slices: Annotated[tuple[EvidenceSliceEventRef, ...], Field(max_length=64)]
    failure_code: Literal[
        "llm_unavailable",
        "invalid_structured_output",
        "reference_validation_failed",
        "concurrent_state_change",
        "unsupported_media",
    ]
    retryable: bool
    safe_summary: Annotated[str, Field(min_length=1, max_length=2048)]
    call_metadata: PlanningCallMetadataEventRecord | None = None
    call_input_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_failure_policy(self) -> InterpretationFailedEventPayload:
        unsupported = self.failure_code == "unsupported_media"
        if unsupported:
            if self.retryable or self.attempted_slices or self.call_metadata is not None:
                raise ValueError("unsupported_media must be terminal without an LLM call")
        elif not self.retryable or not self.attempted_slices:
            raise ValueError("interpretation failures require retryable positive slices")
        if any(item.evidence_id != self.evidence_id for item in self.attempted_slices):
            raise ValueError("attempted slices must use evidence_id")
        return self


class PlanRequestedEventPayload(_PlanningEventPayload):
    kind: Literal["plan_requested"] = "plan_requested"
    request_id: UUID
    lane_key: Annotated[str, Field(pattern=r"^lane-[0-9a-f]{32}$")]
    situation_digest: Sha256Hex
    material_event_revision: JournalRevision
    input_ledger_digest: Sha256Hex
    canonical_revision: Sha256Hex
    source_registry_digest: Sha256Hex
    max_proposals: Annotated[int, Field(ge=3, le=8)]
    hindsight_candidate_ids: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()
    hindsight_query_digests: Annotated[tuple[Sha256Hex, ...], Field(max_length=16)] = ()
    request_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_request_digest(self) -> PlanRequestedEventPayload:
        if len(self.hindsight_candidate_ids) != len(self.hindsight_query_digests):
            raise ValueError("hindsight telemetry ids and query digests must align")
        if self.hindsight_candidate_ids != tuple(sorted(set(self.hindsight_candidate_ids))):
            raise ValueError("hindsight candidate ids must be sorted and unique")
        canonical = self.model_dump(
            mode="json", exclude={"kind", "request_digest"}, warnings="error"
        )
        expected = sha256(
            json.dumps(
                canonical,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        accepted_digests = {expected}
        if not self.hindsight_candidate_ids and not self.hindsight_query_digests:
            legacy = dict(canonical)
            legacy.pop("hindsight_candidate_ids")
            legacy.pop("hindsight_query_digests")
            accepted_digests.add(
                sha256(
                    json.dumps(
                        legacy,
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()
            )
        if self.request_digest not in accepted_digests:
            raise ValueError("request_digest does not match canonical request")
        return self


class FrontierProposedEventPayload(_PlanningEventPayload):
    kind: Literal["frontier_proposed"] = "frontier_proposed"
    request_id: UUID
    frontier_id: UUID
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)]
    proposal_count: Annotated[int, Field(ge=1, le=8)]
    proposal: FrontierProposalEventRecord
    situation_digest: Sha256Hex
    input_ledger_digest: Sha256Hex
    knowledge_context_digest: Sha256Hex
    draft_digest: Sha256Hex
    call_metadata: PlanningCallMetadataEventRecord
    planner_call_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_ordinal(self) -> FrontierProposedEventPayload:
        if (
            self.proposal_ordinal > self.proposal_count
            or self.proposal.rank != self.proposal_ordinal
        ):
            raise ValueError("proposal ordinal must match rank and count")
        return self


class FrontierCriticizedEventPayload(_PlanningEventPayload):
    kind: Literal["frontier_criticized"] = "frontier_criticized"
    request_id: UUID
    frontier_id: UUID
    critic_pass: Literal[1, 2]
    accepted: bool
    finding_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...], Field(max_length=32)
    ] = ()
    cited_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    call_metadata: PlanningCallMetadataEventRecord
    call_input_digest: Sha256Hex
    call_output_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_acceptance(self) -> FrontierCriticizedEventPayload:
        if self.accepted != (not self.finding_codes):
            raise ValueError("accepted iff finding_codes is empty")
        return self


class FrontierRepairedEventPayload(_PlanningEventPayload):
    kind: Literal["frontier_repaired"] = "frontier_repaired"
    request_id: UUID
    frontier_id: UUID
    repair_attempt: Literal[1] = 1
    critic_event_id: UUID
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)]
    proposal_count: Annotated[int, Field(ge=1, le=8)]
    proposal: FrontierProposalEventRecord
    repaired_draft_digest: Sha256Hex
    call_metadata: PlanningCallMetadataEventRecord
    call_input_digest: Sha256Hex
    call_output_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_ordinal(self) -> FrontierRepairedEventPayload:
        if (
            self.proposal_ordinal > self.proposal_count
            or self.proposal.rank != self.proposal_ordinal
        ):
            raise ValueError("proposal ordinal must match rank and count")
        return self


class FrontierRejectedEventPayload(_PlanningEventPayload):
    kind: Literal["frontier_rejected"] = "frontier_rejected"
    request_id: UUID
    frontier_id: UUID
    critic_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=2)]
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(min_length=1, max_length=32),
    ]
    rejected_draft_digest: Sha256Hex


class PlanningGapRecordedEventPayload(_PlanningEventPayload):
    kind: Literal["planning_gap_recorded"] = "planning_gap_recorded"
    request_id: UUID | None = None
    code: Literal[
        "planner_input_too_large",
        "journal_payload_too_large",
        "concurrent_state_change",
        "invalid_planner_output",
        "llm_unavailable",
        "critic_rejected",
        "retrieval_unavailable",
        "journal_unavailable",
        "engagement_terminal",
    ]
    summary: Annotated[str, Field(min_length=1, max_length=2048)]
    retryable: bool
    situation_digest: Sha256Hex
    ledger_digest: Sha256Hex
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()


class StrategyReconciledEventPayload(_PlanningEventPayload):
    kind: Literal["strategy_reconciled"] = "strategy_reconciled"
    request_id: UUID
    frontier_id: UUID
    reconciliation_id: UUID
    item_ordinal: Annotated[int, Field(ge=1, le=256)]
    item_count: Annotated[int, Field(ge=1, le=256)]
    input_ledger_digest: Sha256Hex
    resulting_ledger_digest: Sha256Hex
    operation: StrategyReconciliationEventOperation
    resulting_snapshot: StrategyResultSnapshot
    reconciliation_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_ordinal(self) -> StrategyReconciledEventPayload:
        if self.item_ordinal > self.item_count:
            raise ValueError("item ordinal exceeds count")
        return self


class StrategyArchivedEventPayload(_PlanningEventPayload):
    kind: Literal["strategy_archived"] = "strategy_archived"
    request_id: UUID
    archive_batch_id: UUID
    entry_ordinal: Annotated[int, Field(ge=1, le=256)]
    entry_count: Annotated[int, Field(ge=1, le=256)]
    archive_record: ArchivedStrategyEventRecord
    resulting_archive_digest: Sha256Hex

    @model_validator(mode="after")
    def validate_ordinal(self) -> StrategyArchivedEventPayload:
        if self.entry_ordinal > self.entry_count:
            raise ValueError("entry ordinal exceeds count")
        return self


class StrategyReactivatedEventPayload(_PlanningEventPayload):
    kind: Literal["strategy_reactivated"] = "strategy_reactivated"
    request_id: UUID
    reactivation_batch_id: UUID
    entry_ordinal: Annotated[int, Field(ge=1, le=256)]
    entry_count: Annotated[int, Field(ge=1, le=256)]
    source_archive_event_id: UUID
    triggering_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    matched_predicate_ids: Annotated[tuple[StableRef, ...], Field(min_length=1, max_length=16)]
    prior_archive_entry_digest: Sha256Hex
    resulting_archive_digest: Sha256Hex
    restored_snapshot: Annotated[
        StrategyFamilyEventRecord | ExecutionVariantEventRecord, Field(discriminator="record_kind")
    ]

    @model_validator(mode="after")
    def validate_ordinal(self) -> StrategyReactivatedEventPayload:
        if self.entry_ordinal > self.entry_count:
            raise ValueError("entry ordinal exceeds count")
        return self


class WriteupAuthorizationScope(BaseModel):
    """Narrow target-and-technique scope for one class of writeup source."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_class: Literal["machine_writeup", "challenge_writeup"]
    target_terms: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(min_length=1, max_length=8),
    ]
    technique_terms: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(min_length=1, max_length=8),
    ]

    @model_validator(mode="after")
    def validate_specific_terms(self) -> WriteupAuthorizationScope:
        generic = {
            "attack",
            "box",
            "challenge",
            "ctf",
            "exploit",
            "guide",
            "guides",
            "hackthebox",
            "host",
            "htb",
            "lab",
            "machine",
            "method",
            "platform",
            "procedure",
            "solution",
            "solutions",
            "system",
            "target",
            "technique",
            "tutorial",
            "tutorials",
            "vulnerability",
            "walkthrough",
            "walkthroughs",
            "walk-through",
            "walk-throughs",
            "walk through",
            "walk throughs",
            "writeup",
            "writeups",
            "write-up",
            "write-ups",
            "write up",
            "write ups",
        }
        for values in (self.target_terms, self.technique_terms):
            normalized = tuple(" ".join(value.lower().split()) for value in values)
            if values != normalized or values != tuple(sorted(set(values))):
                raise ValueError(
                    "writeup authorization terms must be normalized, sorted, and unique"
                )
            if not any(value not in generic for value in values):
                raise ValueError("writeup authorization scope requires specific terms")
            if any(value in generic for value in values):
                raise ValueError("writeup authorization scope terms cannot be generic")
        if set(self.target_terms) & set(self.technique_terms):
            raise ValueError("writeup authorization target and technique terms must be disjoint")
        return self


class WriteupAuthorizationGrant(BaseModel):
    """Explicit user grant required before consulting any writeup source."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    authorized_by: Annotated[str, Field(min_length=1, max_length=256)]
    authorized_at: Annotated[
        str,
        Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"),
    ]
    authorization_reference: Annotated[str, Field(min_length=1, max_length=512)]
    scope: Annotated[
        tuple[WriteupAuthorizationScope, ...],
        Field(min_length=1, max_length=16),
    ]

    @model_validator(mode="after")
    def validate_scope(self) -> WriteupAuthorizationGrant:
        keys = tuple(
            (item.source_class, item.target_terms, item.technique_terms) for item in self.scope
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("writeup authorization scope must be sorted and unique")
        return self


class ResearchQueryProposedEventPayload(_PlanningEventPayload):
    kind: Literal["research_query_proposed"] = "research_query_proposed"
    query_id: UUID
    normalized_query: Annotated[str, Field(min_length=1, max_length=2048)]
    query_digest: Sha256Hex
    policy_decision: Literal["allowed", "rejected"]
    policy_version: StableRef
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(min_length=1, max_length=16),
    ]
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    candidate_source_ids: Annotated[tuple[StableRef, ...], Field(max_length=16)] = ()
    writeup_authorization: WriteupAuthorizationGrant | None = None

    @model_validator(mode="after")
    def validate_query_digest(self) -> ResearchQueryProposedEventPayload:
        if self.query_digest != sha256(self.normalized_query.encode("utf-8")).hexdigest():
            raise ValueError("query_digest does not match normalized_query")
        explicitly_authorized = "explicit_writeup_authorization" in self.reason_codes
        if explicitly_authorized != (self.writeup_authorization is not None):
            raise ValueError("writeup authorization metadata does not match policy decision")
        return self


class ResearchSourceConsultedEventPayload(_PlanningEventPayload):
    kind: Literal["research_source_consulted"] = "research_source_consulted"
    query_id: UUID
    source_id: StableRef
    normalized_locator: Annotated[str, Field(min_length=1, max_length=2048)]
    locator_digest: Sha256Hex
    content_digest: Sha256Hex
    media_type: MediaType
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    tool_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_locator_digest(self) -> ResearchSourceConsultedEventPayload:
        if self.locator_digest != sha256(self.normalized_locator.encode("utf-8")).hexdigest():
            raise ValueError("locator_digest does not match normalized_locator")
        return self


class ResearchSourceAssessedEventPayload(_PlanningEventPayload):
    kind: Literal["research_source_assessed"] = "research_source_assessed"
    query_id: UUID
    source_id: StableRef
    consulted_event_id: UUID
    assessment: Literal["useful", "contradicted", "stale", "irrelevant", "ambiguous"]
    confidence: Confidence
    summary: PrivateText
    related_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]
    assessment_digest: Sha256Hex
    suggested_registry_status: Literal["consulted", "useful", "contradicted", "stale"] | None = None

    @model_validator(mode="after")
    def validate_consulted_reference(self) -> ResearchSourceAssessedEventPayload:
        if self.consulted_event_id not in self.related_event_ids:
            raise ValueError("consulted_event_id must occur in related_event_ids")
        canonical = self.model_dump(
            mode="json", exclude={"kind", "assessment_digest"}, warnings="error"
        )
        expected = sha256(
            json.dumps(
                canonical,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if self.assessment_digest != expected:
            raise ValueError("assessment_digest does not match canonical assessment")
        return self


class ReportGeneratedPayload(_Payload):
    kind: Literal["report_generated"] = "report_generated"
    report: ReportRef
    generation_reason: Literal["closure", "repair_json", "manual_report"]


class EngagementClosedPayload(_Payload):
    kind: Literal["engagement_closed"] = "engagement_closed"
    report_id: UUID
    report_revision: int = Field(ge=1)
    closure_request_event_id: UUID
    terminal_watermark: int = Field(ge=0)


class ReportCommitAbandonedPayload(_Payload):
    kind: Literal["report_commit_abandoned"] = "report_commit_abandoned"
    intent_id: UUID
    report_id: UUID
    report_revision: int = Field(ge=1)
    expected_revision: JournalRevision
    json_sha256: Sha256Hex
    markdown_sha256: Sha256Hex
    orphan_directory: ConfinedRelativePath
    displaced_batch_count: int = Field(ge=1, le=MAX_JOURNAL_BATCH_EVENTS - 1)
    displaced_batch_digest: Sha256Hex


PromotionTerminationReason: TypeAlias = Literal[
    "transport_failure",
    "invalid_structured_response",
    "invalid_provenance",
    "unsafe_material",
    "critic_rejected",
    "required_case_missing",
    "source_commit_failed",
    "semantic_quarantined",
    "semantic_failure",
    "promotion_stage_too_large",
    "canonical_unavailable",
    "recovery_conflict",
    "lease_abandoned",
    "promotion_asset_invalid",
    "verification_revoked",
    "engagement_reopened",
]


class RevocationLifecycleIntent(BaseModel):
    """Durable, self-authenticating lifecycle authority for promotion cleanup."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    operation: Literal["reject", "reopen"]
    lane: ExecutionLaneKey
    reopen_reason: Annotated[str, Field(min_length=1, max_length=2048)]
    prior_status: Literal["closed_verified"] = "closed_verified"
    proof_revalidation: Literal["retain_rejections", "invalidate_all"]
    receipt_authoritative_revision: JournalRevision | None = None
    situation_sha256: Sha256Hex | None = None
    proof_requirement_id: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    assessment_generation: int | None = Field(default=None, ge=1)
    flag_event_id: UUID | None = None
    rejected_value_sha256: Sha256Hex | None = None
    intent_sha256: Sha256Hex

    @classmethod
    def canonical_digest(cls, value: RevocationLifecycleIntent) -> str:
        payload = value.model_dump(mode="json", warnings="error")
        payload.pop("intent_sha256", None)
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sha256(canonical).hexdigest()

    @classmethod
    def build(cls, **values: Any) -> RevocationLifecycleIntent:
        provisional = cls.model_construct(intent_sha256="0" * 64, **values)
        return cls(intent_sha256=cls.canonical_digest(provisional), **values)

    @model_validator(mode="after")
    def validate_intent(self) -> RevocationLifecycleIntent:
        receipt_fields = (
            self.receipt_authoritative_revision,
            self.situation_sha256,
            self.proof_requirement_id,
            self.assessment_generation,
            self.flag_event_id,
            self.rejected_value_sha256,
        )
        if self.operation == "reject":
            if self.proof_revalidation != "retain_rejections" or any(
                item is None for item in receipt_fields
            ):
                raise ValueError("reject revocation intent requires the complete proof receipt")
        elif self.proof_revalidation != "invalidate_all" or any(
            item is not None for item in receipt_fields
        ):
            raise ValueError("reopen revocation intent forbids proof receipt fields")
        if self.intent_sha256 != self.canonical_digest(self):
            raise ValueError("revocation lifecycle intent digest does not match")
        return self


class PromotionRequestedPayload(_Payload):
    kind: Literal["promotion_requested"] = "promotion_requested"
    attempt_id: UUID
    attempt_ordinal: int = Field(ge=1, le=3)
    promotion_revision: int = Field(ge=1)
    idempotency_key: Sha256Hex
    verified_revision: JournalRevision
    verification_event_id: UUID
    compiler_version: str = Field(min_length=1, max_length=64)
    extractor_prompt_version: str = Field(min_length=1, max_length=64)
    critic_prompt_version: str = Field(min_length=1, max_length=64)
    repair_prompt_version: str = Field(min_length=1, max_length=64)
    renderer_version: str = Field(min_length=1, max_length=64)
    semantic_compiler_version: str = Field(min_length=1, max_length=64)
    semantic_prompt_versions: tuple[str, ...] = Field(min_length=1, max_length=8)
    claim_expires_at: datetime


class PromotionCandidateReadyPayload(_Payload):
    kind: Literal["promotion_candidate_ready"] = "promotion_candidate_ready"
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    candidate_relative_path: ConfinedRelativePath
    candidate_sha256: Sha256Hex
    repair_count: int = Field(ge=0, le=1)


class PromotionSourceCommittedPayload(_Payload):
    kind: Literal["promotion_source_committed"] = "promotion_source_committed"
    attempt_id: UUID
    source_id: PromotionSourceId
    promotion_revision: int = Field(ge=1)
    source_relative_path: ConfinedRelativePath
    source_sha256: Sha256Hex
    provenance_relative_path: ConfinedRelativePath
    provenance_sha256: Sha256Hex
    verified_revision: JournalRevision
    verification_event_id: UUID


class PromotionSemanticCommittedPayload(_Payload):
    kind: Literal["promotion_semantic_committed"] = "promotion_semantic_committed"
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    source_id: PromotionSourceId
    foundation_manifest_sha256: Sha256Hex
    artifact_ids: tuple[PromotionArtifactId, ...] = Field(min_length=1, max_length=128)


class PromotionIndexPendingPayload(_Payload):
    kind: Literal["promotion_index_pending"] = "promotion_index_pending"
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    source_id: PromotionSourceId
    expected_canonical_revision: Sha256Hex


class PromotionIndexRetryFailedPayload(_Payload):
    kind: Literal["promotion_index_retry_failed"] = "promotion_index_retry_failed"
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    retry_count: int = Field(ge=1, le=3)
    reason_code: Literal["index_rebuild_failed", "index_unavailable"]


class CasePromotedPayload(_Payload):
    kind: Literal["case_promoted"] = "case_promoted"
    attempt_id: UUID
    source_id: PromotionSourceId
    promotion_revision: int = Field(ge=1)
    case_ids: tuple[PromotionCaseId, ...] = Field(min_length=1, max_length=128)


class PromotionAttemptTerminatedPayload(_Payload):
    kind: Literal["promotion_attempt_terminated"] = "promotion_attempt_terminated"
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    disposition: Literal["quarantined", "failed", "abandoned", "cancelled"]
    reason_code: PromotionTerminationReason
    cleanup_source_id: PromotionSourceId | None = None
    cleanup_canonical_revision: Sha256Hex | None = None

    @model_validator(mode="after")
    def validate_cleanup(self) -> PromotionAttemptTerminatedPayload:
        if (self.cleanup_source_id is None) != (self.cleanup_canonical_revision is None):
            raise ValueError("promotion cleanup identity and revision must occur together")
        return self


class PromotionAttemptCancellationRequestedPayload(_Payload):
    kind: Literal["promotion_attempt_cancellation_requested"] = (
        "promotion_attempt_cancellation_requested"
    )
    attempt_id: UUID
    promotion_revision: int = Field(ge=1)
    verification_event_id: UUID
    stage: Literal[
        "requested",
        "candidate_ready",
        "source_committed",
        "semantic_committed",
        "index_pending",
    ]
    reason: Literal["flag_rejected", "reopened"]
    lifecycle_intent: RevocationLifecycleIntent


class PromotionRevocationRequestedPayload(_Payload):
    kind: Literal["promotion_revocation_requested"] = "promotion_revocation_requested"
    attempt_id: UUID
    source_id: PromotionSourceId
    promoted_case_ids: tuple[PromotionCaseId, ...] = Field(min_length=1, max_length=128)
    reason: Literal["flag_rejected", "reopened"]
    lifecycle_intent: RevocationLifecycleIntent


class CasePromotionRevokedPayload(_Payload):
    kind: Literal["case_promotion_revoked"] = "case_promotion_revoked"
    attempt_id: UUID
    source_id: PromotionSourceId
    removed_case_ids: tuple[PromotionCaseId, ...] = Field(min_length=1, max_length=128)
    canonical_revision: Sha256Hex


class CasePromotionSupersededPayload(_Payload):
    kind: Literal["case_promotion_superseded"] = "case_promotion_superseded"
    prior_attempt_id: UUID
    replacement_attempt_id: UUID
    source_id: PromotionSourceId
    removed_case_ids: tuple[PromotionCaseId, ...] = Field(min_length=1, max_length=128)


EventPayload: TypeAlias = Annotated[
    EngagementOpenedPayload
    | EngagementResumedPayload
    | LaneBoundPayload
    | LaneUnboundPayload
    | ChildLaneLinkedPayload
    | SessionStartedPayload
    | SessionCheckpointedPayload
    | SessionFinalizedPayload
    | ObjectiveChangedPayload
    | ScopeChangedPayload
    | DecisionRecordedPayload
    | AgentDeviationRecordedPayload
    | ToolCallStartedPayload
    | ToolCallCompletedPayload
    | ToolCallTerminatedPayload
    | EvidenceAttachedPayload
    | EvidenceCaptureFailedPayload
    | UnmatchedToolCompletionPayload
    | UnplannedActionPayload
    | ControlToolInvokedPayload
    | ClosureRequestedPayload
    | ClosureCancelledPayload
    | EngagementVerifiedPayload
    | FlagRejectedPayload
    | EngagementReopenedPayload
    | EngagementAbandonedPayload
    | SourceSuggestedPayload
    | RecoveryWarningPayload
    | UncertainCorrelationPayload
    | UserNotePayload
    | JournalCorrectionRecordedPayload
    | ObservationExtractedEventPayload
    | HypothesisFormedEventPayload
    | MissingInformationIdentifiedEventPayload
    | OutcomeAssessedEventPayload
    | ObjectiveProofObservedEventPayload
    | InterpretationSucceededEventPayload
    | InterpretationFailedEventPayload
    | PlanRequestedEventPayload
    | FrontierProposedEventPayload
    | FrontierCriticizedEventPayload
    | FrontierRepairedEventPayload
    | FrontierRejectedEventPayload
    | PlanningGapRecordedEventPayload
    | StrategyReconciledEventPayload
    | StrategyArchivedEventPayload
    | StrategyReactivatedEventPayload
    | ResearchQueryProposedEventPayload
    | ResearchSourceConsultedEventPayload
    | ResearchSourceAssessedEventPayload
    | ReportGeneratedPayload
    | EngagementClosedPayload
    | ReportCommitAbandonedPayload
    | PromotionRequestedPayload
    | PromotionCandidateReadyPayload
    | PromotionSourceCommittedPayload
    | PromotionSemanticCommittedPayload
    | PromotionIndexPendingPayload
    | PromotionIndexRetryFailedPayload
    | CasePromotedPayload
    | PromotionAttemptTerminatedPayload
    | PromotionAttemptCancellationRequestedPayload
    | PromotionRevocationRequestedPayload
    | CasePromotionRevokedPayload
    | CasePromotionSupersededPayload,
    Field(discriminator="kind"),
]

EventPayloadAdapter = TypeAdapter(EventPayload)


class EventType(StrEnum):
    ENGAGEMENT_OPENED = "engagement_opened"
    ENGAGEMENT_RESUMED = "engagement_resumed"
    LANE_BOUND = "lane_bound"
    LANE_UNBOUND = "lane_unbound"
    CHILD_LANE_LINKED = "child_lane_linked"
    SESSION_STARTED = "session_started"
    SESSION_CHECKPOINTED = "session_checkpointed"
    SESSION_FINALIZED = "session_finalized"
    OBJECTIVE_CHANGED = "objective_changed"
    SCOPE_CHANGED = "scope_changed"
    DECISION_RECORDED = "decision_recorded"
    AGENT_DEVIATION_RECORDED = "agent_deviation_recorded"
    TOOL_CALL_STARTED = "tool_call_started"
    TOOL_CALL_COMPLETED = "tool_call_completed"
    TOOL_CALL_TERMINATED = "tool_call_terminated"
    EVIDENCE_ATTACHED = "evidence_attached"
    EVIDENCE_CAPTURE_FAILED = "evidence_capture_failed"
    UNMATCHED_TOOL_COMPLETION = "unmatched_tool_completion"
    UNPLANNED_ACTION = "unplanned_action"
    CONTROL_TOOL_INVOKED = "control_tool_invoked"
    CLOSURE_REQUESTED = "closure_requested"
    CLOSURE_CANCELLED = "closure_cancelled"
    ENGAGEMENT_VERIFIED = "engagement_verified"
    FLAG_REJECTED = "flag_rejected"
    ENGAGEMENT_REOPENED = "engagement_reopened"
    ENGAGEMENT_ABANDONED = "engagement_abandoned"
    SOURCE_SUGGESTED = "source_suggested"
    RECOVERY_WARNING = "recovery_warning"
    UNCERTAIN_CORRELATION = "uncertain_correlation"
    USER_NOTE = "user_note"
    JOURNAL_CORRECTION_RECORDED = "journal_correction_recorded"
    OBSERVATION_EXTRACTED = "observation_extracted"
    HYPOTHESIS_FORMED = "hypothesis_formed"
    MISSING_INFORMATION_IDENTIFIED = "missing_information_identified"
    OUTCOME_ASSESSED = "outcome_assessed"
    OBJECTIVE_PROOF_OBSERVED = "objective_proof_observed"
    INTERPRETATION_SUCCEEDED = "interpretation_succeeded"
    INTERPRETATION_FAILED = "interpretation_failed"
    PLAN_REQUESTED = "plan_requested"
    FRONTIER_PROPOSED = "frontier_proposed"
    FRONTIER_CRITICIZED = "frontier_criticized"
    FRONTIER_REPAIRED = "frontier_repaired"
    FRONTIER_REJECTED = "frontier_rejected"
    PLANNING_GAP_RECORDED = "planning_gap_recorded"
    STRATEGY_RECONCILED = "strategy_reconciled"
    STRATEGY_ARCHIVED = "strategy_archived"
    STRATEGY_REACTIVATED = "strategy_reactivated"
    RESEARCH_QUERY_PROPOSED = "research_query_proposed"
    RESEARCH_SOURCE_CONSULTED = "research_source_consulted"
    RESEARCH_SOURCE_ASSESSED = "research_source_assessed"
    REPORT_GENERATED = "report_generated"
    ENGAGEMENT_CLOSED = "engagement_closed"
    REPORT_COMMIT_ABANDONED = "report_commit_abandoned"
    PROMOTION_REQUESTED = "promotion_requested"
    PROMOTION_CANDIDATE_READY = "promotion_candidate_ready"
    PROMOTION_SOURCE_COMMITTED = "promotion_source_committed"
    PROMOTION_SEMANTIC_COMMITTED = "promotion_semantic_committed"
    PROMOTION_INDEX_PENDING = "promotion_index_pending"
    PROMOTION_INDEX_RETRY_FAILED = "promotion_index_retry_failed"
    CASE_PROMOTED = "case_promoted"
    PROMOTION_ATTEMPT_TERMINATED = "promotion_attempt_terminated"
    PROMOTION_ATTEMPT_CANCELLATION_REQUESTED = "promotion_attempt_cancellation_requested"
    PROMOTION_REVOCATION_REQUESTED = "promotion_revocation_requested"
    CASE_PROMOTION_REVOKED = "case_promotion_revoked"
    CASE_PROMOTION_SUPERSEDED = "case_promotion_superseded"


_LANE_REQUIRED_TYPES = frozenset(
    {
        EventType.LANE_BOUND,
        EventType.LANE_UNBOUND,
        EventType.CHILD_LANE_LINKED,
        EventType.SESSION_STARTED,
        EventType.SESSION_CHECKPOINTED,
        EventType.SESSION_FINALIZED,
        EventType.DECISION_RECORDED,
        EventType.AGENT_DEVIATION_RECORDED,
        EventType.TOOL_CALL_STARTED,
        EventType.TOOL_CALL_COMPLETED,
        EventType.TOOL_CALL_TERMINATED,
        EventType.UNMATCHED_TOOL_COMPLETION,
        EventType.EVIDENCE_ATTACHED,
        EventType.EVIDENCE_CAPTURE_FAILED,
        EventType.UNPLANNED_ACTION,
        EventType.CONTROL_TOOL_INVOKED,
        EventType.UNCERTAIN_CORRELATION,
    }
)

_SYSTEM_SOURCE_BY_TYPE: dict[EventType, str] = {
    EventType.ENGAGEMENT_OPENED: "lifecycle",
    EventType.ENGAGEMENT_RESUMED: "lifecycle",
    EventType.OBJECTIVE_CHANGED: "lifecycle",
    EventType.SCOPE_CHANGED: "lifecycle",
    EventType.CLOSURE_CANCELLED: "lifecycle",
    EventType.ENGAGEMENT_VERIFIED: "lifecycle",
    EventType.FLAG_REJECTED: "lifecycle",
    EventType.ENGAGEMENT_REOPENED: "lifecycle",
    EventType.ENGAGEMENT_ABANDONED: "lifecycle",
    EventType.SOURCE_SUGGESTED: "planning",
    EventType.RECOVERY_WARNING: "recovery",
    EventType.OBSERVATION_EXTRACTED: "planning",
    EventType.HYPOTHESIS_FORMED: "planning",
    EventType.MISSING_INFORMATION_IDENTIFIED: "planning",
    EventType.OUTCOME_ASSESSED: "planning",
    EventType.OBJECTIVE_PROOF_OBSERVED: "planning",
    EventType.INTERPRETATION_SUCCEEDED: "planning",
    EventType.INTERPRETATION_FAILED: "planning",
    EventType.PLAN_REQUESTED: "planning",
    EventType.FRONTIER_PROPOSED: "planning",
    EventType.FRONTIER_CRITICIZED: "planning",
    EventType.FRONTIER_REPAIRED: "planning",
    EventType.FRONTIER_REJECTED: "planning",
    EventType.PLANNING_GAP_RECORDED: "planning",
    EventType.STRATEGY_RECONCILED: "planning",
    EventType.STRATEGY_ARCHIVED: "planning",
    EventType.STRATEGY_REACTIVATED: "planning",
    EventType.RESEARCH_QUERY_PROPOSED: "planning",
    EventType.RESEARCH_SOURCE_CONSULTED: "planning",
    EventType.RESEARCH_SOURCE_ASSESSED: "planning",
    EventType.REPORT_GENERATED: "reporting",
    EventType.ENGAGEMENT_CLOSED: "reporting",
    EventType.REPORT_COMMIT_ABANDONED: "recovery",
    EventType.PROMOTION_REQUESTED: "promotion",
    EventType.PROMOTION_CANDIDATE_READY: "promotion",
    EventType.PROMOTION_SOURCE_COMMITTED: "promotion",
    EventType.PROMOTION_SEMANTIC_COMMITTED: "promotion",
    EventType.PROMOTION_INDEX_PENDING: "promotion",
    EventType.PROMOTION_INDEX_RETRY_FAILED: "promotion",
    EventType.CASE_PROMOTED: "promotion",
    EventType.PROMOTION_ATTEMPT_TERMINATED: "promotion",
    EventType.PROMOTION_ATTEMPT_CANCELLATION_REQUESTED: "promotion",
    EventType.PROMOTION_REVOCATION_REQUESTED: "promotion",
    EventType.CASE_PROMOTION_REVOKED: "promotion",
    EventType.CASE_PROMOTION_SUPERSEDED: "promotion",
}


def _validate_envelope(
    *,
    event_type: EventType,
    payload: EventPayload,
    lane: ExecutionLaneKey | None,
    actor: str,
    system_correlation: SystemCorrelation | None,
) -> None:
    if event_type.value != payload.kind:
        raise ValueError("event type must match payload kind")
    if event_type in _LANE_REQUIRED_TYPES and lane is None:
        raise ValueError("this event type requires an execution lane")
    payload_lane = getattr(payload, "lane", None)
    if payload_lane is not None and payload_lane != lane:
        raise ValueError("event lane must exactly match the payload lane")
    expected_source = _SYSTEM_SOURCE_BY_TYPE.get(event_type)
    if (
        event_type is EventType.CLOSURE_REQUESTED
        and isinstance(payload, ClosureRequestedPayload)
        and payload.origin == "proof_settlement"
    ):
        expected_source = "proof_settlement"
    if expected_source is not None:
        if actor != "system" or lane is not None or system_correlation is None:
            raise ValueError(
                "system-owned event requires its typed system correlation without a lane"
            )
        if system_correlation.source != expected_source:
            raise ValueError("system correlation source does not match the event type")
        return
    if actor == "system" or system_correlation is not None:
        raise ValueError("ordinary user or host event cannot use system ownership")
    if actor == "host_agent" and lane is None:
        raise ValueError("host events require an exact execution lane")


def canonical_event_json_bytes(value: object) -> bytes:
    """The ONE canonical serialization for event envelopes and their hashes.

    Every producer and verifier of an event digest must use this function. Three
    divergent serializations previously existed in this codebase; the reducer's
    used ``json.dumps`` defaults (``ensure_ascii=True``) while the repository's
    used ``ensure_ascii=False``. For any non-ASCII content the creation and
    validation digests therefore differed, and every append to such an
    engagement was refused with
    ``EngagementReplayError("event hash does not match its canonical envelope")``.
    """
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("value cannot be canonically serialized") from exc


def canonical_event_envelope(event: JournalEvent) -> object:
    """The envelope material an event hash is computed over (hash excluded)."""
    return event.model_dump(mode="json", warnings="error", exclude={"event_hash"})


def canonical_event_hash(event: JournalEvent) -> str:
    """Compute an event's canonical digest exactly as creation does."""
    return sha256(canonical_event_json_bytes(canonical_event_envelope(event))).hexdigest()


def _canonical_event_line_bytes(event: JournalEvent) -> bytes:
    try:
        return json.dumps(
            event.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("event cannot be canonically serialized") from exc


class JournalEventDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    event_id: UUID | None = None
    lane: ExecutionLaneKey | None = None
    turn_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    actor_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    actor: Annotated[str, Field(min_length=1, max_length=128)]
    type: EventType
    payload: EventPayload
    system_correlation: SystemCorrelation | None = None
    idempotency_key: Annotated[str | None, Field(min_length=1, max_length=1024)] = None

    @model_validator(mode="after")
    def validate_envelope(self) -> JournalEventDraft:
        _validate_envelope(
            event_type=self.type,
            payload=self.payload,
            lane=self.lane,
            actor=self.actor,
            system_correlation=self.system_correlation,
        )
        return self


class JournalEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal[EVENT_ENVELOPE_SCHEMA_VERSION] = EVENT_ENVELOPE_SCHEMA_VERSION
    event_id: UUID
    sequence: StrictInt = Field(ge=1, le=MAX_JOURNAL_EVENTS)
    occurred_at: datetime
    engagement_id: UUID
    previous_hash: Sha256Hex | None = None
    event_hash: Sha256Hex
    lane: ExecutionLaneKey | None = None
    turn_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    actor_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    actor: Annotated[str, Field(min_length=1, max_length=128)]
    type: EventType
    payload: EventPayload
    system_correlation: SystemCorrelation | None = None
    idempotency_key: Annotated[str | None, Field(min_length=1, max_length=1024)] = None

    @field_validator("occurred_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("occurred_at must be UTC-aware")
        return value

    @model_validator(mode="after")
    def validate_envelope(self) -> JournalEvent:
        _validate_envelope(
            event_type=self.type,
            payload=self.payload,
            lane=self.lane,
            actor=self.actor,
            system_correlation=self.system_correlation,
        )
        if self.sequence == 1 and self.previous_hash is not None:
            raise ValueError("the first event cannot have a previous hash")
        if self.sequence > 1 and self.previous_hash is None:
            raise ValueError("later events require a previous hash")
        if len(_canonical_event_line_bytes(self)) > MAX_JOURNAL_EVENT_BYTES:
            raise ValueError("canonical event line exceeds the journal event byte bound")
        return self


class EngagementSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    revision: JournalRevision
    manifest: EngagementManifest
    events: tuple[JournalEvent, ...] = Field(max_length=MAX_JOURNAL_EVENTS)
    state: EngagementState

    @model_validator(mode="after")
    def validate_snapshot(self) -> EngagementSnapshot:
        if self.manifest.engagement_id != self.engagement_id:
            raise ValueError("manifest identity does not match snapshot")
        if self.state.revision != self.revision:
            raise ValueError("state revision does not match snapshot")
        if any(event.engagement_id != self.engagement_id for event in self.events):
            raise ValueError("event identity does not match snapshot")
        if self.events:
            seen_event_ids: set[UUID] = set()
            previous: JournalEvent | None = None
            for expected_sequence, event in enumerate(self.events, start=1):
                if event.sequence != expected_sequence:
                    raise ValueError("event sequence must start at one and be contiguous")
                if event.event_id in seen_event_ids:
                    raise ValueError("event_id values must be unique")
                seen_event_ids.add(event.event_id)
                if previous is not None and event.previous_hash != previous.event_hash:
                    raise ValueError("event previous hash does not match the prior event")
                previous = event
            last = self.events[-1]
            if (last.sequence, last.event_hash) != (
                self.revision.sequence,
                self.revision.event_hash,
            ):
                raise ValueError("revision does not match the event chain")
        elif self.revision.sequence != 0:
            raise ValueError("an empty snapshot requires revision zero")
        if self.state.projection_version != ENGAGEMENT_STATE_PROJECTION_SCHEMA_VERSION:
            raise ValueError("state projection version is not supported")
        return self


__all__ = [name for name in globals() if name.endswith("Payload") and not name.startswith("_")]
__all__ += [
    "CONTROL_TOOL_NAMES",
    "CONTROL_TOOL_POLICY_VERSION",
    "CorrelationKind",
    "EngagementSnapshot",
    "EventPayload",
    "EventType",
    "JournalEvent",
    "JournalEventDraft",
    "SystemCorrelation",
    "ToolCorrelation",
]
