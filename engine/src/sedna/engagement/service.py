"""Stable engagement journal service facade with sealed lifecycle ownership."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.engagement.events import (
    ChildLaneLinkedPayload,
    ClosureCancelledPayload,
    ClosureRequestedPayload,
    DecisionRecordedPayload,
    EngagementAbandonedPayload,
    EngagementOpenedPayload,
    EngagementReopenedPayload,
    EngagementResumedPayload,
    EngagementSnapshot,
    EngagementVerifiedPayload,
    EventPayload,
    EventType,
    FlagRejectedPayload,
    JournalCorrectionRecordedPayload,
    JournalEvent,
    JournalEventDraft,
    LaneBoundPayload,
    ObjectiveChangedPayload,
    ScopeChangedPayload,
    SystemCorrelation,
    ToolCallStartedPayload,
    ToolCallTerminatedPayload,
    ToolCorrelation,
)
from sedna.engagement.models import (
    MAX_EVIDENCE_ITEM_BYTES,
    MAX_JOURNAL_BATCH_EVENTS,
    MAX_JOURNAL_EVENTS,
    MAX_PUBLIC_INVENTORY_ITEMS,
    MAX_SETTLEMENT_PENDING_RANGES,
    MAX_STRATEGY_ARCHIVE_PAGE,
    ActiveDecision,
    AuthorizationScope,
    EngagementManifest,
    EvidenceId,
    EvidenceReference,
    EvidenceSlice,
    ExecutionLaneKey,
    HostAdaptedCommandRecord,
    HostIdentity,
    HostKind,
    JournalRevision,
    PendingSubjectCursor,
    ProofRequirement,
    SettlementSafeCode,
    Sha256Hex,
    StrategyArchiveCommitResult,
    StrategyArchivePage,
    StrategyArchiveRecordDraft,
    scope_references,
)
from sedna.engagement.normalization import (
    bounded_safe_argument_summary,
    sanitize_host_arguments,
)
from sedna.engagement.repository import (
    EngagementAppendAuthorityError,
    EngagementJournalRepository,
    ProjectionOwnershipError,
)

ProjectionT = TypeVar("ProjectionT", bound=BaseModel)

PLANNING_PROJECTION_NAMES = frozenset({"state", "frontier", "strategy-ledger"})
LOADABLE_PROJECTION_NAMES = PLANNING_PROJECTION_NAMES | {"engagement-state"}
EVENT_APPEND_OWNER_BY_TYPE: dict[str, str] = {
    "engagement_opened": "repository_create",
    "engagement_resumed": "lifecycle_service",
    "lane_bound": "lifecycle_service",
    "lane_unbound": "lifecycle_service",
    "child_lane_linked": "lifecycle_service",
    "objective_changed": "lifecycle_service",
    "scope_changed": "lifecycle_service",
    "decision_recorded": "lifecycle_service",
    "agent_deviation_recorded": "lifecycle_service",
    "engagement_verified": "lifecycle_commit_capability",
    "flag_rejected": "lifecycle_commit_capability",
    "engagement_reopened": "lifecycle_commit_capability",
    "engagement_abandoned": "lifecycle_service",
    "session_started": "hook_adapter",
    "session_checkpointed": "hook_adapter",
    "session_finalized": "hook_adapter",
    "tool_call_started": "hook_adapter",
    "tool_call_completed": "hook_adapter",
    "evidence_attached": "hook_adapter",
    "evidence_capture_failed": "hook_adapter",
    "unmatched_tool_completion": "hook_adapter",
    "unplanned_action": "hook_adapter",
    "control_tool_invoked": "hook_adapter",
    "uncertain_correlation": "hook_adapter",
    "tool_call_terminated": "tool_resolution_service",
    "closure_requested": "closure_service",
    "closure_cancelled": "closure_service",
    "source_suggested": "source_registry",
    "recovery_warning": "recovery_repository",
    "user_note": "caller_facade",
    "journal_correction_recorded": "caller_facade",
    "observation_extracted": "planning_capability",
    "hypothesis_formed": "planning_capability",
    "missing_information_identified": "planning_capability",
    "outcome_assessed": "planning_capability",
    "objective_proof_observed": "planning_capability",
    "interpretation_succeeded": "planning_capability",
    "interpretation_failed": "planning_capability",
    "plan_requested": "planning_capability",
    "frontier_proposed": "planning_capability",
    "frontier_criticized": "planning_capability",
    "frontier_repaired": "planning_capability",
    "frontier_rejected": "planning_capability",
    "planning_gap_recorded": "planning_capability",
    "strategy_reconciled": "planning_capability",
    "strategy_archived": "planning_capability",
    "strategy_reactivated": "planning_capability",
    "research_query_proposed": "planning_capability",
    "research_source_consulted": "planning_capability",
    "research_source_assessed": "planning_capability",
    "report_generated": "report_commit_capability",
    "engagement_closed": "report_commit_capability",
    "report_commit_abandoned": "report_recovery_capability",
    "promotion_requested": "promotion_commit_capability",
    "promotion_candidate_ready": "promotion_commit_capability",
    "promotion_source_committed": "promotion_commit_capability",
    "promotion_semantic_committed": "promotion_commit_capability",
    "promotion_index_pending": "promotion_commit_capability",
    "promotion_index_retry_failed": "promotion_commit_capability",
    "case_promoted": "promotion_commit_capability",
    "promotion_attempt_terminated": "promotion_commit_capability",
    "promotion_attempt_cancellation_requested": "promotion_commit_capability",
    "promotion_revocation_requested": "promotion_commit_capability",
    "case_promotion_revoked": "revocation_lifecycle_commit_capability",
    "case_promotion_superseded": "promotion_commit_capability",
}

SettlementReason = Literal[
    "plan",
    "close",
    "verify",
    "reject",
    "reopen",
    "report",
    "resume",
    "session_finalize",
]


class EngagementAmbiguousError(ValueError):
    """A resume or lane resolution matched more than one engagement."""

    def __init__(
        self,
        candidates: tuple[EngagementListItem, ...] | list[EngagementListItem],
    ) -> None:
        self.candidates = tuple(candidates)
        super().__init__("engagement selection is ambiguous")


class EngagementNotFoundError(ValueError):
    """A resume or lane resolution selector matched no engagement."""

    def __init__(self) -> None:
        super().__init__("no matching engagement exists")


class EngagementTransitionError(ValueError):
    """A lifecycle mutation is invalid for the authoritative journal state."""


class EngagementMutationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    snapshot: EngagementSnapshot
    created_event_ids: tuple[UUID, ...] = ()
    existing_event_ids: tuple[UUID, ...] = ()

    @property
    def engagement_id(self) -> UUID:
        return self.snapshot.engagement_id


class JournalEventPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    authoritative_revision: JournalRevision
    through_revision: JournalRevision | None = None
    events: tuple[JournalEvent, ...] = Field(max_length=256)
    next_after_sequence: int = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    complete: bool


class EvidenceDescriptor(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    attachment_event_id: UUID
    event_sequence: int = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    reference: EvidenceReference


class EvidenceDescriptorPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    authoritative_revision: JournalRevision
    through_revision: JournalRevision | None = None
    items: tuple[EvidenceDescriptor, ...] = Field(max_length=256)
    next_after_sequence: int = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    complete: bool


class EngagementListItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    display_name: str
    status: str
    created_at: datetime
    revision: JournalRevision


class EngagementListPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    items: tuple[EngagementListItem, ...] = Field(max_length=MAX_PUBLIC_INVENTORY_ITEMS)
    total_count: int = Field(ge=0)
    next_after_engagement_id: UUID | None = None
    omitted_items_sha256: Sha256Hex | None = None


class LaneBindingResolution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    mode: Literal["exact", "session_unique", "linked_child_unique", "ambiguous", "unbound"]
    engagement_id: UUID | None = None
    lane: ExecutionLaneKey | None = None
    candidates: tuple[EngagementListItem, ...] = ()
    total_count: int = Field(ge=0)
    omitted_items_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> LaneBindingResolution:
        unique = {"exact", "session_unique", "linked_child_unique"}
        if self.mode in unique and self.engagement_id is None:
            raise ValueError("unique lane resolution requires an engagement id")
        if self.mode == "ambiguous" and not self.candidates:
            raise ValueError("ambiguous lane resolution requires candidates")
        if self.mode not in unique and self.engagement_id is not None:
            raise ValueError("identity is allowed only for unique resolutions")
        return self


class EngagementSettlementOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    status: Literal["complete", "incomplete", "failed", "unavailable"]
    pending_range_count: int = Field(ge=0, le=MAX_SETTLEMENT_PENDING_RANGES)
    next_pending_offset: int | None = Field(default=None, ge=0, le=MAX_EVIDENCE_ITEM_BYTES)
    next_pending_subject: PendingSubjectCursor | None = None
    pending_inventory_sha256: Sha256Hex | None = None
    safe_code: SettlementSafeCode | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> EngagementSettlementOutcome:
        has_pending = self.pending_range_count > 0 or (
            self.next_pending_offset is not None
            or self.next_pending_subject is not None
            or self.pending_inventory_sha256 is not None
        )
        if self.status == "complete" and (has_pending or self.safe_code is not None):
            raise ValueError("complete settlement carries no pending metadata")
        if self.status == "unavailable" and (
            has_pending
            or self.safe_code
            not in {
                "journal_unavailable",
                "journal_corrupt",
                "settlement_unavailable",
            }
        ):
            raise ValueError("unavailable settlement requires a safe code")
        return self


class EngagementSettlementPort(Protocol):
    def settle(
        self,
        engagement_id: UUID,
        *,
        reason: SettlementReason,
    ) -> EngagementSettlementOutcome: ...


class EngagementSettlementPortFactory(Protocol):
    def open(self, resolved_root: Path) -> AbstractContextManager[EngagementSettlementPort]: ...


class ClosureFinalizer(Protocol):
    def finalize(self, *, snapshot: EngagementSnapshot) -> EngagementSnapshot: ...


def utc_now() -> datetime:
    return datetime.now(UTC)


def create_operational_start_draft(lane: ExecutionLaneKey, *, call_id: str) -> JournalEventDraft:
    sanitized = sanitize_host_arguments({"call_id": call_id})
    value = sanitized.value if isinstance(sanitized, BaseModel) else {}
    summary, _ = bounded_safe_argument_summary(value)
    return JournalEventDraft(
        lane=lane,
        actor="host_agent",
        type="tool_call_started",
        payload=ToolCallStartedPayload(
            call_id=call_id,
            tool_name="terminal",
            correlation=ToolCorrelation.uncertain("missing_stable_identity"),
            safe_arguments=summary or {},
        ),
    )


PLANNING_EVENT_KINDS = frozenset(
    kind for kind, owner in EVENT_APPEND_OWNER_BY_TYPE.items() if owner == "planning_capability"
)
MAX_PLANNING_EVENT_BATCH = MAX_JOURNAL_BATCH_EVENTS - 1


class PlanningEventCommitItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    event_id: UUID
    payload: EventPayload
    idempotency_key: Annotated[str, Field(min_length=1, max_length=1024)]

    @model_validator(mode="after")
    def validate_planning_payload(self) -> PlanningEventCommitItem:
        if self.payload.kind not in PLANNING_EVENT_KINDS:
            raise ValueError("commit item requires a planning event payload")
        return self


class PlanningEventCommitCapability:
    """Repository-issued append authority for sealed planner facts."""

    def __init__(self, service: EngagementJournalService, token: object):
        if token is not service._planning_capability_token:
            raise ValueError("invalid planning capability token")
        self._service = service

    def commit_planning_events(
        self,
        engagement_id: UUID,
        items: Sequence[PlanningEventCommitItem],
        *,
        operation_id: UUID,
        expected_revision: JournalRevision,
    ) -> EngagementMutationResult:
        validated = tuple(
            PlanningEventCommitItem.model_validate(item.model_dump(mode="python")) for item in items
        )
        if not 1 <= len(validated) <= MAX_PLANNING_EVENT_BATCH:
            raise ValueError("planning event batch exceeds its bound")
        event_ids = tuple(item.event_id for item in validated)
        keys = tuple(item.idempotency_key for item in validated)
        if len(event_ids) != len(set(event_ids)) or len(keys) != len(set(keys)):
            raise ValueError("planning event IDs and idempotency keys must be unique")
        drafts = tuple(
            JournalEventDraft(
                event_id=item.event_id,
                actor="system",
                type=item.payload.kind,
                payload=item.payload,
                system_correlation={"source": "planning", "operation_id": operation_id},
                idempotency_key=item.idempotency_key,
            )
            for item in validated
        )
        result = self._service._repository.append_batch(
            engagement_id, drafts, expected_revision=expected_revision
        )
        return _mutation_result(self._service._repository, engagement_id, result)


@dataclass(frozen=True, slots=True, repr=False)
class SettledProofRejectionReceipt:
    engagement_id: UUID
    authoritative_revision: JournalRevision
    situation_sha256: Sha256Hex
    proof_requirement_id: str
    assessment_generation: int
    proof_event_id: UUID
    rejected_value_sha256: Sha256Hex
    _issuer_token: object


class LifecycleCommitCapability:
    """Repository-issued append authority for sealed terminal lifecycle facts."""

    def __init__(self, service: EngagementJournalService, token: object):
        if token is not service._lifecycle_capability_token:
            raise ValueError("invalid lifecycle capability token")
        self._service = service

    def commit_verified(
        self,
        engagement_id: UUID,
        draft: JournalEventDraft,
        *,
        expected_revision: JournalRevision,
    ) -> EngagementMutationResult:
        validated = JournalEventDraft.model_validate(draft.model_dump(mode="python"))
        snapshot = self._service._repository.load_snapshot(engagement_id)
        report = snapshot.state.active_report
        if (
            validated.type != "engagement_verified"
            or not isinstance(validated.payload, EngagementVerifiedPayload)
            or snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_unverified"
            or report is None
            or validated.payload.report_id != report.report_id
            or validated.payload.report_revision != report.report_revision
        ):
            raise EngagementTransitionError("verification_requires_closed_report")
        result = self._service._repository.append_batch(
            engagement_id, (validated,), expected_revision=expected_revision
        )
        return _mutation_result(self._service._repository, engagement_id, result)

    def rejection_receipt(
        self, settlement: Any, flag_event_id: UUID
    ) -> SettledProofRejectionReceipt:
        situation = settlement.situation
        matches = [
            (proof, reference)
            for proof in situation.objective_progress.requirements
            for reference in proof.value_references
            if reference.proof_event_id == flag_event_id
            and reference.assessment == "supported"
            and reference.assessment_generation == proof.assessment_generation
            and proof.status == "supported"
        ]
        if len(matches) != 1:
            raise EngagementTransitionError("rejection_requires_current_supported_proof")
        proof, reference = matches[0]
        return SettledProofRejectionReceipt(
            engagement_id=situation.engagement_id,
            authoritative_revision=settlement.authoritative_journal_revision,
            situation_sha256=situation.state_digest,
            proof_requirement_id=proof.proof_requirement_id,
            assessment_generation=proof.assessment_generation,
            proof_event_id=flag_event_id,
            rejected_value_sha256=reference.value_sha256,
            _issuer_token=self._service._lifecycle_capability_token,
        )

    def commit_rejection_and_reopen(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        rejection: JournalEventDraft,
        reopen: JournalEventDraft,
        *,
        proof_rejection: SettledProofRejectionReceipt,
        expected_revision: JournalRevision,
    ) -> EngagementMutationResult:
        validated = tuple(
            JournalEventDraft.model_validate(item.model_dump(mode="python"))
            for item in (rejection, reopen)
        )
        snapshot = self._service._repository.load_snapshot(engagement_id)
        if snapshot.state.status.value == "closed_verified":
            raise EngagementTransitionError("canonical_revocation_required")
        if (
            tuple(item.type for item in validated) != ("flag_rejected", "engagement_reopened")
            or not isinstance(validated[0].payload, FlagRejectedPayload)
            or not isinstance(validated[1].payload, EngagementReopenedPayload)
            or any(item.actor != "system" or item.lane is not None for item in validated)
            or any(
                item.system_correlation is None or item.system_correlation.source != "lifecycle"
                for item in validated
            )
            or validated[0].system_correlation != validated[1].system_correlation
            or validated[0].payload.reason != validated[1].payload.reason
            or validated[1].payload.prior_status != snapshot.state.status.value
            or validated[1].payload.proof_revalidation != "retain_rejections"
            or proof_rejection._issuer_token is not self._service._lifecycle_capability_token
            or proof_rejection.engagement_id != engagement_id
            or proof_rejection.authoritative_revision != expected_revision
            or validated[0].payload.flag_event_id != proof_rejection.proof_event_id
            or validated[0].payload.rejected_value_sha256 != proof_rejection.rejected_value_sha256
        ):
            raise EngagementAppendAuthorityError("invalid sealed lifecycle batch")
        from sedna.planning.situation import SituationReducer

        current_situation = SituationReducer.rebuild(snapshot)
        proof_events = [
            event
            for event in snapshot.events
            if event.event_id == proof_rejection.proof_event_id
            and event.type.value == "objective_proof_observed"
            and event.payload.proof_requirement_id == proof_rejection.proof_requirement_id
            and event.payload.assessment_generation == proof_rejection.assessment_generation
            and event.payload.assessment == "supported"
            and event.payload.candidate_value.value_sha256 == proof_rejection.rejected_value_sha256
        ]
        if (
            snapshot.revision != expected_revision
            or snapshot.state.status.value not in {"closed_unverified", "closed_verified"}
            or current_situation.state_digest != proof_rejection.situation_sha256
            or len(proof_events) != 1
        ):
            raise EngagementTransitionError("rejection_requires_current_supported_proof")
        result = self._service._repository.append_lifecycle_batch(
            engagement_id,
            lane,
            validated,
            binding_reason="reject",
            expected_revision=expected_revision,
        )
        return _mutation_result(self._service._repository, engagement_id, result)

    def commit_reopen(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        reopen: JournalEventDraft,
        *,
        expected_revision: JournalRevision,
    ) -> EngagementMutationResult:
        validated = JournalEventDraft.model_validate(reopen.model_dump(mode="python"))
        snapshot = self._service._repository.load_snapshot(engagement_id)
        if snapshot.state.status.value == "closed_verified":
            raise EngagementTransitionError("canonical_revocation_required")
        if (
            validated.type != "engagement_reopened"
            or not isinstance(validated.payload, EngagementReopenedPayload)
            or validated.actor != "system"
            or validated.lane is not None
            or validated.system_correlation is None
            or validated.system_correlation.source != "lifecycle"
            or validated.payload.prior_status != snapshot.state.status.value
            or validated.payload.proof_revalidation != "invalidate_all"
        ):
            raise EngagementAppendAuthorityError("invalid sealed lifecycle batch")
        if snapshot.revision != expected_revision or snapshot.state.status.value not in {
            "closing",
            "closed_unverified",
            "closed_verified",
            "abandoned",
        }:
            raise EngagementTransitionError("reopen_requires_terminal_state")
        result = self._service._repository.append_lifecycle_batch(
            engagement_id,
            lane,
            (validated,),
            binding_reason="reopen",
            expected_revision=expected_revision,
        )
        return _mutation_result(self._service._repository, engagement_id, result)


class ProofClosureCapability:
    """Repository-issued authority for automatic proof-settlement barriers."""

    def __init__(self, service: EngagementJournalService, token: object):
        if token is not service._proof_closure_capability_token:
            raise ValueError("invalid proof closure capability token")
        self._service = service

    def request_proof_close(
        self,
        engagement_id: UUID,
        *,
        authoritative_revision: JournalRevision,
        lane: None,
        reason: str,
    ) -> EngagementMutationResult:
        if lane is not None:
            raise EngagementAppendAuthorityError("proof closure cannot use a host lane")
        snapshot = self._service._repository.load_snapshot(engagement_id)
        if snapshot.revision != authoritative_revision or snapshot.state.status.value != "active":
            raise EngagementTransitionError("proof_closure_requires_active_revision")
        draft = JournalEventDraft(
            actor="system",
            type="closure_requested",
            payload=ClosureRequestedPayload(
                terminal_watermark=snapshot.revision.sequence,
                in_flight_call_ids=snapshot.state.in_flight_call_ids,
                reason=reason,
                origin="proof_settlement",
            ),
            system_correlation=SystemCorrelation(
                source="proof_settlement", operation_id=self._service._uuid_factory()
            ),
        )
        result = self._service._repository.append_batch(
            engagement_id, (draft,), expected_revision=authoritative_revision
        )
        return _mutation_result(self._service._repository, engagement_id, result)

    def cancel_proof_close(
        self,
        engagement_id: UUID,
        *,
        authoritative_revision: JournalRevision,
        reason: str,
    ) -> EngagementMutationResult:
        snapshot = self._service._repository.load_snapshot(engagement_id)
        barrier = snapshot.state.closure
        if (
            snapshot.revision != authoritative_revision
            or snapshot.state.status.value != "closing"
            or barrier is None
            or barrier.origin != "proof_settlement"
        ):
            raise EngagementTransitionError("proof_closure_barrier_mismatch")
        draft = JournalEventDraft(
            actor="system",
            type="closure_cancelled",
            payload=ClosureCancelledPayload(closure_event_id=barrier.event_id, reason=reason),
            system_correlation=SystemCorrelation(
                source="proof_settlement", operation_id=self._service._uuid_factory()
            ),
        )
        result = self._service._repository.append_batch(
            engagement_id, (draft,), expected_revision=authoritative_revision
        )
        return _mutation_result(self._service._repository, engagement_id, result)


class EngagementJournalService:
    """Context-managed facade over the engagement journal repository."""

    def __init__(
        self,
        repository: EngagementJournalRepository,
        *,
        clock: Callable[[], datetime],
        uuid_factory: Callable[[], UUID],
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._planning_capability_token = object()
        self._lifecycle_capability_token = repository._lifecycle_capability_token
        self._proof_closure_capability_token = object()

    def _issue_planning_event_commit_capability(self) -> PlanningEventCommitCapability:
        return PlanningEventCommitCapability(self, self._planning_capability_token)

    def _issue_lifecycle_commit_capability(self) -> LifecycleCommitCapability:
        return LifecycleCommitCapability(self, self._lifecycle_capability_token)

    def _issue_proof_closure_capability(self) -> ProofClosureCapability:
        return ProofClosureCapability(self, self._proof_closure_capability_token)

    @classmethod
    @contextmanager
    def open(
        cls,
        knowledge_root: Path,
        *,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], UUID] = uuid4,
        evidence_quota: Any | None = None,
    ) -> Any:
        with EngagementJournalRepository(
            knowledge_root,
            clock=clock,
            uuid_factory=uuid_factory,
            evidence_quota=evidence_quota,
        ) as repository:
            yield cls(repository, clock=clock, uuid_factory=uuid_factory)

    def _manifest(
        self,
        *,
        display_name: str,
        objective: str,
        scope: AuthorizationScope,
        required_proofs: Sequence[ProofRequirement],
    ) -> EngagementManifest:
        return EngagementManifest(
            engagement_id=self._uuid_factory(),
            display_name=display_name,
            initial_objective=objective,
            initial_scope=scope,
            required_proofs=tuple(required_proofs),
            created_at=self._clock(),
            created_by_host=HostIdentity(kind=HostKind.HADES, adapter_version="1"),
        )

    def create_engagement(
        self,
        *,
        display_name: str,
        objective: str,
        scope: AuthorizationScope,
        lane: ExecutionLaneKey,
        required_proofs: Sequence[ProofRequirement] = (),
    ) -> EngagementMutationResult:
        manifest = self._manifest(
            display_name=display_name,
            objective=objective,
            scope=scope,
            required_proofs=required_proofs,
        )
        return self.create_from_manifest(manifest, lane=lane)

    def create_from_manifest(
        self,
        manifest: EngagementManifest,
        *,
        lane: ExecutionLaneKey,
    ) -> EngagementMutationResult:
        from sedna.engagement.events import SystemCorrelation

        opening = JournalEventDraft(
            lane=None,
            actor="system",
            type="engagement_opened",
            payload=EngagementOpenedPayload(
                scope_references=scope_references(manifest.initial_scope)
            ),
            system_correlation=SystemCorrelation(
                source="lifecycle",
                operation_id=self._uuid_factory(),
            ),
        )
        binding = JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="lane_bound",
            payload=LaneBoundPayload(lane=lane, binding_reason="initial binding"),
        )
        snapshot = self._repository.create(manifest, (opening, binding))
        return EngagementMutationResult(
            snapshot=snapshot,
            created_event_ids=tuple(event.event_id for event in snapshot.events),
        )

    def _list_snapshots(self) -> tuple[EngagementSnapshot, ...]:
        identifiers = self._repository.list_snapshot_ids()
        return tuple(self._repository.load_snapshot(identifier) for identifier in identifiers)

    def resume_engagement(
        self,
        *,
        lane: ExecutionLaneKey,
        engagement_id: UUID | None = None,
        display_name: str | None = None,
        scope: AuthorizationScope | None = None,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        if engagement_id is not None:
            snapshot = self._repository.load_snapshot(engagement_id)
        else:
            snapshots = self._list_snapshots()
            resumable = [item for item in snapshots if item.state.status in {"active", "closing"}]
            candidates: list[EngagementSnapshot] = []
            if display_name is not None:
                candidates = [
                    item for item in resumable if item.manifest.display_name == display_name
                ]
            elif scope is not None:
                supplied = scope_references(scope)
                supplied_ids = {ref.reference_id for ref in supplied}
                candidates = [
                    item
                    for item in resumable
                    if any(ref.reference_id in supplied_ids for ref in item.state.scope_references)
                ]
            else:
                candidates = resumable
            if len(candidates) > 1:
                raise EngagementAmbiguousError(_engagement_list_items(candidates))
            if not candidates:
                raise EngagementNotFoundError()
            snapshot = candidates[0]
        resolved = self._repository.load_snapshot(snapshot.engagement_id)
        from sedna.engagement.events import SystemCorrelation

        resumed_draft = JournalEventDraft(
            lane=None,
            actor="system",
            type="engagement_resumed",
            payload=EngagementResumedPayload(reason="resumed from another session"),
            system_correlation=SystemCorrelation(
                source="lifecycle", operation_id=self._uuid_factory()
            ),
        )
        if lane.stable_key not in {
            binding.lane.stable_key for binding in resolved.state.bound_lanes
        }:
            resumed = self._repository.append_batch(
                resolved.engagement_id,
                (
                    resumed_draft,
                    JournalEventDraft(
                        lane=lane,
                        actor="host_agent",
                        type="lane_bound",
                        payload=LaneBoundPayload(lane=lane, binding_reason="resume binding"),
                    ),
                ),
                expected_revision=expected_revision,
            )
        else:
            resumed = self._repository.append_batch(
                resolved.engagement_id,
                (resumed_draft,),
                expected_revision=expected_revision,
            )
        return _mutation_result(self._repository, resolved.engagement_id, resumed)

    def inspect_engagement(self, engagement_id: UUID) -> EngagementSnapshot:
        return self._repository.load_snapshot(engagement_id)

    def list_snapshot_ids(self) -> tuple[UUID, ...]:
        return self._repository.list_snapshot_ids()

    def rebuild_logbooks(self, engagement_id: UUID) -> tuple[Path, ...]:
        """Rebuild and atomically publish the session logbook projection."""
        from sedna.engagement.logbook import rebuild_session_logbooks

        return rebuild_session_logbooks(self._repository, engagement_id)

    def list_engagements(
        self,
        *,
        after_engagement_id: UUID | None = None,
        limit: int = MAX_PUBLIC_INVENTORY_ITEMS,
    ) -> EngagementListPage:
        if not 1 <= limit <= MAX_PUBLIC_INVENTORY_ITEMS:
            raise ValueError("engagement list limit is out of bounds")
        snapshots = self._list_snapshots()
        items = _engagement_list_items(snapshots)
        if after_engagement_id is not None:
            items = tuple(item for item in items if item.engagement_id > after_engagement_id)
        page = items[:limit]
        omitted = items[limit:]
        digest = (
            sha256(
                ",".join(str(item.engagement_id) for item in omitted).encode("utf-8")
            ).hexdigest()
            if omitted
            else None
        )
        return EngagementListPage(
            items=page,
            total_count=len(items),
            next_after_engagement_id=page[-1].engagement_id if len(items) > limit else None,
            omitted_items_sha256=digest,
        )

    def resolve_lane_binding(self, lane: ExecutionLaneKey) -> LaneBindingResolution:
        snapshots = self._list_snapshots()
        exact = [
            item
            for item in snapshots
            if any(binding.lane == lane for binding in item.state.bound_lanes)
        ]
        if len(exact) == 1:
            return LaneBindingResolution(
                mode="exact",
                engagement_id=exact[0].engagement_id,
                lane=lane,
                total_count=1,
            )
        session_unique = [
            item
            for item in snapshots
            if any(
                binding.lane.session_id == lane.session_id
                and binding.lane.host_kind == lane.host_kind
                for binding in item.state.bound_lanes
            )
        ]
        if len(session_unique) == 1:
            return LaneBindingResolution(
                mode="session_unique",
                engagement_id=session_unique[0].engagement_id,
                lane=lane,
                total_count=1,
            )
        if len(session_unique) > 1:
            return LaneBindingResolution(
                mode="ambiguous",
                candidates=_engagement_list_items(session_unique),
                total_count=len(session_unique),
            )
        return LaneBindingResolution(mode="unbound", total_count=0)

    def bind_lane(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        *,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        result = self._repository.bind_lane(
            engagement_id, lane, reason=reason, expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def unbind_lane(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        *,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        result = self._repository.unbind_lane(
            engagement_id, lane, reason=reason, expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def link_child_session(
        self,
        *,
        parent_session_id: str,
        parent_task_id: str | None,
        child_session_id: str,
        child_subagent_id: str | None,
    ) -> LaneBindingResolution:
        snapshots = self._list_snapshots()
        parents = [
            item
            for item in snapshots
            if any(
                binding.lane.session_id == parent_session_id
                and (parent_task_id is None or binding.lane.task_id == parent_task_id)
                for binding in item.state.bound_lanes
            )
        ]
        if len(parents) == 1:
            parent = parents[0]
            self._repository.append_batch(
                parent.engagement_id,
                (
                    JournalEventDraft(
                        lane=parent.state.bound_lanes[0].lane,
                        actor="host_agent",
                        type="child_lane_linked",
                        payload=ChildLaneLinkedPayload(
                            parent_session_id=parent_session_id,
                            child_session_id=child_session_id,
                            child_subagent_id=child_subagent_id or "subagent",
                        ),
                    ),
                ),
            )
            return LaneBindingResolution(
                mode="linked_child_unique",
                engagement_id=parent.engagement_id,
                total_count=1,
            )
        if len(parents) > 1:
            return LaneBindingResolution(
                mode="ambiguous",
                candidates=_engagement_list_items(parents),
                total_count=len(parents),
            )
        return LaneBindingResolution(mode="unbound", total_count=0)

    def change_objective(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        objective: str,
        authorization_basis: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        from sedna.engagement.events import SystemCorrelation

        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=None,
                    actor="system",
                    type="objective_changed",
                    payload=ObjectiveChangedPayload(
                        objective=objective,
                        authorization_basis=authorization_basis,
                    ),
                    system_correlation=SystemCorrelation(
                        source="lifecycle", operation_id=self._uuid_factory()
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def change_scope(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        scope: AuthorizationScope,
        authorization_basis: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        from sedna.engagement.events import SystemCorrelation

        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=None,
                    actor="system",
                    type="scope_changed",
                    payload=ScopeChangedPayload(
                        scope=scope,
                        scope_references=scope_references(scope),
                        authorization_basis=authorization_basis,
                    ),
                    system_correlation=SystemCorrelation(
                        source="lifecycle", operation_id=self._uuid_factory()
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def reopen_engagement(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        from sedna.engagement.events import SystemCorrelation

        drafts: list[JournalEventDraft] = []
        snapshot = self._repository.load_snapshot(engagement_id)
        if snapshot.state.status.value in {"closed_unverified", "closed_verified"}:
            raise EngagementTransitionError("orchestrated_lifecycle_required")
        if lane.stable_key not in {
            binding.lane.stable_key for binding in snapshot.state.bound_lanes
        }:
            drafts.append(
                JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="lane_bound",
                    payload=LaneBoundPayload(lane=lane, binding_reason="reopen binding"),
                )
            )
        drafts.append(
            JournalEventDraft(
                lane=None,
                actor="system",
                type="engagement_reopened",
                payload=EngagementReopenedPayload(reason=reason),
                system_correlation=SystemCorrelation(
                    source="lifecycle", operation_id=self._uuid_factory()
                ),
            )
        )
        result = self._repository.append_batch(
            engagement_id, tuple(drafts), expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def abandon_engagement(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        from sedna.engagement.events import SystemCorrelation

        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=None,
                    actor="system",
                    type="engagement_abandoned",
                    payload=EngagementAbandonedPayload(reason=reason),
                    system_correlation=SystemCorrelation(
                        source="lifecycle", operation_id=self._uuid_factory()
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def load_snapshot(self, engagement_id: UUID) -> EngagementSnapshot:
        return self._repository.load_snapshot(engagement_id)

    def report_artifact_status(self, engagement_id: UUID, report) -> tuple[bool, bool]:
        return self._repository.report_artifact_status(engagement_id, report)

    def load_events(
        self,
        engagement_id: UUID,
        *,
        after_sequence: int = 0,
        through_revision: JournalRevision | None = None,
        limit: int = 256,
    ) -> JournalEventPage:
        if not 1 <= limit <= 256:
            raise ValueError("event page limit must be within 1..256")
        snapshot = self._repository.load_snapshot(engagement_id)
        selected = [
            event
            for event in snapshot.events
            if event.sequence > after_sequence
            and (through_revision is None or event.sequence <= through_revision.sequence)
        ]
        page = tuple(selected[:limit])
        complete = len(selected) <= limit
        return JournalEventPage(
            engagement_id=engagement_id,
            authoritative_revision=snapshot.revision,
            through_revision=through_revision,
            events=page,
            next_after_sequence=page[-1].sequence + 1 if page else after_sequence,
            complete=complete,
        )

    def list_evidence_descriptors(
        self,
        engagement_id: UUID,
        *,
        after_sequence: int = 0,
        through_revision: JournalRevision | None = None,
        limit: int = 256,
    ) -> EvidenceDescriptorPage:
        if not 1 <= limit <= 256:
            raise ValueError("evidence page limit must be within 1..256")
        snapshot = self._repository.load_snapshot(engagement_id)
        selected: list[EvidenceDescriptor] = []
        for event in snapshot.events:
            if event.sequence <= after_sequence:
                continue
            if through_revision is not None and event.sequence > through_revision.sequence:
                continue
            if event.type.value != "evidence_attached":
                continue
            selected.append(
                EvidenceDescriptor(
                    attachment_event_id=event.event_id,
                    event_sequence=event.sequence,
                    reference=event.payload.evidence,
                )
            )
        page = tuple(selected[:limit])
        complete = len(selected) <= limit
        return EvidenceDescriptorPage(
            engagement_id=engagement_id,
            authoritative_revision=snapshot.revision,
            through_revision=through_revision,
            items=page,
            next_after_sequence=page[-1].event_sequence if page else after_sequence,
            complete=complete,
        )

    def append_journal_correction(
        self,
        engagement_id: UUID,
        *,
        actor: str,
        payload: JournalCorrectionRecordedPayload,
        expected_revision: JournalRevision,
    ) -> EngagementMutationResult:
        """Append an operator correction without changing the target event.

        Validation (target membership, correction-id uniqueness, one
        correction per target claim) lives in append_events so the generic
        facade cannot bypass it.
        """
        draft = JournalEventDraft(
            actor=actor,
            type=EventType.JOURNAL_CORRECTION_RECORDED,
            payload=payload,
            idempotency_key=f"journal-correction:{payload.correction_id}",
        )
        return self.append_events(
            engagement_id,
            (draft,),
            expected_revision=expected_revision,
        )

    def append_events(
        self,
        engagement_id: UUID,
        drafts: Sequence[JournalEventDraft],
        *,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        validated = tuple(
            JournalEventDraft.model_validate(item.model_dump(mode="python")) for item in drafts
        )
        correction_payloads = tuple(
            draft.payload
            for draft in validated
            if isinstance(draft.payload, JournalCorrectionRecordedPayload)
        )
        if correction_payloads:
            if expected_revision is None:
                raise ValueError("correction_expected_revision_required")
            snapshot = self._repository.load_snapshot(engagement_id)
            event_ids = {event.event_id for event in snapshot.events}
            corrections_by_event: dict[UUID, JournalCorrectionRecordedPayload] = {
                event.event_id: event.payload
                for event in snapshot.events
                if isinstance(event.payload, JournalCorrectionRecordedPayload)
            }
            correction_ids = {payload.correction_id for payload in corrections_by_event.values()}
            # Lineage model. A claim may be corrected once, and every journal
            # event may have at most ONE correction child. A second correction
            # of the same root claim must therefore target the previous
            # correction event: the chain stays linear (no branching) and the
            # original events are never rewritten (append-only).
            corrected_targets: set[UUID] = {
                payload.target_event_id for payload in corrections_by_event.values()
            }

            for payload in correction_payloads:
                target = payload.target_event_id
                if target not in event_ids:
                    raise ValueError("correction_target_not_in_journal")
                if payload.correction_id in correction_ids:
                    raise ValueError("correction_id_already_recorded")
                if target in corrected_targets:
                    # The target already carries a correction child: correct
                    # that child instead of branching from the same event.
                    raise ValueError("correction_target_already_corrected")
                prior = corrections_by_event.get(target)
                if prior is not None and payload.target_claim_ref != prior.target_claim_ref:
                    # Correcting a correction must not relabel the root claim,
                    # or a chain could be hijacked onto another claim.
                    raise ValueError("correction_root_claim_changed")
                correction_ids.add(payload.correction_id)
                corrected_targets.add(target)
        for draft in validated:
            owner = EVENT_APPEND_OWNER_BY_TYPE.get(draft.type)
            if owner != "caller_facade":
                raise EngagementAppendAuthorityError(
                    f"generic facade cannot append {draft.type}; owner is {owner}"
                )
        result = self._repository.append_batch(
            engagement_id, validated, expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def append_operational_start(
        self,
        engagement_id: UUID,
        draft: JournalEventDraft,
        *,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        validated = JournalEventDraft.model_validate(draft.model_dump(mode="python"))
        owner = EVENT_APPEND_OWNER_BY_TYPE.get(validated.type)
        if owner not in {"hook_adapter", "tool_resolution_service"}:
            raise ValueError(f"operational start cannot append {validated.type}; owner is {owner}")
        result = self._repository.append_batch(
            engagement_id, (validated,), expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def append_hook_events(
        self,
        engagement_id: UUID,
        drafts: Sequence[JournalEventDraft],
        *,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        """Append one sealed hook-adapter batch (hook, closure, resolution owners)."""
        validated = tuple(
            JournalEventDraft.model_validate(item.model_dump(mode="python")) for item in drafts
        )
        allowed_owners = {
            "hook_adapter",
            "closure_service",
            "tool_resolution_service",
            "recovery_repository",
        }
        for draft in validated:
            owner = EVENT_APPEND_OWNER_BY_TYPE.get(draft.type)
            if owner not in allowed_owners:
                raise ValueError(f"hook batch cannot append {draft.type}; owner is {owner}")
        result = self._repository.append_batch(
            engagement_id, validated, expected_revision=expected_revision
        )
        return _mutation_result(self._repository, engagement_id, result)

    def request_close(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        snapshot = self._repository.load_snapshot(engagement_id)
        terminal_watermark = snapshot.revision.sequence
        in_flight = snapshot.state.in_flight_call_ids
        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="closure_requested",
                    payload=ClosureRequestedPayload(
                        terminal_watermark=terminal_watermark,
                        in_flight_call_ids=in_flight,
                        reason=reason,
                        origin="manual",
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def read_evidence_slice(
        self,
        engagement_id: UUID,
        evidence_id: EvidenceId,
        *,
        offset: int,
        limit: int,
    ) -> EvidenceSlice:
        return self._repository.read_evidence_slice(
            engagement_id, evidence_id, offset=offset, limit=limit
        )

    def write_evidence(
        self,
        engagement_id: UUID,
        data: bytes,
        *,
        media_type: str,
        representation: str,
        capture_limitations: tuple[Any, ...] = (),
    ) -> EvidenceReference:
        return self._repository.write_evidence(
            engagement_id,
            data,
            media_type=media_type,
            representation=representation,
            capture_limitations=capture_limitations,
        )

    def load_projection(
        self,
        engagement_id: UUID,
        name: str,
        model_type: type[ProjectionT],
    ) -> ProjectionT | None:
        if name not in LOADABLE_PROJECTION_NAMES:
            raise ProjectionOwnershipError("projection name is not owned by this reader")
        if name == "engagement-state":
            value = self._repository.load_projection(engagement_id, name=name, owner="engagement")
            if value is None:
                return None
            return model_type.model_validate(value["state"])
        value = self._repository.load_projection(engagement_id, name=name, owner="planning")
        if value is None:
            return None
        return model_type.model_validate(value["payload"])

    def commit_projection(
        self,
        engagement_id: UUID,
        name: str,
        projection: BaseModel,
        *,
        expected_revision: JournalRevision,
    ) -> Path:
        if name not in PLANNING_PROJECTION_NAMES:
            raise ProjectionOwnershipError("projection name is not owned by this writer")
        self._repository.write_projection(
            engagement_id,
            name=name,
            owner="planning",
            envelope={
                "payload": projection.model_dump(mode="json"),
                "schema": "sedna.planning.v1",
            },
            expected_revision=expected_revision,
        )
        return (
            self._repository._knowledge_root / "engagements" / str(engagement_id) / f"{name}.json"
        )

    def load_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        after_entry_id: UUID | None = None,
        limit: int = MAX_STRATEGY_ARCHIVE_PAGE,
    ) -> StrategyArchivePage | None:
        return self._repository.load_strategy_archive(
            engagement_id, after_entry_id=after_entry_id, limit=limit
        )

    def commit_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        schema_id: str,
        records: Iterable[StrategyArchiveRecordDraft],
        expected_archive_revision: int | None,
        expected_journal_revision: JournalRevision,
    ) -> StrategyArchiveCommitResult:
        return self._repository.commit_strategy_archive(
            engagement_id,
            schema_id=schema_id,
            records=records,
            expected_archive_revision=expected_archive_revision,
            expected_journal_revision=expected_journal_revision,
        )

    def resolve_lane_binding_method(self, lane: ExecutionLaneKey) -> LaneBindingResolution:
        return self.resolve_lane_binding(lane)

    def rollback_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        failed_archive_revision: int,
        expected_journal_revision: JournalRevision,
        previous: StrategyArchivePage | None,
    ) -> None:
        """Restore the exact prior cold projection after its journal transaction fails."""
        self._repository.rollback_strategy_archive(
            engagement_id,
            failed_archive_revision=failed_archive_revision,
            expected_journal_revision=expected_journal_revision,
            previous=previous,
        )

    def load_active_decision(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
    ) -> ActiveDecision | None:
        snapshot = self._repository.load_snapshot(engagement_id)
        for decision in snapshot.state.active_decisions:
            if decision.lane == lane:
                return decision
        return None

    def terminate_tool_call(
        self,
        engagement_id: UUID,
        call_id: str,
        *,
        resolution: Literal["timed_out", "abandoned"],
        reason: str,
        lane: ExecutionLaneKey,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        snapshot = self._repository.load_snapshot(engagement_id)
        if call_id not in snapshot.state.in_flight_call_ids:
            raise ValueError("call_id is not an in-flight tool call")
        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="tool_call_terminated",
                    payload=ToolCallTerminatedPayload(
                        call_id=call_id,
                        resolution=resolution,
                        reason=reason,
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def record_decision(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        proposal_id: UUID | None = None,
        strategy: Annotated[str | None, Field(min_length=1, max_length=8192)] = None,
        rationale: Annotated[str | None, Field(min_length=1, max_length=8192)] = None,
        host_adapted_command: HostAdaptedCommandRecord | None = None,
        expected_revision: JournalRevision | None = None,
    ) -> EngagementMutationResult:
        if (proposal_id is None) == (strategy is None):
            raise ValueError("proposal_id and strategy are mutually exclusive")
        if strategy is not None and rationale is None:
            raise ValueError("custom decisions require a rationale")
        resolved_strategy = strategy
        resolved_rationale = rationale
        if proposal_id is not None:
            stored_frontier = self._repository.load_projection(
                engagement_id, name="frontier", owner="planning"
            )
            frontier = stored_frontier.get("payload") if stored_frontier is not None else None
            proposals = frontier.get("proposals", ()) if isinstance(frontier, dict) else ()
            proposal = next(
                (
                    item
                    for item in proposals
                    if isinstance(item, dict) and item.get("proposal_id") == str(proposal_id)
                ),
                None,
            )
            snapshot = self.load_snapshot(engagement_id)
            owned_by_lane = any(
                event.type.value in {"frontier_proposed", "frontier_repaired"}
                and event.lane is not None
                and event.lane.stable_key == lane.stable_key
                and getattr(getattr(event.payload, "proposal", None), "proposal_id", None)
                == proposal_id
                for event in snapshot.events
            )
            if proposal is None or not owned_by_lane:
                raise ValueError("proposal_not_found")
            resolved_strategy = proposal.get("title")
            resolved_rationale = proposal.get("rationale")
        assert resolved_strategy is not None
        assert resolved_rationale is not None
        result = self._repository.append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="decision_recorded",
                    payload=DecisionRecordedPayload(
                        decision_id=f"decision-{self._uuid_factory()}",
                        proposal_id=proposal_id,
                        strategy=resolved_strategy,
                        rationale=resolved_rationale,
                        host_adapted_command=host_adapted_command,
                    ),
                ),
            ),
            expected_revision=expected_revision,
        )
        return _mutation_result(self._repository, engagement_id, result)

    def __enter__(self) -> EngagementJournalService:
        return self

    def __exit__(self, *_: object) -> None:
        self._repository.close()


def _mutation_result(
    repository: EngagementJournalRepository,
    engagement_id: UUID,
    result: Any,
) -> EngagementMutationResult:
    snapshot = repository.load_snapshot(engagement_id)
    return EngagementMutationResult(
        snapshot=snapshot,
        created_event_ids=tuple(result.created_event_ids),
        existing_event_ids=tuple(result.existing_event_ids),
    )


def _engagement_list_items(
    snapshots: Sequence[EngagementSnapshot],
) -> tuple[EngagementListItem, ...]:
    items = [
        EngagementListItem(
            engagement_id=snapshot.engagement_id,
            display_name=snapshot.manifest.display_name,
            status=snapshot.state.status.value,
            created_at=snapshot.manifest.created_at,
            revision=snapshot.revision,
        )
        for snapshot in snapshots
    ]
    return tuple(sorted(items, key=lambda item: (item.display_name, item.created_at)))


__all__ = [
    "ClosureFinalizer",
    "EngagementAmbiguousError",
    "EngagementJournalService",
    "EngagementListItem",
    "EngagementListPage",
    "EngagementMutationResult",
    "EngagementNotFoundError",
    "EngagementSettlementOutcome",
    "EngagementSettlementPort",
    "EngagementSettlementPortFactory",
    "EvidenceDescriptor",
    "EvidenceDescriptorPage",
    "JournalEventPage",
    "LaneBindingResolution",
    "SettlementReason",
    "create_operational_start_draft",
]
