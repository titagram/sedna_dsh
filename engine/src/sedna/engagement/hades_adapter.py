"""Hades control tools and observer-hook adapter for engagement journals."""

from __future__ import annotations

import json
import os
import re
import stat
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from sedna.planning.ports import SednaRuntimeFactory

from sedna.engagement.events import (
    CONTROL_TOOL_NAMES,
    CONTROL_TOOL_POLICY_VERSION,
    ClosureCancelledPayload,
    ControlToolInvokedPayload,
    EventType,
    EvidenceAttachedPayload,
    EvidenceCaptureFailedPayload,
    EvidenceSliceEventRef,
    InterpretationSucceededEventPayload,
    JournalEventDraft,
    ObjectiveProofObservedEventPayload,
    PlanningCallMetadataEventRecord,
    PrivateValueEventRecord,
    SessionCheckpointedPayload,
    SessionFinalizedPayload,
    SessionStartedPayload,
    SystemCorrelation,
    ToolCallCompletedPayload,
    ToolCallStartedPayload,
    ToolCorrelation,
    UncertainCorrelationPayload,
    UnmatchedToolCompletionPayload,
    UnplannedActionPayload,
)
from sedna.engagement.models import (
    MAX_HEALTH_ENTRIES_PER_STORE,
    MAX_HEALTH_ENTRIES_TOTAL,
    MAX_HEALTH_OCCURRENCES,
    MAX_HOST_RESULT_BYTES,
    MAX_JOURNAL_EVENTS,
    MAX_PUBLIC_INVENTORY_ITEMS,
    MAX_REQUIRED_PROOFS,
    MAX_TOOL_DURATION_MS,
    AuthorizationScope,
    EngagementStatus,
    HostAdaptedCommandRecord,
    HostKind,
    JournalRevision,
    PromotionSagaInProgressError,
    ProofRequirement,
    Sha256Hex,
)
from sedna.engagement.normalization import (
    NormalizationFailure,
    SanitizedHostValue,
    normalize_host_payload,
    sanitize_host_arguments,
)
from sedna.engagement.service import (
    EngagementJournalService,
    EngagementSettlementOutcome,
    EngagementSettlementPortFactory,
    PlanningEventCommitItem,
    SettlementReason,
)
from sedna.engagement.sources import (
    SharedSourceEntry,
    SharedSourceRegistry,
    SourceRegistryLimitError,
)

HookHealthCode = Literal[
    "journal_unavailable",
    "journal_corrupt",
    "evidence_capture_failed",
    "in_flight_limit_exceeded",
    "unmatched_completion",
    "ambiguous_binding",
    "unbound_lane",
    "unknown_child_status",
    "settlement_incomplete",
    "settlement_failed",
    "settlement_unavailable",
    "logbook_rebuild_conflict",
]

_HEALTH_CODES = frozenset(HookHealthCode.__args__)  # type: ignore[attr-defined]


class _ManageEngagementInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    action: Literal[
        "create",
        "resume",
        "inspect",
        "list",
        "close",
        "reopen",
        "abandon",
        "change_scope",
        "change_objective",
        "unbind",
        "resolve_call",
        "record_proof",
        "verify",
        "reject",
        "report",
    ]
    engagement_id: UUID | None = None
    display_name: Annotated[str | None, Field(min_length=1, max_length=256)] = None
    objective: Annotated[str | None, Field(min_length=1, max_length=8192)] = None
    authorization: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=2048)], ...],
        Field(max_length=256),
    ] = ()
    required_proofs: Annotated[
        tuple[ProofRequirement, ...], Field(max_length=MAX_REQUIRED_PROOFS)
    ] = ()
    reason: Annotated[str | None, Field(min_length=1, max_length=2048)] = None
    authorization_basis: Annotated[str | None, Field(min_length=1, max_length=2048)] = None
    call_id: Annotated[str | None, Field(pattern=r"^call-[0-9a-f]{64}$")] = None
    resolution: Literal["timed_out", "abandoned"] | None = None
    flag_event_id: UUID | None = None
    proof_requirement_id: Annotated[str | None, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")] = None
    proof_file: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    attestation_reference: Annotated[str | None, Field(min_length=1, max_length=256)] = None
    allow_unsettled_evidence: bool = False
    verification_kind: Literal["platform", "user"] | None = None
    verification_reference: Annotated[str | None, Field(min_length=1, max_length=2048)] = None
    after_engagement_id: UUID | None = None
    after_call_id: Annotated[str | None, Field(pattern=r"^call-[0-9a-f]{64}$")] = None
    limit: int = Field(default=64, ge=1, le=64)

    @model_validator(mode="after")
    def validate_action(self) -> _ManageEngagementInput:
        if self.action == "create" and (
            not self.display_name or not self.objective or not self.authorization
        ):
            raise ValueError("create requires display_name, objective, authorization")
        if self.action == "resolve_call" and not (self.call_id and self.resolution and self.reason):
            raise ValueError("resolve_call requires call_id, resolution, reason")
        if self.action == "verify" and not (self.verification_kind and self.verification_reference):
            raise ValueError("verify requires verification_kind and verification_reference")
        if self.action == "reject" and not (self.flag_event_id and self.reason):
            raise ValueError("reject requires flag_event_id and reason")
        if self.action == "record_proof" and not (
            self.proof_requirement_id and self.proof_file and self.attestation_reference
        ):
            raise ValueError(
                "record_proof requires proof_requirement_id, proof_file, and attestation_reference"
            )
        if self.action == "inspect" and (
            self.after_call_id is not None and self.after_engagement_id is not None
        ):
            raise ValueError("inspect accepts at most one pagination cursor")
        if self.action != "inspect" and self.after_call_id is not None:
            raise ValueError("after_call_id is accepted only by inspect")
        return self


class RecordDecisionInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID | None = None
    proposal_id: UUID | None = None
    custom_strategy: Annotated[str | None, Field(min_length=1, max_length=8192)] = None
    rationale: Annotated[str | None, Field(min_length=1, max_length=8192)] = None
    host_adapted_command: HostAdaptedCommandRecord | None = None

    @model_validator(mode="after")
    def validate_branch(self) -> RecordDecisionInput:
        if self.proposal_id is not None:
            if self.custom_strategy is not None or self.rationale is not None:
                raise ValueError("proposal selection forbids custom strategy and rationale")
        else:
            if not (self.custom_strategy and self.rationale):
                raise ValueError("custom selection requires strategy and rationale")
        return self


class AddSourceInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    name: Annotated[str, Field(min_length=1, max_length=256)]
    locator: Annotated[str, Field(min_length=1, max_length=4096)]
    topics: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=128)], ...],
        Field(max_length=64),
    ] = ()
    notes: Annotated[str, Field(max_length=8192)] = ""


class PublicStringInventoryPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    items: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(
        max_length=MAX_PUBLIC_INVENTORY_ITEMS
    )
    total_count: int = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    next_after_id: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    omitted_items_sha256: Sha256Hex | None = None


class EngagementPublicSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    display_name: Annotated[str, Field(min_length=1, max_length=256)]
    status: EngagementStatus
    revision: JournalRevision
    bound_lanes: PublicStringInventoryPage
    active_decisions: PublicStringInventoryPage
    in_flight_call_ids: PublicStringInventoryPage


def _bounded_page(
    values: tuple[str, ...], *, limit: int = MAX_PUBLIC_INVENTORY_ITEMS
) -> PublicStringInventoryPage:
    ordered = tuple(sorted(values))
    page = ordered[:limit]
    omitted = ordered[limit:]
    digest = sha256(",".join(omitted).encode("utf-8")).hexdigest() if omitted else None
    return PublicStringInventoryPage(
        items=page,
        total_count=len(ordered),
        next_after_id=page[-1] if len(ordered) > limit else None,
        omitted_items_sha256=digest,
    )


class _HealthEntry:
    __slots__ = ("code", "count")

    def __init__(self, code: str) -> None:
        self.code = code
        self.count = 1


class _HealthMap:
    """Thread-safe bounded insertion-ordered health map keyed by store+session."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], _HealthEntry] = {}

    def record(self, store_digest: str, session_id: str, code: str) -> None:
        if code not in _HEALTH_CODES:
            raise ValueError("unknown hook health code")
        with self._lock:
            key = (store_digest, session_id)
            entry = self._entries.get(key)
            if entry is not None and entry.code == code:
                if entry.count < MAX_HEALTH_OCCURRENCES:
                    entry.count += 1
                return
            if entry is not None:
                del self._entries[key]
            self._entries[key] = _HealthEntry(code)
            self._evict()

    def purge(self, store_digest: str, session_id: str) -> None:
        with self._lock:
            self._entries.pop((store_digest, session_id), None)

    def peek(self, store_digest: str, session_id: str) -> tuple[str, int] | None:
        with self._lock:
            entry = self._entries.get((store_digest, session_id))
            if entry is None:
                return None
            return entry.code, entry.count

    def _evict(self) -> None:
        while len(self._entries) > MAX_HEALTH_ENTRIES_TOTAL:
            oldest = next(iter(self._entries))
            del self._entries[oldest]
        per_store: dict[str, int] = {}
        for store, _ in self._entries:
            per_store[store] = per_store.get(store, 0) + 1
        for store, count in per_store.items():
            while count > MAX_HEALTH_ENTRIES_PER_STORE:
                for key in list(self._entries):
                    if key[0] == store:
                        del self._entries[key]
                        count -= 1
                        break


class HadesEngagementAdapter:
    """Registers Sedna control tools and fail-open observer hooks on a Hades context."""

    def __init__(
        self,
        context: Any,
        *,
        root_resolver: Callable[[], Path],
        settlement_port_factory: EngagementSettlementPortFactory | None = None,
        runtime_factory: SednaRuntimeFactory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._context = context
        self._root_resolver = root_resolver
        self._settlement_port_factory = settlement_port_factory
        self._runtime_factory = runtime_factory
        self._clock = clock or (lambda: datetime.now(UTC))
        self._health = _HealthMap()
        self._invocation_state = threading.local()

    # -- registration -----------------------------------------------------

    def register(self) -> None:
        self._context.register_tool(
            name="sedna_manage_engagement",
            toolset="plugin_sedna",
            description=(
                "Create, resume, inspect, list, close, reopen, abandon, or resolve "
                "calls for the active engagement."
            ),
            schema={
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "create",
                                "resume",
                                "inspect",
                                "list",
                                "close",
                                "reopen",
                                "abandon",
                                "change_scope",
                                "change_objective",
                                "unbind",
                                "resolve_call",
                                "record_proof",
                                "verify",
                                "reject",
                                "report",
                            ],
                        },
                        "engagement_id": {"type": "string", "format": "uuid"},
                        "display_name": {"type": "string", "maxLength": 256},
                        "objective": {"type": "string", "maxLength": 8192},
                        "authorization": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 2048},
                            "maxItems": 256,
                        },
                        "required_proofs": {"type": "array", "items": {"type": "object"}},
                        "reason": {"type": "string", "maxLength": 1024},
                        "authorization_basis": {"type": "string", "maxLength": 2048},
                        "call_id": {"type": "string", "pattern": "^call-[0-9a-f]{64}$"},
                        "resolution": {"type": "string", "enum": ["timed_out", "abandoned"]},
                        "flag_event_id": {"type": "string", "format": "uuid"},
                        "proof_requirement_id": {
                            "type": "string",
                            "pattern": "^[a-z0-9][a-z0-9-]{0,63}$",
                        },
                        "proof_file": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "attestation_reference": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                        },
                        "allow_unsettled_evidence": {"type": "boolean", "default": False},
                        "verification_kind": {
                            "type": "string",
                            "enum": ["platform", "user"],
                        },
                        "verification_reference": {"type": "string", "maxLength": 2048},
                        "after_engagement_id": {"type": "string", "format": "uuid"},
                        "after_call_id": {"type": "string", "pattern": "^call-[0-9a-f]{64}$"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 64},
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                }
            },
            handler=self._handle_manage,
        )
        self._context.register_tool(
            name="sedna_record_decision",
            toolset="plugin_sedna",
            description="Record one strategy decision bound to the calling lane.",
            schema={
                "parameters": {
                    "type": "object",
                    "properties": {
                        "engagement_id": {"type": "string", "format": "uuid"},
                        "proposal_id": {"type": "string", "format": "uuid"},
                        "custom_strategy": {"type": "string", "maxLength": 8192},
                        "rationale": {"type": "string", "maxLength": 8192},
                        "host_adapted_command": {"type": "object"},
                    },
                    "additionalProperties": False,
                }
            },
            handler=self._handle_decision,
        )
        self._context.register_tool(
            name="sedna_add_source",
            toolset="plugin_sedna",
            description="Suggest a shared external source in the sources registry.",
            schema={
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 256},
                        "locator": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "topics": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 128},
                            "maxItems": 64,
                        },
                        "notes": {"type": "string", "maxLength": 8192},
                    },
                    "required": ["name", "locator"],
                    "additionalProperties": False,
                }
            },
            handler=self._handle_add_source,
        )

        self._context.register_hook("pre_tool_call", self._pre_tool_call)
        self._context.register_hook("post_tool_call", self._post_tool_call)
        self._context.register_hook("pre_llm_call", self._pre_llm_call)
        self._context.register_hook("on_session_start", self._on_session_start)
        self._context.register_hook("on_session_end", self._on_session_end)
        self._context.register_hook("on_session_finalize", self._on_session_finalize)
        self._context.register_hook("on_session_reset", self._on_session_reset)
        self._context.register_hook("subagent_start", self._subagent_start)
        self._context.register_hook("subagent_stop", self._subagent_stop)

    # -- invocation helpers -----------------------------------------------

    def _pin_root(self) -> Path:
        """Resolve and retain the active root exactly once per invocation."""
        root = self._root_resolver()
        if not isinstance(root, Path):
            raise ValueError("root resolver must return a Path")
        root = root.resolve()
        self._invocation_state.pinned_root = root
        return root

    def _open_service(self) -> Any:
        return EngagementJournalService.open(
            self._invocation_state.pinned_root, clock=self._clock, uuid_factory=uuid4
        )

    def _invoke(self) -> tuple[Path, str, Any]:
        root = self._pin_root()
        store_digest = sha256(str(root).encode("utf-8")).hexdigest()
        return root, store_digest, self._open_service()

    def _lane(self, *, session_id: str | None, task_id: str | None) -> Any | None:
        from sedna.engagement.models import ExecutionLaneKey

        if not session_id:
            return None
        return ExecutionLaneKey.from_host(
            host_kind=HostKind.HADES,
            session_id=session_id,
            task_id=task_id or "",
        )

    def _scope(self, authorization: tuple[str, ...]) -> AuthorizationScope:
        from sedna.knowledge.retrieval.models import (
            AuthorizationState,
            ValidatedTarget,
        )

        targets = tuple(ValidatedTarget.parse(value) for value in authorization)
        if any(not target.is_valid for target in targets):
            raise ValueError("invalid_target")
        return AuthorizationScope(
            state=AuthorizationState.AUTHORIZED,
            exact_targets=targets,
        )

    def _summary(
        self, service: EngagementJournalService, engagement_id: UUID
    ) -> EngagementPublicSummary:
        snapshot = service.load_snapshot(engagement_id)
        return EngagementPublicSummary(
            engagement_id=snapshot.engagement_id,
            display_name=snapshot.manifest.display_name,
            status=snapshot.state.status,
            revision=snapshot.revision,
            bound_lanes=_bounded_page(
                tuple(binding.lane.stable_key for binding in snapshot.state.bound_lanes)
            ),
            active_decisions=_bounded_page(
                tuple(decision.decision_id for decision in snapshot.state.active_decisions)
            ),
            in_flight_call_ids=_bounded_page(snapshot.state.in_flight_call_ids),
        )

    def _result(self, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(encoded) > MAX_HOST_RESULT_BYTES:
            return {"ok": False, "error": {"code": "result_too_large", "retryable": False}}
        return json.loads(encoded)

    def _error(self, code: str, *, retryable: bool = False) -> dict[str, Any]:
        return {"ok": False, "error": {"code": code, "retryable": retryable}}

    def _lane_engagement_id(
        self,
        service: EngagementJournalService,
        explicit: UUID | None,
        lane: Any,
    ) -> tuple[UUID | None, bool]:
        """Resolve an engagement id from the payload or the exact lane binding.

        Returns ``(engagement_id, explicit)``; ``explicit`` is True when the
        caller supplied a UUID that must equal the lane binding.
        """
        if explicit is not None:
            resolved = service.resolve_lane_binding(lane)
            if resolved.engagement_id is not None and explicit != resolved.engagement_id:
                return None, True
            return explicit, True
        resolved = service.resolve_lane_binding(lane)
        return resolved.engagement_id, False

    def _record_explicit_proof(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        lane: Any,
        payload: _ManageEngagementInput,
    ) -> dict[str, Any]:
        """Record one user-attested proof without exposing its value in tool arguments."""
        from sedna.planning.situation import SituationReducer

        proof_id = payload.proof_requirement_id
        proof_file = payload.proof_file
        attestation = payload.attestation_reference
        if not (proof_id and proof_file and attestation):
            raise ValueError("explicit_proof_fields_required")

        candidate_path = Path(proof_file).expanduser()
        if not candidate_path.is_absolute():
            raise ValueError("proof_file_must_be_absolute")
        descriptor = os.open(
            candidate_path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 4096:
                raise ValueError("proof_file_must_be_a_small_regular_file")
            candidate = os.read(descriptor, 4097).strip()
        finally:
            os.close(descriptor)
        if not candidate or len(candidate) > 4096:
            raise ValueError("proof_value_size_invalid")
        candidate.decode("utf-8", errors="strict")
        if b"\x00" in candidate:
            raise ValueError("proof_value_contains_nul")
        candidate_digest = sha256(candidate).hexdigest()

        snapshot = service.load_snapshot(engagement_id)
        status = getattr(snapshot.state.status, "value", snapshot.state.status)
        if status != "active":
            raise ValueError("record_proof_requires_active_engagement")
        if proof_id not in {item.proof_id for item in snapshot.manifest.required_proofs}:
            raise ValueError("proof_requirement_not_in_manifest")
        situation = SituationReducer.rebuild(snapshot)
        progress = next(
            item
            for item in situation.objective_progress.requirements
            if item.proof_requirement_id == proof_id
        )
        if progress.status != "pending":
            existing = next(
                (
                    item
                    for item in progress.value_references
                    if item.assessment == "supported" and item.value_sha256 == candidate_digest
                ),
                None,
            )
            if existing is None:
                raise ValueError("proof_requirement_already_assessed")
            return self._result(
                {
                    "ok": True,
                    "engagement": self._summary(service, engagement_id).model_dump(mode="json"),
                    "proof": {
                        "proof_requirement_id": proof_id,
                        "proof_event_id": str(existing.proof_event_id),
                        "value_sha256": candidate_digest,
                        "existing": True,
                    },
                }
            )

        operation_seed = json.dumps(
            {
                "engagement_id": str(engagement_id),
                "proof_requirement_id": proof_id,
                "value_sha256": candidate_digest,
                "attestation_reference": attestation,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        input_digest = sha256(operation_seed).hexdigest()
        operation_id = uuid5(NAMESPACE_URL, f"sedna:explicit-proof:{input_digest}")
        attachment_event_id = uuid5(operation_id, "attachment")
        proof_event_id = uuid5(operation_id, "proof")
        interpretation_event_id = uuid5(operation_id, "interpretation")

        evidence = service.write_evidence(
            engagement_id,
            candidate,
            media_type="text/plain",
            representation="private_proof_utf8",
        )
        attached = service.append_hook_events(
            engagement_id,
            (
                JournalEventDraft(
                    event_id=attachment_event_id,
                    idempotency_key=f"explicit-proof-attachment:{operation_id}",
                    lane=lane,
                    actor="host_agent",
                    type=EventType.EVIDENCE_ATTACHED,
                    payload=EvidenceAttachedPayload(evidence=evidence),
                ),
            ),
            expected_revision=snapshot.revision,
        )
        evidence_slice = EvidenceSliceEventRef(
            evidence_id=evidence.evidence_id,
            start=0,
            end=evidence.size,
            sha256=evidence.sha256,
            media_type=evidence.media_type,
        )
        proof_payload = ObjectiveProofObservedEventPayload(
            proof_requirement_id=proof_id,
            assessment_generation=progress.assessment_generation,
            assessment="supported",
            candidate_value=PrivateValueEventRecord(
                evidence_slice=evidence_slice,
                value_sha256=evidence.sha256,
            ),
            confidence=1.0,
            evidence_ids=(evidence.evidence_id,),
            source_event_ids=(attachment_event_id,),
            interpretation_input_digest=input_digest,
        )
        output_digest = sha256(proof_payload.model_dump_json().encode("utf-8")).hexdigest()
        committed = service._issue_planning_event_commit_capability().commit_planning_events(
            engagement_id,
            (
                PlanningEventCommitItem(
                    event_id=proof_event_id,
                    idempotency_key=f"explicit-proof-observed:{operation_id}",
                    payload=proof_payload,
                ),
                PlanningEventCommitItem(
                    event_id=interpretation_event_id,
                    idempotency_key=f"explicit-proof-interpretation:{operation_id}",
                    payload=InterpretationSucceededEventPayload(
                        interpretation_id=operation_id,
                        attachment_event_id=attachment_event_id,
                        terminal_tool_event_id=None,
                        evidence_id=evidence.evidence_id,
                        covered_slices=(evidence_slice,),
                        emitted_event_ids=(proof_event_id,),
                        call_metadata=PlanningCallMetadataEventRecord(
                            purpose="observe",
                            provider="user-attestation",
                            model="explicit-proof",
                            agent_id=attestation,
                            prompt_id="explicit-proof",
                            prompt_version="1",
                            response_schema_version="1",
                            input_digest=input_digest,
                            input_tokens=0,
                            output_tokens=0,
                            elapsed_ms=0,
                        ),
                        call_input_digest=input_digest,
                        call_output_digest=output_digest,
                    ),
                ),
            ),
            operation_id=operation_id,
            expected_revision=attached.snapshot.revision,
        )
        service.commit_projection(
            engagement_id,
            "state",
            SituationReducer.rebuild(committed.snapshot),
            expected_revision=committed.snapshot.revision,
        )
        return self._result(
            {
                "ok": True,
                "engagement": self._summary(service, engagement_id).model_dump(mode="json"),
                "proof": {
                    "proof_requirement_id": proof_id,
                    "proof_event_id": str(proof_event_id),
                    "value_sha256": candidate_digest,
                    "existing": False,
                },
            }
        )

    # -- control tool handlers --------------------------------------------

    def _handle_manage(self, **kwargs: Any) -> dict[str, Any]:
        session_id = kwargs.pop("session_id", None)
        task_id = kwargs.pop("task_id", None)
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return self._error("host_context_required", retryable=False)
        try:
            payload = _ManageEngagementInput.model_validate(kwargs)
        except Exception:
            return self._error("invalid_input", retryable=False)
        try:
            scope: AuthorizationScope | None = None
            if payload.action == "create":
                scope = self._scope(payload.authorization)
            if self._runtime_factory is not None:
                return self._handle_owned_runtime_action(payload, lane, scope)
            if payload.action == "resume" or (
                payload.action in {"close", "reopen"} and self._runtime_factory is None
            ):
                return self._handle_settlement_action(payload, lane)
            with self._invoke()[2] as service:
                if payload.action == "create":
                    created = service.create_engagement(
                        display_name=payload.display_name or "",
                        objective=payload.objective or "",
                        scope=scope,
                        lane=lane,
                        required_proofs=payload.required_proofs,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(service, created.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "inspect":
                    if payload.engagement_id is None:
                        return self._error("engagement_not_found")
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(service, payload.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "list":
                    page = service.list_engagements(
                        after_engagement_id=payload.after_engagement_id,
                        limit=payload.limit,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagements": [
                                {
                                    "engagement_id": str(item.engagement_id),
                                    "display_name": item.display_name,
                                    "status": item.status,
                                }
                                for item in page.items
                            ],
                            "total_count": page.total_count,
                            "next_after_engagement_id": (
                                str(page.next_after_engagement_id)
                                if page.next_after_engagement_id
                                else None
                            ),
                        }
                    )
                if payload.action == "abandon":
                    engagement_id, _ = self._lane_engagement_id(
                        service, payload.engagement_id, lane
                    )
                    if engagement_id is None:
                        return self._error("engagement_not_found")
                    result = service.abandon_engagement(
                        engagement_id,
                        lane=lane,
                        reason=payload.reason or "manual abandon",
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(service, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "resolve_call":
                    if not (payload.call_id and payload.resolution and payload.reason):
                        return self._error("call_not_found")
                    engagement_id, explicit = self._lane_engagement_id(
                        service, payload.engagement_id, lane
                    )
                    if engagement_id is None:
                        if explicit:
                            return self._error("engagement_conflict", retryable=False)
                        return self._error("call_not_found")
                    result = service.terminate_tool_call(
                        engagement_id,
                        payload.call_id,
                        resolution=payload.resolution,
                        reason=payload.reason,
                        lane=lane,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(service, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "record_proof":
                    engagement_id, explicit = self._lane_engagement_id(
                        service, payload.engagement_id, lane
                    )
                    if engagement_id is None:
                        return self._error(
                            "engagement_conflict" if explicit else "engagement_not_found",
                            retryable=False,
                        )
                    return self._record_explicit_proof(service, engagement_id, lane, payload)
                return self._error("invalid_transition", retryable=False)
        except Exception as exc:
            return _mapped_error(exc)

    def _handle_owned_runtime_action(
        self,
        payload: _ManageEngagementInput,
        lane: Any,
        scope: AuthorizationScope | None,
    ) -> dict[str, Any]:
        if self._runtime_factory is None:
            return self._error("knowledge_runtime_unavailable", retryable=True)
        root = self._pin_root()
        try:
            with self._runtime_factory(root) as runtime:
                journal = runtime.journal
                if journal is None:
                    return self._error("knowledge_runtime_unavailable", retryable=True)
                if payload.action == "create":
                    created = journal.create_engagement(
                        display_name=payload.display_name or "",
                        objective=payload.objective or "",
                        scope=scope,
                        lane=lane,
                        required_proofs=payload.required_proofs,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, created.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "inspect":
                    if payload.engagement_id is None:
                        return self._error("engagement_not_found")
                    snapshot = journal.load_snapshot(payload.engagement_id)
                    if (
                        runtime.promotion is not None
                        and snapshot.state.status.value == "closed_verified"
                    ):
                        recovery = runtime.promotion.resume_for_engagement(payload.engagement_id)
                        if recovery.disposition == "failed":
                            return self._error(
                                recovery.reason_code or "promotion_recovery_failed",
                                retryable=True,
                            )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, payload.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "list":
                    page = journal.list_engagements(
                        after_engagement_id=payload.after_engagement_id,
                        limit=payload.limit,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagements": [
                                {
                                    "engagement_id": str(item.engagement_id),
                                    "display_name": item.display_name,
                                    "status": item.status,
                                }
                                for item in page.items
                            ],
                            "total_count": page.total_count,
                            "next_after_engagement_id": (
                                str(page.next_after_engagement_id)
                                if page.next_after_engagement_id
                                else None
                            ),
                        }
                    )
                if payload.action == "resume":
                    from sedna.planning.ports import settlement_outcome

                    resumed = journal.resume_engagement(
                        lane=lane,
                        engagement_id=payload.engagement_id,
                        display_name=payload.display_name,
                        scope=(
                            self._scope(payload.authorization) if payload.authorization else None
                        ),
                    )
                    settlement = settlement_outcome(
                        runtime.planning.settle_pending_evidence(
                            resumed.engagement_id,
                            reason="resume",
                        )
                    )
                    if settlement.status != "complete":
                        return self._settlement_error(settlement)
                    snapshot = journal.load_snapshot(resumed.engagement_id)
                    if (
                        runtime.promotion is not None
                        and snapshot.state.status.value == "closed_verified"
                    ):
                        recovery = runtime.promotion.resume_for_engagement(resumed.engagement_id)
                        if recovery.disposition == "failed":
                            return self._error(
                                recovery.reason_code or "promotion_recovery_failed",
                                retryable=True,
                            )
                    store_digest = sha256(str(root).encode("utf-8")).hexdigest()
                    self._rebuild_logbook(
                        journal,
                        resumed.engagement_id,
                        store_digest,
                        lane.session_id,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, resumed.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                engagement_id, explicit = self._lane_engagement_id(
                    journal, payload.engagement_id, lane
                )
                if engagement_id is None:
                    return self._error(
                        "engagement_conflict" if explicit else "engagement_not_found",
                        retryable=False,
                    )
                if payload.action == "abandon":
                    result = journal.abandon_engagement(
                        engagement_id,
                        lane=lane,
                        reason=payload.reason or "manual abandon",
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "resolve_call":
                    if not (payload.call_id and payload.resolution and payload.reason):
                        return self._error("call_not_found")
                    result = journal.terminate_tool_call(
                        engagement_id,
                        payload.call_id,
                        resolution=payload.resolution,
                        reason=payload.reason,
                        lane=lane,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "change_objective":
                    if payload.objective is None or payload.authorization_basis is None:
                        return self._error("invalid_input", retryable=False)
                    result = journal.change_objective(
                        engagement_id,
                        lane=lane,
                        objective=payload.objective,
                        authorization_basis=payload.authorization_basis,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "change_scope":
                    if not payload.authorization or payload.authorization_basis is None:
                        return self._error("invalid_input", retryable=False)
                    result = journal.change_scope(
                        engagement_id,
                        lane=lane,
                        scope=self._scope(payload.authorization),
                        authorization_basis=payload.authorization_basis,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "unbind":
                    result = journal.unbind_lane(
                        engagement_id,
                        lane,
                        reason=payload.reason or "manual unbind",
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "record_proof":
                    return self._record_explicit_proof(journal, engagement_id, lane, payload)
                if payload.action == "verify":
                    if (
                        runtime.engagements is None
                        or payload.verification_kind is None
                        or payload.verification_reference is None
                    ):
                        return self._error("knowledge_runtime_unavailable", retryable=True)
                    result = runtime.engagements.verify(
                        engagement_id,
                        verification_kind=payload.verification_kind,
                        verification_reference=payload.verification_reference,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "reject":
                    if (
                        runtime.engagements is None
                        or payload.flag_event_id is None
                        or payload.reason is None
                    ):
                        return self._error("invalid_input", retryable=False)
                    result = runtime.engagements.reject_flag(
                        engagement_id,
                        lane=lane,
                        flag_event_id=payload.flag_event_id,
                        reason=payload.reason,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "close":
                    if runtime.engagements is None:
                        return self._error("knowledge_runtime_unavailable", retryable=True)
                    result = runtime.engagements.close(
                        engagement_id,
                        lane=lane,
                        reason=payload.reason or "manual close",
                        allow_unsettled_evidence=payload.allow_unsettled_evidence,
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "reopen":
                    if runtime.engagements is None:
                        return self._error("knowledge_runtime_unavailable", retryable=True)
                    result = runtime.engagements.reopen(
                        engagement_id, lane=lane, reason=payload.reason or "manual reopen"
                    )
                    return self._result(
                        {
                            "ok": True,
                            "engagement": self._summary(journal, result.engagement_id).model_dump(
                                mode="json"
                            ),
                        }
                    )
                if payload.action == "report":
                    if runtime.reporting is None:
                        return self._error("knowledge_runtime_unavailable", retryable=True)
                    report = runtime.reporting.report(engagement_id)
                    return self._result({"ok": True, "report": report.model_dump(mode="json")})
                return self._error("invalid_transition", retryable=False)
        except Exception as exc:
            return _mapped_error(exc)

    def _handle_settlement_action(
        self, payload: _ManageEngagementInput, lane: Any
    ) -> dict[str, Any]:
        """No-lock settlement sequence for resume, close, and reopen."""
        root = self._pin_root()
        if payload.action == "resume":
            with self._open_service() as service:
                result = service.resume_engagement(
                    lane=lane,
                    engagement_id=payload.engagement_id,
                    display_name=payload.display_name,
                    scope=(self._scope(payload.authorization) if payload.authorization else None),
                )
            outcome = self._settle(root, result.engagement_id, "resume")
            if outcome.status != "complete":
                return self._settlement_error(outcome)
            store_digest = sha256(str(root).encode("utf-8")).hexdigest()
            with self._open_service() as service:
                self._rebuild_logbook(
                    service,
                    result.engagement_id,
                    store_digest,
                    lane.session_id,
                )
                return self._result(
                    {
                        "ok": True,
                        "engagement": self._summary(service, result.engagement_id).model_dump(
                            mode="json"
                        ),
                    }
                )
        reason: SettlementReason = "close" if payload.action == "close" else "reopen"
        with self._open_service() as service:
            engagement_id, explicit = self._lane_engagement_id(service, payload.engagement_id, lane)
            if engagement_id is None:
                if explicit:
                    return self._error("engagement_conflict", retryable=False)
                return self._error("engagement_not_found")
        outcome = self._settle(root, engagement_id, reason)
        if outcome.status != "complete":
            return self._settlement_error(outcome)
        with self._open_service() as service:
            snapshot = service.load_snapshot(engagement_id)
            if payload.action == "close":
                result = service.request_close(
                    engagement_id,
                    lane=lane,
                    reason=payload.reason or "manual close",
                    expected_revision=snapshot.revision,
                )
            else:
                result = service.reopen_engagement(
                    engagement_id,
                    lane=lane,
                    reason=payload.reason or "manual reopen",
                    expected_revision=snapshot.revision,
                )
            store_digest = sha256(str(root).encode("utf-8")).hexdigest()
            self._rebuild_logbook(service, engagement_id, store_digest, lane.session_id)
            return self._result(
                {
                    "ok": True,
                    "engagement": self._summary(service, result.engagement_id).model_dump(
                        mode="json"
                    ),
                }
            )

    def _handle_decision(self, **kwargs: Any) -> dict[str, Any]:
        session_id = kwargs.pop("session_id", None)
        task_id = kwargs.pop("task_id", None)
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return self._error("host_context_required", retryable=False)
        try:
            payload = RecordDecisionInput.model_validate(kwargs)
        except Exception:
            return self._error("invalid_input", retryable=False)
        try:
            with self._invoke()[2] as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is None:
                    return self._error("lane_unbound", retryable=True)
                engagement_id = payload.engagement_id or resolved.engagement_id
                if (
                    payload.engagement_id is not None
                    and payload.engagement_id != resolved.engagement_id
                ):
                    return self._error("engagement_conflict", retryable=False)
                result = service.record_decision(
                    engagement_id,
                    lane=lane,
                    proposal_id=payload.proposal_id,
                    strategy=payload.custom_strategy,
                    rationale=payload.rationale,
                    host_adapted_command=payload.host_adapted_command,
                )
                self._rebuild_logbook(
                    service,
                    engagement_id,
                    sha256(str(self._invocation_state.pinned_root).encode("utf-8")).hexdigest(),
                    session_id,
                )
                return self._result(
                    {
                        "ok": True,
                        "decision_id": result.snapshot.state.active_decisions[-1].decision_id
                        if result.snapshot.state.active_decisions
                        else None,
                        "engagement": self._summary(service, engagement_id).model_dump(mode="json"),
                    }
                )
        except Exception as exc:
            return _mapped_error(exc)

    def _handle_add_source(self, **kwargs: Any) -> dict[str, Any]:
        try:
            payload = AddSourceInput.model_validate(kwargs)
        except Exception:
            return self._error("invalid_input", retryable=False)
        try:
            root, _, _ = self._invoke()
            from sedna.engagement.repository import EngagementJournalRepository

            with EngagementJournalRepository(root) as repository:
                registry = SharedSourceRegistry(repository)
                entry = SharedSourceEntry.suggested(
                    name=payload.name,
                    locator=payload.locator,
                    topics=payload.topics,
                    notes=payload.notes,
                )
                result = registry.add_or_update(entry)
                return self._result(
                    {
                        "ok": True,
                        "source_id": result.entry.source_id,
                        "changed": result.changed,
                    }
                )
        except (SourceRegistryLimitError, ValueError) as exc:
            code = getattr(exc, "reason_code", None) or getattr(exc, "code", None)
            return self._error(code or "source_registry_failed", retryable=True)

    # -- observer hooks ---------------------------------------------------
    def _pre_tool_call(
        self,
        tool_name: str,
        args: Any,
        task_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._record_pre_tool(tool_name, args, task_id, kwargs)
        except PromotionSagaInProgressError:
            raise
        except Exception:
            return None

    def _record_pre_tool(
        self, tool_name: str, args: Any, task_id: str | None, kwargs: dict[str, Any]
    ) -> None:
        session_id = kwargs.get("session_id")
        if not session_id:
            return None
        store_digest = self._pinned_store_digest()
        if tool_name in CONTROL_TOOL_NAMES:
            self._record_control_invocation(tool_name, session_id, task_id, kwargs, store_digest)
            return None
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            self._health.record(store_digest, session_id, "unbound_lane")
            return None
        try:
            with self._open_service() as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is None:
                    engagement_id = self._child_link_engagement(service, session_id)
                    if engagement_id is None:
                        self._health.record(store_digest, session_id, "unbound_lane")
                        return None
                    service.bind_lane(
                        engagement_id,
                        lane,
                        reason="child session inheritance",
                    )
                else:
                    engagement_id = resolved.engagement_id
                snapshot = service.load_snapshot(engagement_id)
                if snapshot.state.promotion.active_attempt is not None:
                    raise PromotionSagaInProgressError()
                sanitized = sanitize_host_arguments(args)
                correlation = self._correlation(lane, tool_name, sanitized, kwargs)
                if (
                    correlation.stable_key is not None
                    and self._find_stable_start(service, correlation) is not None
                ):
                    # Exact duplicate stable pre: no-op, and never cancels a
                    # closure that was requested after the original capture.
                    return None
                call_id = correlation.call_id or f"call-{uuid4().hex * 2}"
                drafts: list[JournalEventDraft] = []
                self._ensure_session_started(service, engagement_id, lane)
                if (
                    isinstance(sanitized, SanitizedHostValue)
                    and sanitized.canonical_bytes is not None
                ):
                    reference = service.write_evidence(
                        engagement_id,
                        sanitized.canonical_bytes,
                        media_type="application/json",
                        representation="sanitized_host_json",
                    )
                    drafts.append(
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type="evidence_attached",
                            payload=EvidenceAttachedPayload(evidence=reference),
                        )
                    )
                else:
                    reason = (
                        sanitized.reason_code
                        if isinstance(sanitized, NormalizationFailure)
                        else "unsupported_value"
                    )
                    drafts.append(
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type="evidence_capture_failed",
                            payload=EvidenceCaptureFailedPayload(
                                call_id=call_id,
                                capture_role="arguments",
                                reason_code=reason,
                            ),
                        )
                    )
                closure = snapshot.state.closure
                if snapshot.state.status == "closing" and closure is not None:
                    drafts.append(
                        JournalEventDraft(
                            lane=None,
                            actor="system",
                            type="closure_cancelled",
                            payload=ClosureCancelledPayload(
                                closure_event_id=closure.event_id,
                                reason="new host tool call while closing",
                            ),
                            system_correlation=SystemCorrelation(
                                source="lifecycle",
                                operation_id=uuid4(),
                            ),
                        )
                    )
                active_decision = next(
                    (
                        decision
                        for decision in snapshot.state.active_decisions
                        if decision.lane.stable_key == lane.stable_key
                    ),
                    None,
                )
                drafts.append(
                    JournalEventDraft(
                        lane=lane,
                        actor="host_agent",
                        type="tool_call_started",
                        payload=ToolCallStartedPayload(
                            call_id=call_id,
                            tool_name=tool_name,
                            correlation=correlation,
                            safe_arguments={},
                            decision_id=(
                                None if active_decision is None else active_decision.decision_id
                            ),
                        ),
                    )
                )
                if active_decision is None:
                    drafts.append(
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type="unplanned_action",
                            payload=UnplannedActionPayload(
                                call_id=call_id,
                                reason=("bound lane has no recorded decision for this tool call"),
                            ),
                        )
                    )
                if correlation.kind.value == "uncertain":
                    drafts.append(
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type="uncertain_correlation",
                            payload=UncertainCorrelationPayload(
                                call_id=call_id,
                                reason_code=(correlation.reason or "missing_stable_identity"),
                            ),
                        )
                    )
                service.append_hook_events(engagement_id, tuple(drafts))
                self._rebuild_logbook(service, engagement_id, store_digest, session_id)
        except PromotionSagaInProgressError:
            raise
        except Exception:
            self._health.record(store_digest, session_id, "journal_unavailable")

    def _record_control_invocation(
        self,
        tool_name: str,
        session_id: str,
        task_id: str | None,
        kwargs: dict[str, Any],
        store_digest: str,
    ) -> None:
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return None
        try:
            with self._open_service() as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is None:
                    return None
                snapshot = service.load_snapshot(resolved.engagement_id)
                if snapshot.state.promotion.active_attempt is not None:
                    raise PromotionSagaInProgressError()
                sanitized = sanitize_host_arguments(kwargs.get("args") or {})
                correlation = self._correlation(lane, tool_name, sanitized, kwargs)
                draft = JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="control_tool_invoked",
                    payload=ControlToolInvokedPayload(
                        control_tool=tool_name,
                        policy_version=CONTROL_TOOL_POLICY_VERSION,
                        correlation=correlation,
                    ),
                    idempotency_key=(
                        f"control:{CONTROL_TOOL_POLICY_VERSION}:"
                        f"{correlation.stable_key or correlation.reason or 'uncertain'}:"
                        f"{tool_name}"
                    ),
                )
                service.append_hook_events(resolved.engagement_id, (draft,))
                self._rebuild_logbook(
                    service,
                    resolved.engagement_id,
                    store_digest,
                    session_id,
                )
        except PromotionSagaInProgressError:
            raise
        except Exception:
            self._health.record(store_digest, session_id, "journal_unavailable")

    def _correlation(
        self,
        lane: Any,
        tool_name: str,
        sanitized: SanitizedHostValue | NormalizationFailure,
        kwargs: dict[str, Any],
    ) -> ToolCorrelation:
        return ToolCorrelation.from_hook(
            lane=lane,
            tool_name=tool_name,
            sanitized_arguments=sanitized,
            tool_call_id=kwargs.get("tool_call_id"),
            turn_id=kwargs.get("turn_id"),
            api_request_id=kwargs.get("api_request_id"),
            api_call_count=kwargs.get("api_call_count"),
            tool_call_ordinal=kwargs.get("tool_call_ordinal"),
        )

    def _post_tool_call(
        self,
        tool_name: str,
        args: Any,
        result: Any,
        task_id: str | None = None,
        duration_ms: int | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._record_post_tool(tool_name, args, result, task_id, duration_ms, kwargs)
        except PromotionSagaInProgressError:
            raise
        except Exception:
            return None

    def _record_post_tool(
        self,
        tool_name: str,
        args: Any,
        result: Any,
        task_id: str | None,
        duration_ms: int | None,
        kwargs: dict[str, Any],
    ) -> None:
        session_id = kwargs.get("session_id")
        if not session_id:
            return None
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return None
        store_digest = self._pinned_store_digest()
        try:
            with self._open_service() as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is not None:
                    snapshot = service.load_snapshot(resolved.engagement_id)
                    if snapshot.state.promotion.active_attempt is not None:
                        raise PromotionSagaInProgressError()
                sanitized = sanitize_host_arguments(args or {})
                correlation = self._correlation(lane, tool_name, sanitized, kwargs)
                status = _host_technical_status(
                    kwargs.get("tool_status") or kwargs.get("status"),
                    result,
                )
                if correlation.stable_key is not None:
                    start = self._find_stable_start(service, correlation)
                    if start is None:
                        self._health.record(store_digest, session_id, "unmatched_completion")
                        return None
                    engagement_id, call_id = start
                    snapshot = service.load_snapshot(engagement_id)
                    if snapshot.state.promotion.active_attempt is not None:
                        raise PromotionSagaInProgressError()
                    terminal = self._terminal_kind(service, engagement_id, call_id)
                    if terminal == "tool_call_completed":
                        # Duplicate stable post delivery: idempotent no-op.
                        return None
                    if terminal == "tool_call_terminated":
                        self._append_unmatched(
                            service,
                            engagement_id,
                            lane,
                            correlation,
                            status,
                            duration_ms,
                            "call_already_terminated",
                        )
                        self._rebuild_logbook(service, engagement_id, store_digest, session_id)
                        return None
                else:
                    candidates = self._uncertain_candidates(service, lane)
                    if len(candidates) == 1:
                        engagement_id, call_id = candidates[0]
                        snapshot = service.load_snapshot(engagement_id)
                        if snapshot.state.promotion.active_attempt is not None:
                            raise PromotionSagaInProgressError()
                    else:
                        engagements = {eid for eid, _ in candidates}
                        if len(engagements) == 1:
                            engagement_id = next(iter(engagements))
                            snapshot = service.load_snapshot(engagement_id)
                            if snapshot.state.promotion.active_attempt is not None:
                                raise PromotionSagaInProgressError()
                            self._append_unmatched(
                                service,
                                engagement_id,
                                lane,
                                correlation,
                                status,
                                duration_ms,
                                "ambiguous_within_engagement",
                            )
                            self._rebuild_logbook(
                                service,
                                engagement_id,
                                store_digest,
                                session_id,
                            )
                        else:
                            self._health.record(
                                store_digest,
                                session_id,
                                "unmatched_completion",
                            )
                        return None
                self._complete_call(
                    service,
                    engagement_id,
                    lane,
                    call_id,
                    correlation,
                    result,
                    status,
                    duration_ms,
                    store_digest,
                    session_id,
                )
        except PromotionSagaInProgressError:
            raise
        except Exception:
            self._health.record(store_digest, session_id, "journal_unavailable")

    def _find_stable_start(
        self,
        service: EngagementJournalService,
        correlation: ToolCorrelation,
    ) -> tuple[UUID, str] | None:
        """Locate a stable start across all engagement journals."""
        if correlation.stable_key is None:
            return None
        for engagement_id in service.list_snapshot_ids():
            snapshot = service.load_snapshot(engagement_id)
            for event in reversed(snapshot.events):
                if event.type.value != "tool_call_started":
                    continue
                if event.payload.correlation.stable_key == correlation.stable_key:
                    return engagement_id, event.payload.call_id
        return None

    def _terminal_kind(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        call_id: str,
    ) -> str | None:
        """Return the terminal event kind for a call, or None while in flight."""
        snapshot = service.load_snapshot(engagement_id)
        for event in snapshot.events:
            if event.type.value not in {
                "tool_call_completed",
                "tool_call_terminated",
            }:
                continue
            if event.payload.call_id == call_id:
                return event.type.value
        return None

    def _uncertain_candidates(
        self,
        service: EngagementJournalService,
        lane: Any,
    ) -> list[tuple[UUID, str]]:
        """In-flight uncertain starts on the same lane across engagements."""
        matches: list[tuple[UUID, str]] = []
        for engagement_id in service.list_snapshot_ids():
            snapshot = service.load_snapshot(engagement_id)
            for event in snapshot.events:
                if event.type.value != "tool_call_started":
                    continue
                correlation = event.payload.correlation
                if correlation.kind.value != "uncertain":
                    continue
                if correlation.lane_key != lane.stable_key:
                    continue
                if event.payload.call_id in snapshot.state.in_flight_call_ids:
                    matches.append((engagement_id, event.payload.call_id))
        return matches

    def _append_unmatched(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        lane: Any,
        correlation: ToolCorrelation,
        status: str,
        duration_ms: int | None,
        reason_code: str,
    ) -> None:
        bounded_duration = _bounded_duration(duration_ms)
        service.append_hook_events(
            engagement_id,
            (
                JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="unmatched_tool_completion",
                    payload=UnmatchedToolCompletionPayload(
                        correlation=correlation,
                        technical_status=status,
                        duration_ms=bounded_duration,
                        reason_code=reason_code,
                    ),
                ),
            ),
        )

    def _complete_call(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        lane: Any,
        call_id: str,
        correlation: ToolCorrelation,
        result: Any,
        status: str,
        duration_ms: int | None,
        store_digest: str,
        session_id: str,
    ) -> None:
        normalized = normalize_host_payload(result)
        if isinstance(normalized, NormalizationFailure):
            failed = JournalEventDraft(
                lane=lane,
                actor="host_agent",
                type="evidence_capture_failed",
                payload=EvidenceCaptureFailedPayload(
                    call_id=call_id,
                    capture_role="result",
                    reason_code=normalized.reason_code,
                ),
            )
            completed = self._completion_draft(lane, call_id, correlation, status, duration_ms)
            service.append_hook_events(engagement_id, (failed, completed))
            self._rebuild_logbook(service, engagement_id, store_digest, session_id)
            return None
        if normalized.representation == "host_returned_no_result":
            completed = self._completion_draft(lane, call_id, correlation, "unknown", duration_ms)
            service.append_hook_events(engagement_id, (completed,))
            self._rebuild_logbook(service, engagement_id, store_digest, session_id)
            return None
        reference = service.write_evidence(
            engagement_id,
            normalized.canonical_bytes or b"",
            media_type=_media_type(normalized.representation),
            representation=normalized.representation,
        )
        attached = JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="evidence_attached",
            payload=EvidenceAttachedPayload(evidence=reference),
        )
        completed = self._completion_draft(
            lane,
            call_id,
            correlation,
            status,
            duration_ms,
            possible_terminal_evidence=_flag_shaped(result),
        )
        service.append_hook_events(engagement_id, (attached, completed))
        self._rebuild_logbook(service, engagement_id, store_digest, session_id)

    def _find_start_call_id(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        correlation: ToolCorrelation,
    ) -> str | None:
        if correlation.stable_key is None:
            return None
        start = self._find_stable_start(service, correlation)
        if start is None:
            return None
        return start[1]

    def _completion_draft(
        self,
        lane: Any,
        call_id: str,
        correlation: ToolCorrelation,
        status: str,
        duration_ms: int | None,
        *,
        possible_terminal_evidence: bool = False,
    ) -> JournalEventDraft:
        return JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="tool_call_completed",
            payload=ToolCallCompletedPayload(
                call_id=call_id,
                correlation=correlation,
                technical_status=status,
                duration_ms=_bounded_duration(duration_ms),
                possible_terminal_evidence=possible_terminal_evidence,
            ),
        )

    def _pre_llm_call(self, **kwargs: Any) -> dict[str, Any] | None:
        session_id = kwargs.get("session_id")
        if not session_id:
            return None
        store_digest = self._pinned_store_digest()
        health = self._health.peek(store_digest, session_id)
        if health is None:
            return None
        code, _ = health
        if code in {"journal_unavailable", "journal_corrupt"}:
            return {
                "context": (
                    "Engagement journaling is not reliably journaled; results may be incomplete."
                ),
                "kind": "sedna_engagement_health_v1",
                "code": code,
            }
        if code == "settlement_unavailable":
            return {
                "context": ("settlement unavailable: evidence may remain unsettled"),
                "kind": "sedna_engagement_health_v1",
                "code": code,
            }
        return None

    # -- session and child hooks (fail-open) ------------------------------

    def _on_session_start(
        self,
        session_id: str,
        task_id: str | None = None,
        model: str | None = None,
        platform: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._record_session_start(session_id, task_id, model, platform)
        except Exception:
            return None

    def _record_session_start(
        self,
        session_id: str,
        task_id: str | None,
        model: str | None = None,
        platform: str | None = None,
    ) -> None:
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return None
        try:
            store_digest = self._pinned_store_digest()
            with self._open_service() as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is None:
                    return None
                self._ensure_session_started(
                    service,
                    resolved.engagement_id,
                    lane,
                    model=model,
                    platform=platform,
                )
                self._rebuild_logbook(
                    service,
                    resolved.engagement_id,
                    store_digest,
                    session_id,
                )
        except Exception:
            return None

    def _ensure_session_started(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        lane: Any,
        *,
        model: str | None = None,
        platform: str | None = None,
    ) -> None:
        """Append one idempotent session_started unless already present."""
        key = f"session-start:{lane.stable_key}"
        snapshot = service.load_snapshot(engagement_id)
        if any(event.idempotency_key == key for event in snapshot.events):
            return None
        draft = JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="session_started",
            payload=SessionStartedPayload(
                model=_bounded_identity_128(model),
                platform=_bounded_identity_128(platform),
            ),
            idempotency_key=key,
        )
        service.append_hook_events(engagement_id, (draft,))
        return None

    def _on_session_end(
        self,
        session_id: str,
        task_id: str | None = None,
        completed: bool = False,
        interrupted: bool = False,
        reason: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._record_session_end(session_id, task_id, completed, interrupted, reason, kwargs)
        except Exception:
            return None

    def _record_session_end(
        self,
        session_id: str,
        task_id: str | None,
        completed: bool,
        interrupted: bool,
        reason: str | None,
        kwargs: dict[str, Any],
    ) -> None:
        if completed and interrupted:
            return None
        lane = self._lane(session_id=session_id, task_id=task_id)
        if lane is None:
            return None
        identity = (
            kwargs.get("turn_id")
            or kwargs.get("api_request_id")
            or kwargs.get("callback_id")
            or "no-identity"
        )
        try:
            store_digest = self._pinned_store_digest()
            with self._open_service() as service:
                resolved = service.resolve_lane_binding(lane)
                if resolved.engagement_id is None:
                    return None
                draft = JournalEventDraft(
                    lane=lane,
                    actor="host_agent",
                    type="session_checkpointed",
                    payload=SessionCheckpointedPayload(
                        completed=completed,
                        interrupted=interrupted,
                        reason=(reason or "session ended")[:2048],
                    ),
                    idempotency_key=(f"session-end:{lane.stable_key}:{identity}"),
                )
                service.append_hook_events(resolved.engagement_id, (draft,))
                self._rebuild_logbook(
                    service,
                    resolved.engagement_id,
                    store_digest,
                    session_id,
                )
        except Exception:
            return None

    def _on_session_finalize(
        self,
        session_id: str,
        platform: str | None = None,
        reason: str | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._record_session_finalize(session_id, platform, reason)
        except Exception:
            return None

    def _record_session_finalize(
        self, session_id: str, platform: str | None, reason: str | None
    ) -> None:
        if not session_id:
            return None
        store_digest = self._pinned_store_digest()
        self._health.purge(store_digest, session_id)
        try:
            root = self._pin_root()
            with self._open_service() as service:
                engagement_ids = self._session_engagement_ids(service, session_id)
            if not engagement_ids:
                return None
            outcomes: dict[UUID, EngagementSettlementOutcome] = {}
            if self._settlement_port_factory is None:
                outcomes = {
                    engagement_id: EngagementSettlementOutcome(
                        status="complete", pending_range_count=0
                    )
                    for engagement_id in engagement_ids
                }
            else:
                with self._settlement_port_factory.open(root) as port:
                    for engagement_id in engagement_ids:
                        try:
                            outcomes[engagement_id] = port.settle(
                                engagement_id, reason="session_finalize"
                            )
                        except Exception:
                            outcomes[engagement_id] = EngagementSettlementOutcome(
                                status="unavailable",
                                pending_range_count=0,
                                safe_code="settlement_unavailable",
                            )
            with self._open_service() as service:
                for engagement_id in engagement_ids:
                    outcome = outcomes[engagement_id]
                    lane = self._lowest_session_lane(service, engagement_id, session_id)
                    if lane is None:
                        continue
                    snapshot = service.load_snapshot(engagement_id)
                    payload = self._finalized_payload(outcome, reason)
                    service.append_hook_events(
                        engagement_id,
                        (
                            JournalEventDraft(
                                lane=lane,
                                actor="host_agent",
                                type="session_finalized",
                                payload=payload,
                                idempotency_key=(f"session-finalize:{engagement_id}:{session_id}"),
                            ),
                        ),
                        expected_revision=snapshot.revision,
                    )
                    self._rebuild_logbook(service, engagement_id, store_digest, session_id)
                    if outcome.status != "complete":
                        self._health.record(
                            store_digest,
                            session_id,
                            {
                                "incomplete": "settlement_incomplete",
                                "failed": "settlement_failed",
                            }.get(outcome.status, "settlement_unavailable"),
                        )
        except Exception:
            self._health.record(store_digest, session_id, "journal_unavailable")

    def _finalized_payload(
        self,
        outcome: EngagementSettlementOutcome,
        reason: str | None,
    ) -> SessionFinalizedPayload:
        if outcome.status == "complete":
            return SessionFinalizedPayload(
                reason=(reason or "finalized")[:2048],
                settlement_status="complete",
            )
        return SessionFinalizedPayload(
            reason=f"settlement_{outcome.status}"[:2048],
            settlement_status=outcome.status,
            pending_range_count=outcome.pending_range_count,
            next_pending_offset=outcome.next_pending_offset,
            next_pending_subject=outcome.next_pending_subject,
            pending_inventory_sha256=outcome.pending_inventory_sha256,
            safe_code=outcome.safe_code,
        )

    def _session_engagement_ids(
        self, service: EngagementJournalService, session_id: str
    ) -> tuple[UUID, ...]:
        """Distinct engagements with any lane bound to this host session."""
        ids: set[UUID] = set()
        for engagement_id in service.list_snapshot_ids():
            snapshot = service.load_snapshot(engagement_id)
            if any(binding.lane.session_id == session_id for binding in snapshot.state.bound_lanes):
                ids.add(engagement_id)
        return tuple(sorted(ids))

    def _lowest_session_lane(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        session_id: str,
    ) -> Any | None:
        """Lexicographically lowest already-exact bound lane for session."""
        snapshot = service.load_snapshot(engagement_id)
        lanes = [
            binding.lane
            for binding in snapshot.state.bound_lanes
            if binding.lane.session_id == session_id
        ]
        if not lanes:
            return None
        return min(lanes, key=lambda item: item.stable_key)

    def _on_session_reset(
        self,
        session_id: str,
        old_session_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        store_digest = self._pinned_store_digest()
        self._health.purge(store_digest, session_id)

    def _subagent_start(self, **kwargs: Any) -> None:
        try:
            self._record_subagent_start(kwargs)
        except Exception:
            return None

    def _record_subagent_start(self, kwargs: dict[str, Any]) -> None:
        parent_session_id = kwargs.get("parent_session_id")
        child_session_id = kwargs.get("child_session_id")
        if not parent_session_id or not child_session_id:
            return None
        store_digest = self._pinned_store_digest()
        try:
            with self._open_service() as service:
                resolved = service.link_child_session(
                    parent_session_id=parent_session_id,
                    parent_task_id=kwargs.get("parent_task_id"),
                    child_session_id=child_session_id,
                    child_subagent_id=kwargs.get("child_subagent_id"),
                )
                if resolved.engagement_id is None:
                    code = "ambiguous_binding" if resolved.mode == "ambiguous" else "unbound_lane"
                    self._health.record(store_digest, parent_session_id, code)
                else:
                    self._rebuild_logbook(
                        service,
                        resolved.engagement_id,
                        store_digest,
                        parent_session_id,
                    )
        except Exception:
            self._health.record(store_digest, parent_session_id, "journal_unavailable")

    def _subagent_stop(self, **kwargs: Any) -> None:
        try:
            self._record_subagent_stop(kwargs)
        except Exception:
            return None

    def _record_subagent_stop(self, kwargs: dict[str, Any]) -> None:
        parent_session_id = kwargs.get("parent_session_id")
        child_session_id = kwargs.get("child_session_id")
        if not parent_session_id or not child_session_id:
            return None
        store_digest = self._pinned_store_digest()
        completed, interrupted, reason, unknown = _map_child_status(kwargs.get("child_status"))
        try:
            with self._open_service() as service:
                child_link = self._resolve_child_link(
                    service,
                    parent_session_id,
                    child_session_id,
                    kwargs.get("child_subagent_id"),
                )
                if child_link is None:
                    self._health.record(store_digest, parent_session_id, "unbound_lane")
                    return None
                engagement_id, ambiguous = child_link
                if ambiguous:
                    self._health.record(store_digest, parent_session_id, "ambiguous_binding")
                    return None
                child_task_id = kwargs.get("task_id")
                child_lane = (
                    self._lane(session_id=child_session_id, task_id=child_task_id)
                    if child_task_id
                    else None
                )
                checkpoint_lane = child_lane or self._parent_bound_lane(
                    service, engagement_id, parent_session_id
                )
                if checkpoint_lane is None:
                    return None
                service.append_hook_events(
                    engagement_id,
                    (
                        JournalEventDraft(
                            lane=checkpoint_lane,
                            actor="host_agent",
                            type="session_checkpointed",
                            payload=SessionCheckpointedPayload(
                                completed=completed,
                                interrupted=interrupted,
                                reason=reason[:2048],
                            ),
                            idempotency_key=(f"child-stop:{parent_session_id}:{child_session_id}"),
                        ),
                    ),
                )
                self._rebuild_logbook(service, engagement_id, store_digest, parent_session_id)
                if unknown:
                    self._health.record(store_digest, parent_session_id, "unknown_child_status")
                if child_lane is not None and not self._lane_has_in_flight(
                    service, engagement_id, child_lane
                ):
                    service.unbind_lane(
                        engagement_id,
                        child_lane,
                        reason="child session ended",
                    )
        except Exception:
            self._health.record(store_digest, parent_session_id, "journal_unavailable")

    def _resolve_child_link(
        self,
        service: EngagementJournalService,
        parent_session_id: str,
        child_session_id: str,
        child_subagent_id: str | None,
    ) -> tuple[UUID, bool] | None:
        """Resolve a unique prior child_lane_linked relation.

        Returns ``(engagement_id, ambiguous)`` or None when unbound.
        """
        matches: list[UUID] = []
        for engagement_id in service.list_snapshot_ids():
            snapshot = service.load_snapshot(engagement_id)
            for event in snapshot.events:
                if event.type.value != "child_lane_linked":
                    continue
                payload = event.payload
                if (
                    payload.parent_session_id != parent_session_id
                    or payload.child_session_id != child_session_id
                ):
                    continue
                if child_subagent_id is not None and payload.child_subagent_id != child_subagent_id:
                    continue
                matches.append(engagement_id)
        if not matches:
            return None
        if len(matches) > 1:
            return matches[0], True
        return matches[0], False

    def _parent_bound_lane(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        session_id: str,
    ) -> Any | None:
        return self._lowest_session_lane(service, engagement_id, session_id)

    def _lane_has_in_flight(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        lane: Any,
    ) -> bool:
        snapshot = service.load_snapshot(engagement_id)
        started: dict[str, Any] = {
            event.payload.call_id: event.lane
            for event in snapshot.events
            if event.type.value == "tool_call_started"
        }
        return any(
            call_id in started
            and started[call_id] is not None
            and started[call_id].stable_key == lane.stable_key
            for call_id in snapshot.state.in_flight_call_ids
        )

    def _child_link_engagement(
        self, service: EngagementJournalService, session_id: str
    ) -> UUID | None:
        """Unique engagement linked to this child session, or None."""
        matches: set[UUID] = set()
        for engagement_id in service.list_snapshot_ids():
            snapshot = service.load_snapshot(engagement_id)
            for event in snapshot.events:
                if event.type.value != "child_lane_linked":
                    continue
                if event.payload.child_session_id == session_id:
                    matches.add(engagement_id)
        if len(matches) == 1:
            return next(iter(matches))
        return None

    def _pinned_store_digest(self) -> str:
        root = getattr(self, "_pinned_root", None)
        if root is None:
            root = self._pin_root()
        return sha256(str(root).encode("utf-8")).hexdigest()

    def _rebuild_logbook(
        self,
        service: EngagementJournalService,
        engagement_id: UUID,
        store_digest: str | None,
        session_id: str | None,
    ) -> None:
        """Rebuild the revision-CAS logbook; conflict is fail-open health."""
        if store_digest is None or session_id is None:
            return None
        try:
            service.rebuild_logbooks(engagement_id)
        except Exception:
            self._health.record(store_digest, session_id, "logbook_rebuild_conflict")
        return None

    def _settle(
        self, root: Path, engagement_id: UUID, reason: SettlementReason
    ) -> EngagementSettlementOutcome:
        """Settle outside every journal lock; unavailable on port failure."""
        if self._settlement_port_factory is None:
            return EngagementSettlementOutcome(status="complete", pending_range_count=0)
        with self._settlement_port_factory.open(root) as port:
            try:
                return port.settle(engagement_id, reason=reason)
            except Exception:
                return EngagementSettlementOutcome(
                    status="unavailable",
                    pending_range_count=0,
                    safe_code="settlement_unavailable",
                )

    def _settlement_error(self, outcome: EngagementSettlementOutcome) -> dict[str, Any]:
        """One typed non-complete envelope without snapshot/status/frontier."""
        code = outcome.safe_code or {
            "incomplete": "evidence_budget_exhausted",
            "failed": "interpretation_failed",
        }.get(outcome.status, "settlement_unavailable")
        return {
            "ok": False,
            "error": {"code": code, "retryable": True},
            "settlement": {
                "status": outcome.status,
                "pending_range_count": outcome.pending_range_count,
                "next_pending_offset": outcome.next_pending_offset,
                "next_pending_subject": (
                    str(outcome.next_pending_subject)
                    if outcome.next_pending_subject is not None
                    else None
                ),
                "pending_inventory_sha256": outcome.pending_inventory_sha256,
            },
        }


def _media_type(representation: str) -> str:
    if representation == "host_text":
        return "text/plain"
    if representation in {"sanitized_host_json", "canonical_host_json"}:
        return "application/json"
    return "application/octet-stream"


_HOST_TECHNICAL_STATUSES = frozenset({"returned", "blocked", "cancelled", "error", "unknown"})


def _bounded_identity_128(value: Any) -> str:
    """Normalize a bounded 1..128 character host identity with 'unknown'."""
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip()[:128]
    return normalized or "unknown"


_CHILD_STATUS_MAP: dict[str, tuple[bool, bool]] = {
    "ok": (True, False),
    "timeout": (False, True),
    "interrupted": (False, True),
    "error": (False, False),
}


def _map_child_status(
    status: Any,
) -> tuple[bool, bool, str, bool]:
    """Map child_status to completed/interrupted plus a bounded reason."""
    if isinstance(status, str) and status in _CHILD_STATUS_MAP:
        completed, interrupted = _CHILD_STATUS_MAP[status]
        reason = {
            "ok": "child session completed",
            "timeout": "child session timed out",
            "interrupted": "child session interrupted",
            "error": "child session errored",
        }[status]
        return completed, interrupted, reason, False
    return False, False, "unknown child status", True


def _host_technical_status(raw_status: Any, result: Any) -> str:
    if isinstance(raw_status, str) and raw_status in _HOST_TECHNICAL_STATUSES:
        return raw_status
    return "returned" if result is not None else "unknown"


def _bounded_duration(duration_ms: int | None) -> int:
    if duration_ms is None:
        return 0
    return max(0, min(int(duration_ms), MAX_TOOL_DURATION_MS))


def _flag_shaped(value: Any) -> bool:
    """Simple flag-shaped text detection; never used for strategic outcome."""
    if not isinstance(value, str):
        return False
    return bool(re.search(r"[A-Za-z0-9_]+{[^}\n]{1,256}}", value))


def _mapped_error(exc: Exception) -> dict[str, Any]:
    from sedna.engagement.service import (
        EngagementAmbiguousError,
        EngagementNotFoundError,
    )

    name = type(exc).__name__
    if isinstance(exc, EngagementNotFoundError):
        return {"ok": False, "error": {"code": "engagement_not_found", "retryable": False}}
    if isinstance(exc, EngagementAmbiguousError):
        return {"ok": False, "error": {"code": "engagement_ambiguous", "retryable": False}}
    host_code = getattr(exc, "code", None)
    if host_code == "promotion_saga_in_progress":
        return {"ok": False, "error": {"code": host_code, "retryable": True}}
    if isinstance(host_code, str) and host_code in {
        "invalid_input",
        "invalid_target",
        "knowledge_root_required",
    }:
        return {"ok": False, "error": {"code": host_code, "retryable": False}}
    if "invalid_target" in str(exc).lower():
        return {"ok": False, "error": {"code": "invalid_target", "retryable": False}}
    if "unauthorized" in str(exc).lower():
        return {"ok": False, "error": {"code": "unauthorized_scope", "retryable": False}}
    if "proposal" in name.lower() or "proposal" in str(exc).lower():
        return {"ok": False, "error": {"code": "proposal_not_found", "retryable": False}}
    if "revision" in name.lower() or "conflict" in name.lower():
        return {"ok": False, "error": {"code": "engagement_conflict", "retryable": True}}
    if "quota" in str(exc).lower():
        return {"ok": False, "error": {"code": "evidence_capture_failed", "retryable": True}}
    if "journal" in str(exc).lower():
        return {"ok": False, "error": {"code": "journal_unavailable", "retryable": True}}
    return {"ok": False, "error": {"code": "invalid_transition", "retryable": False}}


__all__ = [
    "AddSourceInput",
    "EngagementPublicSummary",
    "HadesEngagementAdapter",
    "HookHealthCode",
    "PublicStringInventoryPage",
    "RecordDecisionInput",
]
