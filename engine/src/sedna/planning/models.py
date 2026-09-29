"""Immutable, bounded contracts for adaptive engagement planning."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from sedna.engagement import (
    MAX_HOST_RESULT_BYTES,
    MAX_JOURNAL_BATCH_EVENTS,
    MAX_REQUIRED_PROOFS,
    MAX_SETTLEMENT_PENDING_RANGES,
    EvidenceId,
    JournalRevision,
    PendingSubjectCursor,
    ProofRequirement,
    SettlementReason,
)
from sedna.engagement.events import (
    ArchivedStrategyEventRecord,
    EvidenceSliceEventRef,
    ExtractedObservationEventRecord,
    FrontierProposalEventRecord,
    PrivateValueEventRecord,
    StrategyReconciliationEventOperation,
    StrategyResultSnapshot,
    WriteupAuthorizationGrant,  # noqa: F401 - intentional public planning re-export
    WriteupAuthorizationScope,  # noqa: F401 - intentional public planning re-export
)
from sedna.planning.commands import CommandSuggestionDraft

ProofRequirementId: TypeAlias = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Sha256Hex: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ShortText: TypeAlias = Annotated[str, Field(min_length=1, max_length=2048)]
MediaType: TypeAlias = Annotated[str, Field(min_length=1, max_length=255)]

MAX_ATTEMPTS_PER_VARIANT = 8
MAX_HOT_ATTEMPTS = 256
MAX_RECENT_EVENTS = 64
MAX_RECENT_EVENT_TEXT_BYTES = 64 * 1024
MAX_PLANNER_REQUEST_BYTES = 512 * 1024
MAX_PLANNING_EVENT_BATCH = MAX_JOURNAL_BATCH_EVENTS - 1
MAX_PLANNING_PAYLOAD_BYTES = 60 * 1024
MAX_PLANNING_RESULT_BYTES = MAX_HOST_RESULT_BYTES - 16 * 1024
EVIDENCE_SLICE_BYTES = 32 * 1024
MAX_EVIDENCE_SLICES_PER_SETTLEMENT = 64
MAX_SITUATION_INTERPRETATIONS = 100_000
# Bounded retention for the projected situation tuples (facts/facets). The
# journal keeps every observation; the projection retains the most recent so a
# long engagement cannot overflow the schema and stall the planner.
MAX_SITUATION_ITEMS = 64
MAX_EVIDENCE_BYTES_PER_SETTLEMENT = 2 * 1024 * 1024


class OutcomeCategory(StrEnum):
    PROGRESS = "progress"
    PARTIAL_PROGRESS = "partial_progress"
    NO_EFFECT = "no_effect"
    NEGATIVE_EVIDENCE = "negative_evidence"
    INCOMPATIBLE = "incompatible"
    EXECUTION_ERROR = "execution_error"
    AMBIGUOUS = "ambiguous"


class StrategyStatus(StrEnum):
    AVAILABLE = "available"
    DEFERRED = "deferred"
    BLOCKED = "blocked"
    EXHAUSTED = "exhausted"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"


class RetryPredicateKind(StrEnum):
    FACT_PRESENT = "fact_present"
    FACT_CHANGED = "fact_changed"
    PREREQUISITE_SATISFIED = "prerequisite_satisfied"
    EVIDENCE_CATEGORY_PRESENT = "evidence_category_present"
    CREDENTIAL_AVAILABLE = "credential_available"
    STATE_REVISION_AFTER = "state_revision_after"


class ObservationDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    kind: Literal["text", "facet", "access", "secret", "incompatibility"]
    text: Annotated[str, Field(min_length=1, max_length=8192)]
    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _event_ids_are_sorted_unique(self) -> Self:
        if self.event_ids != tuple(sorted(self.event_ids, key=str)) or len(self.event_ids) != len(
            set(self.event_ids)
        ):
            raise ValueError("event_ids_required")
        return self


class HypothesisDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    text: Annotated[str, Field(min_length=1, max_length=8192)]
    confidence: float
    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _grounding_and_confidence(self) -> Self:
        if self.event_ids != tuple(sorted(self.event_ids, key=str)) or len(self.event_ids) != len(
            set(self.event_ids)
        ):
            raise ValueError("event_ids_required")
        if not 0 <= self.confidence <= 1 or self.confidence != self.confidence:
            raise ValueError("finite_confidence_required")
        return self


class ProofValueReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_event_id: UUID
    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)]
    assessment: Literal["supported", "contradicted"]
    evidence_id: EvidenceId
    candidate_start: Annotated[int, Field(ge=0)]
    candidate_end: Annotated[int, Field(gt=0)]
    value_sha256: Sha256Hex

    @model_validator(mode="after")
    def _candidate_range_is_positive(self) -> Self:
        if self.candidate_end <= self.candidate_start:
            raise ValueError("proof_value_range_must_be_positive")
        return self


class ProofRejectionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)]
    rejection_event_id: UUID
    rejected_proof_event_id: UUID
    rejected_value_sha256: Sha256Hex


class ProofProgress(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)] = 1
    generation_started_event_id: UUID | None = None
    status: Literal["pending", "supported", "contradicted"]
    supporting_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    contradicting_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    value_references: Annotated[tuple[ProofValueReference, ...], Field(max_length=16)] = ()
    historical_assessment_count: Annotated[int, Field(ge=0)] = 0
    historical_assessment_digest: Sha256Hex
    rejected_value_sha256s: Annotated[tuple[Sha256Hex, ...], Field(max_length=32)] = ()
    rejected_value_overflow_count: Annotated[int, Field(ge=0)] = 0
    rejected_value_overflow_digest: Sha256Hex

    @model_validator(mode="after")
    def _event_ids_are_sorted_and_status_is_grounded(self) -> Self:
        for name, event_ids in (
            ("supporting_event_ids", self.supporting_event_ids),
            ("contradicting_event_ids", self.contradicting_event_ids),
        ):
            is_sorted_unique = event_ids == tuple(sorted(event_ids, key=str))
            if not is_sorted_unique or len(event_ids) != len(set(event_ids)):
                raise ValueError(f"{name}_not_sorted_unique")
        if self.status == "pending" and (self.supporting_event_ids or self.contradicting_event_ids):
            raise ValueError("pending_proof_has_assessment_events")
        if self.status == "supported" and not self.supporting_event_ids:
            raise ValueError("supported_proof_requires_support")
        if self.status == "contradicted" and not self.contradicting_event_ids:
            raise ValueError("contradicted_proof_requires_contradiction")
        for reference in self.value_references:
            if (
                reference.proof_requirement_id != self.proof_requirement_id
                or reference.assessment_generation != self.assessment_generation
            ):
                raise ValueError("proof_value_reference_binding_mismatch")
            is_missing_support = (
                reference.assessment == "supported"
                and reference.proof_event_id not in self.supporting_event_ids
            )
            if is_missing_support:
                raise ValueError("proof_value_reference_event_mismatch")
            if (
                reference.assessment == "contradicted"
                and reference.proof_event_id not in self.contradicting_event_ids
            ):
                raise ValueError("proof_value_reference_event_mismatch")
        if len(self.rejected_value_sha256s) != len(set(self.rejected_value_sha256s)):
            raise ValueError("rejected_values_not_unique")
        return self


class ObjectiveProgress(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    requirements: Annotated[tuple[ProofProgress, ...], Field(max_length=MAX_REQUIRED_PROOFS)] = ()

    @model_validator(mode="after")
    def _requirements_are_sorted_unique(self) -> Self:
        ids = tuple(item.proof_requirement_id for item in self.requirements)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("requirements_not_sorted_unique")
        return self


class HypothesisBelief(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    hypothesis_event_id: UUID
    prior: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    posterior: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    update_event_ids: Annotated[tuple[UUID, ...], Field(max_length=256)] = ()

    @model_validator(mode="after")
    def _updates_are_sorted_unique(self) -> Self:
        if self.update_event_ids != tuple(sorted(set(self.update_event_ids), key=str)):
            raise ValueError("belief update event ids must be sorted and unique")
        return self


class SituationProjection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    authoritative_journal_revision: JournalRevision
    material_event_revision: Annotated[int, Field(ge=0)]
    state_digest: Sha256Hex
    objective_progress: ObjectiveProgress
    facts: Annotated[tuple[ObservedFact, ...], Field(max_length=64)] = ()
    facets: Annotated[tuple[ObservedFacet, ...], Field(max_length=64)] = ()
    hypotheses: Annotated[tuple[SituationHypothesis, ...], Field(max_length=64)] = ()
    hypothesis_beliefs: Annotated[tuple[HypothesisBelief, ...], Field(max_length=64)] = ()
    unresolved_information: Annotated[tuple[UnresolvedInformation, ...], Field(max_length=64)] = ()
    research_sources: Annotated[tuple[ResearchSourceAssessment, ...], Field(max_length=64)] = ()
    access_states: Annotated[tuple[AccessState, ...], Field(max_length=64)] = ()
    interpretations: Annotated[
        tuple[EvidenceInterpretationState, ...], Field(max_length=MAX_SITUATION_INTERPRETATIONS)
    ] = ()
    secret_references: Annotated[tuple[SecretReference, ...], Field(max_length=64)] = ()
    available_credentials: Annotated[tuple[AvailableCredential, ...], Field(max_length=64)] = ()
    """Credential labels a command binding may cite.

    Populated from ``secret_references`` by the situation reducer. It exists so the
    planner is told which labels are valid: a credential_ref binding must name one
    of these, and previously the planner was given no way to discover them.
    """
    attempts: Annotated[tuple[AttemptSummary, ...], Field(max_length=64)] = ()
    incompatibilities: Annotated[tuple[Incompatibility, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def _material_revision_is_not_ahead(self) -> Self:
        if self.material_event_revision > self.authoritative_journal_revision.sequence:
            raise ValueError("material_revision_after_authoritative_revision")
        return self


class RetryPredicate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    kind: RetryPredicateKind
    value: Annotated[str, Field(min_length=1, max_length=512)]


class ProposalPrerequisite(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    kind: Literal["scope_authorized", "event_observed"]
    statement: ShortText
    event_type: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    scope_kind: Literal["exact_target", "cidr", "hostname", "url_origin", "generic_id"] | None = (
        None
    )
    scope_value: Annotated[str, Field(min_length=1, max_length=2048)] | None = None

    @model_validator(mode="after")
    def _validate_reference_constraint(self) -> Self:
        if self.kind == "event_observed":
            if (
                self.event_type is None
                or self.scope_kind is not None
                or self.scope_value is not None
            ):
                raise ValueError("event_prerequisite_requires_event_type_only")
        elif self.event_type is not None or self.scope_kind is None or self.scope_value is None:
            raise ValueError("scope_prerequisite_requires_scope_kind_and_value")
        return self


class PrerequisiteProof(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    prerequisite_index: Annotated[int, Field(ge=0, le=15)]
    proof_kind: Literal["scope_authorized", "event_observed"]
    reference_id: Annotated[str, Field(min_length=1, max_length=128)]


class FrontierProposalDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proposal_id: None = None
    family_runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    variant_runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    title: ShortText
    score: Annotated[int, Field(ge=0, le=100)]
    previous_score: Annotated[int, Field(ge=0, le=100)] | None = None
    score_explanation: ShortText | None = None
    status: StrategyStatus = StrategyStatus.AVAILABLE
    terminal_reason: Literal["impossibility", "incompatibility"] | None = None
    retry_predicates: Annotated[tuple[RetryPredicate, ...], Field(max_length=16)] = ()
    confidence: Annotated[int, Field(ge=0, le=100)]
    rationale: ShortText
    strategic_intent: ShortText | None = None
    prerequisites: Annotated[tuple[ProposalPrerequisite, ...], Field(max_length=16)] = ()
    prerequisite_proofs: Annotated[tuple[PrerequisiteProof, ...], Field(max_length=16)] = ()
    expected_information_gain: ShortText = "Reduce current uncertainty."
    expected_evidence: Annotated[tuple[ShortText, ...], Field(max_length=16)] = ()
    stop_conditions: Annotated[tuple[ShortText, ...], Field(max_length=16)] = ()
    event_refs: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    knowledge_refs: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    scope_reference_ids: Annotated[tuple[str, ...], Field(max_length=8)] = ()
    commands: Annotated[tuple[CommandSuggestionDraft, ...], Field(max_length=1)] = ()

    @model_validator(mode="after")
    def _references_and_commands_are_unique(self) -> Self:
        for values in (
            self.event_refs,
            self.knowledge_refs,
            self.scope_reference_ids,
        ):
            if len(values) != len(set(values)):
                raise ValueError("planner_proposal_references_not_unique")
        proof_indexes = tuple(item.prerequisite_index for item in self.prerequisite_proofs)
        if proof_indexes != tuple(range(len(self.prerequisites))):
            raise ValueError("prerequisite_proof_count_mismatch")
        event_ref_strings = {str(value) for value in self.event_refs}
        for proof in self.prerequisite_proofs:
            prerequisite = self.prerequisites[proof.prerequisite_index]
            if proof.proof_kind != prerequisite.kind:
                raise ValueError("prerequisite_proof_kind_mismatch")
            if proof.proof_kind == "scope_authorized":
                grounded = proof.reference_id in self.scope_reference_ids
            else:
                grounded = proof.reference_id in event_ref_strings
            if not grounded:
                raise ValueError("prerequisite_proof_reference_not_grounded")
        command_keys = tuple(
            (command.command_template, command.origin, command.source_example_id)
            for command in self.commands
        )
        if len(command_keys) != len(set(command_keys)):
            raise ValueError("planner_commands_not_unique")
        if self.score == 0 and self.status not in {
            StrategyStatus.BLOCKED,
            StrategyStatus.EXHAUSTED,
        }:
            raise ValueError("zero_score_requires_impossibility_or_incompatibility")
        terminal = self.status in {StrategyStatus.BLOCKED, StrategyStatus.EXHAUSTED}
        if terminal != bool(self.retry_predicates):
            raise ValueError("terminal_strategy_retry_predicate_policy")
        if terminal and not self.event_refs:
            raise ValueError("terminal_strategy_requires_cited_event")
        if self.score == 0 and self.terminal_reason is None:
            raise ValueError("zero_score_requires_explicit_terminal_reason")
        if self.score != 0 and self.terminal_reason is not None:
            raise ValueError("terminal_reason_requires_zero_score")
        return self


class PlannerDraft(BaseModel):
    """Complete untrusted planner output before runtime allocation."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proposals: Annotated[tuple[FrontierProposalDraft, ...], Field(max_length=8)]
    research_queries: Annotated[tuple[ShortText, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def _proposals_are_semantically_unique(self) -> Self:
        identities = tuple(
            (proposal.family_runtime_key, proposal.variant_runtime_key)
            for proposal in self.proposals
        )
        if len(identities) != len(set(identities)):
            raise ValueError("planner_proposals_not_unique")
        variant_runtime_keys = tuple(proposal.variant_runtime_key for proposal in self.proposals)
        if len(variant_runtime_keys) != len(set(variant_runtime_keys)):
            raise ValueError("planner_variant_runtime_keys_not_unique")
        normalized_queries = tuple(
            " ".join(query.lower().split()) for query in self.research_queries
        )
        if len(normalized_queries) != len(set(normalized_queries)):
            raise ValueError("planner_research_queries_not_unique")
        return self


class FrontierProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proposal_id: UUID
    family_id: UUID
    variant_id: UUID
    title: ShortText
    score: Annotated[int, Field(ge=0, le=100)]
    confidence: Annotated[int, Field(ge=0, le=100)]
    rationale: ShortText


class FrontierProjection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    frontier_id: UUID
    engagement_id: UUID
    state_digest: Sha256Hex
    input_ledger_digest: Sha256Hex
    resulting_ledger_digest: Sha256Hex
    proposals: Annotated[tuple[FrontierProposal, ...], Field(max_length=8)] = ()
    constrained_rationale: ShortText | None = None
    stale: bool = False

    @model_validator(mode="after")
    def _proposals_are_viable(self) -> Self:
        proposal_ids = tuple(proposal.proposal_id for proposal in self.proposals)
        if len(proposal_ids) != len(set(proposal_ids)):
            raise ValueError("frontier_proposal_ids_not_unique")
        if len(self.proposals) < 3 and self.constrained_rationale is None:
            raise ValueError("frontier_requires_constrained_rationale")
        if len(self.proposals) >= 3 and self.constrained_rationale is not None:
            raise ValueError("frontier_unexpected_constrained_rationale")
        return self


class PlannerFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    summary: ShortText
    material: bool


class PlannerCriticVerdict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    accepted: bool
    findings: Annotated[tuple[PlannerFinding, ...], Field(max_length=64)] = ()
    request_id: UUID | None = None
    frontier_id: UUID | None = None
    critic_pass: Literal[1, 2] | None = None
    cited_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def _acceptance_matches_material_findings(self) -> Self:
        has_material_finding = any(finding.material for finding in self.findings)
        if self.accepted == has_material_finding:
            raise ValueError("critic_acceptance_policy")
        return self


class StrategyReconciliation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    input_family_ids: Annotated[tuple[UUID, ...], Field(max_length=32)]
    input_variant_ids: Annotated[tuple[UUID, ...], Field(max_length=64)]
    retained_family_ids: Annotated[tuple[UUID, ...], Field(max_length=32)]
    retained_variant_ids: Annotated[tuple[UUID, ...], Field(max_length=64)]
    items: Annotated[tuple[StrategyReconciliationItem, ...], Field(max_length=256)] = ()

    @model_validator(mode="after")
    def _reject_silent_loss(self) -> Self:
        for input_ids, retained_ids in (
            (self.input_family_ids, self.retained_family_ids),
            (self.input_variant_ids, self.retained_variant_ids),
        ):
            if len(input_ids) != len(set(input_ids)) or len(retained_ids) != len(set(retained_ids)):
                raise ValueError("strategy_reconciliation_ids_not_unique")
            if set(input_ids) != set(retained_ids):
                raise ValueError("strategy_reconciliation_silent_loss")
        return self


class PlanningCallMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    purpose: Literal["observe", "plan", "critic", "repair"]
    provider: Annotated[str, Field(min_length=1, max_length=256)]
    model: Annotated[str, Field(min_length=1, max_length=256)]
    agent_id: Annotated[str, Field(min_length=1, max_length=256)]
    prompt_id: Annotated[str, Field(min_length=1, max_length=512)]
    prompt_version: Annotated[str, Field(min_length=1, max_length=512)]
    response_schema_version: Annotated[str, Field(min_length=1, max_length=512)]
    input_digest: Sha256Hex
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    elapsed_ms: Annotated[int, Field(ge=0)]


class LocalEventIdBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    local_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
    event_id: UUID


class ProofIndexRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)]
    rejection_inventory_digest: Sha256Hex


class _PlanningEventSource(BaseModel):
    """A typed, pre-allocation-bound source record; never a journal payload."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    local_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]


class ObservationExtractedSource(_PlanningEventSource):
    kind: Literal["observation_extracted"] = "observation_extracted"
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    observation: ExtractedObservationEventRecord
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    evidence_slices: Annotated[
        tuple[EvidenceSliceEventRef, ...], Field(min_length=1, max_length=64)
    ]
    scope_reference_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class HypothesisFormedSource(_PlanningEventSource):
    kind: Literal["hypothesis_formed"] = "hypothesis_formed"
    statement: Annotated[str, Field(min_length=1, max_length=4096)]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    supporting_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    contradicting_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    scope_reference_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class MissingInformationIdentifiedSource(_PlanningEventSource):
    kind: Literal["missing_information_identified"] = "missing_information_identified"
    question: ShortText
    reason: Annotated[str, Field(min_length=1, max_length=4096)]
    importance: Annotated[int, Field(ge=0, le=100)]
    related_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    scope_reference_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class OutcomeAssessedSource(_PlanningEventSource):
    kind: Literal["outcome_assessed"] = "outcome_assessed"
    attachment_event_id: UUID
    terminal_tool_event_id: UUID
    decision_id: UUID | None = None
    tool_call_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    category: OutcomeCategory
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    strategic_impact: Annotated[str, Field(min_length=1, max_length=4096)]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=64)] = ()
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]


class ObjectiveProofObservedSource(_PlanningEventSource):
    kind: Literal["objective_proof_observed"] = "objective_proof_observed"
    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)]
    assessment: Literal["supported", "contradicted"]
    candidate_value: PrivateValueEventRecord
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]


class InterpretationSucceededSource(_PlanningEventSource):
    kind: Literal["interpretation_succeeded"] = "interpretation_succeeded"
    interpretation_id: UUID
    attachment_event_id: UUID
    terminal_tool_event_id: UUID | None = None
    evidence_id: EvidenceId
    covered_slices: Annotated[tuple[EvidenceSliceEventRef, ...], Field(max_length=64)]
    emitted_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)]


class InterpretationFailedSource(_PlanningEventSource):
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
    safe_summary: ShortText


class PlanRequestedSource(_PlanningEventSource):
    kind: Literal["plan_requested"] = "plan_requested"
    request_id: UUID
    lane_key: Annotated[str, Field(pattern=r"^lane-[0-9a-f]{32}$")]
    situation_digest: Sha256Hex
    material_event_revision: JournalRevision
    input_ledger_digest: Sha256Hex
    canonical_revision: Sha256Hex
    source_registry_digest: Sha256Hex
    max_proposals: Annotated[int, Field(ge=3, le=8)]
    hindsight_candidate_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    hindsight_query_digests: Annotated[tuple[Sha256Hex, ...], Field(max_length=16)] = ()


class FrontierProposedSource(_PlanningEventSource):
    kind: Literal["frontier_proposed"] = "frontier_proposed"
    request_id: UUID
    frontier_id: UUID
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)]
    proposal_count: Annotated[int, Field(ge=1, le=8)]
    proposal: FrontierProposalEventRecord
    situation_digest: Sha256Hex
    input_ledger_digest: Sha256Hex
    knowledge_context_digest: Sha256Hex


class FrontierCriticizedSource(_PlanningEventSource):
    kind: Literal["frontier_criticized"] = "frontier_criticized"
    request_id: UUID
    frontier_id: UUID
    critic_pass: Literal[1, 2]
    accepted: bool
    finding_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...], Field(max_length=32)
    ] = ()
    cited_event_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()


class FrontierRepairedSource(_PlanningEventSource):
    kind: Literal["frontier_repaired"] = "frontier_repaired"
    request_id: UUID
    frontier_id: UUID
    critic_event_id: UUID
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)]
    proposal_count: Annotated[int, Field(ge=1, le=8)]
    proposal: FrontierProposalEventRecord


class FrontierRejectedSource(_PlanningEventSource):
    kind: Literal["frontier_rejected"] = "frontier_rejected"
    request_id: UUID
    frontier_id: UUID
    critic_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=2)]
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(min_length=1, max_length=32),
    ]


class PlanningGapRecordedSource(_PlanningEventSource):
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
    summary: ShortText
    retryable: bool
    situation_digest: Sha256Hex
    ledger_digest: Sha256Hex
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()


class StrategyReconciledSource(_PlanningEventSource):
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


class StrategyArchivedSource(_PlanningEventSource):
    kind: Literal["strategy_archived"] = "strategy_archived"
    request_id: UUID
    archive_batch_id: UUID
    entry_ordinal: Annotated[int, Field(ge=1, le=256)]
    entry_count: Annotated[int, Field(ge=1, le=256)]
    archive_record: ArchivedStrategyEventRecord
    resulting_archive_digest: Sha256Hex


class StrategyReactivatedSource(_PlanningEventSource):
    kind: Literal["strategy_reactivated"] = "strategy_reactivated"
    request_id: UUID
    reactivation_batch_id: UUID
    entry_ordinal: Annotated[int, Field(ge=1, le=256)]
    entry_count: Annotated[int, Field(ge=1, le=256)]
    source_archive_event_id: UUID
    triggering_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]
    matched_predicate_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]
    prior_archive_entry_digest: Sha256Hex
    resulting_archive_digest: Sha256Hex
    restored_snapshot: StrategyResultSnapshot


class ResearchQueryProposedSource(_PlanningEventSource):
    kind: Literal["research_query_proposed"] = "research_query_proposed"
    query_id: UUID
    normalized_query: ShortText
    policy_decision: Literal["allowed", "rejected"]
    policy_version: Annotated[str, Field(min_length=1, max_length=512)]
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(min_length=1, max_length=16),
    ]
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    candidate_source_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class ResearchSourceConsultedSource(_PlanningEventSource):
    kind: Literal["research_source_consulted"] = "research_source_consulted"
    query_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    normalized_locator: ShortText
    content: bytes = Field(min_length=1, max_length=MAX_HOST_RESULT_BYTES)
    media_type: MediaType
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    tool_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]


class ResearchSourceAssessedSource(_PlanningEventSource):
    kind: Literal["research_source_assessed"] = "research_source_assessed"
    query_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    consulted_event_id: UUID
    assessment: Literal["useful", "contradicted", "stale", "irrelevant", "ambiguous"]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    related_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]
    suggested_registry_status: Literal["consulted", "useful", "contradicted", "stale"] | None = None


PlanningEventSource: TypeAlias = Annotated[
    ObservationExtractedSource
    | HypothesisFormedSource
    | MissingInformationIdentifiedSource
    | OutcomeAssessedSource
    | ObjectiveProofObservedSource
    | InterpretationSucceededSource
    | InterpretationFailedSource
    | PlanRequestedSource
    | FrontierProposedSource
    | FrontierCriticizedSource
    | FrontierRepairedSource
    | FrontierRejectedSource
    | PlanningGapRecordedSource
    | StrategyReconciledSource
    | StrategyArchivedSource
    | StrategyReactivatedSource
    | ResearchQueryProposedSource
    | ResearchSourceConsultedSource
    | ResearchSourceAssessedSource,
    Field(discriminator="kind"),
]


class _ConversionEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    local_event_bindings: Annotated[tuple[LocalEventIdBinding, ...], Field(max_length=512)]
    valid_event_ids: Annotated[tuple[UUID, ...], Field(max_length=512)]
    valid_evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=512)]
    valid_scope_reference_ids: Annotated[tuple[str, ...], Field(max_length=512)] = ()
    valid_proof_indexes: Annotated[tuple[ProofIndexRecord, ...], Field(max_length=64)] = ()
    proof_candidate_admissions: Annotated[
        tuple[ProofCandidateAdmission, ...], Field(max_length=64)
    ] = ()
    valid_decision_ids: Annotated[tuple[UUID, ...], Field(max_length=512)] = ()
    valid_proposal_ids: Annotated[tuple[UUID, ...], Field(max_length=512)] = ()
    valid_family_ids: Annotated[tuple[UUID, ...], Field(max_length=64)] = ()
    valid_variant_ids: Annotated[tuple[UUID, ...], Field(max_length=128)] = ()
    valid_knowledge_ids: Annotated[tuple[str, ...], Field(max_length=512)] = ()
    valid_source_ids: Annotated[tuple[str, ...], Field(max_length=512)] = ()
    evidence_slices: Annotated[tuple[EvidenceSliceInput, ...], Field(max_length=64)] = ()
    sources: Annotated[
        tuple[PlanningEventSource, ...], Field(max_length=MAX_PLANNING_EVENT_BATCH)
    ] = ()

    @model_validator(mode="after")
    def _bindings_and_indexes_are_deterministic(self) -> Self:
        binding_keys = tuple(binding.local_id for binding in self.local_event_bindings)
        bindings_are_sorted_unique = binding_keys == tuple(sorted(binding_keys)) and len(
            binding_keys
        ) == len(set(binding_keys))
        if not bindings_are_sorted_unique:
            raise ValueError("local_event_bindings_not_sorted_unique")
        event_ids = tuple(sorted(self.valid_event_ids, key=str))
        if self.valid_event_ids != event_ids or len(event_ids) != len(set(event_ids)):
            raise ValueError("valid_event_ids_not_sorted_unique")
        if self.valid_evidence_ids != tuple(sorted(set(self.valid_evidence_ids))):
            raise ValueError("valid_evidence_ids_not_sorted_unique")
        indexed_uuid_tuples = (
            self.valid_decision_ids,
            self.valid_proposal_ids,
            self.valid_family_ids,
            self.valid_variant_ids,
        )
        has_unsorted_uuid_index = any(
            values != tuple(sorted(values, key=str)) or len(values) != len(set(values))
            for values in indexed_uuid_tuples
        )
        if has_unsorted_uuid_index:
            raise ValueError("valid_uuid_index_not_sorted_unique")
        indexed_text_tuples = (
            self.valid_scope_reference_ids,
            self.valid_knowledge_ids,
            self.valid_source_ids,
        )
        if any(values != tuple(sorted(set(values))) for values in indexed_text_tuples):
            raise ValueError("valid_text_index_not_sorted_unique")
        proof_keys = tuple(
            (item.proof_requirement_id, item.assessment_generation)
            for item in self.valid_proof_indexes
        )
        if proof_keys != tuple(sorted(proof_keys)) or len(proof_keys) != len(set(proof_keys)):
            raise ValueError("valid_proof_indexes_not_sorted_unique")
        indexed_proofs = set(proof_keys)
        for admission in self.proof_candidate_admissions:
            admission_key = (admission.proof_requirement_id, admission.assessment_generation)
            if admission_key not in indexed_proofs:
                raise ValueError("proof_candidate_admission_not_in_index")
        has_unindexed_binding = any(
            binding.event_id not in self.valid_event_ids for binding in self.local_event_bindings
        )
        if has_unindexed_binding:
            raise ValueError("local_event_binding_not_in_index")
        source_ids = tuple(source.local_id for source in self.sources)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source_local_ids_not_unique")
        if set(source_ids) - set(binding_keys):
            raise ValueError("source_local_id_not_preallocated")
        return self


class ObservationEventConversion(_ConversionEnvelope):
    batch: ObservationBatchDraft
    call_metadata: PlanningCallMetadata
    interpretation_audits: Annotated[tuple[InterpretationAudit, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def _source_family(self) -> Self:
        allowed = {
            "observation_extracted",
            "hypothesis_formed",
            "missing_information_identified",
            "outcome_assessed",
            "objective_proof_observed",
            "interpretation_succeeded",
            "interpretation_failed",
        }
        if any(source.kind not in allowed for source in self.sources):
            raise ValueError("observation conversion contains a non-observation source")
        return self


class PlanningAttemptEventConversion(_ConversionEnvelope):
    reconciliation: StrategyReconciliation
    call_metadata: PlanningCallMetadata
    plan_request_audit: PlanRequestAudit | None = None
    planner_draft: PlannerDraft | None = None
    planner_proposals: Annotated[tuple[PlannerProposalAudit, ...], Field(max_length=8)] = ()
    critic_verdicts: Annotated[tuple[PlannerCriticVerdict, ...], Field(max_length=2)] = ()
    repair_audits: Annotated[tuple[PlannerRepairAudit, ...], Field(max_length=8)] = ()
    rejection_audits: Annotated[tuple[PlannerRejectionAudit, ...], Field(max_length=8)] = ()
    planning_gaps: Annotated[tuple[PlanningGap, ...], Field(max_length=8)] = ()

    @model_validator(mode="after")
    def _source_family(self) -> Self:
        allowed = {
            "plan_requested",
            "frontier_proposed",
            "frontier_criticized",
            "frontier_repaired",
            "frontier_rejected",
            "planning_gap_recorded",
        }
        if any(source.kind not in allowed for source in self.sources):
            raise ValueError("planning conversion contains a non-planning-attempt source")
        return self


class StrategyReconciliationEventConversion(_ConversionEnvelope):
    reconciliation: StrategyReconciliation
    call_metadata: PlanningCallMetadata
    archive_transitions: Annotated[
        tuple[StrategyArchiveTransition, ...], Field(max_length=256)
    ] = ()
    reactivation_transitions: Annotated[
        tuple[StrategyReactivationTransition, ...], Field(max_length=256)
    ] = ()

    @model_validator(mode="after")
    def _source_family(self) -> Self:
        allowed = {"strategy_reconciled", "strategy_archived", "strategy_reactivated"}
        if any(source.kind not in allowed for source in self.sources):
            raise ValueError("reconciliation conversion contains a non-reconciliation source")
        return self


class ResearchEventConversion(_ConversionEnvelope):
    research_sources: Annotated[tuple[ResearchSourceObservationDraft, ...], Field(max_length=64)]
    call_metadata: PlanningCallMetadata
    policy_decisions: Annotated[tuple[ResearchPolicyDecision, ...], Field(max_length=64)] = ()
    research_consultations: Annotated[
        tuple[ResearchSourceConsultation, ...], Field(max_length=64)
    ] = ()
    research_assessments: Annotated[
        tuple[ResearchSourceAssessmentAudit, ...], Field(max_length=64)
    ] = ()

    @model_validator(mode="after")
    def _source_family(self) -> Self:
        allowed = {
            "research_query_proposed",
            "research_source_consulted",
            "research_source_assessed",
        }
        if any(source.kind not in allowed for source in self.sources):
            raise ValueError("research conversion contains a non-research source")
        return self


class InterpretationAudit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    subject: InterpretationSubject
    call_metadata: PlanningCallMetadata
    status: Literal["succeeded", "failed"]
    safe_code: (
        Literal["evidence_read_failed", "extractor_unavailable", "invalid_extractor_output"] | None
    ) = None

    @model_validator(mode="after")
    def _failure_code_matches_status(self) -> Self:
        if (self.status == "failed") != (self.safe_code is not None):
            raise ValueError("interpretation_audit_status_policy")
        return self


class PlanRequestAudit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    call_metadata: PlanningCallMetadata
    state_digest: Sha256Hex
    ledger_digest: Sha256Hex
    request_id: UUID | None = None
    lane_key: Annotated[str, Field(pattern=r"^lane-[0-9a-f]{32}$")] | None = None
    material_event_revision: JournalRevision | None = None
    canonical_revision: Sha256Hex | None = None
    source_registry_digest: Sha256Hex | None = None
    max_proposals: Annotated[int, Field(ge=3, le=8)] | None = None
    hindsight_candidate_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    hindsight_query_digests: Annotated[tuple[Sha256Hex, ...], Field(max_length=16)] = ()


class PlannerProposalAudit(BaseModel):
    """The fully allocated proposal that may be journaled for one draft ordinal."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    request_id: UUID
    frontier_id: UUID
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)]
    proposal_count: Annotated[int, Field(ge=1, le=8)]
    proposal: FrontierProposalEventRecord
    situation_digest: Sha256Hex
    input_ledger_digest: Sha256Hex
    knowledge_context_digest: Sha256Hex


class PlannerRepairAudit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    call_metadata: PlanningCallMetadata
    critic_finding_codes: Annotated[tuple[str, ...], Field(max_length=64)]
    request_id: UUID | None = None
    frontier_id: UUID | None = None
    critic_event_id: UUID | None = None
    proposal_ordinal: Annotated[int, Field(ge=1, le=8)] | None = None
    proposal_count: Annotated[int, Field(ge=1, le=8)] | None = None
    proposal: FrontierProposalEventRecord | None = None


class PlannerRejectionAudit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    call_metadata: PlanningCallMetadata
    safe_code: Literal["critic_rejected", "repair_exhausted", "result_too_large"]
    request_id: UUID | None = None
    frontier_id: UUID | None = None
    critic_event_ids: Annotated[tuple[UUID, ...], Field(max_length=2)] = ()
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(max_length=32),
    ] = ()


class ResearchPolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    decision_id: UUID
    allowed: bool
    rationale: ShortText
    query_id: UUID | None = None
    normalized_query: ShortText | None = None
    policy_version: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    reason_codes: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")], ...],
        Field(max_length=16),
    ] = ()
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    candidate_source_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()


class StrategyArchiveTransition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    family_id: UUID
    event_id: UUID
    rationale: ShortText
    request_id: UUID | None = None
    archive_batch_id: UUID | None = None
    entry_ordinal: Annotated[int, Field(ge=1, le=256)] | None = None
    entry_count: Annotated[int, Field(ge=1, le=256)] | None = None
    archive_record: ArchivedStrategyEventRecord | None = None
    resulting_archive_digest: Sha256Hex | None = None


class StrategyReactivationTransition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    family_id: UUID
    event_id: UUID
    rationale: ShortText
    request_id: UUID | None = None
    reactivation_batch_id: UUID | None = None
    entry_ordinal: Annotated[int, Field(ge=1, le=256)] | None = None
    entry_count: Annotated[int, Field(ge=1, le=256)] | None = None
    source_archive_event_id: UUID | None = None
    triggering_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    matched_predicate_ids: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    prior_archive_entry_digest: Sha256Hex | None = None
    resulting_archive_digest: Sha256Hex | None = None
    restored_snapshot: StrategyResultSnapshot | None = None


class PlanningGap(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    code: Literal[
        "no_viable_strategy",
        "planning_constraints",
        "planner_input_too_large",
        "journal_payload_too_large",
        "concurrent_state_change",
        "invalid_planner_output",
        "llm_unavailable",
        "critic_rejected",
        "retrieval_unavailable",
        "journal_unavailable",
        "engagement_terminal",
        "settlement_incomplete",
    ]
    summary: ShortText
    request_id: UUID | None = None
    retryable: bool | None = None
    situation_digest: Sha256Hex | None = None
    ledger_digest: Sha256Hex | None = None
    related_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)] = ()
    pending_ranges: Annotated[tuple[PendingEvidenceRange, ...], Field(max_length=512)] = ()
    stale_frontier: FrontierProjection | None = None


class StrategyReconciliationItem(BaseModel):
    """One complete accepted reconciliation operation and its resulting snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    request_id: UUID
    frontier_id: UUID
    reconciliation_id: UUID
    item_ordinal: Annotated[int, Field(ge=1, le=256)]
    item_count: Annotated[int, Field(ge=1, le=256)]
    input_ledger_digest: Sha256Hex
    resulting_ledger_digest: Sha256Hex
    operation: StrategyReconciliationEventOperation
    resulting_snapshot: StrategyResultSnapshot


class ResearchSourceConsultation(BaseModel):
    """Host-evidence-backed source consultation before journal allocation."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    query_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    normalized_locator: ShortText
    content: bytes = Field(min_length=1, max_length=MAX_HOST_RESULT_BYTES)
    media_type: MediaType
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    tool_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=16)]


class ResearchSourceAssessmentAudit(BaseModel):
    """Authoritative assessed-source semantics, distinct from allocation IDs."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    query_id: UUID
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    consulted_event_id: UUID
    assessment: Literal["useful", "contradicted", "stale", "irrelevant", "ambiguous"]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    related_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]
    suggested_registry_status: Literal["consulted", "useful", "contradicted", "stale"] | None = None


class PlanningResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    status: Literal["success", "gap", "failed"]
    engagement_id: UUID
    current_authoritative_journal_revision: JournalRevision
    frontier: FrontierProjection | None = None
    gap: PlanningGap | None = None
    failure_code: (
        Literal["planning_failed", "settlement_unavailable", "result_too_large"] | None
    ) = None

    @model_validator(mode="after")
    def _exclusive_status_payload(self) -> Self:
        payload_count = sum(
            value is not None for value in (self.frontier, self.gap, self.failure_code)
        )
        expected = {
            "success": self.frontier is not None,
            "gap": self.gap is not None,
            "failed": self.failure_code is not None,
        }[self.status]
        if not expected or payload_count != 1:
            raise ValueError("planning_result_shape")
        return self


class StrategyFamilyState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    family_id: UUID
    runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    status: StrategyStatus
    variant_ids: tuple[UUID, ...] = ()

    @model_validator(mode="after")
    def _variant_ids_are_sorted_unique(self) -> Self:
        is_sorted_unique = self.variant_ids == tuple(sorted(self.variant_ids, key=str))
        if not is_sorted_unique or len(self.variant_ids) != len(set(self.variant_ids)):
            raise ValueError("family_variant_ids_not_sorted_unique")
        return self


class AttemptState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    attempt_event_id: UUID
    outcome_event_id: UUID | None = Field(default=None, exclude=True)
    outcome: OutcomeCategory
    summary: ShortText


class ArchivedStrategyState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    family_id: UUID
    summary: Annotated[str, Field(min_length=1, max_length=16 * 1024)]
    archived_event_id: UUID


class ExecutionVariantState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    variant_id: UUID
    family_id: UUID
    runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    status: StrategyStatus
    recent_attempts: Annotated[
        tuple[AttemptState, ...], Field(max_length=MAX_ATTEMPTS_PER_VARIANT)
    ] = ()
    historical_attempt_count: Annotated[int, Field(ge=0)] = 0
    outcome_category_totals: dict[OutcomeCategory, Annotated[int, Field(ge=1)]] = Field(
        default_factory=dict
    )
    historical_oldest_revision: JournalRevision | None = None
    historical_newest_revision: JournalRevision | None = None
    historical_attempt_digest: Sha256Hex = sha256(b"[]").hexdigest()

    @model_validator(mode="after")
    def _attempt_ids_are_unique(self) -> Self:
        attempt_ids = tuple(attempt.attempt_event_id for attempt in self.recent_attempts)
        if len(attempt_ids) != len(set(attempt_ids)):
            raise ValueError("variant_attempt_ids_not_unique")
        if self.outcome_category_totals and sum(self.outcome_category_totals.values()) != (
            self.historical_attempt_count + len(self.recent_attempts)
        ):
            raise ValueError("attempt_outcomes_do_not_match_count")
        has_bounds = (
            self.historical_oldest_revision is not None
            and self.historical_newest_revision is not None
        )
        if (self.historical_attempt_count > 0) != has_bounds:
            raise ValueError("historical_attempt_revisions_do_not_match_count")
        return self


class StrategyLedger(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    families: Annotated[tuple[StrategyFamilyState, ...], Field(max_length=32)] = ()
    variants: Annotated[tuple[ExecutionVariantState, ...], Field(max_length=64)] = ()
    archive: Annotated[tuple[ArchivedStrategyState, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def _bind_families_and_variants(self) -> Self:
        family_ids = tuple(item.family_id for item in self.families)
        family_keys = tuple(item.runtime_key for item in self.families)
        variant_ids = tuple(item.variant_id for item in self.variants)
        variant_keys = tuple(item.runtime_key for item in self.variants)
        if len(family_ids) != len(set(family_ids)) or len(family_keys) != len(set(family_keys)):
            raise ValueError("duplicate_strategy_runtime_key")
        if len(variant_ids) != len(set(variant_ids)) or len(variant_keys) != len(set(variant_keys)):
            raise ValueError("duplicate_strategy_runtime_key")
        declared = {item.family_id: set(item.variant_ids) for item in self.families}
        for variant in self.variants:
            family_variant_ids = declared.get(variant.family_id, set())
            if variant.variant_id not in family_variant_ids:
                raise ValueError("variant_family_not_declared")
        hot_attempt_count = sum(len(variant.recent_attempts) for variant in self.variants)
        if hot_attempt_count > MAX_HOT_ATTEMPTS:
            raise ValueError("strategy_hot_attempt_limit")
        return self


class EvidenceSliceInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    evidence_id: EvidenceId
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(gt=0)]
    media_type: MediaType
    content: bytes = Field(min_length=1, max_length=EVIDENCE_SLICE_BYTES)

    @model_validator(mode="after")
    def _range_matches_content(self) -> Self:
        if self.end <= self.start or self.end - self.start != len(self.content):
            raise ValueError("evidence_slice_range_mismatch")
        return self


class PrivateValueDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    evidence_id: EvidenceId
    candidate_start: Annotated[int, Field(ge=0)]
    candidate_end: Annotated[int, Field(gt=0)]
    claimed_utf8: Annotated[str, Field(min_length=1, max_length=8192)]

    @model_validator(mode="after")
    def _candidate_range_is_bounded(self) -> Self:
        if self.candidate_end <= self.candidate_start:
            raise ValueError("reference_validation_failed")
        if self.candidate_end - self.candidate_start > 8192:
            raise ValueError("reference_validation_failed")
        return self

    def resolve(self, evidence_slices: tuple[EvidenceSliceInput, ...]) -> Sha256Hex:
        matches: list[bytes] = []
        for evidence_slice in evidence_slices:
            if evidence_slice.evidence_id != self.evidence_id:
                continue
            contains_candidate = (
                evidence_slice.start <= self.candidate_start
                and self.candidate_end <= evidence_slice.end
            )
            if not contains_candidate:
                continue
            offset_start = self.candidate_start - evidence_slice.start
            offset_end = self.candidate_end - evidence_slice.start
            candidate = evidence_slice.content[offset_start:offset_end]
            if candidate == self.claimed_utf8.encode("utf-8"):
                matches.append(candidate)
        if len(matches) != 1:
            raise ValueError("reference_validation_failed")
        return sha256(matches[0]).hexdigest()


class _GroundedDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _event_ids_are_sorted_unique(self) -> Self:
        if self.event_ids != tuple(sorted(self.event_ids, key=str)) or len(self.event_ids) != len(
            set(self.event_ids)
        ):
            raise ValueError("event_ids_not_sorted_unique")
        return self


class FacetObservationDraft(_GroundedDraft):
    key: ShortText
    value: ShortText


class AccessStateDeltaDraft(_GroundedDraft):
    subject: ShortText
    state: ShortText


class SecretReferenceDraft(_GroundedDraft):
    label: ShortText
    value: PrivateValueDraft


class IncompatibilityObservationDraft(_GroundedDraft):
    subject: ShortText
    explanation: ShortText


class MissingInformationDraft(_GroundedDraft):
    question: ShortText


class ResearchSourceObservationDraft(_GroundedDraft):
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    assessment: Literal["useful", "not_useful", "inconclusive"]


class InterpretationSubject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    attachment_event_id: UUID
    terminal_tool_event_id: UUID | None = None
    evidence_id: EvidenceId


class OutcomeAssessmentDraft(_GroundedDraft):
    category: OutcomeCategory
    summary: ShortText


class ObservationBatchDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    subject: InterpretationSubject | None = None
    observations: Annotated[tuple[ObservationDraft, ...], Field(max_length=64)] = ()
    facets: Annotated[tuple[FacetObservationDraft, ...], Field(max_length=64)] = ()
    access_deltas: Annotated[tuple[AccessStateDeltaDraft, ...], Field(max_length=64)] = ()
    secret_references: Annotated[tuple[SecretReferenceDraft, ...], Field(max_length=64)] = ()
    incompatibilities: Annotated[
        tuple[IncompatibilityObservationDraft, ...], Field(max_length=64)
    ] = ()
    missing_information: Annotated[tuple[MissingInformationDraft, ...], Field(max_length=64)] = ()
    research_sources: Annotated[
        tuple[ResearchSourceObservationDraft, ...], Field(max_length=64)
    ] = ()
    outcomes: Annotated[tuple[OutcomeAssessmentDraft, ...], Field(max_length=64)] = ()
    hypotheses: Annotated[tuple[HypothesisDraft, ...], Field(max_length=64)] = ()
    objective_proofs: Annotated[tuple[ObjectiveProofDraft, ...], Field(max_length=64)] = ()


class ObjectiveProofDraft(_GroundedDraft):
    proof_requirement_id: ProofRequirementId
    assessment: Literal["supported", "contradicted"]

    def bind_manifest(self, requirements: tuple[ProofRequirement, ...]) -> Self:
        matching = tuple(
            requirement
            for requirement in requirements
            if requirement.proof_id == self.proof_requirement_id
        )
        if len(matching) != 1:
            raise ValueError("proof_requirement_not_in_manifest")
        return self


class _DerivedSituationRecord(_GroundedDraft):
    """Data-only, event-grounded state record for deterministic situation replay."""


class ObservedFact(_DerivedSituationRecord):
    text: ShortText


class ObservedFacet(_DerivedSituationRecord):
    key: ShortText
    value: ShortText


class SituationHypothesis(_DerivedSituationRecord):
    text: ShortText
    confidence: Annotated[float, Field(ge=0, le=1)]


class UnresolvedInformation(_DerivedSituationRecord):
    question: ShortText


class ResearchSourceAssessment(_DerivedSituationRecord):
    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    assessment: Literal["useful", "not_useful", "inconclusive"]


class AccessState(_DerivedSituationRecord):
    subject: ShortText
    state: ShortText


class EvidenceInterpretationState(_DerivedSituationRecord):
    event_ids: Annotated[
        tuple[UUID, ...], Field(min_length=1, max_length=MAX_SITUATION_INTERPRETATIONS)
    ]
    subject: InterpretationSubject
    status: Literal["pending", "completed", "failed"]


class SecretReference(_DerivedSituationRecord):
    label: ShortText
    evidence_id: EvidenceId
    candidate_start: Annotated[int | None, Field(ge=0)] = None
    candidate_end: Annotated[int | None, Field(gt=0)] = None
    value_sha256: Sha256Hex

    @model_validator(mode="after")
    def _private_locator_is_positive(self) -> Self:
        if (self.candidate_start is None) != (self.candidate_end is None):
            raise ValueError("secret_reference_range_pair_required")
        if (
            self.candidate_start is not None
            and self.candidate_end is not None
            and self.candidate_end <= self.candidate_start
        ):
            raise ValueError("secret_reference_range_must_be_positive")
        return self


class AvailableCredential(_DerivedSituationRecord):
    """A credential the planner may cite in a command binding.

    Only the label and kind are exposed, never the value. A binding's
    reference_id must equal a label from ``CurrentSituation.secret_references``,
    and without this view the planner had no way to learn which labels exist, so
    it could not write a valid credential binding at all.
    """

    label: ShortText
    secret_kind: Annotated[str, Field(min_length=1, max_length=128)] = "other"


class AttemptSummary(_DerivedSituationRecord):
    attempt_event_id: UUID
    outcome: OutcomeCategory
    summary: ShortText


class Incompatibility(_DerivedSituationRecord):
    subject: ShortText
    explanation: ShortText


class StrategyFamilyDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    family_id: None = None
    runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    title: ShortText


class ExecutionVariantDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    variant_id: None = None
    family_runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    runtime_key: Annotated[str, Field(min_length=1, max_length=128)]
    title: ShortText


class StrategyArchive(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    entries: Annotated[tuple[ArchivedStrategyState, ...], Field(max_length=16)] = ()


class ProofCandidateAdmission(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    proof_requirement_id: ProofRequirementId
    assessment_generation: Annotated[int, Field(ge=1)]
    candidate_sha256: Sha256Hex
    decision: Literal["allowed", "previously_rejected"]
    matched_rejection_event_id: UUID | None = None

    @model_validator(mode="after")
    def _matched_event_policy(self) -> Self:
        was_previously_rejected = self.decision == "previously_rejected"
        has_matched_event = self.matched_rejection_event_id is not None
        if was_previously_rejected != has_matched_event:
            raise ValueError("proof_candidate_admission_policy")
        return self


class PendingEvidenceRange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    evidence_id: EvidenceId
    attachment_event_id: UUID
    terminal_tool_event_id: UUID | None = None
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(gt=0)]
    media_type: MediaType
    reason: Literal["budget_exhausted", "retryable_interpretation_failure", "read_failure"]

    @model_validator(mode="after")
    def _positive_range(self) -> Self:
        if self.end <= self.start:
            raise ValueError("pending_range_must_be_positive")
        return self


class _SettlementResultBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    engagement_id: UUID
    reason: SettlementReason
    authoritative_journal_revision: JournalRevision | None
    situation: SituationProjection | None
    required_proof_ids: Annotated[
        tuple[ProofRequirementId, ...], Field(max_length=MAX_REQUIRED_PROOFS)
    ] = ()
    pending_ranges: Annotated[tuple[PendingEvidenceRange, ...], Field(max_length=512)] = ()
    pending_total_count: Annotated[int, Field(ge=0, le=MAX_SETTLEMENT_PENDING_RANGES)] = 0
    pending_inventory_sha256: Sha256Hex | None = None
    next_pending_subject: PendingSubjectCursor | None = None
    incomplete_reason: Literal["budget_exhausted", "interpretation_incomplete"] | None = None
    all_required_proofs_satisfied: bool
    possible_terminal_evidence: bool

    @model_validator(mode="after")
    def _bind_projection_ranges_and_proofs(self) -> Self:
        if (self.situation is None) != (self.authoritative_journal_revision is None):
            raise ValueError("settlement_projection_revision_pair_required")
        if (
            self.situation is not None
            and self.authoritative_journal_revision != self.situation.authoritative_journal_revision
        ):
            raise ValueError("settlement_projection_revision_mismatch")
        range_keys = tuple(
            (
                str(item.attachment_event_id),
                str(item.terminal_tool_event_id or ""),
                str(item.evidence_id),
                item.start,
                item.end,
            )
            for item in self.pending_ranges
        )
        if range_keys != tuple(sorted(range_keys)) or len(range_keys) != len(set(range_keys)):
            raise ValueError("pending_ranges_not_sorted_unique")
        latest_end: dict[tuple[str, str, str], int] = {}
        for attachment, terminal, evidence, start, end in range_keys:
            subject = (attachment, terminal, evidence)
            if start < latest_end.get(subject, 0):
                raise ValueError("pending_ranges_overlap")
            latest_end[subject] = end
        if self.pending_total_count < len(self.pending_ranges):
            raise ValueError("pending_total_smaller_than_page")
        if (self.pending_total_count > 0) != (self.pending_inventory_sha256 is not None):
            raise ValueError("pending_inventory_digest_policy")
        has_next_page = self.pending_total_count > len(self.pending_ranges)
        if has_next_page != (self.next_pending_subject is not None):
            raise ValueError("pending_cursor_policy")
        if self.required_proof_ids != tuple(sorted(set(self.required_proof_ids))):
            raise ValueError("required_proof_ids_not_sorted_unique")
        if self.situation is None:
            if (
                self.required_proof_ids
                or self.all_required_proofs_satisfied
                or self.possible_terminal_evidence
            ):
                raise ValueError("proof_state_requires_situation")
            return self
        progress = {
            item.proof_requirement_id: item.status
            for item in self.situation.objective_progress.requirements
        }
        if tuple(sorted(progress)) != self.required_proof_ids:
            raise ValueError("settlement_manifest_proof_mismatch")
        expected = bool(self.required_proof_ids) and all(
            progress[proof_id] == "supported" for proof_id in self.required_proof_ids
        )
        if self.all_required_proofs_satisfied is not expected:
            raise ValueError("settlement_proof_completion_mismatch")
        return self


class SettledSettlementResult(_SettlementResultBase):
    status: Literal["settled"] = "settled"
    authoritative_journal_revision: JournalRevision
    situation: SituationProjection
    pending_ranges: Annotated[tuple[PendingEvidenceRange, ...], Field(max_length=0)] = ()
    pending_total_count: Literal[0] = 0
    pending_inventory_sha256: None = None
    next_pending_subject: None = None
    incomplete_reason: None = None
    failure_code: None = None
    failure_summary: None = None


class NothingPendingSettlementResult(_SettlementResultBase):
    status: Literal["nothing_pending"] = "nothing_pending"
    authoritative_journal_revision: JournalRevision
    situation: SituationProjection
    pending_ranges: Annotated[tuple[PendingEvidenceRange, ...], Field(max_length=0)] = ()
    pending_total_count: Literal[0] = 0
    pending_inventory_sha256: None = None
    next_pending_subject: None = None
    incomplete_reason: None = None
    failure_code: None = None
    failure_summary: None = None


class FailedSettlementResult(_SettlementResultBase):
    status: Literal["failed"] = "failed"
    incomplete_reason: None = None
    failure_code: Literal[
        "journal_unavailable",
        "journal_corrupt",
        "evidence_read_failed",
        "extractor_unavailable",
        "invalid_extractor_output",
        "journal_append_failed",
        "concurrent_state_change",
        "terminal_reconciliation_failed",
    ]
    failure_summary: ShortText

    @model_validator(mode="after")
    def _failure_projection_policy(self) -> Self:
        journal_missing = self.failure_code in {"journal_unavailable", "journal_corrupt"}
        if journal_missing != (self.situation is None):
            raise ValueError("failed_settlement_projection_policy")
        return self


class IncompleteSettlementResult(_SettlementResultBase):
    status: Literal["incomplete"] = "incomplete"
    authoritative_journal_revision: JournalRevision
    situation: SituationProjection
    pending_ranges: Annotated[tuple[PendingEvidenceRange, ...], Field(min_length=1, max_length=512)]
    pending_total_count: Annotated[int, Field(ge=1, le=MAX_SETTLEMENT_PENDING_RANGES)]
    pending_inventory_sha256: Sha256Hex
    incomplete_reason: Literal["budget_exhausted", "interpretation_incomplete"]
    failure_code: None = None
    failure_summary: None = None


SettlementResult = Annotated[
    SettledSettlementResult
    | NothingPendingSettlementResult
    | IncompleteSettlementResult
    | FailedSettlementResult,
    Field(discriminator="status"),
]
SettlementResultAdapter = TypeAdapter(SettlementResult)


__all__ = [
    "EVIDENCE_SLICE_BYTES",
    "MAX_EVIDENCE_BYTES_PER_SETTLEMENT",
    "MAX_PLANNING_EVENT_BATCH",
    "MAX_PLANNING_PAYLOAD_BYTES",
    "MAX_PLANNING_RESULT_BYTES",
    "MAX_PLANNER_REQUEST_BYTES",
    "MAX_RECENT_EVENTS",
    "MAX_RECENT_EVENT_TEXT_BYTES",
    "IncompleteSettlementResult",
    "NothingPendingSettlementResult",
    "ObjectiveProgress",
    "OutcomeCategory",
    "PendingEvidenceRange",
    "ProofProgress",
    "RetryPredicateKind",
    "SituationProjection",
    "StrategyStatus",
    "ExecutionVariantState",
    "StrategyFamilyState",
    "StrategyLedger",
]
