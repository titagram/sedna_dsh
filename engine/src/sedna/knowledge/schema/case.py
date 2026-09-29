"""Immutable contracts for chronological, provenance-backed case studies."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.schema.common import (
    ArtifactType,
    CanonicalArtifactMetadata,
    KnowledgeRole,
    Origin,
    SearchableNonEmptyString,
    SearchableString,
    SourceQuality,
)

NonEmptyString = SearchableNonEmptyString


class CaseState(BaseModel):
    """The relevant environment and access state at a point in a case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    access: NonEmptyString
    environment: tuple[NonEmptyString, ...] = ()
    privileges: tuple[NonEmptyString, ...] = ()


class CaseHypothesis(BaseModel):
    """An explicit or inferred explanation considered during a case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    statement: NonEmptyString
    origin: Origin


class CaseAction(BaseModel):
    """A selected action expressed as intent instead of a tool recipe."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent: NonEmptyString
    capability_ref: SearchableString | None = None


class CaseEvidence(BaseModel):
    """A categorized observation supporting or constraining a case step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: NonEmptyString
    origin: Origin
    category: NonEmptyString | None = None


class CaseStep(CanonicalArtifactMetadata):
    """One ordered, source-backed transition in a case study."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: Literal[ArtifactType.CASE_STEP]
    knowledge_role: Literal[KnowledgeRole.CASE_STUDY, KnowledgeRole.NEGATIVE_CASE]
    step_id: NonEmptyString
    ordinal: int = Field(ge=1)
    state_before: CaseState
    observations: tuple[SearchableString, ...]
    hypotheses: tuple[CaseHypothesis, ...]
    selected_action: CaseAction
    expected_information_gain: NonEmptyString | None = None
    evidence: tuple[CaseEvidence, ...]
    state_after: CaseState
    negative_evidence: tuple[SearchableString, ...] = ()
    transfer_conditions: tuple[SearchableString, ...] = ()
    case_specific_details: tuple[SearchableString, ...] = ()
    requires_validation: bool = True


class KnowledgeCase(CanonicalArtifactMetadata):
    """An ordered case study with transferable and local context kept distinct."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: Literal[ArtifactType.CASE]
    knowledge_role: Literal[KnowledgeRole.CASE_STUDY, KnowledgeRole.NEGATIVE_CASE]
    case_id: NonEmptyString
    title: NonEmptyString
    starting_access: NonEmptyString
    steps: tuple[CaseStep, ...]
    outcome: NonEmptyString
    source_quality: SourceQuality
    difficulty: NonEmptyString | None = None
    transferable_properties: tuple[NonEmptyString, ...] = ()
    non_transferable_properties: tuple[NonEmptyString, ...] = ()

    @model_validator(mode="after")
    def validate_unique_ordinals(self) -> KnowledgeCase:
        """Keep chronology unique and every nested step in the case's lane."""
        if len({step.ordinal for step in self.steps}) != len(self.steps):
            raise ValueError("case step ordinals must be unique")
        if any(step.knowledge_role is not self.knowledge_role for step in self.steps):
            raise ValueError("case step knowledge_role must match its knowledge case")
        return self

    @property
    def platform(self) -> str | None:
        """Expose the former platform field from the shared applicability context."""
        assertion = self.applicability.typed_context.execution_environment
        return assertion.value if assertion is not None else None

    @property
    def operating_system(self) -> str | None:
        """Expose the former operating-system field from shared applicability."""
        assertion = self.applicability.typed_context.os_family
        return assertion.value if assertion is not None else None
