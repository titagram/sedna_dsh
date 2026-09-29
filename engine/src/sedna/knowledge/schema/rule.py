"""Immutable contracts for source-backed decision rules."""

from typing import Literal

from pydantic import ConfigDict, Field

from sedna.knowledge.schema.common import (
    ArtifactType,
    CanonicalArtifactMetadata,
    KnowledgeRole,
    SearchableNonEmptyString,
    SourceRef,
)

NonEmptyString = SearchableNonEmptyString


class DecisionRule(CanonicalArtifactMetadata):
    """A source-backed rule connecting observations to an action intent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: Literal[ArtifactType.DECISION_RULE]
    knowledge_role: Literal[KnowledgeRole.REFERENCE]
    rule_id: NonEmptyString
    trigger_observations: tuple[NonEmptyString, ...] = Field(min_length=1)
    rationale: NonEmptyString
    action_intent: NonEmptyString
    prerequisites: tuple[NonEmptyString, ...] = ()
    expected_evidence: tuple[NonEmptyString, ...] = ()
    success_transitions: tuple[NonEmptyString, ...] = ()
    failure_transitions: tuple[NonEmptyString, ...] = ()
    stop_conditions: tuple[NonEmptyString, ...] = ()
    exceptions: tuple[NonEmptyString, ...] = ()
    alternative_hypotheses: tuple[NonEmptyString, ...] = ()
    capability_refs: tuple[NonEmptyString, ...] = ()
    contradicting_source_refs: tuple[SourceRef, ...] = ()
