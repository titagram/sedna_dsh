"""Immutable contracts for source-backed, transferable reference artifacts."""

from typing import Literal

from pydantic import ConfigDict

from sedna.knowledge.schema.common import (
    ArtifactType,
    CanonicalArtifactMetadata,
    KnowledgeRole,
    SearchableNonEmptyString,
)

NonEmptyString = SearchableNonEmptyString


class ReferenceArtifact(CanonicalArtifactMetadata):
    """A concise, source-backed statement that can inform future cases."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: Literal[
        ArtifactType.CONCEPT,
        ArtifactType.METHODOLOGY,
        ArtifactType.CONSTRAINT,
        ArtifactType.EVIDENCE_INTERPRETATION,
        ArtifactType.NEGATIVE_EVIDENCE,
        ArtifactType.ANTI_PATTERN,
        ArtifactType.EXCEPTION,
    ]
    knowledge_role: Literal[KnowledgeRole.REFERENCE]
    artifact_id: NonEmptyString
    subject: NonEmptyString
    statement: NonEmptyString
    applicable_situations: tuple[NonEmptyString, ...] = ()
    prerequisites: tuple[NonEmptyString, ...] = ()
    action_intent: NonEmptyString | None = None
    expected_information_gain: NonEmptyString | None = None
    expected_evidence: tuple[NonEmptyString, ...] = ()
    evidence_interpretation: NonEmptyString | None = None
    success_implications: tuple[NonEmptyString, ...] = ()
    failure_implications: tuple[NonEmptyString, ...] = ()
    stop_implications: tuple[NonEmptyString, ...] = ()
    exceptions: tuple[NonEmptyString, ...] = ()
    warnings: tuple[NonEmptyString, ...] = ()
    capability_refs: tuple[NonEmptyString, ...] = ()
    observed_at: NonEmptyString | None = None
