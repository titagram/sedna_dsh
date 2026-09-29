"""Public shared schema contracts for Sedna knowledge ingestion."""

from sedna.knowledge.schema.common import (
    ArtifactType,
    CanonicalArtifactMetadata,
    DocumentType,
    ExtractionMetadata,
    Generalizability,
    IngestionStatus,
    KnowledgeRole,
    Origin,
    ReviewStatus,
    SourceLocation,
    SourceQuality,
    SourceRef,
    VerificationStatus,
    verification_from_legacy_review,
)
from sedna.knowledge.schema.execution import (
    ExecutionCondition,
    ExecutionExample,
    ExecutionPlaceholder,
    ExecutionPlatformConstraint,
    PlaceholderBindingPolicy,
    PlaceholderKind,
)
from sedna.knowledge.schema.context import (
    ApplicabilityContext,
    ContextAssertion,
    ContextFacet,
    ContextRelation,
    EpistemicAssessment,
    ObservedOutcome,
    ServiceContext,
    TypedContext,
)
from sedna.knowledge.schema.case import (
    CaseAction,
    CaseEvidence,
    CaseHypothesis,
    CaseState,
    CaseStep,
    KnowledgeCase,
)
from sedna.knowledge.schema.manifest import (
    AssetRef,
    DocumentManifest,
    foundation_manifest_digest,
)
from sedna.knowledge.schema.reference import ReferenceArtifact
from sedna.knowledge.schema.rule import DecisionRule
from sedna.knowledge.schema.semantic import (
    SemanticCallMetadata,
    SemanticCompilationManifest,
    SemanticKnowledgeBundle,
    SemanticQuarantineRecord,
    SemanticVerificationRecord,
    VerificationFinding,
)

for _canonical_model in (
    CanonicalArtifactMetadata,
    ReferenceArtifact,
    CaseStep,
    KnowledgeCase,
    DecisionRule,
):
    _canonical_model.model_rebuild(
        force=True,
        _types_namespace={
            "ApplicabilityContext": ApplicabilityContext,
            "EpistemicAssessment": EpistemicAssessment,
        },
    )

__all__ = [
    "ArtifactType",
    "ApplicabilityContext",
    "AssetRef",
    "CaseAction",
    "CaseEvidence",
    "CaseHypothesis",
    "CaseState",
    "CaseStep",
    "CanonicalArtifactMetadata",
    "ContextAssertion",
    "ContextFacet",
    "ContextRelation",
    "DecisionRule",
    "DocumentType",
    "EpistemicAssessment",
    "ExecutionCondition",
    "ExecutionExample",
    "ExecutionPlaceholder",
    "ExecutionPlatformConstraint",
    "DocumentManifest",
    "ExtractionMetadata",
    "foundation_manifest_digest",
    "Generalizability",
    "IngestionStatus",
    "KnowledgeRole",
    "KnowledgeCase",
    "Origin",
    "PlaceholderBindingPolicy",
    "PlaceholderKind",
    "ObservedOutcome",
    "ReviewStatus",
    "ReferenceArtifact",
    "SourceLocation",
    "SourceQuality",
    "SourceRef",
    "ServiceContext",
    "SemanticCallMetadata",
    "SemanticCompilationManifest",
    "SemanticKnowledgeBundle",
    "SemanticQuarantineRecord",
    "SemanticVerificationRecord",
    "TypedContext",
    "VerificationStatus",
    "VerificationFinding",
    "verification_from_legacy_review",
]
