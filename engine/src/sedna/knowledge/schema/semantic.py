"""Immutable source-level records emitted by semantic knowledge compilation."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.schema.case import KnowledgeCase
from sedna.knowledge.schema.common import ExtractionMetadata, SearchableNonEmptyString, SourceRef
from sedna.knowledge.schema.execution import ExecutionExample
from sedna.knowledge.schema.manifest import Sha256
from sedna.knowledge.schema.reference import ReferenceArtifact
from sedna.knowledge.schema.rule import DecisionRule

NonEmptyString = SearchableNonEmptyString
TokenCount = int
FindingCode = Literal[
    "unsupported_claim",
    "missing_prerequisite",
    "missing_exception",
    "context_omission",
    "overgeneralization",
    "origin_mismatch",
    "unsafe_material",
    "lost_negative_evidence",
    "invalid_provenance",
]
FindingSeverity = Literal["warning", "material"]
CompilationDisposition = Literal["verified", "quarantined", "failed", "unchanged"]
CANONICAL_FINDING_MESSAGES: dict[FindingCode, str] = {
    "unsupported_claim": "The source does not support the claim.",
    "missing_prerequisite": "A required prerequisite is not represented.",
    "missing_exception": "A relevant exception is not represented.",
    "context_omission": "Required applicability context is omitted.",
    "overgeneralization": "The claim generalizes beyond the cited context.",
    "origin_mismatch": "The claim origin does not match the cited evidence.",
    "unsafe_material": "The artifact contains unsafe material.",
    "lost_negative_evidence": "Negative evidence from the source is missing.",
    "invalid_provenance": "The artifact provenance is invalid.",
}


class SemanticCallMetadata(BaseModel):
    """Safe operational metadata for one semantic model call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    purpose: NonEmptyString
    provider: NonEmptyString
    model: NonEmptyString
    agent_id: NonEmptyString
    input_tokens: TokenCount = Field(ge=0, le=1_000_000)
    output_tokens: TokenCount = Field(ge=0, le=1_000_000)


class VerificationFinding(BaseModel):
    """A closed-vocabulary critic finding safe to retain in canonical audits."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: FindingCode
    severity: FindingSeverity
    artifact_local_id: NonEmptyString | None = None
    message: NonEmptyString
    segment_indexes: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_segment_indexes(self) -> VerificationFinding:
        """Keep finding summaries canonical and citations deterministic."""
        if self.message != CANONICAL_FINDING_MESSAGES[self.code]:
            raise ValueError("verification finding message must match its canonical message")
        if any(index < 0 for index in self.segment_indexes):
            raise ValueError("segment indexes must be non-negative")
        if len(set(self.segment_indexes)) != len(self.segment_indexes):
            raise ValueError("segment indexes must be unique")
        if tuple(sorted(self.segment_indexes)) != self.segment_indexes:
            raise ValueError("segment indexes must be sorted")
        return self


class SemanticCompilationManifest(BaseModel):
    """Reproducibility metadata for one semantic compilation attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: NonEmptyString
    source_sha256: Sha256
    foundation_schema_version: NonEmptyString
    foundation_parser_id: NonEmptyString
    foundation_parser_version: NonEmptyString
    foundation_extraction: ExtractionMetadata | None = None
    foundation_manifest_sha256: Sha256 | None = None
    compiler_version: NonEmptyString
    extractor_prompt_version: NonEmptyString
    critic_prompt_version: NonEmptyString
    repair_prompt_version: NonEmptyString
    extractor_model_id: NonEmptyString
    critic_model_id: NonEmptyString
    disposition: CompilationDisposition
    repair_count: int = Field(ge=0, le=1)
    emitted_artifact_ids: tuple[NonEmptyString, ...] = ()
    execution_example_schema_version: NonEmptyString | None = None
    emitted_execution_example_ids: tuple[NonEmptyString, ...] = ()
    started_at: datetime
    completed_at: datetime

    @model_validator(mode="after")
    def validate_manifest(self) -> SemanticCompilationManifest:
        """Keep emitted identities canonical and caller timestamps chronological."""
        if tuple(sorted(self.emitted_artifact_ids)) != self.emitted_artifact_ids:
            raise ValueError("emitted artifact IDs must be sorted")
        if len(set(self.emitted_artifact_ids)) != len(self.emitted_artifact_ids):
            raise ValueError("emitted artifact IDs must be unique")
        if tuple(sorted(self.emitted_execution_example_ids)) != self.emitted_execution_example_ids:
            raise ValueError("emitted execution-example IDs must be sorted")
        if len(set(self.emitted_execution_example_ids)) != len(self.emitted_execution_example_ids):
            raise ValueError("emitted execution-example IDs must be unique")
        if (self.execution_example_schema_version is None) != (
            not self.emitted_execution_example_ids
        ):
            raise ValueError("execution-example schema version must match emitted example IDs")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class SemanticVerificationRecord(BaseModel):
    """A safe, source-level verification audit without model prose or prompts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: NonEmptyString
    source_sha256: Sha256
    critic_call: SemanticCallMetadata
    repair_count: int = Field(default=0, ge=0, le=1)
    findings: tuple[VerificationFinding, ...] = ()
    adjudication: CompilationDisposition
    recorded_at: datetime

    @model_validator(mode="after")
    def validate_adjudication(self) -> SemanticVerificationRecord:
        """Do not mark material critic disagreement as verified."""
        if self.critic_call.purpose != "sedna.semantic.critic":
            raise ValueError("verification critic call purpose must be sedna.semantic.critic")
        has_material_finding = any(finding.severity == "material" for finding in self.findings)
        if self.adjudication == "verified" and has_material_finding:
            raise ValueError("verified adjudication cannot contain material findings")
        return self


class SemanticQuarantineRecord(BaseModel):
    """An explainable semantic quarantine that contains only safe citations and messages."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: NonEmptyString
    source_sha256: Sha256
    reason_codes: tuple[FindingCode, ...] = Field(min_length=1)
    messages: tuple[NonEmptyString, ...] = Field(min_length=1)
    segment_indexes: tuple[int, ...] = ()
    recorded_at: datetime
    compilation_manifest: SemanticCompilationManifest | None = None
    semantic_schema_version: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_quarantine_citations(self) -> SemanticQuarantineRecord:
        """Require a safe message for every quarantine reason and valid citations."""
        if len(self.reason_codes) != len(self.messages):
            raise ValueError("quarantine reason codes and messages must have matching lengths")
        if any(index < 0 for index in self.segment_indexes):
            raise ValueError("segment indexes must be non-negative")
        if len(set(self.segment_indexes)) != len(self.segment_indexes):
            raise ValueError("segment indexes must be unique")
        if tuple(sorted(self.segment_indexes)) != self.segment_indexes:
            raise ValueError("segment indexes must be sorted")
        if self.compilation_manifest is not None and (
            self.compilation_manifest.source_id != self.source_id
            or self.compilation_manifest.source_sha256 != self.source_sha256
            or self.compilation_manifest.disposition != "quarantined"
        ):
            raise ValueError("quarantine compilation manifest must match its quarantined source")
        return self


class SemanticKnowledgeBundle(BaseModel):
    """Validated canonical artifacts emitted for a single source identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: NonEmptyString
    source_id: NonEmptyString
    source_sha256: Sha256
    compilation_manifest: SemanticCompilationManifest
    references: tuple[ReferenceArtifact, ...] = ()
    cases: tuple[KnowledgeCase, ...] = ()
    guidance: tuple[DecisionRule, ...] = ()
    execution_examples: tuple[ExecutionExample, ...] = ()

    @model_validator(mode="after")
    def validate_bundle(self) -> SemanticKnowledgeBundle:
        """Require sorted unique artifacts and exact manifest coverage of nested IDs."""
        if self.compilation_manifest.disposition != "verified":
            raise ValueError("semantic bundle requires a verified compilation manifest")
        self._validate_sorted_unique(self.references, "artifact_id", "references")
        self._validate_sorted_unique(self.cases, "case_id", "cases")
        self._validate_sorted_unique(self.guidance, "rule_id", "guidance")
        self._validate_sorted_unique(self.execution_examples, "example_id", "execution_examples")

        if (
            self.compilation_manifest.source_id != self.source_id
            or self.compilation_manifest.source_sha256 != self.source_sha256
        ):
            raise ValueError("bundle source identity must match its compilation manifest")

        for artifact in (*self.references, *self.cases, *self.guidance):
            self._validate_bundle_source_provenance(artifact.source_refs, "top-level artifact")
        for knowledge_case in self.cases:
            for step in knowledge_case.steps:
                self._validate_bundle_source_provenance(step.source_refs, "nested case step")
        for example in self.execution_examples:
            self._validate_bundle_source_provenance(example.source_refs, "execution example")

        nested_ids = (
            tuple(reference.artifact_id for reference in self.references)
            + tuple(knowledge_case.case_id for knowledge_case in self.cases)
            + tuple(step.step_id for knowledge_case in self.cases for step in knowledge_case.steps)
            + tuple(rule.rule_id for rule in self.guidance)
        )
        if len(set(nested_ids)) != len(nested_ids):
            raise ValueError("artifact IDs must be unique across the semantic bundle")
        if set(self.compilation_manifest.emitted_artifact_ids) != set(nested_ids):
            raise ValueError("compilation manifest IDs must exactly match bundle artifact IDs")
        example_ids = tuple(example.example_id for example in self.execution_examples)
        if len(set(example_ids)) != len(example_ids):
            raise ValueError("execution example IDs must be unique across the semantic bundle")
        parent_ids = {reference.artifact_id for reference in self.references} | {
            step.step_id for knowledge_case in self.cases for step in knowledge_case.steps
        }
        for example in self.execution_examples:
            if example.parent_artifact_id not in parent_ids:
                raise ValueError("execution example parent must be a bundle reference or case step")
        if set(self.compilation_manifest.emitted_execution_example_ids) != {
            example.example_id for example in self.execution_examples
        }:
            raise ValueError("compilation manifest example IDs must exactly match bundle examples")
        return self

    @staticmethod
    def _validate_sorted_unique(
        artifacts: tuple[ReferenceArtifact, ...]
        | tuple[KnowledgeCase, ...]
        | tuple[DecisionRule, ...]
        | tuple[ExecutionExample, ...],
        attribute: Literal["artifact_id", "case_id", "rule_id", "example_id"],
        field_name: str,
    ) -> None:
        identifiers = tuple(getattr(artifact, attribute) for artifact in artifacts)
        if tuple(sorted(identifiers)) != identifiers:
            raise ValueError(f"{field_name} must be sorted")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"{field_name} must be unique")

    def _validate_bundle_source_provenance(
        self,
        source_refs: tuple[SourceRef, ...],
        record_kind: str,
    ) -> None:
        if not any(source_ref.source_id == self.source_id for source_ref in source_refs):
            raise ValueError(f"{record_kind} must cite the bundle source")
