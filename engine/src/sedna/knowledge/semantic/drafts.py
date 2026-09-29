"""Strict, source-identity-free contracts for semantic model completions."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.schema.case import CaseAction, CaseEvidence, CaseHypothesis, CaseState
from sedna.knowledge.schema.common import (
    ArtifactType,
    KnowledgeRole,
    Origin,
    SearchableNonEmptyString,
    SearchableString,
    SourceLocation,
    SourceQuality,
    SourceRef,
)
from sedna.knowledge.schema.context import ContextRelation
from sedna.knowledge.schema.execution import (
    ExecutionPlatformConstraint,
    _ordered_placeholders,
    _validate_command_template,
    _validate_platform_prose,
)
from sedna.knowledge.schema.semantic import (
    SemanticCallMetadata,
    SemanticKnowledgeBundle,
    SemanticQuarantineRecord,
    SemanticVerificationRecord,
    VerificationFinding,
)

DraftLocalId = Annotated[
    SearchableNonEmptyString,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
]
CompilationDisposition = Literal["verified", "quarantined", "failed", "unchanged"]
CompilationFailureCode = Literal[
    "transport_failure",
    "missing_parsed_response",
    "invalid_structured_response",
    "invalid_input",
    "materialization_failure",
    "required_case_missing",
    "internal_failure",
]
CANONICAL_COMPILATION_FAILURE_MESSAGES: dict[CompilationFailureCode, str] = {
    "transport_failure": "The host LLM request failed.",
    "missing_parsed_response": "The host LLM returned no parsed structured response.",
    "invalid_structured_response": "The host LLM response failed semantic validation.",
    "invalid_input": "The semantic compiler input failed validation.",
    "materialization_failure": "Semantic artifacts could not be materialized safely.",
    "required_case_missing": "Journal promotion semantics require at least one case artifact.",
    "internal_failure": "The semantic compiler encountered an internal failure.",
}
_SAFE_DRAFT_LOCAL_ID = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9][A-Za-z0-9._-]*$")
_VALID_CALL_SEQUENCES = (
    (),
    ("sedna.semantic.extract",),
    ("sedna.semantic.extract", "sedna.semantic.critic"),
    ("sedna.semantic.extract", "sedna.semantic.critic", "sedna.semantic.repair"),
    (
        "sedna.semantic.extract",
        "sedna.semantic.critic",
        "sedna.semantic.repair",
        "sedna.semantic.critic",
    ),
)


class DraftCitation(BaseModel):
    """A draft-only citation into the compiler input's segment sequence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    segment_indexes: tuple[int, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_segment_indexes(self) -> Self:
        """Keep citations deterministic before a compiler binds the input range."""
        _validate_deterministic_indexes(self.segment_indexes)
        return self


class DraftContextAssertion(BaseModel):
    """A source-segment-cited assertion that limits a draft's applicability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: SearchableString
    relation: ContextRelation
    origin: Origin
    confidence: float = Field(ge=0.0, le=1.0)
    citations: tuple[DraftCitation, ...] = Field(min_length=1)


class DraftServiceContext(BaseModel):
    """A typed service identity available to a draft applicability context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_type: SearchableNonEmptyString
    identity: DraftContextAssertion


class DraftTypedContext(BaseModel):
    """Draft variants of the shared typed applicability vocabulary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    os_family: DraftContextAssertion | None = None
    os_version: DraftContextAssertion | None = None
    cpu_architecture: DraftContextAssertion | None = None
    execution_environment: DraftContextAssertion | None = None
    system_role: DraftContextAssertion | None = None
    identity_context: DraftContextAssertion | None = None
    initial_access: DraftContextAssertion | None = None
    network_position: DraftContextAssertion | None = None
    observation_date: DraftContextAssertion | None = None
    services: tuple[DraftServiceContext, ...] = ()
    privileges: tuple[DraftContextAssertion, ...] = ()
    security_controls: tuple[DraftContextAssertion, ...] = ()


class DraftContextFacet(BaseModel):
    """A namespaced applicability assertion with only draft citations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: SearchableNonEmptyString
    key: SearchableNonEmptyString
    assertion: DraftContextAssertion


class DraftApplicabilityContext(BaseModel):
    """Applicability facts without a canonical source identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    typed_context: DraftTypedContext = Field(default_factory=DraftTypedContext)
    facets: tuple[DraftContextFacet, ...] = ()

    @model_validator(mode="after")
    def validate_unique_context_entries(self) -> Self:
        """Match canonical context uniqueness while retaining draft citations."""
        service_identities = {
            (service.service_type, service.identity.value, service.identity.relation)
            for service in self.typed_context.services
        }
        if len(service_identities) != len(self.typed_context.services):
            raise ValueError("typed service identities must be unique")

        facet_entries = {
            (facet.namespace, facet.key, facet.assertion.value, facet.assertion.relation)
            for facet in self.facets
        }
        if len(facet_entries) != len(self.facets):
            raise ValueError("context facets must be unique")
        return self


class DraftArtifactBase(BaseModel):
    """Fields shared by all source-identity-free draft artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    local_id: DraftLocalId
    origin: Origin
    applicability: DraftApplicabilityContext = Field(default_factory=DraftApplicabilityContext)
    citations: tuple[DraftCitation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_local_id(self) -> Self:
        """Defend cross-reference IDs even when Pydantic schema hints are bypassed."""
        if not _SAFE_DRAFT_LOCAL_ID.fullmatch(self.local_id):
            raise ValueError("draft local_id must be a safe path segment")
        return self


class DraftReference(DraftArtifactBase):
    """A draft equivalent of a canonical transferable reference artifact."""

    draft_type: Literal["reference"]
    artifact_type: Literal[
        ArtifactType.CONCEPT,
        ArtifactType.METHODOLOGY,
        ArtifactType.CONSTRAINT,
        ArtifactType.EVIDENCE_INTERPRETATION,
        ArtifactType.NEGATIVE_EVIDENCE,
        ArtifactType.ANTI_PATTERN,
        ArtifactType.EXCEPTION,
    ]
    knowledge_role: Literal[KnowledgeRole.REFERENCE] = KnowledgeRole.REFERENCE
    subject: SearchableNonEmptyString
    statement: SearchableNonEmptyString
    applicable_situations: tuple[SearchableNonEmptyString, ...] = ()
    prerequisites: tuple[SearchableNonEmptyString, ...] = ()
    action_intent: SearchableNonEmptyString | None = None
    expected_information_gain: SearchableNonEmptyString | None = None
    expected_evidence: tuple[SearchableNonEmptyString, ...] = ()
    evidence_interpretation: SearchableNonEmptyString | None = None
    success_implications: tuple[SearchableNonEmptyString, ...] = ()
    failure_implications: tuple[SearchableNonEmptyString, ...] = ()
    stop_implications: tuple[SearchableNonEmptyString, ...] = ()
    exceptions: tuple[SearchableNonEmptyString, ...] = ()
    warnings: tuple[SearchableNonEmptyString, ...] = ()
    capability_refs: tuple[SearchableNonEmptyString, ...] = ()
    observed_at: SearchableNonEmptyString | None = None


class DraftCaseStep(BaseModel):
    """One ordered draft equivalent of a canonical case step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: Literal[ArtifactType.CASE_STEP] = ArtifactType.CASE_STEP
    local_id: DraftLocalId
    ordinal: int = Field(ge=1)
    state_before: CaseState
    observations: tuple[SearchableString, ...]
    hypotheses: tuple[CaseHypothesis, ...]
    selected_action: CaseAction
    expected_information_gain: SearchableNonEmptyString | None = None
    evidence: tuple[CaseEvidence, ...]
    state_after: CaseState
    negative_evidence: tuple[SearchableString, ...] = ()
    transfer_conditions: tuple[SearchableString, ...] = ()
    case_specific_details: tuple[SearchableString, ...] = ()
    requires_validation: bool = True
    origin: Origin
    applicability: DraftApplicabilityContext = Field(default_factory=DraftApplicabilityContext)
    citations: tuple[DraftCitation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_local_id(self) -> Self:
        """Retain the response-local ID boundary for case-step citations."""
        if not _SAFE_DRAFT_LOCAL_ID.fullmatch(self.local_id):
            raise ValueError("draft local_id must be a safe path segment")
        return self


class DraftCase(DraftArtifactBase):
    """A source-identity-free ordered case-study draft."""

    draft_type: Literal["case"]
    artifact_type: Literal[ArtifactType.CASE] = ArtifactType.CASE
    knowledge_role: Literal[KnowledgeRole.CASE_STUDY, KnowledgeRole.NEGATIVE_CASE]
    title: SearchableNonEmptyString
    starting_access: SearchableNonEmptyString
    steps: tuple[DraftCaseStep, ...]
    outcome: SearchableNonEmptyString
    source_quality: SourceQuality
    difficulty: SearchableNonEmptyString | None = None
    transferable_properties: tuple[SearchableNonEmptyString, ...] = ()
    non_transferable_properties: tuple[SearchableNonEmptyString, ...] = ()

    @model_validator(mode="after")
    def validate_steps(self) -> Self:
        """Require steps to be supplied in their chronological order."""
        ordinals = tuple(step.ordinal for step in self.steps)
        if ordinals != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("draft case steps must have consecutive ordinals starting at one")
        return self


class DraftGuidance(DraftArtifactBase):
    """A draft equivalent of a canonical decision rule."""

    draft_type: Literal["guidance"]
    artifact_type: Literal[ArtifactType.DECISION_RULE] = ArtifactType.DECISION_RULE
    knowledge_role: Literal[KnowledgeRole.REFERENCE] = KnowledgeRole.REFERENCE
    trigger_observations: tuple[SearchableNonEmptyString, ...] = Field(min_length=1)
    rationale: SearchableNonEmptyString
    action_intent: SearchableNonEmptyString
    prerequisites: tuple[SearchableNonEmptyString, ...] = ()
    expected_evidence: tuple[SearchableNonEmptyString, ...] = ()
    success_transitions: tuple[SearchableNonEmptyString, ...] = ()
    failure_transitions: tuple[SearchableNonEmptyString, ...] = ()
    stop_conditions: tuple[SearchableNonEmptyString, ...] = ()
    exceptions: tuple[SearchableNonEmptyString, ...] = ()
    alternative_hypotheses: tuple[SearchableNonEmptyString, ...] = ()
    capability_refs: tuple[SearchableNonEmptyString, ...] = ()


DraftArtifact = Annotated[
    DraftReference | DraftCase | DraftGuidance,
    Field(discriminator="draft_type"),
]


class DraftExecutionPlaceholder(BaseModel):
    """A draft placeholder with the same binding policy as its canonical form."""

    model_config = ConfigDict(frozen=True, extra="forbid")

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
    role: SearchableNonEmptyString

    @model_validator(mode="after")
    def validate_binding_policy(self) -> Self:
        if self.kind == "target" and self.binding_policy != "authorized_scope":
            raise ValueError("target placeholders require authorized_scope")
        if self.kind == "source_case_credential" and self.binding_policy != "never_auto_bind":
            raise ValueError("source-case credentials can never request automatic binding")
        return self


class DraftExecutionCondition(BaseModel):
    """A draft prerequisite cited into the compiler input's segments."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    statement: SearchableNonEmptyString
    citations: tuple[DraftCitation, ...] = Field(min_length=1)


class DraftExecutionPlatformConstraint(BaseModel):
    """A draft platform assertion with draft segment citations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dimension: Literal[
        "os_family",
        "os_version",
        "cpu_architecture",
        "execution_environment",
    ]
    relation: Literal["required", "compatible", "incompatible"]
    value: SearchableNonEmptyString
    citations: tuple[DraftCitation, ...] = Field(min_length=1)


class DraftExecutionExample(BaseModel):
    """A draft executable example awaiting canonical materialization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    local_id: DraftLocalId
    parent_local_id: DraftLocalId
    command_template: Annotated[str, Field(min_length=1, max_length=8192)]
    placeholders: tuple[DraftExecutionPlaceholder, ...]
    capability_hint: SearchableNonEmptyString
    purpose: SearchableNonEmptyString
    observed_role: SearchableNonEmptyString
    applicability: DraftApplicabilityContext = Field(default_factory=DraftApplicabilityContext)
    prerequisites: tuple[DraftExecutionCondition, ...] = ()
    platform_constraints: tuple[DraftExecutionPlatformConstraint, ...] = ()
    citations: tuple[DraftCitation, ...] = Field(min_length=1)
    requires_validation: Literal[True] = True

    @model_validator(mode="after")
    def validate_example(self) -> Self:
        if not _SAFE_DRAFT_LOCAL_ID.fullmatch(self.local_id):
            raise ValueError("draft local_id must be a safe path segment")
        if not _SAFE_DRAFT_LOCAL_ID.fullmatch(self.parent_local_id):
            raise ValueError("draft parent_local_id must be a safe path segment")
        _validate_command_template(self.command_template)
        ordered = _ordered_placeholders(self.placeholders)
        object.__setattr__(self, "placeholders", ordered)
        declared = {placeholder.name for placeholder in ordered}
        tokens = set(re.findall(r"\{\{\s*([a-z][a-z0-9_]{0,63})\s*\}\}", self.command_template))
        if tokens != declared:
            raise ValueError("template placeholders must exactly cover the declared placeholders")
        _validate_platform_prose(
            self.purpose,
            self.capability_hint,
            self.observed_role,
            _platform_constraints_canonical(self.platform_constraints),
        )
        constraint_entries = {
            (constraint.dimension, constraint.relation, constraint.value)
            for constraint in self.platform_constraints
        }
        if len(constraint_entries) != len(self.platform_constraints):
            raise ValueError(
                "platform constraints must be unique by dimension, relation, and value"
            )
        return self


def _platform_constraints_canonical(
    constraints: tuple[DraftExecutionPlatformConstraint, ...],
) -> tuple[ExecutionPlatformConstraint, ...]:
    marker = SourceRef(
        source_id="prose-check",
        path="prose-check",
        location=SourceLocation(section="prose-check"),
    )
    return tuple(
        ExecutionPlatformConstraint(
            dimension=constraint.dimension,
            relation=constraint.relation,
            value=constraint.value,
            source_refs=(marker,),
        )
        for constraint in constraints
    )


class SemanticDraftBundle(BaseModel):
    """Extractor or repair output before canonical identity and provenance assignment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifacts: tuple[DraftArtifact, ...] = ()
    execution_examples: tuple[DraftExecutionExample, ...] = ()
    ignored_segment_indexes: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_draft_bundle(self) -> Self:
        """Prevent ambiguous response-local references and invalid ignored indexes."""
        _validate_deterministic_indexes(self.ignored_segment_indexes)
        local_ids = (
            tuple(artifact.local_id for artifact in self.artifacts)
            + tuple(
                step.local_id
                for artifact in self.artifacts
                if isinstance(artifact, DraftCase)
                for step in artifact.steps
            )
            + tuple(example.local_id for example in self.execution_examples)
        )
        if len(set(local_ids)) != len(local_ids):
            raise ValueError("draft local IDs must be unique within a bundle")
        parent_ids = {
            artifact.local_id for artifact in self.artifacts if isinstance(artifact, DraftReference)
        } | {
            step.local_id
            for artifact in self.artifacts
            if isinstance(artifact, DraftCase)
            for step in artifact.steps
        }
        for example in self.execution_examples:
            if example.parent_local_id not in parent_ids:
                raise ValueError(
                    "execution example parent must be a reference or case-step local ID"
                )
        return self

    def validate_against_segment_count(self, segment_count: int) -> None:
        """Bind draft citations to the compiler input length without retaining the input."""
        _validate_input_segment_range(self._segment_indexes(), segment_count)

    def _segment_indexes(self) -> tuple[int, ...]:
        indexes = list(self.ignored_segment_indexes)
        for artifact in self.artifacts:
            indexes.extend(_citation_indexes(artifact.citations))
            indexes.extend(_applicability_indexes(artifact.applicability))
            if isinstance(artifact, DraftCase):
                for step in artifact.steps:
                    indexes.extend(_citation_indexes(step.citations))
                    indexes.extend(_applicability_indexes(step.applicability))
        for example in self.execution_examples:
            indexes.extend(_citation_indexes(example.citations))
            indexes.extend(_applicability_indexes(example.applicability))
            for condition in example.prerequisites:
                indexes.extend(_citation_indexes(condition.citations))
            for constraint in example.platform_constraints:
                indexes.extend(_citation_indexes(constraint.citations))
        return tuple(indexes)


class CriticVerdict(BaseModel):
    """A closed-vocabulary critic result that can guide at most one repair attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    accepted: bool
    findings: tuple[VerificationFinding, ...] = ()

    @model_validator(mode="after")
    def validate_acceptance(self) -> Self:
        """Require acceptance to exactly reflect material critic findings."""
        if any(
            finding.artifact_local_id is not None
            and not _SAFE_DRAFT_LOCAL_ID.fullmatch(finding.artifact_local_id)
            for finding in self.findings
        ):
            raise ValueError("critic artifact_local_id must be a safe path segment")
        has_material_finding = any(finding.severity == "material" for finding in self.findings)
        if self.accepted == has_material_finding:
            raise ValueError("accepted must be false exactly when a material finding exists")
        return self

    def validate_against_segment_count(self, segment_count: int) -> None:
        """Bind critic citations to the compiler input length without model prose."""
        _validate_input_segment_range(
            tuple(index for finding in self.findings for index in finding.segment_indexes),
            segment_count,
        )


class SemanticCompilationResult(BaseModel):
    """The safe, exclusive terminal result of semantic compilation orchestration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    disposition: CompilationDisposition
    bundle: SemanticKnowledgeBundle | None = None
    verification: SemanticVerificationRecord | None = None
    quarantine: SemanticQuarantineRecord | None = None
    failure_code: CompilationFailureCode | None = None
    failure_message: SearchableNonEmptyString | None = None
    calls: tuple[SemanticCallMetadata, ...] = ()

    @model_validator(mode="after")
    def validate_payload_shape(self) -> Self:
        """Keep completed outcomes mutually exclusive and failed results safely bounded."""
        purposes = tuple(call.purpose for call in self.calls)
        if purposes not in _VALID_CALL_SEQUENCES:
            raise ValueError("semantic call metadata must follow the bounded purpose sequence")
        if self.disposition == "verified":
            if self.bundle is None or self.verification is None:
                raise ValueError("verified and unchanged results require a bundle and verification")
            if any((self.quarantine, self.failure_code, self.failure_message)):
                raise ValueError("verified and unchanged results cannot contain other payloads")
            if self.verification.adjudication != "verified":
                raise ValueError(
                    "verified result verification adjudication must agree with disposition"
                )
            self._validate_final_critic_call(purposes)
            self._validate_normal_bundle()
            return self

        if self.disposition == "unchanged":
            if purposes or self.verification is None or self.failure_code or self.failure_message:
                raise ValueError("unchanged results cannot contain a new semantic call or failure")
            if self.bundle is not None and self.quarantine is None:
                if self.verification.adjudication != "verified":
                    raise ValueError("unchanged bundle results must retain a verified audit")
                self._validate_normal_bundle()
                return self
            if self.quarantine is not None and self.bundle is None:
                if self.verification.adjudication != "quarantined":
                    raise ValueError("unchanged quarantine results must retain a quarantined audit")
                self._validate_quarantine()
                return self
            raise ValueError(
                "unchanged results require a bundle and verification or a quarantine "
                "and verification"
            )

        if self.disposition == "quarantined":
            if self.verification is None or self.quarantine is None:
                raise ValueError("quarantined results require verification and quarantine")
            if any((self.bundle, self.failure_code, self.failure_message)):
                raise ValueError("quarantined results cannot contain bundle or failure payloads")
            if self.verification.adjudication != self.disposition:
                raise ValueError(
                    "quarantined result verification adjudication must agree with disposition"
                )
            self._validate_final_critic_call(purposes)
            self._validate_quarantine()
            return self

        if (
            self.failure_code is None
            or self.failure_message is None
            or any((self.bundle, self.verification, self.quarantine))
        ):
            raise ValueError("failed results contain only a safe failure reason")
        if self.failure_message != CANONICAL_COMPILATION_FAILURE_MESSAGES[self.failure_code]:
            raise ValueError("failed result message must match its canonical failure code")
        return self

    def _validate_final_critic_call(self, purposes: tuple[str, ...]) -> None:
        if purposes not in _VALID_CALL_SEQUENCES[2::2] or self.verification is None:
            raise ValueError("terminal semantic results require an extractor and final critic call")
        if self.verification.critic_call != self.calls[-1]:
            raise ValueError("verification critic call must match final call metadata")

    def _validate_normal_bundle(self) -> None:
        if self.bundle is None or self.verification is None:
            raise ValueError("normal results require a bundle and verification")
        manifest = self.bundle.compilation_manifest
        if (
            self.bundle.source_id != self.verification.source_id
            or self.bundle.source_sha256 != self.verification.source_sha256
            or manifest.source_id != self.bundle.source_id
            or manifest.source_sha256 != self.bundle.source_sha256
        ):
            raise ValueError("bundle and verification source identity must match")
        if self.disposition == "unchanged":
            if manifest.disposition != "verified":
                raise ValueError("unchanged results must retain a verified compilation manifest")
            if manifest.repair_count != self.verification.repair_count:
                raise ValueError("manifest repair_count must match verification repair_count")
            return
        if manifest.disposition != "verified":
            raise ValueError("verified result manifest disposition must be verified")
        expected_repair_count = 0 if len(self.calls) == 2 else 1
        if (
            manifest.repair_count != expected_repair_count
            or self.verification.repair_count != expected_repair_count
        ):
            raise ValueError("manifest repair_count must match the semantic call path")
        if (
            manifest.extractor_model_id != self.calls[0].model
            or manifest.critic_model_id != self.calls[-1].model
        ):
            raise ValueError("manifest model IDs must match extractor and final critic calls")

    def _validate_quarantine(self) -> None:
        if self.quarantine is None or self.verification is None:
            raise ValueError("quarantined results require quarantine and verification")
        if (
            self.quarantine.source_id != self.verification.source_id
            or self.quarantine.source_sha256 != self.verification.source_sha256
        ):
            raise ValueError("quarantine and verification source identity must match")
        manifest = self.quarantine.compilation_manifest
        if self.disposition == "quarantined":
            expected_repair_count = 0 if len(self.calls) == 2 else 1
            if self.verification.repair_count != expected_repair_count:
                raise ValueError("verification repair_count must match the semantic call path")
        if manifest is None:
            return
        if manifest.repair_count != self.verification.repair_count:
            raise ValueError("manifest repair_count must match verification repair_count")
        if self.disposition == "quarantined" and (
            manifest.extractor_model_id != self.calls[0].model
            or manifest.critic_model_id != self.calls[-1].model
        ):
            raise ValueError("manifest model IDs must match extractor and final critic calls")


def _validate_deterministic_indexes(indexes: tuple[int, ...]) -> None:
    """Reject indexes that would make a model completion ambiguous or nondeterministic."""
    if any(index < 0 for index in indexes):
        raise ValueError("segment indexes must be non-negative")
    if len(set(indexes)) != len(indexes):
        raise ValueError("segment indexes must be unique")
    if tuple(sorted(indexes)) != indexes:
        raise ValueError("segment indexes must be sorted")


def _validate_input_segment_range(indexes: tuple[int, ...], segment_count: int) -> None:
    """Require every draft reference to resolve inside a concrete compiler input."""
    if segment_count < 0:
        raise ValueError("input segment count must be non-negative")
    if any(index >= segment_count for index in indexes):
        raise ValueError("segment indexes must remain in the input segment range")


def _citation_indexes(citations: tuple[DraftCitation, ...]) -> tuple[int, ...]:
    return tuple(index for citation in citations for index in citation.segment_indexes)


def _applicability_indexes(context: DraftApplicabilityContext) -> tuple[int, ...]:
    assertions = [
        context.typed_context.os_family,
        context.typed_context.os_version,
        context.typed_context.cpu_architecture,
        context.typed_context.execution_environment,
        context.typed_context.system_role,
        context.typed_context.identity_context,
        context.typed_context.initial_access,
        context.typed_context.network_position,
        context.typed_context.observation_date,
        *(service.identity for service in context.typed_context.services),
        *context.typed_context.privileges,
        *context.typed_context.security_controls,
        *(facet.assertion for facet in context.facets),
    ]
    return tuple(
        index
        for assertion in assertions
        if assertion is not None
        for citation in assertion.citations
        for index in citation.segment_indexes
    )
