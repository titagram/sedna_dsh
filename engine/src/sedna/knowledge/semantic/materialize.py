"""Bind semantic drafts to one prepared source and canonical identities."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.parsing.models import validate_prepared_source
from sedna.knowledge.schema import (
    ApplicabilityContext,
    CaseStep,
    ContextAssertion,
    ContextFacet,
    DecisionRule,
    EpistemicAssessment,
    ExtractionMetadata,
    Generalizability,
    KnowledgeCase,
    KnowledgeRole,
    ObservedOutcome,
    ReferenceArtifact,
    ServiceContext,
    SourceLocation,
    SourceQuality,
    SourceRef,
    TypedContext,
    VerificationStatus,
)
from sedna.knowledge.schema.execution import (
    ExecutionCondition,
    ExecutionExample,
    ExecutionPlaceholder,
    ExecutionPlatformConstraint,
)
from sedna.knowledge.schema.semantic import SemanticCallMetadata
from sedna.knowledge.semantic.drafts import (
    DraftApplicabilityContext,
    DraftCase,
    DraftCaseStep,
    DraftCitation,
    DraftContextAssertion,
    DraftExecutionExample,
    DraftGuidance,
    DraftReference,
    SemanticDraftBundle,
)
from sedna.knowledge.semantic.prompts import EXTRACTOR_PROMPT_ID, EXTRACTOR_PROMPT_VERSION

CanonicalArtifact = ReferenceArtifact | KnowledgeCase | DecisionRule
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class MaterializedSemanticContent:
    """Canonical artifacts plus their bundle-owned execution examples."""

    artifacts: tuple[CanonicalArtifact, ...]
    execution_examples: tuple[ExecutionExample, ...]


def materialize_bundle(
    prepared: PreparedSource,
    drafts: SemanticDraftBundle,
    call_metadata: SemanticCallMetadata,
    verification_status: VerificationStatus,
) -> tuple[CanonicalArtifact, ...]:
    """Materialize validated drafts with exact source evidence and stable identities."""
    return materialize_semantic_content(
        prepared,
        drafts,
        call_metadata,
        verification_status,
    ).artifacts


def materialize_semantic_content(
    prepared: PreparedSource,
    drafts: SemanticDraftBundle,
    call_metadata: SemanticCallMetadata,
    verification_status: VerificationStatus,
) -> MaterializedSemanticContent:
    """Materialize canonical artifacts and their execution examples together."""
    prepared = validate_prepared_source(prepared)
    drafts = SemanticDraftBundle.model_validate(drafts.model_dump(mode="json"))
    call_metadata = SemanticCallMetadata.model_validate(call_metadata.model_dump(mode="json"))
    verification_status = VerificationStatus(verification_status)

    drafts.validate_against_segment_count(len(prepared.segments))
    validate_segment_accounting(prepared, drafts)

    artifacts, local_to_canonical = _materialize_artifacts_with_local_ids(
        prepared,
        drafts,
        call_metadata,
        verification_status,
    )
    examples = _materialize_execution_examples(
        prepared,
        drafts.execution_examples,
        local_to_canonical,
        call_metadata,
    )
    return MaterializedSemanticContent(
        artifacts=artifacts,
        execution_examples=examples,
    )


def _materialize_artifacts_with_local_ids(
    prepared: PreparedSource,
    drafts: SemanticDraftBundle,
    call_metadata: SemanticCallMetadata,
    verification_status: VerificationStatus,
) -> tuple[tuple[CanonicalArtifact, ...], Mapping[str, str]]:
    extraction = _extraction_metadata(prepared, call_metadata)
    materialized = tuple(
        _materialize_artifact(
            prepared,
            draft,
            extraction,
            verification_status,
        )
        for draft in drafts.artifacts
    )
    artifacts = _deduplicate_and_sort(tuple(item[0] for item in materialized))
    local_to_canonical: dict[str, str] = {}
    for draft, (artifact, local_map) in zip(drafts.artifacts, materialized, strict=True):
        local_to_canonical.update(local_map)
        local_to_canonical[draft.local_id] = artifact_id_for(artifact)
    return artifacts, local_to_canonical


def artifact_id_for(artifact: CanonicalArtifact) -> str:
    if isinstance(artifact, ReferenceArtifact):
        return artifact.artifact_id
    if isinstance(artifact, KnowledgeCase):
        return artifact.case_id
    return artifact.rule_id


def _materialize_execution_examples(
    prepared: PreparedSource,
    drafts: tuple[DraftExecutionExample, ...],
    local_to_canonical: Mapping[str, str],
    call_metadata: SemanticCallMetadata,
) -> tuple[ExecutionExample, ...]:
    extraction = _extraction_metadata(prepared, call_metadata)
    examples: list[ExecutionExample] = []
    for draft in drafts:
        if draft.parent_local_id not in local_to_canonical:
            raise ValueError(
                "execution example parent must be a materialized reference or case step"
            )
        parent = local_to_canonical[draft.parent_local_id]
        source_refs = _resolve_citations(prepared, draft.citations)
        applicability = _materialize_applicability(prepared, draft.applicability)
        prerequisites = tuple(
            ExecutionCondition(
                statement=condition.statement,
                source_refs=_resolve_citations(prepared, condition.citations),
            )
            for condition in draft.prerequisites
        )
        platform_constraints = tuple(
            ExecutionPlatformConstraint(
                dimension=constraint.dimension,
                relation=constraint.relation,
                value=constraint.value,
                source_refs=_resolve_citations(prepared, constraint.citations),
            )
            for constraint in draft.platform_constraints
        )
        placeholders = tuple(
            ExecutionPlaceholder(
                name=placeholder.name,
                kind=placeholder.kind,
                binding_policy=placeholder.binding_policy,
                role=placeholder.role,
            )
            for placeholder in draft.placeholders
        )
        example_id = stable_execution_example_id(
            prepared.manifest.source_id,
            parent,
            draft.command_template,
            placeholders,
            draft.capability_hint,
            draft.purpose,
            draft.observed_role,
            prerequisites,
            applicability,
            platform_constraints,
            source_refs,
        )
        examples.append(
            ExecutionExample(
                schema_version="1",
                example_id=example_id,
                parent_artifact_id=parent,
                command_template=draft.command_template,
                placeholders=placeholders,
                capability_hint=draft.capability_hint,
                purpose=draft.purpose,
                observed_role=draft.observed_role,
                prerequisites=prerequisites,
                applicability=applicability,
                platform_constraints=platform_constraints,
                source_refs=source_refs,
                extraction=extraction,
                requires_validation=True,
            )
        )
    unique_by_id = {example.example_id: example for example in examples}
    return tuple(unique_by_id[example_id] for example_id in sorted(unique_by_id))


def stable_execution_example_id(
    source_id: str,
    parent_artifact_id: str,
    command_template: str,
    placeholders: tuple[ExecutionPlaceholder, ...],
    capability_hint: str,
    purpose: str,
    observed_role: str,
    prerequisites: tuple[ExecutionCondition, ...],
    applicability: ApplicabilityContext,
    platform_constraints: tuple[ExecutionPlatformConstraint, ...],
    source_refs: tuple[SourceRef, ...],
) -> str:
    """Content-addressed example identity; never includes the parent's draft ID."""
    canonical = {
        "source_id": source_id,
        "parent_artifact_id": parent_artifact_id,
        "command_template": command_template,
        "placeholders": _primitive(
            tuple(sorted(placeholders, key=lambda placeholder: placeholder.name))
        ),
        "capability_hint": capability_hint,
        "purpose": purpose,
        "observed_role": observed_role,
        "prerequisites": _primitive(
            tuple(
                {
                    "statement": condition.statement,
                    "source_refs": _primitive(_sorted_source_refs(condition.source_refs)),
                }
                for condition in prerequisites
            )
        ),
        "applicability": _primitive(applicability),
        "platform_constraints": _primitive(
            tuple(
                {
                    "dimension": constraint.dimension,
                    "relation": constraint.relation,
                    "value": constraint.value,
                    "source_refs": _primitive(_sorted_source_refs(constraint.source_refs)),
                }
                for constraint in platform_constraints
            )
        ),
        "source_refs": _primitive(_sorted_source_refs(source_refs)),
    }
    digest = hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()[:24]
    return f"execution-example-{digest}"


def stable_artifact_id(
    source_id: str,
    artifact_type: str,
    semantic_content: object,
    source_refs: tuple[SourceRef, ...],
    applicability: ApplicabilityContext,
) -> str:
    """Create a readable, content-addressed ID without runtime or draft-local fields."""
    canonical = {
        "source_id": source_id,
        "artifact_type": artifact_type,
        "semantic_content": _primitive(semantic_content),
        "source_refs": _primitive(_sorted_source_refs(source_refs)),
        "applicability": _primitive(applicability),
    }
    digest = hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()[:24]
    return f"{artifact_type}-{digest}"


def _materialize_artifact(
    prepared: PreparedSource,
    draft: DraftReference | DraftCase | DraftGuidance,
    extraction: ExtractionMetadata,
    verification_status: VerificationStatus,
) -> tuple[CanonicalArtifact, Mapping[str, str]]:
    applicability = _materialize_applicability(prepared, draft.applicability)
    source_refs = _resolve_citations(prepared, draft.citations)
    assessment = _assessment(prepared, draft.knowledge_role, verification_status)

    if isinstance(draft, DraftReference):
        content = {
            "knowledge_role": draft.knowledge_role,
            "origin": draft.origin,
            "subject": draft.subject,
            "statement": draft.statement,
            "applicable_situations": _sorted_unique(draft.applicable_situations),
            "prerequisites": _sorted_unique(draft.prerequisites),
            "action_intent": draft.action_intent,
            "expected_information_gain": draft.expected_information_gain,
            "expected_evidence": _sorted_unique(draft.expected_evidence),
            "evidence_interpretation": draft.evidence_interpretation,
            "success_implications": _sorted_unique(draft.success_implications),
            "failure_implications": _sorted_unique(draft.failure_implications),
            "stop_implications": _sorted_unique(draft.stop_implications),
            "exceptions": _sorted_unique(draft.exceptions),
            "warnings": _sorted_unique(draft.warnings),
            "capability_refs": _sorted_unique(draft.capability_refs),
            "observed_at": draft.observed_at,
        }
        identity_content = {key: value for key, value in content.items() if key != "observed_at"}
        artifact_id = stable_artifact_id(
            prepared.manifest.source_id,
            draft.artifact_type,
            identity_content,
            source_refs,
            applicability,
        )
        return ReferenceArtifact(
            artifact_type=draft.artifact_type,
            artifact_id=artifact_id,
            applicability=applicability,
            assessment=assessment,
            source_refs=source_refs,
            extraction=extraction,
            **content,
        ), {}

    if isinstance(draft, DraftGuidance):
        content = {
            "knowledge_role": draft.knowledge_role,
            "origin": draft.origin,
            "trigger_observations": _sorted_unique(draft.trigger_observations),
            "rationale": draft.rationale,
            "action_intent": draft.action_intent,
            "prerequisites": _sorted_unique(draft.prerequisites),
            "expected_evidence": _sorted_unique(draft.expected_evidence),
            "success_transitions": _sorted_unique(draft.success_transitions),
            "failure_transitions": _sorted_unique(draft.failure_transitions),
            "stop_conditions": _sorted_unique(draft.stop_conditions),
            "exceptions": _sorted_unique(draft.exceptions),
            "alternative_hypotheses": _sorted_unique(draft.alternative_hypotheses),
            "capability_refs": _sorted_unique(draft.capability_refs),
        }
        rule_id = stable_artifact_id(
            prepared.manifest.source_id,
            draft.artifact_type,
            content,
            source_refs,
            applicability,
        )
        return DecisionRule(
            artifact_type=draft.artifact_type,
            rule_id=rule_id,
            applicability=applicability,
            assessment=assessment,
            source_refs=source_refs,
            extraction=extraction,
            **content,
        ), {}

    steps = tuple(
        _materialize_case_step(
            prepared, step, extraction, verification_status, draft.knowledge_role
        )
        for step in draft.steps
    )
    content = {
        "knowledge_role": draft.knowledge_role,
        "origin": draft.origin,
        "title": draft.title,
        "starting_access": draft.starting_access,
        "steps": steps,
        "outcome": draft.outcome,
        "source_quality": draft.source_quality,
        "difficulty": draft.difficulty,
        "transferable_properties": _sorted_unique(draft.transferable_properties),
        "non_transferable_properties": _sorted_unique(draft.non_transferable_properties),
    }
    identity_content = {
        **content,
        "steps": tuple(_stable_case_step_content(step) for step in steps),
    }
    case_id = stable_artifact_id(
        prepared.manifest.source_id,
        draft.artifact_type,
        identity_content,
        source_refs,
        applicability,
    )
    step_map = {
        step_draft.local_id: step.step_id
        for step_draft, step in zip(draft.steps, steps, strict=True)
    }
    return KnowledgeCase(
        artifact_type=draft.artifact_type,
        case_id=case_id,
        applicability=applicability,
        assessment=assessment,
        source_refs=source_refs,
        extraction=extraction,
        **content,
    ), step_map


def _materialize_case_step(
    prepared: PreparedSource,
    draft: DraftCaseStep,
    extraction: ExtractionMetadata,
    verification_status: VerificationStatus,
    knowledge_role: KnowledgeRole,
) -> CaseStep:
    applicability = _materialize_applicability(prepared, draft.applicability)
    source_refs = _resolve_citations(prepared, draft.citations)
    content = {
        "knowledge_role": knowledge_role,
        "origin": draft.origin,
        "ordinal": draft.ordinal,
        "state_before": _sorted_case_state(draft.state_before),
        "observations": _sorted_unique(draft.observations),
        "hypotheses": _sorted_models(draft.hypotheses),
        "selected_action": draft.selected_action,
        "expected_information_gain": draft.expected_information_gain,
        "evidence": _sorted_models(draft.evidence),
        "state_after": _sorted_case_state(draft.state_after),
        "negative_evidence": _sorted_unique(draft.negative_evidence),
        "transfer_conditions": _sorted_unique(draft.transfer_conditions),
        "case_specific_details": _sorted_unique(draft.case_specific_details),
        "requires_validation": draft.requires_validation,
    }
    step_id = stable_artifact_id(
        prepared.manifest.source_id,
        draft.artifact_type,
        content,
        source_refs,
        applicability,
    )
    return CaseStep(
        artifact_type=draft.artifact_type,
        step_id=step_id,
        applicability=applicability,
        assessment=_assessment(prepared, knowledge_role, verification_status),
        source_refs=source_refs,
        extraction=extraction,
        **content,
    )


def _materialize_applicability(
    prepared: PreparedSource,
    context: DraftApplicabilityContext,
) -> ApplicabilityContext:
    typed = context.typed_context
    canonical_typed = TypedContext(
        os_family=_materialize_assertion(prepared, typed.os_family),
        os_version=_materialize_assertion(prepared, typed.os_version),
        cpu_architecture=_materialize_assertion(prepared, typed.cpu_architecture),
        execution_environment=_materialize_assertion(prepared, typed.execution_environment),
        system_role=_materialize_assertion(prepared, typed.system_role),
        identity_context=_materialize_assertion(prepared, typed.identity_context),
        initial_access=_materialize_assertion(prepared, typed.initial_access),
        network_position=_materialize_assertion(prepared, typed.network_position),
        observation_date=_materialize_assertion(prepared, typed.observation_date),
        services=tuple(
            sorted(
                (
                    ServiceContext(
                        service_type=service.service_type,
                        identity=_materialize_assertion(prepared, service.identity),
                    )
                    for service in typed.services
                ),
                key=_model_key,
            )
        ),
        privileges=_sorted_models(
            _materialize_assertion(prepared, assertion) for assertion in typed.privileges
        ),
        security_controls=_sorted_models(
            _materialize_assertion(prepared, assertion) for assertion in typed.security_controls
        ),
    )
    facets = tuple(
        sorted(
            (
                ContextFacet(
                    namespace=facet.namespace,
                    key=facet.key,
                    assertion=_materialize_assertion(prepared, facet.assertion),
                )
                for facet in context.facets
            ),
            key=_model_key,
        )
    )
    return ApplicabilityContext(typed_context=canonical_typed, facets=facets)


def _materialize_assertion(
    prepared: PreparedSource,
    assertion: DraftContextAssertion | None,
) -> ContextAssertion | None:
    if assertion is None:
        return None
    return ContextAssertion(
        value=assertion.value,
        relation=assertion.relation,
        origin=assertion.origin,
        confidence=assertion.confidence,
        source_refs=_resolve_citations(prepared, assertion.citations),
    )


def _resolve_citations(
    prepared: PreparedSource,
    citations: tuple[DraftCitation, ...],
) -> tuple[SourceRef, ...]:
    if not citations:
        raise ValueError("explicit or inferred claims require one or more citations")
    refs = []
    for citation in citations:
        for index in citation.segment_indexes:
            try:
                segment = prepared.segments[index]
            except IndexError as error:
                raise ValueError(
                    "citation segment index is outside the input segment range"
                ) from error
            refs.append(
                SourceRef(
                    source_id=prepared.manifest.source_id,
                    path=prepared.manifest.path,
                    location=SourceLocation(
                        start_line=segment.start_line,
                        end_line=segment.end_line,
                        section=" > ".join(segment.heading_path) or None,
                    ),
                )
            )
    return _sorted_source_refs(tuple(refs))


def validate_segment_accounting(prepared: PreparedSource, drafts: SemanticDraftBundle) -> None:
    """Require every prepared segment to have draft evidence or an explicit omission."""
    cited_indexes = set(_all_cited_indexes(drafts))
    ignored_indexes = set(drafts.ignored_segment_indexes)
    missing = set(range(len(prepared.segments))) - cited_indexes - ignored_indexes
    if missing:
        raise ValueError("every input segment must be cited or explicitly ignored")


def _all_cited_indexes(drafts: SemanticDraftBundle) -> tuple[int, ...]:
    indexes: list[int] = []
    for draft in drafts.artifacts:
        indexes.extend(_indexes_from_citations(draft.citations))
        indexes.extend(_indexes_from_context(draft.applicability))
        if isinstance(draft, DraftCase):
            for step in draft.steps:
                indexes.extend(_indexes_from_citations(step.citations))
                indexes.extend(_indexes_from_context(step.applicability))
    for example in drafts.execution_examples:
        indexes.extend(_indexes_from_citations(example.citations))
        indexes.extend(_indexes_from_context(example.applicability))
        for condition in example.prerequisites:
            indexes.extend(_indexes_from_citations(condition.citations))
        for constraint in example.platform_constraints:
            indexes.extend(_indexes_from_citations(constraint.citations))
    return tuple(indexes)


def _indexes_from_citations(citations: Iterable[DraftCitation]) -> tuple[int, ...]:
    return tuple(index for citation in citations for index in citation.segment_indexes)


def _indexes_from_context(context: DraftApplicabilityContext) -> tuple[int, ...]:
    typed = context.typed_context
    assertions = (
        typed.os_family,
        typed.os_version,
        typed.cpu_architecture,
        typed.execution_environment,
        typed.system_role,
        typed.identity_context,
        typed.initial_access,
        typed.network_position,
        typed.observation_date,
        *(service.identity for service in typed.services),
        *typed.privileges,
        *typed.security_controls,
        *(facet.assertion for facet in context.facets),
    )
    return tuple(
        index
        for assertion in assertions
        if assertion is not None
        for index in _indexes_from_citations(assertion.citations)
    )


def _extraction_metadata(
    prepared: PreparedSource,
    call_metadata: SemanticCallMetadata,
) -> ExtractionMetadata:
    foundation = prepared.manifest.extraction
    return ExtractionMetadata(
        schema_version=foundation.schema_version,
        parser_id=foundation.parser_id,
        parser_version=foundation.parser_version,
        extractor_id=EXTRACTOR_PROMPT_ID,
        extractor_version=EXTRACTOR_PROMPT_VERSION,
        prompt_id=EXTRACTOR_PROMPT_ID,
        prompt_version=EXTRACTOR_PROMPT_VERSION,
        model_id=call_metadata.model,
    )


def _assessment(
    prepared: PreparedSource,
    role: KnowledgeRole,
    verification_status: VerificationStatus,
) -> EpistemicAssessment:
    reliability = {
        SourceQuality.COMPLETE: 0.75,
        SourceQuality.PARTIAL: 0.5,
        SourceQuality.MINIMAL: 0.25,
        SourceQuality.UNUSABLE: 0.0,
    }[prepared.manifest.quality]
    return EpistemicAssessment(
        source_reliability=reliability,
        extraction_confidence=0.5,
        generalizability=(
            Generalizability.LOW
            if role in {KnowledgeRole.CASE_STUDY, KnowledgeRole.NEGATIVE_CASE}
            else Generalizability.MEDIUM
        ),
        context_specificity=(0.75 if role is not KnowledgeRole.REFERENCE else 0.5),
        verification_status=verification_status,
        observed_outcome=(
            ObservedOutcome.FAILURE
            if role is KnowledgeRole.NEGATIVE_CASE
            else ObservedOutcome.INFORMATIONAL
        ),
        # Byte-identical imports share evidence independence without guessing at paraphrases.
        independence_group=prepared.manifest.sha256,
    )


def _deduplicate_and_sort(
    artifacts: tuple[CanonicalArtifact, ...],
) -> tuple[CanonicalArtifact, ...]:
    duplicates: dict[str, list[CanonicalArtifact]] = {}
    for artifact in artifacts:
        key = _canonical_json(_identity_payload(artifact))
        duplicates.setdefault(key, []).append(artifact)
    unique = tuple(_select_duplicate(group) for group in duplicates.values())
    return tuple(sorted(unique, key=_artifact_id))


def _identity_payload(artifact: CanonicalArtifact) -> object:
    payload = artifact.model_dump(mode="json")
    payload.pop("artifact_id", None)
    payload.pop("case_id", None)
    payload.pop("rule_id", None)
    payload.pop("assessment", None)
    payload.pop("extraction", None)
    if isinstance(artifact, ReferenceArtifact):
        payload.pop("observed_at", None)
    if "steps" in payload:
        for step in payload["steps"]:
            step.pop("step_id", None)
            step.pop("assessment", None)
            step.pop("extraction", None)
    return payload


def _select_duplicate(artifacts: list[CanonicalArtifact]) -> CanonicalArtifact:
    """Select one canonical duplicate independently of extractor response order."""
    first = artifacts[0]
    if isinstance(first, ReferenceArtifact):
        return min(
            artifacts,
            key=lambda artifact: (
                not isinstance(artifact, ReferenceArtifact) or artifact.observed_at is None,
                artifact.observed_at if isinstance(artifact, ReferenceArtifact) else "",
            ),
        )
    return min(artifacts, key=lambda artifact: _canonical_json(artifact.model_dump(mode="json")))


def _stable_case_step_content(step: CaseStep) -> object:
    """Retain nested evidence in a case identity without runtime-derived step metadata."""
    content = step.model_dump(mode="json")
    for field in ("step_id", "assessment", "extraction"):
        content.pop(field, None)
    return content


def _artifact_id(artifact: CanonicalArtifact) -> str:
    if isinstance(artifact, ReferenceArtifact):
        return artifact.artifact_id
    if isinstance(artifact, KnowledgeCase):
        return artifact.case_id
    return artifact.rule_id


def _sorted_source_refs(source_refs: tuple[SourceRef, ...]) -> tuple[SourceRef, ...]:
    return _sorted_models(source_refs)


def _sorted_case_state(state: object) -> object:
    return state.model_copy(
        update={
            "environment": _sorted_unique(state.environment),
            "privileges": _sorted_unique(state.privileges),
        }
    )


def _sorted_models(models: Iterable[T]) -> tuple[T, ...]:
    unique: dict[str, T] = {}
    for model in models:
        unique.setdefault(_model_key(model), model)
    return tuple(unique[key] for key in sorted(unique))


def _sorted_unique(values: Iterable[T]) -> tuple[T, ...]:
    return tuple(sorted(set(values)))


def _model_key(model: object) -> str:
    return _canonical_json(_primitive(model))


def _primitive(value: object) -> object:
    if hasattr(value, "model_dump"):
        return _primitive(value.model_dump(mode="json"))  # type: ignore[union-attr]
    if isinstance(value, Mapping):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
