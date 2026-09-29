"""Deterministic, disposable retrieval rows derived from canonical knowledge."""

from __future__ import annotations

import json
from collections.abc import Iterable
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.parsing.sanitize import sanitize_searchable_text
from sedna.knowledge.retrieval.models import (
    ExecutionExampleLocator,
    IndexedArtifactState,
    IndexedExecutionExampleState,
    IndexedSourceState,
)
from sedna.knowledge.schema import (
    ArtifactType,
    CaseStep,
    ContextAssertion,
    DecisionRule,
    Generalizability,
    KnowledgeCase,
    KnowledgeRole,
    ObservedOutcome,
    Origin,
    ReferenceArtifact,
    SemanticKnowledgeBundle,
    SourceLocation,
    SourceRef,
    VerificationStatus,
)
from sedna.knowledge.schema.common import SearchableNonEmptyString, SearchableString
from sedna.knowledge.schema.context import ContextRelation

_MAX_FTS_COLUMN_CHARS = 8_192
SOURCE_PROJECTION_VERSION = "canonical-projection-v3"


class ProjectedFacet(BaseModel):
    """One normalized, source-backed applicability assertion."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: SearchableNonEmptyString
    facet_id: SearchableNonEmptyString
    channel: SearchableNonEmptyString
    namespace: SearchableNonEmptyString
    key: SearchableNonEmptyString
    value: SearchableString
    relation: ContextRelation
    origin: Origin
    confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_identity(self) -> ProjectedFacet:
        if self.facet_id != _facet_id(
            self.channel,
            self.namespace,
            self.key,
            self.value,
            self.relation,
            self.origin,
            self.confidence,
        ):
            raise ValueError("projected facet ID must match its semantic identity")
        return self


class ProjectedSource(BaseModel):
    """Exact source provenance retained for a projected artifact row."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: SearchableNonEmptyString
    source_id: SearchableNonEmptyString
    path: SearchableNonEmptyString
    location: SourceLocation
    independence_group: SearchableNonEmptyString
    relation: SearchableNonEmptyString = "artifact"


class ProjectedLink(BaseModel):
    """A normalized relationship between two projected artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    from_artifact_id: SearchableNonEmptyString
    relation: SearchableNonEmptyString
    to_artifact_id: SearchableNonEmptyString


class ProjectedArtifact(BaseModel):
    """One indexable canonical artifact with normalized supporting rows and FTS fields."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: SearchableNonEmptyString
    artifact_type: ArtifactType
    knowledge_role: KnowledgeRole
    verification_status: VerificationStatus
    source_reliability: float = Field(ge=0.0, le=1.0)
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    generalizability: Generalizability
    context_specificity: float = Field(ge=0.0, le=1.0)
    support_count: int = Field(ge=0)
    contradiction_count: int = Field(ge=0)
    observed_outcome: ObservedOutcome
    observed_at: SearchableString | None = None
    freshness_observed_at: SearchableString | None = None
    independence_group: SearchableNonEmptyString
    canonical_json: SearchableNonEmptyString
    statement: SearchableString = ""
    rationale: SearchableString = ""
    observations: SearchableString = ""
    action_intent: SearchableString = ""
    expected_evidence: SearchableString = ""
    exceptions: SearchableString = ""
    facets: tuple[ProjectedFacet, ...] = ()
    sources: tuple[ProjectedSource, ...] = ()
    links: tuple[ProjectedLink, ...] = ()

    @model_validator(mode="after")
    def validate_normalized_rows(self) -> ProjectedArtifact:
        if any(facet.artifact_id != self.artifact_id for facet in self.facets):
            raise ValueError("projected facets must belong to their artifact")
        if any(source.artifact_id != self.artifact_id for source in self.sources):
            raise ValueError("projected sources must belong to their artifact")
        if any(source.independence_group != self.independence_group for source in self.sources):
            raise ValueError("projected sources must share their artifact independence group")
        if any(link.from_artifact_id != self.artifact_id for link in self.links):
            raise ValueError("projected links must originate from their artifact")
        if tuple(sorted(self.facets, key=_facet_key)) != self.facets:
            raise ValueError("projected facets must be sorted")
        if len(set(self.facets)) != len(self.facets):
            raise ValueError("projected facets must be unique")
        if tuple(sorted(self.sources, key=_source_key)) != self.sources:
            raise ValueError("projected sources must be sorted")
        if len(set(self.sources)) != len(self.sources):
            raise ValueError("projected sources must be unique")
        if tuple(sorted(self.links, key=_link_key)) != self.links:
            raise ValueError("projected links must be sorted")
        if len(set(self.links)) != len(self.links):
            raise ValueError("projected links must be unique")
        return self

    @property
    def fts_text(self) -> str:
        """A deterministic aggregate for tests and backends that need one FTS payload."""
        return "\n".join(
            value
            for value in (
                self.statement,
                self.rationale,
                self.observations,
                self.action_intent,
                self.expected_evidence,
                self.exceptions,
            )
            if value
        )


def project_semantic_bundle(bundle: SemanticKnowledgeBundle) -> tuple[ProjectedArtifact, ...]:
    """Deeply revalidate a canonical bundle and project deterministic retrieval rows.

    SQLite is intentionally not consulted here.  This boundary rejects constructed Pydantic
    instances and emits only primitive-safe, final-flag-sanitized searchable text.
    """
    canonical_bundle = _deep_revalidate_bundle(bundle)
    rows: list[ProjectedArtifact] = []
    rows.extend(_project_reference(reference) for reference in canonical_bundle.references)
    for case in canonical_bundle.cases:
        rows.append(_project_case(case))
        rows.extend(_project_step(step, parent_case_id=case.case_id) for step in case.steps)
    rows.extend(_project_rule(rule) for rule in canonical_bundle.guidance)

    sorted_rows = tuple(sorted(rows, key=lambda row: row.artifact_id))
    if len({row.artifact_id for row in sorted_rows}) != len(sorted_rows):
        raise ValueError("projected artifact IDs must be unique")
    return sorted_rows


def project_source_state(bundle: SemanticKnowledgeBundle) -> IndexedSourceState:
    """Bind one canonical source hash to its deterministic complete artifact projection."""
    projection = project_semantic_bundle(bundle)
    examples = tuple(
        sorted(
            (
                IndexedExecutionExampleState(
                    example_id=example.example_id,
                    parent_artifact_id=example.parent_artifact_id,
                )
                for example in bundle.execution_examples
            ),
            key=lambda item: item.example_id,
        )
    )
    return IndexedSourceState.from_artifacts(
        source_id=bundle.source_id,
        source_sha256=bundle.source_sha256,
        projection_version=SOURCE_PROJECTION_VERSION,
        artifacts=tuple(
            _projected_artifact_state(bundle.source_id, artifact) for artifact in projection
        ),
        execution_examples=examples,
        semantic_schema_version=bundle.schema_version,
        execution_example_schema_version=(
            bundle.compilation_manifest.execution_example_schema_version
        ),
    )


def project_execution_example_locators(
    bundle: SemanticKnowledgeBundle,
) -> tuple[ExecutionExampleLocator, ...]:
    """Project ID-only lookup locators; command text is never projected."""
    locators = tuple(
        ExecutionExampleLocator(
            example_id=example.example_id,
            parent_artifact_id=example.parent_artifact_id,
            source_id=bundle.source_id,
        )
        for example in bundle.execution_examples
    )
    return tuple(sorted(locators, key=lambda item: item.example_id))


def _projected_artifact_state(
    source_id: str,
    artifact: ProjectedArtifact,
) -> IndexedArtifactState:
    digest = projected_artifact_digest(source_id, artifact)
    return IndexedArtifactState(
        artifact_id=artifact.artifact_id,
        projection_digest=digest,
        asserted_projection_digest=digest,
    )


def projected_artifact_digest(source_id: str, artifact: ProjectedArtifact) -> str:
    """Digest every backend-neutral normalized field for one artifact projection."""
    artifact_row = {
        "artifact_id": artifact.artifact_id,
        "owner_source_id": source_id,
        "canonical_path": f"semantic_bundles/{source_id}.json",
        "artifact_type": artifact.artifact_type,
        "knowledge_role": artifact.knowledge_role,
        "verification_status": artifact.verification_status,
        "source_reliability": artifact.source_reliability,
        "extraction_confidence": artifact.extraction_confidence,
        "generalizability": artifact.generalizability,
        "context_specificity": artifact.context_specificity,
        "support_count": artifact.support_count,
        "contradiction_count": artifact.contradiction_count,
        "observed_outcome": artifact.observed_outcome,
        "observed_at": artifact.observed_at,
        "freshness_observed_at": artifact.freshness_observed_at,
        "independence_group": artifact.independence_group,
        "canonical_json": artifact.canonical_json,
    }
    facets = [facet.model_dump(mode="json") for facet in artifact.facets]
    links = [link.model_dump(mode="json") for link in artifact.links]
    sources = [
        {
            "artifact_id": source.artifact_id,
            "source_id": source.source_id,
            "path": source.path,
            "location_json": json.dumps(
                source.location.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
            "independence_group": source.independence_group,
            "relation": source.relation,
        }
        for source in artifact.sources
    ]
    fts = [
        {
            "artifact_id": artifact.artifact_id,
            **{
                field: getattr(artifact, field)
                for field in (
                    "statement",
                    "rationale",
                    "observations",
                    "action_intent",
                    "expected_evidence",
                    "exceptions",
                )
            },
        }
    ]
    payload = json.dumps(
        {
            "artifact": artifact_row,
            "facets": _sorted_digest_rows(facets),
            "links": _sorted_digest_rows(links),
            "sources": _sorted_digest_rows(sources),
            "fts": _sorted_digest_rows(fts),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _sorted_digest_rows(
    rows: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
    )


def _deep_revalidate_bundle(bundle: SemanticKnowledgeBundle) -> SemanticKnowledgeBundle:
    if not isinstance(bundle, SemanticKnowledgeBundle):
        raise ValueError("projection requires a SemanticKnowledgeBundle")
    _reject_hidden_model_state(bundle)
    try:
        primitive = json.loads(json.dumps(bundle.model_dump(mode="json"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError("semantic bundle is not JSON-primitive safe") from error
    return SemanticKnowledgeBundle.model_validate(primitive)


def _project_reference(reference: ReferenceArtifact) -> ProjectedArtifact:
    return _row(
        reference,
        artifact_id=reference.artifact_id,
        statement=(reference.subject, reference.statement, *reference.applicable_situations),
        rationale=(
            reference.expected_information_gain,
            reference.evidence_interpretation,
            *reference.success_implications,
            *reference.failure_implications,
            *reference.stop_implications,
        ),
        observations=reference.prerequisites,
        action_intent=(reference.action_intent, *reference.capability_refs),
        expected_evidence=reference.expected_evidence,
        exceptions=(*reference.exceptions, *reference.warnings),
        observed_at=reference.observed_at,
    )


def _project_case(case: KnowledgeCase) -> ProjectedArtifact:
    return _row(
        case,
        artifact_id=case.case_id,
        statement=(case.title, case.starting_access),
        rationale=(case.outcome, case.difficulty),
        observations=case.transferable_properties,
        exceptions=case.non_transferable_properties,
    )


def _project_step(step: CaseStep, *, parent_case_id: str) -> ProjectedArtifact:
    return _row(
        step,
        artifact_id=step.step_id,
        rationale=(
            *(hypothesis.statement for hypothesis in step.hypotheses),
            step.state_after.access,
            *step.state_after.environment,
            *step.state_after.privileges,
        ),
        observations=(
            step.state_before.access,
            *step.state_before.environment,
            *step.state_before.privileges,
            *step.observations,
        ),
        action_intent=(step.selected_action.intent, step.selected_action.capability_ref),
        expected_evidence=(
            *(evidence.summary for evidence in step.evidence),
            *(evidence.category for evidence in step.evidence),
            *((step.expected_information_gain,) if step.expected_information_gain else ()),
        ),
        exceptions=(*step.negative_evidence, *step.transfer_conditions),
        links=(
            ProjectedLink(
                from_artifact_id=step.step_id,
                relation="parent_case",
                to_artifact_id=parent_case_id,
            ),
        ),
    )


def _project_rule(rule: DecisionRule) -> ProjectedArtifact:
    return _row(
        rule,
        artifact_id=rule.rule_id,
        statement=rule.trigger_observations,
        rationale=(rule.rationale, *rule.alternative_hypotheses),
        observations=rule.prerequisites,
        action_intent=(rule.action_intent, *rule.capability_refs),
        expected_evidence=(
            *rule.expected_evidence,
            *rule.success_transitions,
            *rule.failure_transitions,
        ),
        exceptions=(*rule.stop_conditions, *rule.exceptions),
        additional_sources=tuple(
            (source_ref, "contradicts") for source_ref in rule.contradicting_source_refs
        ),
    )


def _row(
    artifact: ReferenceArtifact | KnowledgeCase | CaseStep | DecisionRule,
    *,
    artifact_id: str,
    statement: str | Iterable[str] | None = None,
    rationale: str | Iterable[str] | None = None,
    observations: str | Iterable[str] | None = None,
    action_intent: str | Iterable[str] | None = None,
    expected_evidence: str | Iterable[str] | None = None,
    exceptions: str | Iterable[str] | None = None,
    observed_at: str | None = None,
    links: tuple[ProjectedLink, ...] = (),
    additional_sources: tuple[tuple[SourceRef, str], ...] = (),
) -> ProjectedArtifact:
    assessment = artifact.assessment
    facets, context_sources = _project_context(artifact_id, artifact.applicability)
    sources = _project_sources(
        artifact_id,
        assessment.independence_group,
        ((source_ref, "artifact") for source_ref in artifact.source_refs),
        context_sources,
        additional_sources,
    )
    return ProjectedArtifact(
        artifact_id=artifact_id,
        artifact_type=artifact.artifact_type,
        knowledge_role=artifact.knowledge_role,
        verification_status=assessment.verification_status,
        source_reliability=assessment.source_reliability,
        extraction_confidence=assessment.extraction_confidence,
        generalizability=assessment.generalizability,
        context_specificity=assessment.context_specificity,
        support_count=assessment.support_count,
        contradiction_count=assessment.contradiction_count,
        observed_outcome=assessment.observed_outcome,
        observed_at=observed_at,
        freshness_observed_at=assessment.freshness_observed_at,
        independence_group=assessment.independence_group,
        canonical_json=_canonical_json(artifact),
        statement=_fts_value(statement),
        rationale=_fts_value(rationale),
        observations=_fts_value(observations),
        action_intent=_fts_value(action_intent),
        expected_evidence=_fts_value(expected_evidence),
        exceptions=_fts_value(exceptions),
        facets=facets,
        sources=sources,
        links=tuple(sorted(links, key=_link_key)),
    )


def _project_context(
    artifact_id: str,
    context: Any,
) -> tuple[tuple[ProjectedFacet, ...], tuple[tuple[SourceRef, str], ...]]:
    typed = context.typed_context
    assertions: list[tuple[str, str, str, ContextAssertion]] = []
    for key in (
        "os_family",
        "os_version",
        "cpu_architecture",
        "execution_environment",
        "system_role",
        "identity_context",
        "initial_access",
        "network_position",
        "observation_date",
    ):
        assertion = getattr(typed, key)
        if assertion is not None:
            assertions.append(("typed", "typed", key, assertion))
    assertions.extend(
        ("typed", "typed", f"services.{service.service_type}", service.identity)
        for service in typed.services
    )
    assertions.extend(("typed", "typed", "privileges", assertion) for assertion in typed.privileges)
    assertions.extend(
        ("typed", "typed", "security_controls", assertion) for assertion in typed.security_controls
    )
    assertions.extend(
        ("extensible", facet.namespace, facet.key, facet.assertion) for facet in context.facets
    )

    facets_by_id: dict[str, ProjectedFacet] = {}
    sources: list[tuple[SourceRef, str]] = []
    for channel, namespace, key, assertion in assertions:
        facet_id = _facet_id(
            channel,
            namespace,
            key,
            assertion.value,
            assertion.relation,
            assertion.origin,
            assertion.confidence,
        )
        facet = ProjectedFacet(
            artifact_id=artifact_id,
            facet_id=facet_id,
            channel=channel,
            namespace=namespace,
            key=key,
            value=assertion.value,
            relation=assertion.relation,
            origin=assertion.origin,
            confidence=assertion.confidence,
        )
        previous = facets_by_id.setdefault(facet_id, facet)
        if previous != facet:
            raise ValueError("projected facet identity collision")
        sources.extend((source_ref, f"facet:{facet_id}") for source_ref in assertion.source_refs)
    facets = tuple(sorted(facets_by_id.values(), key=_facet_key))
    return facets, tuple(sources)


def _project_sources(
    artifact_id: str,
    independence_group: str,
    *source_groups: Iterable[tuple[SourceRef, str]],
) -> tuple[ProjectedSource, ...]:
    sources = tuple(
        sorted(
            {
                ProjectedSource(
                    artifact_id=artifact_id,
                    source_id=source_ref.source_id,
                    path=source_ref.path,
                    location=source_ref.location,
                    independence_group=independence_group,
                    relation=relation,
                )
                for source_group in source_groups
                for source_ref, relation in source_group
            },
            key=_source_key,
        )
    )
    return sources


def _fts_value(value: str | Iterable[str] | None) -> str:
    if value is None:
        return ""
    values = (value,) if isinstance(value, str) else value
    text = " ".join(sorted({item for item in values if item}))
    return sanitize_searchable_text(text, (text,))[:_MAX_FTS_COLUMN_CHARS]


def _canonical_json(artifact: ReferenceArtifact | KnowledgeCase | CaseStep | DecisionRule) -> str:
    try:
        return json.dumps(
            artifact.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("canonical artifact is not JSON-primitive safe") from error


def _facet_key(facet: ProjectedFacet) -> tuple[str, str, str, str, str, str, float]:
    return (
        facet.channel,
        facet.namespace,
        facet.key,
        facet.value,
        facet.relation,
        facet.origin,
        facet.confidence,
    )


def _source_key(source: ProjectedSource) -> tuple[str, str, str, str, str]:
    return (
        source.relation,
        source.independence_group,
        source.source_id,
        source.path,
        _location_key(source.location),
    )


def _link_key(link: ProjectedLink) -> tuple[str, str, str]:
    return (link.from_artifact_id, link.relation, link.to_artifact_id)


def _location_key(location: SourceLocation) -> str:
    return json.dumps(location.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)


def _facet_id(
    channel: str,
    namespace: str,
    key: str,
    value: str,
    relation: ContextRelation,
    origin: Origin,
    confidence: float,
) -> str:
    identity = json.dumps(
        {
            "channel": channel,
            "confidence": confidence,
            "key": key,
            "namespace": namespace,
            "origin": origin,
            "relation": relation,
            "value": value,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"facet-{sha256(identity.encode('utf-8')).hexdigest()}"


def _reject_hidden_model_state(value: object, seen: set[int] | None = None) -> None:
    """Reject unvalidated state injected by ``model_copy(update=...)`` at any depth."""
    seen = set() if seen is None else seen
    value_id = id(value)
    if value_id in seen:
        return
    seen.add(value_id)
    if isinstance(value, BaseModel):
        fields = type(value).model_fields
        if set(value.__dict__) - set(fields) or value.__pydantic_extra__:
            raise ValueError("unsafe canonical model state")
        for field_name in fields:
            if field_name in value.__dict__:
                _reject_hidden_model_state(value.__dict__[field_name], seen)
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_hidden_model_state(item, seen)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _reject_hidden_model_state(item, seen)
