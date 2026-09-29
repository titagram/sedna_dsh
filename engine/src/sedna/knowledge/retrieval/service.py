"""Validated, lane-aware orchestration for the local knowledge retrieval index."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from sedna.knowledge.retrieval import ranking
from sedna.knowledge.retrieval.models import (
    AuthorizationState,
    EpistemicLane,
    ExecutionExampleCoverageCode,
    ExecutionExampleCoverageGap,
    ExecutionExampleDrilldown,
    IndexCandidate,
    IndexedArtifact,
    KnowledgeGap,
    KnowledgeGapCode,
    Reason,
    RetrievalIndex,
    RetrievalQuery,
    RetrievalResult,
)
from sedna.knowledge.schema import CaseStep, DecisionRule, KnowledgeCase, ReferenceArtifact

_ARTIFACT_ID = TypeAdapter(Reason)
_ARTIFACT_TYPES = (ReferenceArtifact, KnowledgeCase, CaseStep, DecisionRule)
_RESULT_REJECTION_LIMIT = 64
_GAP_ITEM_LIMIT = 32
_OBSERVED_DOMAIN_LIMIT = 2048
_LEGACY_SEMANTIC_SCHEMA = "2.4.0"


@dataclass(frozen=True, slots=True)
class KnowledgeRetrievalService:
    """Validate once, query bounded lanes, rank, and return a closed retrieval result."""

    index: RetrievalIndex
    revision_guard: Callable[[], str] | None = None
    execution_example_loader: Callable[..., tuple[object, ...]] | None = None

    def get_execution_examples(self, parent_artifact_id: str) -> ExecutionExampleDrilldown:
        """Return one parent's bundle-owned examples or an exact typed coverage gap."""
        canonical_parent = _strict_artifact_id(parent_artifact_id)
        try:
            revision = self._read_revision()
            locators = self.index.get_execution_example_locators(canonical_parent)
            if locators:
                if self.execution_example_loader is None:
                    raise ValueError("execution example loader is not configured")
                source_id = locators[0].source_id
                if any(locator.source_id != source_id for locator in locators):
                    raise ValueError("locators span multiple sources")
                example_ids = tuple(locator.example_id for locator in locators)
                examples = tuple(
                    self.execution_example_loader(
                        source_id,
                        parent_artifact_id=canonical_parent,
                        example_ids=example_ids,
                    )
                )
                self._require_revision(revision)
                self._validate_drilldown(canonical_parent, source_id, example_ids, examples)
                return ExecutionExampleDrilldown(
                    parent_artifact_id=canonical_parent,
                    examples=examples,
                )
            parent = self.index.get_artifact(canonical_parent)
            source_id = parent.source_refs[0].source_id if parent is not None else canonical_parent
            capability = self.index.get_source_capability(source_id)
            if capability == _LEGACY_SEMANTIC_SCHEMA:
                return ExecutionExampleDrilldown(
                    parent_artifact_id=canonical_parent,
                    coverage_gap=ExecutionExampleCoverageGap(
                        code=ExecutionExampleCoverageCode.LEGACY_BUNDLE_WITHOUT_EXAMPLES,
                        source_id=source_id,
                        semantic_schema_version=capability,
                        explanation=("the legacy bundle could not represent execution examples"),
                    ),
                )
            self._require_revision(revision)
            return ExecutionExampleDrilldown(parent_artifact_id=canonical_parent)
        except Exception:
            raise RuntimeError("execution example drill-down failed") from None

    def _validate_drilldown(
        self,
        parent_artifact_id: str,
        source_id: str,
        example_ids: tuple[str, ...],
        examples: tuple[object, ...],
    ) -> None:

        canonical = tuple(_strict_example(example) for example in examples)
        if any(
            example.parent_artifact_id != parent_artifact_id
            or example.example_id not in example_ids
            for example in canonical
        ):
            raise ValueError("execution example drill-down identity mismatch")
        if set(example_ids) != {example.example_id for example in canonical}:
            raise ValueError("execution example IDs must exactly match the locators")
        del source_id

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Return lane-local knowledge or an explicit pre-backend/knowledge gap."""
        query = _strict_query(query)
        prebackend = _prebackend_result(query)
        if prebackend is not None:
            return prebackend

        try:
            candidates = self._search_lanes(query)
            ranked = ranking.rank_candidates(query, candidates)
            references = ranking.select_diversified_hits(
                ranked.references,
                limit=query.lane_limit,
            )
            case_steps = ranking.select_diversified_hits(
                ranked.case_steps,
                limit=query.lane_limit,
            )
            negative_cases = ranking.select_diversified_hits(
                ranked.negative_cases,
                limit=query.lane_limit,
            )
            decision_guidance = ranking.select_diversified_hits(
                ranked.decision_guidance,
                limit=query.lane_limit,
            )
            rejected = ranked.rejected_candidates[:_RESULT_REJECTION_LIMIT]
            if any((references, case_steps, negative_cases, decision_guidance)):
                return RetrievalResult(
                    target=query.situation.target,
                    authorization=query.situation.authorization,
                    references=references,
                    case_steps=case_steps,
                    negative_cases=negative_cases,
                    decision_guidance=decision_guidance,
                    rejected_candidates=rejected,
                )
            return RetrievalResult(
                target=query.situation.target,
                authorization=query.situation.authorization,
                rejected_candidates=rejected,
                knowledge_gap=_no_applicable_gap(query, ranked.missing_context_questions),
            )
        except Exception:
            return _backend_failure_result(query)

    def get_artifact(self, artifact_id: str) -> IndexedArtifact | None:
        """Return one exact canonical artifact without exposing backend failure details."""
        canonical_id = _strict_artifact_id(artifact_id)
        try:
            revision = self._read_revision()
            artifact = self.index.get_artifact(canonical_id)
            self._require_revision(revision)
            if artifact is None:
                return None
            if type(artifact) not in _ARTIFACT_TYPES:
                raise ValueError("unsupported indexed artifact type")
            ranking._preflight_or_raise(artifact, label="retrieved canonical artifact")
            canonical = ranking._strict_revalidate(artifact, type(artifact))
            if _artifact_identity(canonical) != canonical_id:
                raise ValueError("artifact lookup identity mismatch")
            return canonical
        except Exception:
            raise RuntimeError("knowledge artifact lookup failed") from None

    def _search_lanes(self, query: RetrievalQuery) -> tuple[IndexCandidate, ...]:
        candidates: list[IndexCandidate] = []
        revision = self._read_revision()
        for lane in EpistemicLane:
            lane_candidates = self.index.search_candidates(
                query,
                lane=lane,
                limit=query.max_candidates,
            )
            if type(lane_candidates) is not tuple:
                raise ValueError("retrieval index must return a candidate tuple")
            if len(lane_candidates) > query.max_candidates:
                raise ValueError("retrieval index exceeded the requested candidate limit")
            if any(not isinstance(candidate, IndexCandidate) for candidate in lane_candidates):
                raise ValueError("retrieval index returned a non-canonical candidate")
            candidates.extend(lane_candidates)
        self._require_revision(revision)
        return tuple(candidates)

    def _read_revision(self) -> str | None:
        guard = self.revision_guard
        if guard is None:
            return None
        revision = guard()
        if (
            type(revision) is not str
            or len(revision) != 64
            or any(character not in "0123456789abcdef" for character in revision)
        ):
            raise ValueError("retrieval revision guard returned an invalid token")
        return revision

    def _require_revision(self, expected: str | None) -> None:
        if expected is None:
            return
        if self._read_revision() != expected:
            raise RuntimeError("canonical knowledge changed during retrieval")


def _strict_query(query: RetrievalQuery) -> RetrievalQuery:
    if type(query) is not RetrievalQuery:
        raise ValueError("retrieval requires an exact RetrievalQuery")
    ranking._preflight_or_raise(query, label="retrieval query")
    return ranking._strict_revalidate(query, RetrievalQuery)


def _prebackend_result(query: RetrievalQuery) -> RetrievalResult | None:
    situation = query.situation
    if not situation.target.is_valid:
        return RetrievalResult(
            target=situation.target,
            authorization=situation.authorization,
            knowledge_gap=KnowledgeGap(
                code=KnowledgeGapCode.INVALID_TARGET,
                summary="the supplied target is not syntactically valid",
                observed_domain=_observed_domain(query),
                research_eligible=False,
            ),
        )
    if situation.authorization.state is not AuthorizationState.AUTHORIZED:
        summary = (
            "the supplied target is explicitly outside authorized scope"
            if situation.authorization.state is AuthorizationState.UNAUTHORIZED
            else "authorization for the supplied target has not been established"
        )
        return RetrievalResult(
            target=situation.target,
            authorization=situation.authorization,
            knowledge_gap=KnowledgeGap(
                code=KnowledgeGapCode.UNAUTHORIZED_SCOPE,
                summary=summary,
                observed_domain=_observed_domain(query),
                missing_context=("explicit authorization scope for the supplied target",),
                research_eligible=False,
            ),
        )
    return None


def _no_applicable_gap(
    query: RetrievalQuery,
    ranking_questions: tuple[Reason, ...],
) -> KnowledgeGap:
    missing = tuple(
        sorted(
            {
                *ranking_questions,
                *query.situation.unresolved_questions,
            }
        )
    )[:_GAP_ITEM_LIMIT]
    if not missing:
        missing = ("applicable source-backed evidence for the observed domain",)
    return KnowledgeGap(
        code=KnowledgeGapCode.NO_APPLICABLE_KNOWLEDGE,
        summary="no indexed knowledge qualified for the observed situation",
        observed_domain=_observed_domain(query),
        missing_context=missing,
        suggested_document_ingestion=(
            "ingest source-backed technical documentation matching the observed domain",
            "ingest relevant case studies with explicit applicability context",
        ),
        research_eligible=True,
    )


def _backend_failure_result(query: RetrievalQuery) -> RetrievalResult:
    return RetrievalResult(
        target=query.situation.target,
        authorization=query.situation.authorization,
        knowledge_gap=KnowledgeGap(
            code=KnowledgeGapCode.RETRIEVAL_UNAVAILABLE,
            summary="knowledge retrieval is temporarily unavailable",
            observed_domain=_observed_domain(query),
            missing_context=("retrieval index availability",),
            research_eligible=False,
        ),
    )


def _observed_domain(query: RetrievalQuery) -> str:
    values = {
        *query.situation.terms,
        *query.situation.services,
        *query.terms,
        *query.synonyms,
        *(
            f"{facet.namespace}.{facet.key}={facet.value}"
            for facet in (*query.situation.facts, *query.facets)
        ),
    }
    if not values:
        values.add(query.situation.target.kind.value)
    return "; ".join(sorted(values))[:_OBSERVED_DOMAIN_LIMIT]


def _strict_artifact_id(artifact_id: str) -> str:
    if type(artifact_id) is not str or artifact_id != artifact_id.strip():
        raise ValueError("artifact_id must be a bounded canonical identifier")
    try:
        return _ARTIFACT_ID.validate_python(artifact_id)
    except ValidationError as error:
        raise ValueError("artifact_id must be a bounded canonical identifier") from error


def _strict_example(example: object):
    from sedna.knowledge.schema.execution import ExecutionExample

    if type(example) is ExecutionExample:
        return example
    if not isinstance(example, BaseModel):
        raise ValueError("execution example must be a strict model")
    model = cast(BaseModel, example)
    payload = model.model_dump(mode="json", warnings="error")
    try:
        return ExecutionExample.model_validate(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("execution example must be a strict canonical record") from error


def _artifact_identity(artifact: BaseModel) -> str:
    if isinstance(artifact, ReferenceArtifact):
        return artifact.artifact_id
    if isinstance(artifact, KnowledgeCase):
        return artifact.case_id
    if isinstance(artifact, CaseStep):
        return artifact.step_id
    if isinstance(artifact, DecisionRule):
        return artifact.rule_id
    raise ValueError("unsupported indexed artifact type")


__all__ = ["KnowledgeRetrievalService"]
