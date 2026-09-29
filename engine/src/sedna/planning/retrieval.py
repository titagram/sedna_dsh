"""Bounded situation-conditioned knowledge retrieval for planning."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from hashlib import sha256
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.engagement.models import ScopeReference, Sha256Hex
from sedna.knowledge.retrieval.models import (
    _MAX_QUERY_TEXT,
    AuthorizationScope,
    AuthorizationState,
    CurrentSituation,
    ExecutionExampleCoverageGap,
    KnowledgeGap,
    KnowledgeGapCode,
    RejectedCandidate,
    RetrievalHit,
    RetrievalQuery,
    SituationFacet,
    ValidatedTarget,
)
from sedna.knowledge.schema.execution import ExecutionExample
from sedna.planning.models import SituationProjection

MAX_PLANNER_KNOWLEDGE_BYTES = 512 * 1024
_PRIVATE_VALUE = re.compile(
    r"(?:"
    r"\b(?:password|passwd|secret|token|api[_ -]?key|credential)\b|"
    r"(?:htb|thm|flag)\s*\{|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}\b|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|"
    r"\b(?:cookie|set-cookie)\s*:\s*[^\s;,=]+=[^;\s]{8,}|"
    r"-----BEGIN(?:\s+[A-Z0-9]+)*\s+PRIVATE\s+KEY-----"
    r")",
    re.IGNORECASE,
)


class HindsightCandidateContext(BaseModel):
    """Explicit, bounded, unverified memory candidate supplied by the host agent."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    memory_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")]
    query: Annotated[str, Field(min_length=1, max_length=2048)]
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    relevance: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    tags: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = Field(
        default=(), max_length=32
    )
    provenance: Literal["hindsight"] = "hindsight"
    verification: Literal["unverified_candidate"] = "unverified_candidate"

    @model_validator(mode="after")
    def _safe_deterministic_candidate(self) -> HindsightCandidateContext:
        forwarded_text = (self.memory_id, self.query, self.summary, *self.tags)
        if any(_PRIVATE_VALUE.search(value) for value in forwarded_text):
            raise ValueError("hindsight candidate contains private-value-shaped material")
        if self.tags != tuple(sorted(set(self.tags))):
            raise ValueError("hindsight candidate tags must be sorted and unique")
        return self


class HindsightCandidateReference(BaseModel):
    """Digest-only planner reference for an unverified Hindsight candidate."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    memory_id_digest: Sha256Hex
    query_digest: Sha256Hex
    summary_digest: Sha256Hex
    tags_digest: Sha256Hex
    relevance: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    provenance: Literal["hindsight"] = "hindsight"
    verification: Literal["unverified_candidate"] = "unverified_candidate"


class CandidateResearchSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_id: Annotated[str, Field(min_length=1, max_length=512)]
    locator: Annotated[str, Field(min_length=1, max_length=4096)]
    topics: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = Field(max_length=32)
    origin: Annotated[str, Field(min_length=1, max_length=64)]
    status: Annotated[str, Field(min_length=1, max_length=64)]
    why_applicable: Annotated[str, Field(min_length=1, max_length=2048)]


class PlannerKnowledgeContext(BaseModel):
    """Bounded, data-only planner context preserving retrieval lanes and identities."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    canonical_revision: Sha256Hex
    situation_digest: Sha256Hex
    material_event_revision: Annotated[int, Field(ge=0)]
    source_registry_digest: Sha256Hex
    references: tuple[RetrievalHit, ...] = Field(default=(), max_length=64)
    case_steps: tuple[RetrievalHit, ...] = Field(default=(), max_length=64)
    negative_cases: tuple[RetrievalHit, ...] = Field(default=(), max_length=64)
    decision_guidance: tuple[RetrievalHit, ...] = Field(default=(), max_length=64)
    rejected_candidates: tuple[RejectedCandidate, ...] = Field(default=(), max_length=64)
    knowledge_gaps: tuple[KnowledgeGap, ...] = Field(default=(), max_length=32)
    execution_examples: tuple[ExecutionExample, ...] = Field(default=(), max_length=16)
    execution_example_gaps: tuple[ExecutionExampleCoverageGap, ...] = Field(
        default=(), max_length=32
    )
    candidate_research_sources: tuple[CandidateResearchSource, ...] = Field(
        default=(), max_length=16
    )
    hindsight_candidates: tuple[HindsightCandidateReference, ...] = Field(default=(), max_length=16)
    retrieval_unavailable: bool = False
    context_digest: Sha256Hex

    @model_validator(mode="after")
    def _bounded_context(self) -> PlannerKnowledgeContext:
        if len(self.model_dump_json().encode("utf-8")) > MAX_PLANNER_KNOWLEDGE_BYTES:
            raise ValueError("planner knowledge context exceeds the cumulative bound")
        return self


def digest_hindsight_candidates(
    hindsight_candidates: tuple[HindsightCandidateContext, ...],
) -> tuple[HindsightCandidateReference, ...]:
    memory_ids = tuple(item.memory_id for item in hindsight_candidates)
    if memory_ids != tuple(sorted(set(memory_ids))):
        raise ValueError("hindsight candidate ids must be sorted and unique")
    return tuple(
        HindsightCandidateReference(
            memory_id_digest=sha256(item.memory_id.encode("utf-8")).hexdigest(),
            query_digest=sha256(item.query.encode("utf-8")).hexdigest(),
            summary_digest=sha256(item.summary.encode("utf-8")).hexdigest(),
            tags_digest=sha256(
                json.dumps(item.tags, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            relevance=item.relevance,
        )
        for item in hindsight_candidates
    )


def assemble_planner_knowledge(
    situation: SituationProjection,
    scope_references: tuple[ScopeReference, ...],
    *,
    retrieval: Any,
    source_registry: Any,
    canonical_revision: Callable[[], str],
    hindsight_candidates: tuple[HindsightCandidateContext, ...] = (),
) -> PlannerKnowledgeContext:
    """Retrieve all lanes, drill into qualifying hits, and revision-bind the result."""
    hindsight_references = digest_hindsight_candidates(hindsight_candidates)
    revision = _strict_revision(canonical_revision())
    results = tuple(
        retrieval.retrieve(query) for query in build_retrieval_queries(situation, scope_references)
    )
    references = _unique_by_id((hit for result in results for hit in result.references), limit=64)
    case_steps = _unique_by_id((hit for result in results for hit in result.case_steps), limit=64)
    negative_cases = _unique_by_id(
        (hit for result in results for hit in result.negative_cases), limit=64
    )
    guidance = _unique_by_id(
        (hit for result in results for hit in result.decision_guidance), limit=64
    )
    rejected = _unique_by_id(
        (candidate for result in results for candidate in result.rejected_candidates), limit=64
    )
    gaps = tuple(result.knowledge_gap for result in results if result.knowledge_gap is not None)[
        :32
    ]
    examples: list[ExecutionExample] = []
    example_gaps: list[ExecutionExampleCoverageGap] = []
    seen_example_ids: set[str] = set()
    for hit in (*references, *case_steps, *negative_cases, *guidance):
        if len(examples) >= 16:
            break
        drilldown = retrieval.get_execution_examples(hit.artifact_id)
        if drilldown.coverage_gap is not None:
            example_gaps.append(drilldown.coverage_gap)
        for example in drilldown.examples:
            if len(examples) >= 16:
                break
            if example.example_id not in seen_example_ids and _example_applies(example, situation):
                examples.append(example)
                seen_example_ids.add(example.example_id)
    source_page = source_registry.list_planner_hints(topic_tokens=_planner_topic_tokens(situation))
    retrieval_unavailable = any(gap.code is KnowledgeGapCode.RETRIEVAL_UNAVAILABLE for gap in gaps)
    candidates = (
        ()
        if retrieval_unavailable
        else tuple(
            CandidateResearchSource(
                source_id=entry.source_id,
                locator=entry.locator,
                topics=entry.topics,
                origin=entry.origin.value,
                status=entry.status.value,
                why_applicable="candidate source; validate claims against current evidence",
            )
            for entry in source_page.entries
            if _source_applies(entry.topics, situation)
        )
    )
    if _strict_revision(canonical_revision()) != revision:
        raise RuntimeError("canonical knowledge changed during planner retrieval")
    values = {
        "canonical_revision": revision,
        "situation_digest": situation.state_digest,
        "material_event_revision": situation.material_event_revision,
        "source_registry_digest": source_page.registry_sha256,
        "references": references,
        "case_steps": case_steps,
        "negative_cases": negative_cases,
        "decision_guidance": guidance,
        "rejected_candidates": rejected,
        "knowledge_gaps": gaps,
        "execution_examples": tuple(examples),
        "execution_example_gaps": _bounded_example_gaps(tuple(example_gaps)),
        "candidate_research_sources": candidates,
        "hindsight_candidates": hindsight_references,
        "retrieval_unavailable": retrieval_unavailable,
    }
    serializable = {
        key: [item.model_dump(mode="json") for item in value] if isinstance(value, tuple) else value
        for key, value in values.items()
    }
    digest = sha256(
        json.dumps(serializable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PlannerKnowledgeContext(**values, context_digest=digest)


def _strict_revision(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("invalid canonical knowledge revision")
    return value


def _unique_by_id(items: Any, *, limit: int) -> tuple[Any, ...]:
    selected: list[Any] = []
    seen: set[str] = set()
    for item in items:
        identifier = item.artifact_id
        if identifier in seen:
            continue
        selected.append(item)
        seen.add(identifier)
        if len(selected) == limit:
            break
    return tuple(selected)


def _bounded_example_gaps(
    gaps: tuple[ExecutionExampleCoverageGap, ...],
) -> tuple[ExecutionExampleCoverageGap, ...]:
    selected: list[ExecutionExampleCoverageGap] = []
    seen: set[tuple[str, str, str, str]] = set()
    for gap in gaps:
        identity = (
            gap.code.value,
            gap.source_id,
            gap.semantic_schema_version,
            gap.explanation,
        )
        if identity in seen:
            continue
        selected.append(gap)
        seen.add(identity)
        if len(selected) == 32:
            break
    return tuple(selected)


def _planner_topic_tokens(situation: SituationProjection) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                item.value.casefold()
                for item in situation.facets
                if item.key.casefold() in {"os_family", "cpu_architecture", "service", "protocol"}
                and not _PRIVATE_VALUE.search(item.value)
            }
        )
    )


def _example_applies(example: ExecutionExample, situation: SituationProjection) -> bool:
    observed = {item.key.casefold(): item.value.casefold() for item in situation.facets}
    typed = example.applicability.typed_context
    for dimension in ("os_family", "os_version", "cpu_architecture", "execution_environment"):
        assertion = getattr(typed, dimension)
        if assertion is not None and not _context_assertion_applies(
            observed.get(dimension), assertion.value, assertion.relation.value
        ):
            return False
    for facet in example.applicability.facets:
        if not _context_assertion_applies(
            observed.get(facet.key.casefold()),
            facet.assertion.value,
            facet.assertion.relation.value,
        ):
            return False
    for constraint in example.platform_constraints:
        current = observed.get(constraint.dimension)
        if current is None and constraint.relation == "required":
            return False
        if current is None:
            continue
        expected = constraint.value.casefold()
        if constraint.relation == "incompatible" and current == expected:
            return False
        if constraint.relation == "required" and current != expected:
            return False
    return True


def _context_assertion_applies(current: str | None, expected: str, relation: str) -> bool:
    normalized = expected.casefold()
    if relation == "required":
        return current is not None and current == normalized
    if relation == "incompatible":
        return current is None or current != normalized
    return True


def _source_applies(topics: tuple[str, ...], situation: SituationProjection) -> bool:
    observed = {item.value.casefold() for item in situation.facets}
    topic_set = {item.casefold() for item in topics}
    incompatible = {
        "linux": {"windows", "macos", "darwin", "freebsd"},
        "windows": {"linux", "macos", "darwin", "freebsd"},
        "x86_64": {"aarch64", "arm64", "i386", "armv7"},
        "aarch64": {"x86_64", "amd64", "i386", "armv7"},
    }
    return not any(topic_set & incompatible.get(value, set()) for value in observed)


def build_retrieval_queries(
    situation: SituationProjection,
    scope_references: tuple[ScopeReference, ...],
    *,
    max_candidates: int = 32,
    lane_limit: int = 5,
) -> tuple[RetrievalQuery, ...]:
    """Build one conservative query for each valid, explicitly scoped target.

    Per-field and per-count bounds are not sufficient on their own: 32 terms of
    512 characters, or 32 facets of 2048, overflow the ``CurrentSituation``
    cumulative text bound (``_MAX_QUERY_TEXT``), and the model then raises
    "current situation text exceeds the cumulative bound" — which aborted
    ``plan_next`` on every settled journal long enough to accumulate that much
    evidence. Everything assembled below therefore shares ONE explicit budget.
    """
    # The contract counts terms + access + services + hypotheses + outcomes +
    # unresolved + facets + authorization against ONE limit. Reserve the
    # authorization share first, then split what remains so the running total
    # always fits (a per-field share alone overflowed it by 32 characters on a
    # real settled journal).
    authorization_reserve = min(_MAX_QUERY_TEXT // 4, 2048)
    text_budget = _MAX_QUERY_TEXT - authorization_reserve
    terms_budget = text_budget // 2
    remaining_budget = text_budget - terms_budget
    access_budget = remaining_budget // 4
    services_budget = remaining_budget // 8
    hypotheses_budget = remaining_budget // 4
    outcomes_budget = remaining_budget // 8
    unresolved_budget = remaining_budget // 8
    facts_budget = remaining_budget - (
        access_budget + services_budget + hypotheses_budget + outcomes_budget + unresolved_budget
    )

    terms = _fit_within_budget(
        _safe_texts((item.text for item in situation.facts), limit=32),
        limit=32,
        budget=terms_budget,
    )
    facets = _fit_facets_within_budget(
        tuple(
            SituationFacet(
                namespace="observed",
                key=item.key,
                value=item.value,
                confidence=1.0,
            )
            for item in situation.facets
            if not _PRIVATE_VALUE.search(item.value)
        )[:32],
        budget=facts_budget,
    )
    services = tuple(
        sorted(
            {
                word
                for term in terms
                for word in term.split()
                if word.casefold() in {"http", "https", "ssh", "dns", "smb", "ftp", "rdp"}
            }
        )
    )
    access = _fit_within_budget(
        _safe_texts(
            (
                f"{item.subject}: credential available"
                if " ".join(item.state.split()).casefold() == "credential available"
                else f"{item.subject}: {item.state}"
                for item in situation.access_states
            ),
            limit=64,
            allowed_exact_suffix=": credential available",
        ),
        limit=64,
        budget=access_budget,
    )
    hypotheses = _fit_within_budget(
        _safe_texts((item.text for item in situation.hypotheses), limit=64),
        limit=64,
        budget=hypotheses_budget,
    )
    outcomes = _fit_within_budget(
        tuple(
            _clip_text(item.summary, MAX_TERM_CHARS)
            for item in situation.attempts
            if not _PRIVATE_VALUE.search(item.summary)
        ),
        limit=64,
        budget=outcomes_budget,
    )
    unresolved = _fit_within_budget(
        _safe_texts((item.question for item in situation.unresolved_information), limit=64),
        limit=64,
        budget=unresolved_budget,
    )
    synonyms = _code_intelligence_expansions(
        terms=terms,
        hypotheses=hypotheses,
        facets=facets,
    )
    queries: list[RetrievalQuery] = []
    seen: set[str] = set()
    for reference in sorted(scope_references, key=lambda item: item.reference_id):
        target = ValidatedTarget.parse(reference.value)
        if not target.is_valid or target.normalized is None or target.normalized in seen:
            continue
        authorization = _authorization_for(reference, target)
        if not authorization.authorizes(target):
            continue
        seen.add(target.normalized)
        queries.append(
            RetrievalQuery(
                situation=CurrentSituation(
                    target=target,
                    authorization=authorization,
                    terms=terms,
                    facts=facets,
                    access=access,
                    services=services,
                    hypotheses=hypotheses,
                    tried_outcomes=outcomes,
                    unresolved_questions=unresolved,
                ),
                terms=terms,
                synonyms=synonyms,
                facets=facets,
                max_candidates=max_candidates,
                lane_limit=lane_limit,
            )
        )
    return tuple(queries)


def _code_intelligence_expansions(
    *,
    terms: tuple[str, ...],
    hypotheses: tuple[str, ...],
    facets: tuple[SituationFacet, ...],
) -> tuple[str, ...]:
    """Map concrete observations to transferable source/sink and trust-boundary terms."""

    corpus = " ".join(
        (*terms, *hypotheses, *(f"{item.key} {item.value}" for item in facets))
    ).casefold()
    expansions: set[str] = set()
    controlled = any(token in corpus for token in ("attacker-controlled", "user-controlled"))
    persistent = any(token in corpus for token in ("persist", "stored", "saved server-side"))
    rendered = any(token in corpus for token in ("render", "display", "viewer"))
    privileged = any(token in corpus for token in ("administrator", "admin", "privileged"))
    client_crypto = "client-side" in corpus and any(
        token in corpus for token in ("encryption", "cryptographic", " key")
    )
    forgeable = any(token in corpus for token in ("forged", "forgeable", "permits forg"))

    if controlled and persistent:
        expansions.update(("persistent attacker-controlled input", "stored xss"))
    if persistent and rendered and privileged:
        expansions.update(("blind xss", "privileged renderer", "administrative rendering"))
    if client_crypto and forgeable:
        expansions.update(("client-side integrity bypass", "forged encrypted payload"))
    if any(token in corpus for token in ("symbol mapping", "html symbol", "output encoding")):
        expansions.update(("html injection", "output encoding bypass", "stored xss"))
    return tuple(sorted(expansions))[:32]


# The Term contract in knowledge.retrieval.models bounds each term to 512
# characters. Terms produced here must satisfy it, so clip to the same bound.
MAX_TERM_CHARS = 512


def _fit_within_budget(
    values: tuple[str, ...],
    *,
    limit: int,
    budget: int,
) -> tuple[str, ...]:
    """Clip a term tuple until its TOTAL text fits the budget.

    A per-field share is not enough: with a 512-character per-term bound, 32
    terms reach 16_384 characters and overflow the 8_192 cumulative contract
    (measured on a real settled journal: terms totalled 8_224, 32 over the
    limit). This enforces the running total, shortening the last terms as needed
    and dropping any that no longer carry text.
    """
    selected: list[str] = []
    used = 0
    for value in values:
        remaining = budget - used
        if remaining <= 0:
            break
        text = value if len(value) <= remaining else value[:remaining]
        if len(value) > remaining:
            boundary = text.rfind(" ")
            if boundary > remaining // 2:
                text = text[:boundary]
        text = text.rstrip()
        if not text:
            break
        selected.append(text)
        used += len(text)
        if len(selected) == limit:
            break
    return tuple(selected)


def _clip_text(value: str, limit: int) -> str:
    """Clip text to a limit on a word boundary, preserving determinism."""
    normalized = " ".join(value.split()).casefold()
    if len(normalized) <= limit:
        return normalized
    clipped = normalized[:limit]
    boundary = clipped.rfind(" ")
    if boundary > limit // 2:
        clipped = clipped[:boundary]
    return clipped.rstrip()


def _fit_within_budget(
    values: tuple[str, ...],
    *,
    limit: int,
    budget: int,
) -> tuple[str, ...]:
    """Clip a term tuple until its TOTAL text fits the budget.

    A per-field share is not enough: with a 512-character per-term bound, 32
    terms reach 16_384 characters and overflow the 8_192 cumulative contract
    (measured on a real settled journal: terms totalled 8_224, 32 over the
    limit). This enforces the running total, shortening the last terms as needed
    and dropping any that no longer carry text.
    """
    selected: list[str] = []
    used = 0
    for value in values:
        remaining = budget - used
        if remaining <= 0:
            break
        text = value if len(value) <= remaining else value[:remaining]
        if len(value) > remaining:
            boundary = text.rfind(" ")
            if boundary > remaining // 2:
                text = text[:boundary]
        text = text.rstrip()
        if not text:
            break
        selected.append(text)
        used += len(text)
        if len(selected) == limit:
            break
    return tuple(selected)


def _fit_facets_within_budget(
    facets: tuple[SituationFacet, ...],
    *,
    budget: int,
) -> tuple[SituationFacet, ...]:
    """Clip facets until their combined namespace+key+value text fits the budget.

    Clipping can collapse two distinct observations onto the same truncated text,
    and ``RetrievalQuery`` rejects duplicate facets ("query facets must be
    unique"), so the result is de-duplicated on whole-facet identity after
    clipping.
    """
    selected: list[SituationFacet] = []
    seen: set[tuple[str, str, str]] = set()
    used = 0
    for facet in facets:
        remaining = budget - used
        if remaining <= len(facet.namespace) + len(facet.key):
            break
        value = facet.value
        value_limit = remaining - len(facet.namespace) - len(facet.key)
        if len(value) > value_limit:
            clipped = value[:value_limit]
            boundary = clipped.rfind(" ")
            if boundary > value_limit // 2:
                clipped = clipped[:boundary]
            value = clipped.rstrip()
            if not value:
                break
        identity = (facet.namespace, facet.key, value)
        if identity in seen:
            continue
        seen.add(identity)
        used += len(facet.namespace) + len(facet.key) + len(value)
        selected.append(
            SituationFacet(
                namespace=facet.namespace,
                key=facet.key,
                value=value,
                confidence=facet.confidence,
            )
        )
    return tuple(selected)


def _clip_text(value: str, limit: int) -> str:
    """Clip text to a limit on a word boundary, preserving determinism."""
    normalized = " ".join(value.split()).casefold()
    if len(normalized) <= limit:
        return normalized
    clipped = normalized[:limit]
    boundary = clipped.rfind(" ")
    if boundary > limit // 2:
        clipped = clipped[:boundary]
    return clipped.rstrip()


class _QueryTextBudget:
    """Shared cumulative text budget for one CurrentSituation assembly.

    The contract counts every term, facet and question against a single limit
    (``_MAX_QUERY_TEXT``). Splitting that limit explicitly means no field can
    silently saturate the whole allowance and break construction.
    """

    def __init__(self, total: int) -> None:
        self._total = total

    def share(self, parts: int) -> int:
        """Return this field's allowance, leaving room for the other fields."""
        return max(1, self._total // max(1, parts))


def _bounded_facets(
    facets: Any,
    *,
    limit: int,
    budget: int,
) -> tuple[SituationFacet, ...]:
    """Return facets bounded both in count and in combined text size."""
    selected: list[SituationFacet] = []
    used = 0
    for facet in facets:
        namespace = " ".join(str(facet.namespace).split()).casefold()
        key = " ".join(str(facet.key).split()).casefold()
        value = " ".join(str(facet.value).split()).casefold()
        if not namespace or not key or not value:
            continue
        remaining = budget - used
        if remaining <= len(namespace) + len(key):
            break
        # The value takes whatever remains after the naming fields.
        value_limit = min(len(value), max(1, remaining - len(namespace) - len(key)))
        if value_limit < len(value):
            clipped = value[:value_limit]
            boundary = clipped.rfind(" ")
            if boundary > value_limit // 2:
                clipped = clipped[:boundary]
            value = clipped.rstrip()
            if not value:
                continue
        used += len(namespace) + len(key) + len(value)
        selected.append(
            SituationFacet(
                namespace=namespace,
                key=key,
                value=value,
                confidence=facet.confidence,
            )
        )
        if len(selected) == limit:
            break
    return tuple(selected)


def _safe_texts(
    values: Any,
    *,
    limit: int,
    allowed_exact_suffix: str | None = None,
    max_text_length: int = MAX_TERM_CHARS,
) -> tuple[str, ...]:
    """Return deterministic bounded text after removing private-value-shaped records.

    Both the NUMBER of returned terms and the LENGTH of each one are bounded.
    Bounding only the count was a real defect: a long observation (for example a
    527-character evidence-slice description) produced a term longer than the
    ``Term`` contract (max_length=512), and ``CurrentSituation`` then raised
    ``ValidationError: terms.N Value should have at most 512 items``, aborting
    ``plan_next`` before it could propose anything.
    """
    selected: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = " ".join(value.split()).casefold()
        safe_symbolic = False
        if allowed_exact_suffix is not None and normalized.endswith(allowed_exact_suffix):
            subject = normalized[: -len(allowed_exact_suffix)].strip()
            safe_symbolic = bool(subject) and _PRIVATE_VALUE.search(subject) is None
        if _PRIVATE_VALUE.search(value) and not safe_symbolic:
            continue
        if not normalized or normalized in seen:
            continue
        if len(normalized) > max_text_length:
            # Truncate on a word boundary so the term stays readable and stable.
            clipped = normalized[:max_text_length]
            boundary = clipped.rfind(" ")
            if boundary > max_text_length // 2:
                clipped = clipped[:boundary]
            normalized = clipped.rstrip()
            if not normalized or normalized in seen:
                continue
        selected.append(normalized)
        seen.add(normalized)
        if len(selected) == limit:
            break
    return tuple(sorted(selected))


def _authorization_for(reference: ScopeReference, target: ValidatedTarget) -> AuthorizationScope:
    if reference.kind == "exact_target":
        return AuthorizationScope(state=AuthorizationState.AUTHORIZED, exact_targets=(target,))
    if reference.kind == "hostname":
        return AuthorizationScope(state=AuthorizationState.AUTHORIZED, hostnames=(reference.value,))
    if reference.kind == "url_origin":
        return AuthorizationScope(
            state=AuthorizationState.AUTHORIZED, url_origins=(reference.value,)
        )
    if reference.kind == "generic_id":
        return AuthorizationScope(
            state=AuthorizationState.AUTHORIZED, generic_ids=(reference.value,)
        )
    return AuthorizationScope(state=AuthorizationState.UNKNOWN)
