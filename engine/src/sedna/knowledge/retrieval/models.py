"""Backend-neutral, strict contracts for deterministic local knowledge retrieval."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from enum import StrEnum
from hashlib import sha256
from types import TracebackType
from typing import Annotated, Any, Protocol, TypeAlias, runtime_checkable
from urllib.parse import SplitResult, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sedna.knowledge.parsing.sanitize import sanitize_searchable_text
from sedna.knowledge.schema import (
    ArtifactType,
    CaseStep,
    DecisionRule,
    KnowledgeCase,
    KnowledgeRole,
    ObservedOutcome,
    ReferenceArtifact,
    SemanticKnowledgeBundle,
    SourceRef,
)
from sedna.knowledge.schema.common import SearchableNonEmptyString, SearchableString
from sedna.knowledge.schema.execution import ExecutionExample
from sedna.knowledge.schema.manifest import Sha256
from sedna.knowledge.semantic.compiler import SEMANTIC_SCHEMA_VERSION

Term: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=512)]
FacetNamespace: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=128)]
FacetKey: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=128)]
FacetValue: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=2048)]
Reason: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=2048)]
ScopeValue: TypeAlias = Annotated[SearchableNonEmptyString, Field(max_length=2048)]

_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)
_NUMERIC_DOTTED = re.compile(r"^[0-9.]+$")
_IPV6ISH = re.compile(r"^[0-9a-fA-F:.]+$")
_IPV6_COMPONENT = re.compile(r"^[0-9a-fA-F]{1,4}$")
_HOST_PORT = re.compile(r"^[a-z0-9.-]+:\d+$", re.IGNORECASE)
_EXPLICIT_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_MALFORMED_HTTP_PREFIX = re.compile(r"^https?(?::|/)", re.IGNORECASE)
_MAX_SITUATION_ITEMS = 64
_MAX_QUERY_TERMS = 32
_MAX_HIT_REASONS = 32
_MAX_GAP_ITEMS = 32
_MAX_QUERY_TEXT = 8192
_MAX_AUTHORIZATION_TEXT = 16_384
_MAX_CANDIDATE_MATCH_TEXT = 16_384
_MAX_INDEX_SOURCES = 100_000
_MAX_SOURCE_ARTIFACTS = 100_000
_MAX_INDEX_ARTIFACTS = 10_000_000


class TargetKind(StrEnum):
    """Syntactic target identity categories checked before any backend operation."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HOSTNAME = "hostname"
    URL = "url"
    GENERIC = "generic"
    INVALID = "invalid"


class AuthorizationState(StrEnum):
    """Whether the current target has an explicit authorization decision."""

    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"


class EpistemicLane(StrEnum):
    """Evidence lanes that must not be globally compared as interchangeable scores."""

    REFERENCE = "reference"
    CASE_STEP = "case_step"
    NEGATIVE_EVIDENCE = "negative_evidence"
    GUIDANCE = "guidance"


class KnowledgeGapCode(StrEnum):
    """The closed vocabulary for explicit retrieval non-answers."""

    INVALID_TARGET = "invalid_target"
    NO_APPLICABLE_KNOWLEDGE = "no_applicable_knowledge"
    MISSING_REQUIRED_CONTEXT = "missing_required_context"
    RETRIEVAL_UNAVAILABLE = "retrieval_unavailable"
    UNAUTHORIZED_SCOPE = "unauthorized_scope"


def _normalise_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def _normalise_unique(values: Any) -> Any:
    if not isinstance(values, (list, tuple)) or not all(isinstance(value, str) for value in values):
        return values
    return tuple(sorted({_normalise_text(value) for value in values}))


def _normalise_outcomes(values: Any) -> Any:
    if not isinstance(values, (list, tuple)):
        return values
    normalised: list[tuple[str, str]] = []
    for value in values:
        if (
            not isinstance(value, (list, tuple))
            or len(value) != 2
            or not all(isinstance(part, str) for part in value)
        ):
            return values
        normalised.append((_normalise_text(value[0]), _normalise_text(value[1])))
    return tuple(sorted(set(normalised)))


def _valid_host(value: str) -> bool:
    if _NUMERIC_DOTTED.fullmatch(value):
        try:
            return ipaddress.ip_address(value).version == 4
        except ValueError:
            return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return _HOSTNAME.fullmatch(value) is not None
    return True


def _target_url(value: str) -> tuple[str | None, str | None]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None, "invalid_url"
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        return None, "invalid_url"
    if parsed.username is not None or parsed.password is not None or parsed.hostname is None:
        return None, "invalid_url"
    host = parsed.hostname.casefold()
    if not _valid_host(host):
        return None, "invalid_url"
    rendered_host = f"[{host}]" if ":" in host else host
    netloc = rendered_host if port is None else f"{rendered_host}:{port}"
    normalized = urlunsplit(
        SplitResult(parsed.scheme.casefold(), netloc, parsed.path or "", parsed.query, "")
    )
    if sanitize_searchable_text(normalized, (normalized,)) != normalized:
        return None, "invalid_url"
    return normalized, None


def _looks_structured_target(value: str) -> bool:
    """Catch malformed address/URL syntax before it can become an opaque generic ID."""
    return bool(
        _NUMERIC_DOTTED.fullmatch(value)
        or _IPV6ISH.fullmatch(value)
        or value.startswith("[")
        or _EXPLICIT_URL_SCHEME.match(value) is not None
        or _MALFORMED_HTTP_PREFIX.match(value) is not None
        or _HOST_PORT.fullmatch(value)
        or _looks_ipv6_like(value)
    )


def _looks_ipv6_like(value: str) -> bool:
    """Recognize malformed IPv6 shapes without claiming arbitrary namespaces."""
    if "::" in value:
        return True
    components = value.split(":")
    if len(components) == 8:
        return True
    if len(components) < 3:
        return False
    if _IPV6_COMPONENT.fullmatch(components[0]):
        return True
    return bool(
        all(component and len(component) <= 4 for component in components)
        and (
            any(_IPV6_COMPONENT.fullmatch(component) for component in components)
            or any(character in "0123456789" for component in components for character in component)
        )
    )


class ValidatedTarget(BaseModel):
    """A typed target parse, preserving invalid input as a non-backend result."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    value: str = Field(min_length=1, max_length=2048)
    kind: TargetKind | None = None
    normalized: ScopeValue | None = None
    error: str | None = None

    @model_validator(mode="before")
    @classmethod
    def parse_target(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        raw = payload.get("value")
        if not isinstance(raw, str):
            return payload
        supplied_kind = TargetKind(payload["kind"]) if payload.get("kind") is not None else None
        if not raw or raw != raw.strip():
            payload.update(kind=TargetKind.INVALID, normalized=None, error="invalid_target")
            return payload
        payload["value"] = raw

        inferred_kind, normalized, error = cls._infer(raw)
        if supplied_kind is TargetKind.INVALID:
            payload.update(
                kind=TargetKind.INVALID, normalized=None, error=payload.get("error") or error
            )
            return payload
        if supplied_kind is TargetKind.GENERIC:
            if inferred_kind is not TargetKind.INVALID or _looks_structured_target(raw):
                payload.update(
                    kind=TargetKind.INVALID, normalized=None, error=error or "invalid_target"
                )
                return payload
            normalized = _normalise_text(raw)
            if not normalized or sanitize_searchable_text(normalized, (normalized,)) != normalized:
                payload.update(kind=TargetKind.INVALID, normalized=None, error="invalid_target")
                return payload
            payload.update(kind=TargetKind.GENERIC, normalized=normalized, error=None)
            return payload
        if supplied_kind is not None and supplied_kind is not inferred_kind:
            raise ValueError("target kind does not match its syntactic identifier")
        payload.update(kind=inferred_kind, normalized=normalized, error=error)
        return payload

    @staticmethod
    def _infer(value: str) -> tuple[TargetKind, str | None, str | None]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            return (
                (TargetKind.IPV4 if address.version == 4 else TargetKind.IPV6),
                str(address),
                None,
            )
        if _NUMERIC_DOTTED.fullmatch(value):
            return TargetKind.INVALID, None, "invalid_ipv4"
        if _EXPLICIT_URL_SCHEME.match(value) is not None:
            normalized, error = _target_url(value)
            return (
                (TargetKind.URL, normalized, None)
                if error is None
                else (TargetKind.INVALID, None, error)
            )
        if (
            _IPV6ISH.fullmatch(value)
            or value.startswith("[")
            or _MALFORMED_HTTP_PREFIX.match(value) is not None
            or _HOST_PORT.fullmatch(value)
            or _looks_ipv6_like(value)
        ):
            return TargetKind.INVALID, None, "invalid_target"
        if _HOSTNAME.fullmatch(value) is not None:
            return TargetKind.HOSTNAME, value.casefold(), None
        return TargetKind.INVALID, None, "invalid_target"

    @property
    def is_valid(self) -> bool:
        return self.kind is not TargetKind.INVALID

    @classmethod
    def parse(cls, value: str) -> ValidatedTarget:
        return cls(value=value)


class AuthorizationScope(BaseModel):
    """Typed authorization evidence; free-form scope text is deliberately not accepted."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    state: AuthorizationState
    exact_targets: tuple[ValidatedTarget, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    cidrs: tuple[ScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    hostnames: tuple[ScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    url_origins: tuple[ScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    generic_ids: tuple[ScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)

    @model_validator(mode="before")
    @classmethod
    def normalise_scope(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("cidrs", "hostnames", "url_origins", "generic_ids"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        return payload

    @model_validator(mode="after")
    def validate_scope(self) -> AuthorizationScope:
        targets = tuple(
            sorted(self.exact_targets, key=lambda target: target.normalized or target.value)
        )
        if any(not target.is_valid for target in targets):
            raise ValueError("authorization exact targets must be valid")
        if len({target.normalized for target in targets}) != len(targets):
            raise ValueError("authorization exact targets must be unique")
        networks: list[str] = []
        for value in self.cidrs:
            try:
                networks.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise ValueError("authorization CIDRs must be valid networks") from exc
        hosts: list[str] = []
        for value in self.hostnames:
            if _NUMERIC_DOTTED.fullmatch(value) or _HOSTNAME.fullmatch(value) is None:
                raise ValueError("authorization hostnames must be valid hostnames")
            hosts.append(value)
        origins: list[str] = []
        for value in self.url_origins:
            target = ValidatedTarget.parse(value)
            if target.kind is not TargetKind.URL or target.normalized is None:
                raise ValueError("authorization URL origins must be valid HTTP(S) origins")
            parsed = urlsplit(target.normalized)
            if parsed.path not in {"", "/"} or parsed.query:
                raise ValueError("authorization URL origins cannot contain a path or query")
            origins.append(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
        generic_ids: list[str] = []
        for value in self.generic_ids:
            target = ValidatedTarget(value=value, kind=TargetKind.GENERIC)
            if not target.is_valid or target.normalized is None:
                raise ValueError("authorization generic IDs must be explicit generic targets")
            generic_ids.append(target.normalized)
        object.__setattr__(self, "exact_targets", targets)
        object.__setattr__(self, "cidrs", tuple(sorted(set(networks))))
        object.__setattr__(self, "hostnames", tuple(sorted(set(hosts))))
        object.__setattr__(self, "url_origins", tuple(sorted(set(origins))))
        object.__setattr__(self, "generic_ids", tuple(sorted(set(generic_ids))))
        if self.state is AuthorizationState.AUTHORIZED and not any(
            (targets, networks, hosts, origins, generic_ids)
        ):
            raise ValueError("authorized scope requires at least one typed target constraint")
        if _authorization_text_size(self) > _MAX_AUTHORIZATION_TEXT:
            raise ValueError("authorization scope text exceeds the cumulative bound")
        return self

    def authorizes(self, target: ValidatedTarget) -> bool:
        """Return deterministic authorization membership for one valid target."""
        if self.state is not AuthorizationState.AUTHORIZED or not target.is_valid:
            return False
        if target.normalized in {item.normalized for item in self.exact_targets}:
            return True
        address = _target_ip_address(target)
        if address is not None:
            if any(
                item.kind in {TargetKind.IPV4, TargetKind.IPV6} and item.normalized == str(address)
                for item in self.exact_targets
            ):
                return True
            if any(address in ipaddress.ip_network(network) for network in self.cidrs):
                return True
        if target.kind is TargetKind.HOSTNAME and target.normalized in self.hostnames:
            return True
        if target.kind is TargetKind.URL and target.normalized is not None:
            parsed = urlsplit(target.normalized)
            origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            if origin in self.url_origins or parsed.hostname in self.hostnames:
                return True
        return target.kind is TargetKind.GENERIC and target.normalized in self.generic_ids


class SituationFacet(BaseModel):
    """A live observation. Unlike canonical context, it has no source references."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    namespace: FacetNamespace
    key: FacetKey
    value: FacetValue
    confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="before")
    @classmethod
    def normalise_facet(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("namespace", "key", "value"):
            if isinstance(payload.get(name), str):
                payload[name] = _normalise_text(payload[name])
        return payload


class CurrentSituation(BaseModel):
    """Bounded, deterministic live context and a typed authorization decision."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    target: ValidatedTarget
    authorization: AuthorizationScope = Field(
        default_factory=lambda: AuthorizationScope(state=AuthorizationState.UNKNOWN)
    )
    terms: tuple[Term, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    facts: tuple[SituationFacet, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    access: tuple[Term, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    services: tuple[Term, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    hypotheses: tuple[Term, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    tried_outcomes: tuple[tuple[Term, Term], ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    unresolved_questions: tuple[Term, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)

    @model_validator(mode="before")
    @classmethod
    def normalise_situation(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("terms", "access", "services", "hypotheses", "unresolved_questions"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        if "tried_outcomes" in payload:
            payload["tried_outcomes"] = _normalise_outcomes(payload["tried_outcomes"])
        return payload

    @model_validator(mode="after")
    def validate_facts_and_authorization(self) -> CurrentSituation:
        facts: dict[tuple[str, str, str], SituationFacet] = {}
        for facet in self.facts:
            identity = (facet.namespace, facet.key, facet.value)
            if identity in facts and facts[identity] != facet:
                raise ValueError(
                    "situation facts with the same namespace, key, and value must be unique"
                )
            facts[identity] = facet
        object.__setattr__(self, "facts", tuple(facts[key] for key in sorted(facts)))
        if (
            self.target.is_valid
            and self.authorization.state is AuthorizationState.AUTHORIZED
            and not self.authorization.authorizes(self.target)
        ):
            raise ValueError("target is not within the authorized scope")
        if _situation_text_size(self) > _MAX_QUERY_TEXT:
            raise ValueError("current situation text exceeds the cumulative bound")
        return self


class RetrievalQuery(BaseModel):
    """A bounded query plan. Invalid/unauthorized situations must stop before a backend call."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    situation: CurrentSituation
    terms: tuple[Term, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    synonyms: tuple[Term, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    facets: tuple[SituationFacet, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    max_candidates: int = Field(default=32, ge=1, le=100)
    lane_limit: int = Field(default=5, ge=1, le=20)

    @model_validator(mode="before")
    @classmethod
    def normalise_query(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("terms", "synonyms"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        return payload

    @model_validator(mode="after")
    def validate_query(self) -> RetrievalQuery:
        facets = {(facet.namespace, facet.key, facet.value): facet for facet in self.facets}
        if len(facets) != len(self.facets):
            raise ValueError("query facets must be unique")
        object.__setattr__(self, "facets", tuple(facets[key] for key in sorted(facets)))
        if (
            sum(map(len, (*self.terms, *self.synonyms))) + _facet_text_size(self.facets)
            > _MAX_QUERY_TEXT
        ):
            raise ValueError("retrieval query text exceeds the cumulative bound")
        return self


class ScoreComponents(BaseModel):
    """Finite, bounded, explainable query-local score dimensions."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    lexical_relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    facet_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    context_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    verification_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness: float = Field(default=0.0, ge=0.0, le=1.0)
    source_diversity: float = Field(default=0.0, ge=0.0, le=1.0)
    unknown_condition_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    total: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def require_finite_components(self) -> ScoreComponents:
        if any(not math.isfinite(value) for value in self.model_dump().values()):
            raise ValueError("score components must be finite")
        return self


IndexedArtifact = Annotated[
    ReferenceArtifact | KnowledgeCase | CaseStep | DecisionRule,
    Field(discriminator="artifact_type"),
]
HitArtifact = Annotated[
    ReferenceArtifact | CaseStep | DecisionRule,
    Field(discriminator="artifact_type"),
]
RetrievableArtifact = IndexedArtifact


def _artifact_id(artifact: IndexedArtifact) -> str:
    if isinstance(artifact, ReferenceArtifact):
        return artifact.artifact_id
    if isinstance(artifact, KnowledgeCase):
        return artifact.case_id
    if isinstance(artifact, CaseStep):
        return artifact.step_id
    return artifact.rule_id


def _deep_revalidate_artifact(artifact: IndexedArtifact) -> IndexedArtifact:
    """Defend contract boundaries against `model_copy` and constructed-value bypasses."""
    return type(artifact).model_validate(artifact.model_dump(mode="json"))


def _deep_revalidate_provenance(provenance: tuple[SourceRef, ...]) -> tuple[SourceRef, ...]:
    return tuple(SourceRef.model_validate(source.model_dump(mode="json")) for source in provenance)


def _artifact_lane(artifact: IndexedArtifact) -> EpistemicLane | None:
    if isinstance(artifact, KnowledgeCase):
        return None
    if isinstance(artifact, DecisionRule):
        return EpistemicLane.GUIDANCE
    if isinstance(artifact, CaseStep):
        if (
            artifact.knowledge_role is KnowledgeRole.NEGATIVE_CASE
            or artifact.assessment.observed_outcome is ObservedOutcome.FAILURE
        ):
            return EpistemicLane.NEGATIVE_EVIDENCE
        return EpistemicLane.CASE_STEP
    if artifact.artifact_type in {
        ArtifactType.NEGATIVE_EVIDENCE,
        ArtifactType.ANTI_PATTERN,
        ArtifactType.EXCEPTION,
    }:
        return EpistemicLane.NEGATIVE_EVIDENCE
    return EpistemicLane.REFERENCE


class IndexCandidate(BaseModel):
    """Backend output sufficient for ranking without leaking backend scoring semantics."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Reason
    artifact: IndexedArtifact
    lexical_relevance: float = Field(ge=0.0, le=1.0)
    matched_terms: tuple[Term, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    matched_fields: tuple[FacetKey, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    matched_evidence: tuple[Reason, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)

    @model_validator(mode="before")
    @classmethod
    def normalise_candidate(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("matched_terms", "matched_fields", "matched_evidence"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        return payload

    @model_validator(mode="after")
    def deeply_validate_candidate(self) -> IndexCandidate:
        if not math.isfinite(self.lexical_relevance):
            raise ValueError("lexical relevance must be finite")
        if _candidate_match_text_size(self) > _MAX_CANDIDATE_MATCH_TEXT:
            raise ValueError("candidate match text exceeds the cumulative bound")
        artifact = _deep_revalidate_artifact(self.artifact)
        if self.artifact_id != _artifact_id(artifact):
            raise ValueError("artifact_id must exactly match the canonical artifact identity")
        object.__setattr__(self, "artifact", artifact)
        return self


SearchCandidate: TypeAlias = IndexCandidate


class RetrievalHit(BaseModel):
    """A qualifying artifact, with deep canonical validation and one compatible lane."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Reason
    artifact: HitArtifact
    lane: EpistemicLane
    provenance: tuple[SourceRef, ...] = Field(min_length=1, max_length=_MAX_SITUATION_ITEMS)
    score: ScoreComponents
    matched_facets: tuple[SituationFacet, ...] = Field(default=(), max_length=_MAX_HIT_REASONS)
    qualification_reasons: tuple[Reason, ...] = Field(min_length=1, max_length=_MAX_HIT_REASONS)
    missing_context: tuple[Reason, ...] = Field(default=(), max_length=_MAX_HIT_REASONS)

    @model_validator(mode="before")
    @classmethod
    def normalise_explanation(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("qualification_reasons", "missing_context"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        return payload

    @model_validator(mode="after")
    def validate_hit(self) -> RetrievalHit:
        artifact = _deep_revalidate_artifact(self.artifact)
        if isinstance(artifact, KnowledgeCase):
            raise ValueError("parent knowledge cases are indexed metadata, never qualifying hits")
        provenance = _deep_revalidate_provenance(self.provenance)
        if self.artifact_id != _artifact_id(artifact):
            raise ValueError("artifact_id must exactly match the canonical artifact identity")
        if provenance != artifact.source_refs:
            raise ValueError("provenance must exactly match canonical artifact source_refs")
        expected_lane = _artifact_lane(artifact)
        if self.lane is not expected_lane:
            raise ValueError("artifact does not belong to the supplied epistemic lane")
        facets = {(facet.namespace, facet.key, facet.value): facet for facet in self.matched_facets}
        if len(facets) != len(self.matched_facets):
            raise ValueError("matched facets must be unique")
        object.__setattr__(self, "artifact", artifact)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "matched_facets", tuple(facets[key] for key in sorted(facets)))
        return self


class RejectedCandidate(BaseModel):
    """An excluded candidate with canonical provenance and its true prospective lane."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Reason
    artifact: IndexedArtifact
    lane: EpistemicLane | None
    provenance: tuple[SourceRef, ...] = Field(min_length=1, max_length=_MAX_SITUATION_ITEMS)
    rejection_reasons: tuple[Reason, ...] = Field(min_length=1, max_length=_MAX_HIT_REASONS)
    missing_context: tuple[Reason, ...] = Field(default=(), max_length=_MAX_HIT_REASONS)

    @model_validator(mode="before")
    @classmethod
    def normalise_explanation(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("rejection_reasons", "missing_context"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        return payload

    @model_validator(mode="after")
    def validate_rejection(self) -> RejectedCandidate:
        artifact = _deep_revalidate_artifact(self.artifact)
        provenance = _deep_revalidate_provenance(self.provenance)
        if self.artifact_id != _artifact_id(artifact):
            raise ValueError("artifact_id must exactly match the canonical artifact identity")
        if provenance != artifact.source_refs:
            raise ValueError("provenance must exactly match canonical artifact source_refs")
        if self.lane is not _artifact_lane(artifact):
            raise ValueError("rejected candidate lane must match the artifact epistemic lane")
        object.__setattr__(self, "artifact", artifact)
        object.__setattr__(self, "provenance", provenance)
        return self


class KnowledgeGap(BaseModel):
    """A typed absence of knowledge or a pre-backend input/scope stop."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    code: KnowledgeGapCode
    summary: Reason
    observed_domain: SearchableString | None = Field(default=None, max_length=2048)
    missing_context: tuple[Reason, ...] = Field(default=(), max_length=_MAX_GAP_ITEMS)
    suggested_document_ingestion: tuple[Reason, ...] = Field(default=(), max_length=_MAX_GAP_ITEMS)
    research_eligible: bool = False

    @model_validator(mode="before")
    @classmethod
    def normalise_gap(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        for name in ("missing_context", "suggested_document_ingestion"):
            if name in payload:
                payload[name] = _normalise_unique(payload[name])
        for name in ("summary", "observed_domain"):
            if isinstance(payload.get(name), str):
                payload[name] = _normalise_text(payload[name])
        return payload

    @model_validator(mode="after")
    def validate_unavailable_shape(self) -> KnowledgeGap:
        if self.code is KnowledgeGapCode.RETRIEVAL_UNAVAILABLE and (
            self.research_eligible or self.suggested_document_ingestion
        ):
            raise ValueError(
                "retrieval_unavailable cannot recommend research or document ingestion"
            )
        return self


class RetrievalResult(BaseModel):
    """Exclusive lane results ordered by rank, or exactly one pre-backend/knowledge gap."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    target: ValidatedTarget
    authorization: AuthorizationScope = Field(
        default_factory=lambda: AuthorizationScope(state=AuthorizationState.UNKNOWN)
    )
    references: tuple[RetrievalHit, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    case_steps: tuple[RetrievalHit, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    negative_cases: tuple[RetrievalHit, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    decision_guidance: tuple[RetrievalHit, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    rejected_candidates: tuple[RejectedCandidate, ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    knowledge_gap: KnowledgeGap | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> RetrievalResult:
        lanes = (
            (EpistemicLane.REFERENCE, self.references),
            (EpistemicLane.CASE_STEP, self.case_steps),
            (EpistemicLane.NEGATIVE_EVIDENCE, self.negative_cases),
            (EpistemicLane.GUIDANCE, self.decision_guidance),
        )
        for lane, hits in lanes:
            if any(hit.lane is not lane for hit in hits):
                raise ValueError(f"{lane.value} result lane contains a different hit lane")
            expected = tuple(sorted(hits, key=lambda hit: (-hit.score.total, hit.artifact_id)))
            if hits != expected:
                raise ValueError(
                    "lane hits must be ordered by descending total score then artifact_id"
                )
        hits = tuple(hit for _, lane_hits in lanes for hit in lane_hits)
        hit_ids = {hit.artifact_id for hit in hits}
        rejected_ids = {candidate.artifact_id for candidate in self.rejected_candidates}
        if len(hit_ids) != len(hits):
            raise ValueError("an artifact may occur in only one qualifying hit lane")
        if len(rejected_ids) != len(self.rejected_candidates):
            raise ValueError("rejected candidates must have unique artifact identities")
        if hit_ids & rejected_ids:
            raise ValueError("an artifact cannot be both a hit and a rejected candidate")
        if self.rejected_candidates != tuple(
            sorted(self.rejected_candidates, key=lambda candidate: candidate.artifact_id)
        ):
            raise ValueError("rejected candidates must be ordered by artifact_id")

        prebackend_stop = (
            not self.target.is_valid
            or self.authorization.state is not AuthorizationState.AUTHORIZED
        )
        if prebackend_stop:
            expected_code = (
                KnowledgeGapCode.INVALID_TARGET
                if not self.target.is_valid
                else KnowledgeGapCode.UNAUTHORIZED_SCOPE
            )
            if hits or self.rejected_candidates:
                raise ValueError("pre-backend results cannot contain candidates")
            if self.knowledge_gap is None or self.knowledge_gap.code is not expected_code:
                raise ValueError("pre-backend results require the matching knowledge gap")
        elif not self.authorization.authorizes(self.target):
            raise ValueError(
                "authorized retrieval result target must be within the authorization scope"
            )
        elif self.knowledge_gap is not None:
            if hits:
                raise ValueError("knowledge gap results cannot also contain qualifying lane hits")
            if self.knowledge_gap.code in {
                KnowledgeGapCode.INVALID_TARGET,
                KnowledgeGapCode.UNAUTHORIZED_SCOPE,
            }:
                raise ValueError("pre-backend knowledge gap does not match an authorized target")
            if (
                self.knowledge_gap.code is KnowledgeGapCode.RETRIEVAL_UNAVAILABLE
                and self.rejected_candidates
            ):
                raise ValueError(
                    "retrieval_unavailable results cannot retain untrusted partial candidates"
                )
        elif not hits:
            raise ValueError("valid authorized results without lane hits require a knowledge gap")
        return self

    @property
    def is_invalid_target(self) -> bool:
        return not self.target.is_valid


class IndexAudit(BaseModel):
    """Derived index health; corruption/parity problems always require a rebuild."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_count: int = Field(default=0, ge=0)
    source_count: int = Field(default=0, ge=0)
    facet_count: int = Field(default=0, ge=0)
    fts_count: int = Field(default=0, ge=0)
    orphan_count: int = Field(default=0, ge=0)
    duplicate_id_count: int = Field(default=0, ge=0)
    corruption_count: int = Field(default=0, ge=0)
    issues: tuple[Reason, ...] = Field(default=(), max_length=_MAX_GAP_ITEMS)
    rebuild_required: bool = False

    @model_validator(mode="before")
    @classmethod
    def normalise_issues(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        if "issues" in payload:
            payload["issues"] = _normalise_unique(payload["issues"])
        return payload

    @model_validator(mode="after")
    def derive_rebuild_requirement(self) -> IndexAudit:
        issues = set(self.issues)
        if self.orphan_count:
            issues.add("orphan_rows")
        if self.duplicate_id_count:
            issues.add("duplicate_artifact_ids")
        if self.fts_count != self.artifact_count:
            issues.add("fts_count_mismatch")
        if self.corruption_count:
            issues.add("canonical_corruption")
        normalized = tuple(sorted(issues))
        object.__setattr__(self, "issues", normalized)
        object.__setattr__(self, "rebuild_required", bool(normalized))
        return self


class IndexedArtifactState(BaseModel):
    """Actual and persisted projection identity of one indexed artifact row."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]
    projection_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    asserted_projection_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class IndexedExecutionExampleState(BaseModel):
    """Backend-neutral identity of one indexed execution-example lookup row."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    example_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]
    parent_artifact_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]


class IndexedSourceState(BaseModel):
    """Bounded, backend-neutral identity of one complete source projection."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_id: Annotated[SearchableNonEmptyString, Field(max_length=512)]
    source_sha256: Sha256
    artifact_count: int = Field(ge=0, le=10_000_000)
    projection_version: Annotated[SearchableNonEmptyString, Field(max_length=128)]
    projection_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    asserted_artifact_count: int = Field(ge=0, le=10_000_000)
    asserted_projection_version: Annotated[SearchableNonEmptyString, Field(max_length=128)]
    asserted_projection_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    semantic_schema_version: Annotated[SearchableNonEmptyString, Field(max_length=128)] = (
        SEMANTIC_SCHEMA_VERSION
    )
    execution_example_schema_version: Annotated[
        SearchableNonEmptyString | None, Field(max_length=128)
    ] = None
    execution_examples: tuple[IndexedExecutionExampleState, ...] = Field(
        default=(), max_length=_MAX_SOURCE_ARTIFACTS
    )
    artifacts: tuple[IndexedArtifactState, ...] = Field(
        default=(), max_length=_MAX_SOURCE_ARTIFACTS
    )

    @field_validator("source_id")
    @classmethod
    def require_safe_source_id(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
            raise ValueError("indexed source_id must be a safe path segment")
        return value

    @model_validator(mode="after")
    def validate_artifact_identity(self) -> IndexedSourceState:
        if self.artifacts != tuple(sorted(self.artifacts, key=lambda item: item.artifact_id)):
            raise ValueError("indexed artifact states must be sorted by artifact_id")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("indexed artifact states must have unique artifact IDs")
        if self.artifact_count != len(self.artifacts):
            raise ValueError("indexed artifact count must match its exact artifact states")
        if self.execution_examples != tuple(
            sorted(self.execution_examples, key=lambda item: item.example_id)
        ):
            raise ValueError("indexed execution example states must be sorted by example_id")
        if len({item.example_id for item in self.execution_examples}) != len(
            self.execution_examples
        ):
            raise ValueError("indexed execution example states must have unique example IDs")
        if self.projection_digest != source_projection_digest(
            self.source_id,
            self.source_sha256,
            self.projection_version,
            self.artifacts,
            execution_examples=self.execution_examples,
            semantic_schema_version=self.semantic_schema_version,
            execution_example_schema_version=self.execution_example_schema_version,
        ):
            raise ValueError("indexed source projection digest must match its artifact states")
        return self

    @classmethod
    def from_artifacts(
        cls,
        *,
        source_id: str,
        source_sha256: str,
        projection_version: str,
        artifacts: tuple[IndexedArtifactState, ...],
        asserted_artifact_count: int | None = None,
        asserted_projection_version: str | None = None,
        asserted_projection_digest: str | None = None,
        execution_examples: tuple[IndexedExecutionExampleState, ...] = (),
        semantic_schema_version: str = SEMANTIC_SCHEMA_VERSION,
        execution_example_schema_version: str | None = None,
    ) -> IndexedSourceState:
        ordered = tuple(sorted(artifacts, key=lambda item: item.artifact_id))
        actual_digest = source_projection_digest(
            source_id,
            source_sha256,
            projection_version,
            ordered,
            execution_examples=execution_examples,
            semantic_schema_version=semantic_schema_version,
            execution_example_schema_version=execution_example_schema_version,
        )
        return cls(
            source_id=source_id,
            source_sha256=source_sha256,
            artifact_count=len(ordered),
            projection_version=projection_version,
            projection_digest=actual_digest,
            asserted_artifact_count=(
                len(ordered) if asserted_artifact_count is None else asserted_artifact_count
            ),
            asserted_projection_version=(
                projection_version
                if asserted_projection_version is None
                else asserted_projection_version
            ),
            asserted_projection_digest=(
                actual_digest if asserted_projection_digest is None else asserted_projection_digest
            ),
            semantic_schema_version=semantic_schema_version,
            execution_example_schema_version=execution_example_schema_version,
            execution_examples=execution_examples,
            artifacts=ordered,
        )


class IndexStateSnapshot(BaseModel):
    """One generation-bound audit and exact source/artifact identity snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    generation: int = Field(ge=0)
    audit: IndexAudit
    source_states: tuple[IndexedSourceState, ...] = Field(default=(), max_length=_MAX_INDEX_SOURCES)
    unowned_artifact_ids: tuple[Reason, ...] = Field(default=(), max_length=_MAX_SOURCE_ARTIFACTS)

    @model_validator(mode="after")
    def validate_complete_identity_snapshot(self) -> IndexStateSnapshot:
        if self.source_states != tuple(
            sorted(self.source_states, key=lambda state: state.source_id)
        ):
            raise ValueError("indexed source states must be sorted by source_id")
        if len({state.source_id for state in self.source_states}) != len(self.source_states):
            raise ValueError("indexed source states must have unique source IDs")
        if self.unowned_artifact_ids != tuple(sorted(self.unowned_artifact_ids)) or len(
            set(self.unowned_artifact_ids)
        ) != len(self.unowned_artifact_ids):
            raise ValueError("unowned artifact IDs must be sorted and unique")
        owned_ids = tuple(
            artifact.artifact_id for state in self.source_states for artifact in state.artifacts
        )
        all_ids = (*owned_ids, *self.unowned_artifact_ids)
        if len(all_ids) > _MAX_INDEX_ARTIFACTS:
            raise ValueError("index snapshot exceeds the cumulative artifact bound")
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("index snapshot artifact IDs must be globally unique")
        if self.audit.source_count != len(self.source_states):
            raise ValueError("index audit source count must match its exact source states")
        if self.audit.artifact_count != len(all_ids):
            raise ValueError("index audit artifact count must match its exact artifact states")
        return self


def source_projection_digest(
    source_id: str,
    source_sha256: str,
    projection_version: str,
    artifacts: Iterable[IndexedArtifactState],
    *,
    execution_examples: Iterable[IndexedExecutionExampleState] = (),
    semantic_schema_version: str = SEMANTIC_SCHEMA_VERSION,
    execution_example_schema_version: str | None = None,
) -> str:
    """Compute the backend-neutral aggregate digest for exact artifact projections."""
    payload = json.dumps(
        {
            "source_id": source_id,
            "source_sha256": source_sha256,
            "projection_version": projection_version,
            "semantic_schema_version": semantic_schema_version,
            "execution_example_schema_version": execution_example_schema_version,
            "execution_examples": [
                {
                    "example_id": example.example_id,
                    "parent_artifact_id": example.parent_artifact_id,
                }
                for example in sorted(execution_examples, key=lambda item: item.example_id)
            ],
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "projection_digest": artifact.projection_digest,
                }
                for artifact in artifacts
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _facet_text_size(facets: Iterable[SituationFacet]) -> int:
    return sum(
        len(value) for facet in facets for value in (facet.namespace, facet.key, facet.value)
    )


def _situation_text_size(situation: CurrentSituation) -> int:
    text = (*situation.terms, *situation.access, *situation.services, *situation.hypotheses)
    text += tuple(part for outcome in situation.tried_outcomes for part in outcome)
    text += situation.unresolved_questions
    return (
        sum(map(len, text))
        + _facet_text_size(situation.facts)
        + _authorization_text_size(situation.authorization)
    )


def _authorization_text_size(scope: AuthorizationScope) -> int:
    values = (
        *(target.value for target in scope.exact_targets),
        *scope.cidrs,
        *scope.hostnames,
        *scope.url_origins,
        *scope.generic_ids,
    )
    return sum(map(len, values))


def _candidate_match_text_size(candidate: IndexCandidate) -> int:
    return sum(
        map(
            len,
            (*candidate.matched_terms, *candidate.matched_fields, *candidate.matched_evidence),
        )
    )


def _target_ip_address(
    target: ValidatedTarget,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if target.normalized is None:
        return None
    if target.kind in {TargetKind.IPV4, TargetKind.IPV6}:
        return ipaddress.ip_address(target.normalized)
    if target.kind is TargetKind.URL:
        host = urlsplit(target.normalized).hostname
        if host is not None:
            try:
                return ipaddress.ip_address(host)
            except ValueError:
                return None
    return None


class ExecutionExampleLocator(BaseModel):
    """ID-only lookup identity for one bundle-owned execution example."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    example_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]
    parent_artifact_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]
    source_id: Annotated[SearchableNonEmptyString, Field(max_length=512)]


class ExecutionExampleCoverageCode(StrEnum):
    LEGACY_BUNDLE_WITHOUT_EXAMPLES = "legacy_bundle_without_examples"
    SOURCE_EXAMPLES_UNAVAILABLE = "source_examples_unavailable"


class ExecutionExampleCoverageGap(BaseModel):
    """A typed coverage gap when no example drill-down is possible."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    code: ExecutionExampleCoverageCode
    source_id: Annotated[SearchableNonEmptyString, Field(max_length=512)]
    semantic_schema_version: Annotated[SearchableNonEmptyString, Field(max_length=128)]
    explanation: Annotated[SearchableNonEmptyString, Field(max_length=2048)]


class ExecutionExampleDrilldown(BaseModel):
    """One parent's bundle-owned examples or an exact typed coverage gap."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    parent_artifact_id: Annotated[SearchableNonEmptyString, Field(max_length=2048)]
    examples: tuple[ExecutionExample, ...] = ()
    coverage_gap: ExecutionExampleCoverageGap | None = None

    @model_validator(mode="after")
    def validate_exclusive(self) -> ExecutionExampleDrilldown:
        if self.examples and self.coverage_gap is not None:
            raise ValueError("examples and coverage gap are mutually exclusive")
        return self


@runtime_checkable
class RetrievalIndex(Protocol):
    """Backend-neutral protocol for disposable projections of canonical bundles."""

    def mark_unavailable(self) -> None: ...

    def mark_rebuild_required(self) -> None: ...

    def upsert_bundle(self, bundle: SemanticKnowledgeBundle) -> None: ...

    def delete_source(self, source_id: str) -> None: ...

    def rebuild(
        self,
        bundles: Iterable[SemanticKnowledgeBundle],
        *,
        precommit_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> IndexAudit: ...

    def get_artifact(self, artifact_id: str) -> IndexedArtifact | None: ...

    def get_execution_example_locators(
        self, parent_artifact_id: str
    ) -> tuple[ExecutionExampleLocator, ...]: ...

    def get_source_capability(self, source_id: str) -> str | None: ...

    def list_source_states(
        self,
        *,
        after_source_id: str | None,
        limit: int,
    ) -> tuple[IndexedSourceState, ...]: ...

    def snapshot_state(self) -> IndexStateSnapshot: ...

    def search_candidates(
        self,
        query: RetrievalQuery,
        *,
        lane: EpistemicLane,
        limit: int,
    ) -> tuple[IndexCandidate, ...]: ...

    def audit(self) -> IndexAudit: ...

    def close(self) -> None: ...

    def __enter__(self) -> RetrievalIndex: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
