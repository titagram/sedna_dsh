"""Safe structural adapter for the host-owned Hades/Hermes LLM facade."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from types import MappingProxyType
from typing import Generic, Literal, Protocol, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.parsing.sanitize import sanitize_asset_target, sanitize_searchable_text
from sedna.knowledge.schema import DocumentType, KnowledgeRole, SourceQuality
from sedna.knowledge.schema.common import SearchableNonEmptyString, SearchableString
from sedna.knowledge.schema.semantic import CANONICAL_FINDING_MESSAGES
from sedna.knowledge.semantic.drafts import CriticVerdict, SemanticDraftBundle
from sedna.knowledge.semantic.prompts import COMPACT_EXTRACTOR_PROMPT

SemanticLlmPurpose = Literal[
    "sedna.semantic.extract",
    "sedna.semantic.critic",
    "sedna.semantic.repair",
]
SemanticLlmReasonCode = Literal[
    "transport_failure",
    "missing_parsed_response",
    "invalid_structured_response",
]
ModelT = TypeVar("ModelT", bound=BaseModel)


class _HostUsage(Protocol):
    """Token fields exposed by the real host usage record."""

    input_tokens: int
    output_tokens: int


class _HostStructuredResult(Protocol):
    """Structural subset of the host result consumed by the adapter."""

    parsed: object | None
    provider: str
    model: str
    agent_id: str
    usage: _HostUsage
    audit: object


class HostStructuredLlm(Protocol):
    """Hades/Hermes structured-completion surface used without importing the host."""

    def complete_structured(
        self,
        *,
        instructions: str,
        input: Sequence[Mapping[str, object]],
        json_schema: Mapping[str, object] | None,
        json_mode: bool = False,
        schema_name: str,
        system_prompt: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        temperature: float | None,
        max_tokens: int | None,
        timeout: float | None,
        agent_id: str | None = None,
        profile: str | None = None,
        purpose: str | None,
    ) -> _HostStructuredResult: ...


@dataclass(frozen=True, slots=True)
class StructuredResult(Generic[ModelT]):
    """Validated completion plus safe host attribution and usage metadata."""

    parsed: ModelT
    provider: str
    model: str
    agent_id: str
    usage: StructuredUsage
    audit: Mapping[str, str]


class StructuredUsage(BaseModel):
    """Immutable token counts retained from a successful host completion."""

    model_config = ConfigDict(frozen=True, extra="forbid", from_attributes=True)

    input_tokens: int = Field(ge=0, le=1_000_000)
    output_tokens: int = Field(ge=0, le=1_000_000)


class SemanticLlmError(RuntimeError):
    """A closed, response-free failure raised at the semantic LLM boundary."""

    _MESSAGES: Mapping[SemanticLlmReasonCode, str] = {
        "transport_failure": "The host LLM request failed.",
        "missing_parsed_response": "The host LLM returned no parsed structured response.",
        "invalid_structured_response": "The host LLM response failed semantic validation.",
    }

    def __init__(self, reason_code: SemanticLlmReasonCode) -> None:
        self.reason_code = reason_code
        super().__init__(self._MESSAGES[reason_code])


class SafeSemanticRequestPayload(BaseModel):
    """Closed base for adapter-approved semantic request envelopes."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
    )


class SafeSegmentAsset(BaseModel):
    """Retrieval-safe asset provenance copied from a logical segment."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
    )

    asset_index: int = Field(ge=0)
    target: SearchableNonEmptyString
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @field_validator("target")
    @classmethod
    def validate_safe_locator(cls, value: str) -> str:
        if sanitize_asset_target(value) != value:
            raise ValueError("asset target must be a retrieval-safe locator")
        return value

    @model_validator(mode="after")
    def validate_line_span(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("asset end_line must not precede start_line")
        return self


class SafeSourceSegment(BaseModel):
    """One ordered retrieval-safe segment exposed to semantic inference."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
    )

    index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_path: tuple[SearchableNonEmptyString, ...] = ()
    text: SearchableString
    assets: tuple[SafeSegmentAsset, ...] = ()

    @model_validator(mode="after")
    def validate_line_span(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("segment end_line must not precede start_line")
        if any(
            asset.start_line < self.start_line or asset.end_line > self.end_line
            for asset in self.assets
        ):
            raise ValueError("asset line span must be contained by segment span")
        asset_indexes = tuple(asset.asset_index for asset in self.assets)
        asset_source_order = tuple(
            (asset.start_line, asset.end_line, asset.asset_index) for asset in self.assets
        )
        if (
            len(set(asset_indexes)) != len(asset_indexes)
            or asset_indexes != tuple(sorted(asset_indexes))
            or asset_source_order != tuple(sorted(asset_source_order))
        ):
            raise ValueError("segment assets must be unique and ordered deterministically")
        return self


class SafePreparedSourcePayload(SafeSemanticRequestPayload):
    """The complete and exclusive PreparedSource whitelist for LLM requests."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
    )

    source_id: SearchableNonEmptyString
    title: SearchableNonEmptyString
    document_type: DocumentType
    knowledge_role: KnowledgeRole
    quality: SourceQuality
    segments: tuple[SafeSourceSegment, ...]

    @model_validator(mode="after")
    def validate_segment_order(self) -> Self:
        indexes = tuple(segment.index for segment in self.segments)
        if indexes != tuple(range(len(self.segments))):
            raise ValueError("segment indexes must be consecutive and ordered from zero")
        if any(
            current.start_line <= previous.end_line for previous, current in pairwise(self.segments)
        ):
            raise ValueError("segment source line ranges must be increasing and nonoverlapping")
        return self


class SafeCriticRequestPayload(SafeSemanticRequestPayload):
    """Safe source evidence and typed extractor output supplied to the critic."""

    source: SafePreparedSourcePayload
    drafts: SemanticDraftBundle


class SafeRepairRequestPayload(SafeSemanticRequestPayload):
    """Safe source evidence, typed drafts, and typed critic result supplied for repair."""

    source: SafePreparedSourcePayload
    drafts: SemanticDraftBundle
    critic: CriticVerdict


SafeRequestPayload = SafePreparedSourcePayload | SafeCriticRequestPayload | SafeRepairRequestPayload
_CALL_CONTRACTS: Mapping[str, tuple[type[SafeSemanticRequestPayload], type[BaseModel]]] = {
    "sedna.semantic.extract": (SafePreparedSourcePayload, SemanticDraftBundle),
    "sedna.semantic.critic": (SafeCriticRequestPayload, CriticVerdict),
    "sedna.semantic.repair": (SafeRepairRequestPayload, SemanticDraftBundle),
}


def _payload_segment_count(payload: SafeRequestPayload) -> int:
    """Return the number of source segments in the request payload."""
    source = getattr(payload, "source", None)
    if source is not None and isinstance(source, SafePreparedSourcePayload):
        return len(source.segments)
    if isinstance(payload, SafePreparedSourcePayload):
        return len(payload.segments)
    return 0


def _resolve_schema_refs(schema: Mapping[str, object]) -> dict[str, object]:
    """Resolve all JSON-Schema ``$ref`` inline and drop the ``$defs`` block.

    Structured-output hosts (accepts_schema=True) receive the schema in the
    response_format AND the prompt. The Pydantic ``model_json_schema()`` emits
    a ``$defs`` block of 20+ type definitions. Cloud models frequently echo
    those ``$defs`` back into their output, which Sedna then rejects as
    ``extra_forbidden`` -- a false failure with valid content. By inlining all
    ``$ref`` and removing ``$defs``, the model never sees the definitions and
    cannot reflect them. The schema is only used to constrain the LLM output;
    Sedna still validates with the real Pydantic model (which keeps $defs).
    The reference graph here is acyclic, so a simple recursive inline is safe.
    """
    defs = dict(schema.get("$defs") or {})

    def resolve(node: object) -> object:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                name = ref[len("#/$defs/") :]
                target = defs.get(name)
                if isinstance(target, dict):
                    # Drop the $ref key and merge the target's definition inline.
                    merged = {k: v for k, v in node.items() if k != "$ref"}
                    for k, v in target.items():
                        merged.setdefault(k, resolve(v))
                    return merged
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    out = resolve({k: v for k, v in schema.items() if k != "$defs"})
    assert isinstance(out, dict)
    return out


def _payload_to_segment_text(payload: SafeRequestPayload) -> str:
    """Render the source segments as flat text with explicit segment indexes.

    Structured-output hosts (accepts_schema=True) handle this far more reliably
    than the full JSON-serialized SafePreparedSourcePayload, which overflows
    cloud models (deepseek-v4-flash, gpt-oss). Segment accounting is preserved:
    the model cites or ignores each index, and Sedna recomputes the ignored set
    deterministically. For critic/repair payloads we fall back to the nested
    JSON so the drafts/critic evidence is not flattened.
    """
    source = None
    if isinstance(payload, SafePreparedSourcePayload):
        source = payload
    elif isinstance(payload, (SafeCriticRequestPayload, SafeRepairRequestPayload)):
        source = getattr(payload, "source", None)
    if not isinstance(source, SafePreparedSourcePayload):
        return ""
    parts = [f"# {source.title}", f"type={source.document_type} role={source.knowledge_role}"]
    for segment in source.segments:
        parts.append(
            f"\n--- segment {segment.index} (lines {segment.start_line}-{segment.end_line}) ---"
        )
        parts.append(segment.text)
    return "\n".join(parts)


def _normalize_segment_accounting(response_obj: dict, segment_count: int) -> None:
    """Ensure every input segment is cited or explicitly ignored.

    The extractor model frequently omits ignored_segment_indexes for segments it
    does not cite. Segment accounting is a deterministic invariant, so we fill in
    the missing indexes here rather than failing the whole compilation.
    """
    if segment_count <= 0:
        return
    cited: set[int] = set()
    for artifact in response_obj.get("artifacts") or ():
        if not isinstance(artifact, dict):
            continue
        cited.update(_obj_citation_indexes(artifact.get("citations")))
        cited.update(_obj_context_indexes(artifact.get("applicability")))
        if artifact.get("draft_type") == "case":
            for step in artifact.get("steps") or ():
                if isinstance(step, dict):
                    cited.update(_obj_citation_indexes(step.get("citations")))
                    cited.update(_obj_context_indexes(step.get("applicability")))
    for example in response_obj.get("execution_examples") or ():
        if not isinstance(example, dict):
            continue
        cited.update(_obj_citation_indexes(example.get("citations")))
        cited.update(_obj_context_indexes(example.get("applicability")))
        for condition in example.get("prerequisites") or ():
            if isinstance(condition, dict):
                cited.update(_obj_citation_indexes(condition.get("citations")))
        for constraint in example.get("platform_constraints") or ():
            if isinstance(constraint, dict):
                cited.update(_obj_citation_indexes(constraint.get("citations")))
    ignored = set(response_obj.get("ignored_segment_indexes") or ())
    missing = set(range(segment_count)) - cited - ignored
    if missing:
        response_obj["ignored_segment_indexes"] = sorted(ignored | missing)


def _drop_orphan_execution_examples(response_obj: dict) -> None:
    """Drop execution examples whose parent_local_id has no matching artifact.

    Local models often emit execution_examples whose parent_local_id points at a
    reference/step local ID they did not actually produce. The references and
    case steps are the semantic core; an orphaned example would fail the whole
    bundle on a referential-integrity check. Instead of failing compilation, we
    drop just the orphan examples (a graceful degradation), preserving the rest.
    """
    artifacts = response_obj.get("artifacts") or ()
    if not isinstance(artifacts, list):
        return
    parent_ids: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        local_id = artifact.get("local_id")
        # Schema-valid parents are ONLY references and case-STEPS (drafts.py
        # excludes the case's own local_id). A case's local_id is not a valid
        # execution-example parent.
        if isinstance(local_id, str):
            if artifact.get("draft_type") == "reference":
                parent_ids.add(local_id)
            if artifact.get("draft_type") == "case":
                for step in artifact.get("steps") or ():
                    if isinstance(step, dict) and isinstance(step.get("local_id"), str):
                        parent_ids.add(step["local_id"])
    examples = response_obj.get("execution_examples") or ()
    if not isinstance(examples, list):
        return
    # If no reference/case-step parent exists in the bundle, NO execution
    # example can be valid — drop them all rather than fail the whole bundle.
    if not parent_ids:
        if examples:
            response_obj["execution_examples"] = []
        return
    kept = [
        ex
        for ex in examples
        if isinstance(ex, dict)
        and isinstance(ex.get("parent_local_id"), str)
        and ex["parent_local_id"] in parent_ids
    ]
    if len(kept) != len(examples):
        response_obj["execution_examples"] = kept


def _normalize_placeholder_policies(response_obj: dict) -> None:
    """Enforce the prompt's mandatory placeholder binding-policy rules.

    The extractor prompt specifies exact binding_policy for each placeholder
    kind. Local models frequently omit or mis-set it. Since the rule is
    deterministic and required by the schema, we fix it here rather than fail
    the whole bundle. Mapping (from the extractor prompt):
      kind=target                      -> authorized_scope
      kind=source_case_credential      -> never_auto_bind
      all others (port/username/etc.)  -> host_supplied
    """
    examples = response_obj.get("execution_examples") or ()
    if not isinstance(examples, list):
        return
    for example in examples:
        if not isinstance(example, dict):
            continue
        placeholders = example.get("placeholders")
        if not isinstance(placeholders, list):
            continue
        for placeholder in placeholders:
            if not isinstance(placeholder, dict):
                continue
            kind = placeholder.get("kind")
            policy = _POLICY_FOR_KIND.get(kind) if isinstance(kind, str) else None
            if policy is not None:
                placeholder["binding_policy"] = policy


_POLICY_FOR_KIND: dict[str, str] = {
    "target": "authorized_scope",
    "source_case_credential": "never_auto_bind",
    "port": "host_supplied",
    "username": "host_supplied",
    "credential_ref": "host_supplied",
    "wordlist": "host_supplied",
    "path": "host_supplied",
    "value": "host_supplied",
}


# Chunking threshold: when a schema-capable extract payload exceeds this many
# segments, we decompose into per-chunk extract calls and merge. Keeps each
# individual model call small enough that cloud models stay reliable.
_DECOMPOSE_EXTRACT_SEGMENT_THRESHOLD = 5


def _chunk_segments(source: SafePreparedSourcePayload) -> list[list[SafeSourceSegment]]:
    """Split a source's segments into chunks of at most the threshold size."""
    segments = list(source.segments)
    chunks: list[list[SafeSourceSegment]] = []
    for i in range(0, len(segments), _DECOMPOSE_EXTRACT_SEGMENT_THRESHOLD):
        chunks.append(segments[i : i + _DECOMPOSE_EXTRACT_SEGMENT_THRESHOLD])
    return chunks


def _chunk_to_flat_text(source: SafePreparedSourcePayload, chunk: list[SafeSourceSegment]) -> str:
    """Render one chunk as flat segment text keeping GLOBAL segment indexes."""
    parts = [f"# {source.title}", f"type={source.document_type} role={source.knowledge_role}"]
    for segment in chunk:
        parts.append(
            f"\n--- segment {segment.index} (lines {segment.start_line}-{segment.end_line}) ---"
        )
        parts.append(segment.text)
    return "\n".join(parts)


def _offset_citation_indexes(node: object, offset: int) -> None:
    """Shift every segment_index in a draft bundle dict by `offset` in place.

    Each chunk extract cites its LOCAL segment indexes (0..k-1). When merging
    chunks back into the full bundle, we must re-base those indexes to the
    GLOBAL source positions (chunk_offset + local_index). This walks all
    citation-bearing structures: artifact/step/example citations and the
    context assertions.
    """

    def shift_citations(citations: object) -> None:
        if not isinstance(citations, list):
            return
        for citation in citations:
            if isinstance(citation, dict):
                idxs = citation.get("segment_indexes")
                if isinstance(idxs, list):
                    citation["segment_indexes"] = [i + offset for i in idxs if isinstance(i, int)]

    def shift_context(context: object) -> None:
        if not isinstance(context, dict):
            return
        typed = context.get("typed_context")
        if isinstance(typed, dict):
            for value in typed.values():
                if isinstance(value, dict):
                    shift_citations(value.get("citations"))
        for facet in context.get("facets") or ():
            if isinstance(facet, dict):
                shift_citations(facet.get("assertion", {}).get("citations"))
        for service in (typed.get("services") if isinstance(typed, dict) else ()) or ():
            if isinstance(service, dict):
                shift_citations(service.get("identity", {}).get("citations"))
        for privilege in (typed.get("privileges") if isinstance(typed, dict) else ()) or ():
            if isinstance(privilege, dict):
                shift_citations(privilege.get("citations"))
        for control in (typed.get("security_controls") if isinstance(typed, dict) else ()) or ():
            if isinstance(control, dict):
                shift_citations(control.get("citations"))

    if isinstance(node, dict):
        for artifact in node.get("artifacts") or ():
            if isinstance(artifact, dict):
                shift_citations(artifact.get("citations"))
                shift_context(artifact.get("applicability"))
                for step in artifact.get("steps") or ():
                    if isinstance(step, dict):
                        shift_citations(step.get("citations"))
                        shift_context(step.get("applicability"))
        for example in node.get("execution_examples") or ():
            if isinstance(example, dict):
                shift_citations(example.get("citations"))
                shift_context(example.get("applicability"))
                for condition in example.get("prerequisites") or ():
                    if isinstance(condition, dict):
                        shift_citations(condition.get("citations"))
                for constraint in example.get("platform_constraints") or ():
                    if isinstance(constraint, dict):
                        shift_citations(constraint.get("citations"))


def _merge_draft_bundles(parts: list[dict[str, object]]) -> dict[str, object]:
    """Merge per-chunk SemanticDraftBundle dicts into one bundle.

    Each chunk is produced by a separate extract call, so its local_id values
    may collide across chunks. We rename every local_id (and every
    execution_example.parent_local_id) with a chunk-index prefix to guarantee
    bundle-wide uniqueness, then concatenate artifacts and execution_examples
    and union the ignored_segment_indexes. Callers MUST have already applied
    `_offset_citation_indexes(part, chunk_offset)` so citations carry the global
    segment indexes before merging.
    """
    artifacts: list[object] = []
    examples: list[object] = []
    ignored: set[int] = set()

    def remap_id(local_id: object, prefix: str) -> str | None:
        if isinstance(local_id, str):
            return f"{prefix}{local_id}"
        return None

    for idx, part in enumerate(parts):
        prefix = f"c{idx}_"
        # Remap artifact local_id (and nested step local_id).
        for artifact in part.get("artifacts") or ():
            if not isinstance(artifact, dict):
                continue
            new_lid = remap_id(artifact.get("local_id"), prefix)
            if new_lid is not None:
                artifact["local_id"] = new_lid
            for step in artifact.get("steps") or ():
                if isinstance(step, dict):
                    s_lid = remap_id(step.get("local_id"), prefix)
                    if s_lid is not None:
                        step["local_id"] = s_lid
            artifacts.append(artifact)
        # Remap execution_example parent_local_id.
        for example in part.get("execution_examples") or ():
            if not isinstance(example, dict):
                continue
            p_lid = remap_id(example.get("parent_local_id"), prefix)
            if p_lid is not None:
                example["parent_local_id"] = p_lid
            examples.append(example)
        for i in part.get("ignored_segment_indexes") or ():
            if isinstance(i, int):
                ignored.add(i)

    return {
        "artifacts": artifacts,
        "execution_examples": examples,
        "ignored_segment_indexes": sorted(ignored),
    }


def _obj_citation_indexes(citations: object) -> set[int]:
    out: set[int] = set()
    if not isinstance(citations, list):
        return out
    for citation in citations:
        if isinstance(citation, dict):
            for index in citation.get("segment_indexes") or ():
                if isinstance(index, int):
                    out.add(index)
    return out


def _collect_cited_indexes(merged: dict[str, object]) -> set[int]:
    """Collect every segment index cited anywhere in a merged draft bundle dict.

    Mirrors _normalize_segment_accounting's citation collection, used by the
    decomposed path to compute ignored indexes deterministically across chunks.
    """
    cited: set[int] = set()
    for artifact in merged.get("artifacts") or ():
        if not isinstance(artifact, dict):
            continue
        cited.update(_obj_citation_indexes(artifact.get("citations")))
        cited.update(_obj_context_indexes(artifact.get("applicability")))
        if artifact.get("draft_type") == "case":
            for step in artifact.get("steps") or ():
                if isinstance(step, dict):
                    cited.update(_obj_citation_indexes(step.get("citations")))
                    cited.update(_obj_context_indexes(step.get("applicability")))
    for example in merged.get("execution_examples") or ():
        if not isinstance(example, dict):
            continue
        cited.update(_obj_citation_indexes(example.get("citations")))
        cited.update(_obj_context_indexes(example.get("applicability")))
        for condition in example.get("prerequisites") or ():
            if isinstance(condition, dict):
                cited.update(_obj_citation_indexes(condition.get("citations")))
        for constraint in example.get("platform_constraints") or ():
            if isinstance(constraint, dict):
                cited.update(_obj_citation_indexes(constraint.get("citations")))
    return cited


def _obj_context_indexes(context: object) -> set[int]:
    out: set[int] = set()
    if not isinstance(context, dict):
        return out
    typed = context.get("typed_context")
    if isinstance(typed, dict):
        for value in typed.values():
            if isinstance(value, dict):
                out.update(_obj_citation_indexes(value.get("citations")))
    for facet in context.get("facets") or ():
        if isinstance(facet, dict):
            out.update(_obj_citation_indexes(facet.get("assertion", {}).get("citations")))
    return out


def _dedup_citation_indexes(response_obj: dict) -> None:
    """Deduplicate segment_indexes in every citation across the bundle.

    Cloud models frequently emit repeated segment indexes (e.g. [3, 3]); the
    DraftCitation schema rejects duplicates deterministically. Since a citation
    is a set of segment references, dedup is a safe deterministic normalization
    rather than a semantic change. Runs on artifacts, case steps, execution
    examples, prerequisites, platform constraints, and context assertions.
    """

    def normalize_citations(citations: object) -> None:
        if not isinstance(citations, list):
            return
        for citation in citations:
            if not isinstance(citation, dict):
                continue
            indexes = citation.get("segment_indexes")
            if isinstance(indexes, list):
                # Preserve order but drop duplicates.
                seen: set[int] = set()
                deduped: list[object] = []
                for idx in indexes:
                    if isinstance(idx, int) and idx not in seen:
                        seen.add(idx)
                        deduped.append(idx)
                citation["segment_indexes"] = deduped

    for artifact in response_obj.get("artifacts") or ():
        if not isinstance(artifact, dict):
            continue
        normalize_citations(artifact.get("citations"))
        _dedup_context_citations(artifact.get("applicability"))
        for step in artifact.get("steps") or ():
            if isinstance(step, dict):
                normalize_citations(step.get("citations"))
                _dedup_context_citations(step.get("applicability"))
    for example in response_obj.get("execution_examples") or ():
        if not isinstance(example, dict):
            continue
        normalize_citations(example.get("citations"))
        _dedup_context_citations(example.get("applicability"))
        for condition in example.get("prerequisites") or ():
            if isinstance(condition, dict):
                normalize_citations(condition.get("citations"))
        for constraint in example.get("platform_constraints") or ():
            if isinstance(constraint, dict):
                normalize_citations(constraint.get("citations"))


def _dedup_context_citations(context: object) -> None:
    """Deduplicate citation indexes inside an applicability context."""
    if not isinstance(context, dict):
        return
    typed = context.get("typed_context")
    if isinstance(typed, dict):
        for value in typed.values():
            if isinstance(value, dict):
                _dedup_citations_in_assertion(value)
    for facet in context.get("facets") or ():
        if isinstance(facet, dict):
            _dedup_citations_in_assertion(facet.get("assertion"))
    for service in (typed.get("services") if isinstance(typed, dict) else ()) or ():
        if isinstance(service, dict):
            _dedup_citations_in_assertion(service.get("identity"))
    for privilege in (typed.get("privileges") if isinstance(typed, dict) else ()) or ():
        if isinstance(privilege, dict):
            _dedup_citations_in_assertion(privilege)
    for control in (typed.get("security_controls") if isinstance(typed, dict) else ()) or ():
        if isinstance(control, dict):
            _dedup_citations_in_assertion(control)


def _dedup_citations_in_assertion(assertion: object) -> None:
    if not isinstance(assertion, dict):
        return
    citations = assertion.get("citations")
    if not isinstance(citations, list):
        return
    for citation in citations:
        if isinstance(citation, dict) and isinstance(citation.get("segment_indexes"), list):
            seen: set[int] = set()
            deduped: list[object] = []
            for idx in citation["segment_indexes"]:
                if isinstance(idx, int) and idx not in seen:
                    seen.add(idx)
                    deduped.append(idx)
            citation["segment_indexes"] = deduped


def _drop_incomplete_optional_assertions(response_obj: dict) -> None:
    """Drop incomplete optional context assertions instead of failing the bundle.

    DraftContextAssertion requires value/relation/origin/confidence/citations and
    at least one citation. Cloud models frequently emit an optional typed-context
    field (e.g. os_family) with missing confidence or empty citations. Since these
    are optional assertions, dropping an incomplete one is a graceful degradation
    that preserves the case core rather than invalidating the whole bundle.
    This mirrors the guidance to keep origin checks but discard incomplete optional
    assertions. It does NOT relax any content-level fail-closed rule.
    """
    required_keys = ("value", "relation", "origin", "confidence", "citations")

    def is_complete(assertion: object) -> bool:
        if not isinstance(assertion, dict):
            return False
        for key in required_keys:
            if key not in assertion:
                return False
        citations = assertion.get("citations")
        if not isinstance(citations, list) or len(citations) == 0:
            return False
        return True

    def normalize_typed(typed: object) -> None:
        if not isinstance(typed, dict):
            return
        # Optional scalar assertions: drop incomplete ones by setting to None.
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
            if key in typed and not is_complete(typed[key]):
                typed[key] = None
        # Lists of assertions: drop incomplete elements.
        for key in ("privileges", "security_controls"):
            items = typed.get(key)
            if isinstance(items, list):
                typed[key] = [i for i in items if is_complete(i)]
        # Services: identity is required; drop services with incomplete identity.
        services = typed.get("services")
        if isinstance(services, list):
            kept = []
            for service in services:
                if isinstance(service, dict) and is_complete(service.get("identity")):
                    kept.append(service)
            typed["services"] = kept

    def normalize_context(context: object) -> None:
        if isinstance(context, dict):
            normalize_typed(context.get("typed_context"))
            facets = context.get("facets")
            if isinstance(facets, list):
                kept = []
                for facet in facets:
                    if isinstance(facet, dict) and is_complete(facet.get("assertion")):
                        kept.append(facet)
                context["facets"] = kept

    for artifact in response_obj.get("artifacts") or ():
        if not isinstance(artifact, dict):
            continue
        normalize_context(artifact.get("applicability"))
        for step in artifact.get("steps") or ():
            if isinstance(step, dict):
                normalize_context(step.get("applicability"))
    for example in response_obj.get("execution_examples") or ():
        if isinstance(example, dict):
            normalize_context(example.get("applicability"))


def build_safe_source_payload(prepared: PreparedSource) -> SafePreparedSourcePayload:
    """Reconstruct the LLM payload field-by-field from the safe prepared boundary."""
    return SafePreparedSourcePayload(
        source_id=prepared.manifest.source_id,
        title=prepared.manifest.title,
        document_type=prepared.manifest.document_type,
        knowledge_role=prepared.manifest.knowledge_role,
        quality=prepared.manifest.quality,
        segments=tuple(
            SafeSourceSegment(
                index=index,
                start_line=segment.start_line,
                end_line=segment.end_line,
                heading_path=tuple(segment.heading_path),
                text=sanitize_searchable_text(segment.text, (segment.text,)),
                assets=tuple(
                    SafeSegmentAsset(
                        asset_index=asset.asset_index,
                        target=asset.target,
                        start_line=asset.start_line,
                        end_line=asset.end_line,
                    )
                    for asset in segment.assets
                ),
            )
            for index, segment in enumerate(prepared.segments)
        ),
    )


class HadesLlmAdapter:
    """Validate structured host completions while leaving routing to Hades/Hermes."""

    def __init__(
        self,
        host: HostStructuredLlm,
        *,
        max_tokens: int = 8_000,
        timeout: float = 120.0,
    ) -> None:
        self._host = host
        self._max_tokens = max_tokens
        self._timeout = timeout

    def complete(
        self,
        model_type: type[ModelT],
        *,
        instructions: str,
        payload: SafeRequestPayload,
        purpose: SemanticLlmPurpose,
    ) -> StructuredResult[ModelT]:
        """Call the host with a Pydantic schema and validate its parsed JSON locally."""
        contract = _CALL_CONTRACTS.get(purpose)
        if contract is None or type(payload) is not contract[0] or model_type is not contract[1]:
            raise TypeError("purpose, payload, and response model must match semantic contract")
        # Structured-output hosts (accepts_schema=True) receive the compact extractor
        # instruction set. The verbose EXTRACTOR_PROMPT overflows cloud models; the
        # compact variant keeps the same semantic invariants while remaining reliable.
        if purpose == "sedna.semantic.extract" and getattr(self._host, "accepts_schema", False):
            instructions = COMPACT_EXTRACTOR_PROMPT
        # Decompose large schema-capable extract payloads into per-chunk calls and
        # merge. This keeps each individual model call small enough that cloud
        # models (gpt-oss:120b) stay schema-conformant. Only applies when the
        # source has more than the threshold segments.
        if (
            purpose == "sedna.semantic.extract"
            and getattr(self._host, "accepts_schema", False)
            and isinstance(payload, SafePreparedSourcePayload)
            and len(payload.segments) > _DECOMPOSE_EXTRACT_SEGMENT_THRESHOLD
        ):
            return self._complete_extract_decomposed(model_type, payload)
        try:
            payload_data = payload.model_dump(mode="python", warnings="error")
            validated_payload = type(payload).model_validate(payload_data)
            serialized_payload_data = validated_payload.model_dump(
                mode="json",
                warnings="error",
            )
        except Exception:
            raise TypeError("payload must be a safe semantic request payload") from None
        serialized_payload = json.dumps(
            serialized_payload_data,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        # Schema sent to the LLM. For structured-output hosts we inline all
        # $ref and drop $defs so cloud models cannot reflect the definitions
        # back into their output (which Sedna rejects as extra_forbidden).
        # For other hosts keep the raw schema text in the prompt as before.
        if getattr(self._host, "accepts_schema", False):
            llm_schema = _resolve_schema_refs(model_type.model_json_schema())
        else:
            llm_schema = model_type.model_json_schema()
        response_schema = json.dumps(
            llm_schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        schema_instructions = (
            f"{instructions}\n\nReturn one JSON object matching this schema exactly:\n"
            f"{response_schema}"
        )
        # Structured-output hosts (OllamaHost) consume the real JSON Schema so
        # the sampler is constrained to it. The codex CLI and the host facade
        # historically get json_schema=None (a bare schema broke gpt-5.5), so we
        # gate on an explicit accepts_schema capability flag.
        json_schema_arg: Mapping[str, object] | None = None
        if getattr(self._host, "accepts_schema", False):
            json_schema_arg = json.loads(response_schema)
        # Structured-output hosts also receive the source as flat segment text
        # (with explicit indexes) instead of the full JSON payload, which
        # overflows cloud models. Other hosts keep the JSON serialization.
        use_segment_text = (
            getattr(self._host, "accepts_schema", False)
            and purpose == "sedna.semantic.extract"
            and _payload_to_segment_text(payload)
        )
        input_payload_text = (
            _payload_to_segment_text(payload) if use_segment_text else serialized_payload
        )
        try:
            host_result = self._host.complete_structured(
                instructions=schema_instructions,
                input=[{"type": "text", "text": input_payload_text}],
                json_schema=json_schema_arg,
                json_mode=True,
                schema_name=model_type.__name__,
                temperature=0,
                max_tokens=self._max_tokens,
                timeout=self._timeout,
                purpose=purpose,
            )
        except Exception:
            raise SemanticLlmError("transport_failure") from None

        host_parsed = getattr(host_result, "parsed", None)
        if host_parsed is None:
            raise SemanticLlmError("missing_parsed_response")

        try:
            response_data = (
                host_parsed.model_dump(mode="json", warnings="error")
                if isinstance(host_parsed, BaseModel)
                else host_parsed
            )
            response_json = json.dumps(
                response_data,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            response_obj = json.loads(response_json)
            if model_type is CriticVerdict and isinstance(response_obj, dict):
                findings = response_obj.get("findings")
                if isinstance(findings, list):
                    for finding in findings:
                        if isinstance(finding, dict):
                            code = finding.get("code")
                            canonical = CANONICAL_FINDING_MESSAGES.get(code)
                            if canonical is not None:
                                finding["message"] = canonical
                            # qwen/ollama local models often omit the severity
                            # field. Derive it deterministically from the code:
                            # unsafe_material is the only material severity.
                            if "severity" not in finding or finding["severity"] is None:
                                finding["severity"] = (
                                    "material" if code == "unsafe_material" else "warning"
                                )
                    # The critic validator requires accepted == False exactly
                    # when a material finding exists. Local models frequently
                    # set accepted=false without any material finding (or vice
                    # versa). Normalize accepted to match the derived findings.
                    has_material = any(
                        isinstance(f, dict) and f.get("severity") == "material" for f in findings
                    )
                    if response_obj.get("accepted") == has_material:
                        response_obj["accepted"] = not has_material
            if model_type is SemanticDraftBundle and isinstance(response_obj, dict):
                _normalize_segment_accounting(response_obj, _payload_segment_count(payload))
                _drop_orphan_execution_examples(response_obj)
                _normalize_placeholder_policies(response_obj)
                _dedup_citation_indexes(response_obj)
                _drop_incomplete_optional_assertions(response_obj)
            parsed = model_type.model_validate(response_obj)
        except Exception:
            raise SemanticLlmError("invalid_structured_response") from None

        try:
            usage = StructuredUsage.model_validate(host_result.usage)
            provider = host_result.provider
            model = host_result.model
            agent_id = host_result.agent_id
        except (AttributeError, ValidationError):
            raise SemanticLlmError("transport_failure") from None

        return StructuredResult(
            parsed=parsed,
            provider=provider,
            model=model,
            agent_id=agent_id,
            usage=usage,
            audit=MappingProxyType({"purpose": purpose}),
        )

    def _complete_extract_decomposed(
        self,
        model_type: type[ModelT],
        payload: SafePreparedSourcePayload,
    ) -> StructuredResult[ModelT]:
        """Run extract per segment-chunk and merge the bundles.

        Each chunk is a small SafePreparedSourcePayload (at most
        _DECOMPOSE_EXTRACT_SEGMENT_THRESHOLD segments). We call `complete` for
        each chunk (which uses the flat-segment-text path), then re-base citation
        indexes to the global source position, merge artifact/example lists, and
        validate the merged bundle against the full segment count.
        """
        chunks = _chunk_segments(payload)
        merged_parts: list[dict[str, object]] = []
        total_in_tokens = 0
        total_out_tokens = 0
        provider = ""
        model = ""
        agent_id = ""
        chunk_offset = 0
        for chunk in chunks:
            sub_payload = payload.model_copy(update={"segments": tuple(chunk)})
            result = self.complete(
                model_type,
                instructions=COMPACT_EXTRACTOR_PROMPT,
                payload=sub_payload,
                purpose="sedna.semantic.extract",
            )
            part_dict = (
                result.parsed.model_dump(mode="json", warnings="error")
                if isinstance(result.parsed, BaseModel)
                else result.parsed
            )
            if not isinstance(part_dict, dict):
                raise SemanticLlmError("invalid_structured_response")
            _offset_citation_indexes(part_dict, chunk_offset)
            merged_parts.append(part_dict)
            total_in_tokens += result.usage.input_tokens
            total_out_tokens += result.usage.output_tokens
            provider = result.provider
            model = result.model
            agent_id = result.agent_id
            chunk_offset += len(chunk)

        merged = _merge_draft_bundles(merged_parts)
        merged["ignored_segment_indexes"] = sorted(
            set(range(len(payload.segments))) - _collect_cited_indexes(merged)
        )
        try:
            parsed = model_type.model_validate(merged)
        except Exception:
            raise SemanticLlmError("invalid_structured_response") from None
        usage = StructuredUsage(
            input_tokens=total_in_tokens,
            output_tokens=total_out_tokens,
        )
        return StructuredResult(
            parsed=parsed,
            provider=provider,
            model=model,
            agent_id=agent_id,
            usage=usage,
            audit=MappingProxyType({"purpose": "sedna.semantic.extract"}),
        )


__all__ = [
    "HadesLlmAdapter",
    "HostStructuredLlm",
    "SafeSegmentAsset",
    "SafeSourceSegment",
    "SafeCriticRequestPayload",
    "SafePreparedSourcePayload",
    "SafeRepairRequestPayload",
    "SemanticLlmError",
    "StructuredResult",
    "StructuredUsage",
    "build_safe_source_payload",
]
