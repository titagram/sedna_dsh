"""Immutable structural contracts at the semantic-extraction boundary."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from enum import StrEnum
from itertools import pairwise
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, GetCoreSchemaHandler, model_validator
from pydantic_core import CoreSchema, core_schema

from sedna.knowledge.parsing.sanitize import (
    _contextual_hex_flag_values,
    _sanitize_searchable_text,
    sanitize_asset_target,
    sanitize_searchable_text,
)
from sedna.knowledge.schema import DocumentManifest

NonEmptyString = Annotated[str, Field(min_length=1)]
BlockIndex = Annotated[int, Field(ge=0)]


class FrozenMetadata(Mapping[str, str]):
    """A JSON-serializable immutable string mapping accepted from ordinary dicts."""

    __slots__ = ("_items",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        object.__setattr__(self, "_items", tuple((values or {}).items()))

    def __getitem__(self, key: str) -> str:
        for item_key, value in self._items:
            if item_key == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError(f"{type(self).__name__} is immutable")

    def __repr__(self) -> str:
        return f"{type(self).__name__}({dict(self)!r})"

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: object,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Validate natural dict input and serialize back to a JSON object."""
        del source_type, handler
        dictionary_schema = core_schema.dict_schema(
            keys_schema=core_schema.str_schema(),
            values_schema=core_schema.str_schema(),
        )
        return core_schema.no_info_after_validator_function(
            cls,
            dictionary_schema,
            serialization=core_schema.plain_serializer_function_ser_schema(
                dict,
                return_schema=dictionary_schema,
            ),
        )


class BlockKind(StrEnum):
    """The source-level structure represented by a parsed block."""

    HEADING = "heading"
    PARAGRAPH = "paragraph"
    CODE = "code"
    ORDERED_LIST_ITEM = "ordered_list_item"
    UNORDERED_LIST_ITEM = "unordered_list_item"
    TABLE = "table"
    BLOCKQUOTE = "blockquote"
    IMAGE = "image"
    HTML = "html"
    THEMATIC_BREAK = "thematic_break"


class ParsedBlock(BaseModel):
    """One structural Markdown block with an exact source line span."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: BlockKind
    text: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    level: int | None = Field(default=None, ge=1, le=6)
    language: str | None = None
    metadata: FrozenMetadata = Field(default_factory=FrozenMetadata)

    @model_validator(mode="after")
    def validate_structure(self) -> ParsedBlock:
        """Reject reversed spans and headings without their structural level."""
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.kind is BlockKind.HEADING and self.level is None:
            raise ValueError("heading blocks require a level")
        if self.kind is not BlockKind.HEADING and self.level is not None:
            raise ValueError("only heading blocks may define a level")
        if self.kind is not BlockKind.CODE and self.language is not None:
            raise ValueError("only code blocks may define a language")
        return self


class ParsedAsset(BaseModel):
    """A local or remote asset reference found in a source document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: NonEmptyString
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    alt_text: str | None = None
    title: str | None = None
    metadata: FrozenMetadata = Field(default_factory=FrozenMetadata)

    @model_validator(mode="after")
    def validate_line_range(self) -> ParsedAsset:
        """Keep asset provenance line ranges ordered."""
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class ParsedDocument(BaseModel):
    """The loss-minimized structural representation of a source document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: NonEmptyString
    path: NonEmptyString
    blocks: tuple[ParsedBlock, ...] = ()
    assets: tuple[ParsedAsset, ...] = ()
    relationships: tuple[NonEmptyString, ...] = ()


class SegmentAsset(BaseModel):
    """A retrieval-safe pointer to raw asset provenance in ``ParsedDocument``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_index: int = Field(ge=0)
    target: NonEmptyString
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_safe_reference(self) -> SegmentAsset:
        """Reject reversed spans and any locator that still carries flag material."""
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if sanitize_asset_target(self.target) != self.target:
            raise ValueError("segment asset target contains a final flag marker")
        return self


class LogicalSegment(BaseModel):
    """Searchable text grouped over one or more source blocks."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    block_indices: tuple[BlockIndex, ...] = Field(min_length=1)
    text: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_path: tuple[NonEmptyString, ...] = ()
    assets: tuple[SegmentAsset, ...] = ()

    @model_validator(mode="after")
    def validate_source_span(self) -> LogicalSegment:
        """Require ordered lines and unique, increasing source block indices."""
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if any(current != previous + 1 for previous, current in pairwise(self.block_indices)):
            raise ValueError("block_indices must be unique, increasing, and contiguous")
        if sanitize_searchable_text(self.text, self.heading_path) != self.text:
            raise ValueError("logical segment text must be retrieval-safe")
        for index, component in enumerate(self.heading_path):
            if sanitize_searchable_text(component, self.heading_path[: index + 1]) != component:
                raise ValueError("logical segment heading path must be retrieval-safe")
        return self


class PreparedSource(BaseModel):
    """A manifest plus structural material ready for semantic extraction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest: DocumentManifest
    document: ParsedDocument
    segments: tuple[LogicalSegment, ...]

    @model_validator(mode="after")
    def validate_source_consistency(self) -> PreparedSource:
        """Keep every segment anchored exactly to blocks and assets in its document."""
        if self.manifest.source_id != self.document.source_id:
            raise ValueError("manifest and document source_id must match")
        if self.manifest.path != self.document.path:
            raise ValueError("manifest and document path must match")

        block_contexts = _document_block_contexts(self.document)
        known_hex_flags = frozenset(
            value
            for block, heading_path in block_contexts
            for value in _contextual_hex_flag_values(block.text, heading_path)
        )

        for segment in self.segments:
            if segment.block_indices[-1] >= len(self.document.blocks):
                raise ValueError("segment block index is outside the parsed document")

            referenced_blocks = tuple(
                self.document.blocks[index] for index in segment.block_indices
            )
            expected_start_line = min(block.start_line for block in referenced_blocks)
            expected_end_line = max(block.end_line for block in referenced_blocks)
            if (segment.start_line, segment.end_line) != (
                expected_start_line,
                expected_end_line,
            ):
                raise ValueError("segment line range must exactly span its referenced blocks")

            referenced_contexts = tuple(block_contexts[index] for index in segment.block_indices)
            expected_text = "\n\n".join(
                _sanitize_searchable_text(block.text, heading_path, known_hex_flags)
                for block, heading_path in referenced_contexts
            )
            if segment.text != expected_text:
                raise ValueError("segment text must exactly match retrieval-safe source blocks")
            expected_heading_path = _safe_heading_path(
                referenced_contexts[0][1],
                known_hex_flags,
            )
            if segment.heading_path != expected_heading_path:
                raise ValueError(
                    "segment heading path must exactly match retrieval-safe source scope"
                )

            for asset in segment.assets:
                if asset.asset_index >= len(self.document.assets):
                    raise ValueError("segment asset index is outside the parsed document")
                raw_asset = self.document.assets[asset.asset_index]
                if (asset.start_line, asset.end_line) != (
                    raw_asset.start_line,
                    raw_asset.end_line,
                ):
                    raise ValueError("segment asset span must match its raw parsed asset")
                if asset.target != sanitize_asset_target(raw_asset.target):
                    raise ValueError("segment asset target must be the retrieval-safe raw target")
                if asset.end_line < segment.start_line or asset.start_line > segment.end_line:
                    raise ValueError("segment asset line range must overlap the segment span")
        return self


def validate_prepared_source(prepared: PreparedSource) -> PreparedSource:
    """Deeply revalidate a possibly non-validating Pydantic instance."""
    if not isinstance(prepared, PreparedSource):
        raise TypeError("prepared must be a PreparedSource")
    try:
        payload = prepared.model_dump(mode="json", warnings="error")
        return PreparedSource.model_validate(payload)
    except Exception:
        raise ValueError("prepared source failed deep validation") from None


def _document_block_contexts(
    document: ParsedDocument,
) -> tuple[tuple[ParsedBlock, tuple[str, ...]], ...]:
    heading_stack: list[tuple[int, str]] = []
    contexts: list[tuple[ParsedBlock, tuple[str, ...]]] = []
    for block in document.blocks:
        if block.kind is BlockKind.HEADING:
            assert block.level is not None
            while heading_stack and heading_stack[-1][0] >= block.level:
                heading_stack.pop()
            heading_stack.append((block.level, block.text))
        contexts.append((block, tuple(text for _, text in heading_stack)))
    return tuple(contexts)


def _safe_heading_path(
    heading_path: tuple[str, ...],
    known_hex_flags: frozenset[str],
) -> tuple[str, ...]:
    safe: list[str] = []
    for index, component in enumerate(heading_path):
        sanitized = _sanitize_searchable_text(
            component,
            heading_path[: index + 1],
            known_hex_flags,
        ).strip()
        if sanitized:
            safe.append(sanitized)
    return tuple(safe)
