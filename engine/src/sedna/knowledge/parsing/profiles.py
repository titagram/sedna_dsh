"""Deterministic source-family cleanup over parsed Markdown documents."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from html.parser import HTMLParser

from sedna.knowledge.parsing.models import (
    BlockKind,
    ParsedAsset,
    ParsedBlock,
    ParsedDocument,
)

ProfileAdapter = Callable[[ParsedDocument], ParsedDocument]

_HTB_ARTICLE_BOUNDARIES = frozenset(
    {
        "ad blocker detected",
        "cheatsheet",
        "connect to htb",
        "next",
        "previous",
    }
)
_BOUNDARY_BLOCK_KINDS = frozenset(
    {
        BlockKind.HEADING,
        BlockKind.PARAGRAPH,
        BlockKind.ORDERED_LIST_ITEM,
        BlockKind.UNORDERED_LIST_ITEM,
    }
)
_NOTE_METADATA_RE = re.compile(
    r"^(?P<label>tags|related\s+to|see\s+also|previous)\s*:\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_WIKI_LINK_RE = re.compile(r"(?<!!)\[\[(?P<target>[^\]|]+)(?:\|[^\]]*)?\]\]")
_OBSIDIAN_EMBED_RE = re.compile(r"!\[\[(?P<target>[^\]|]+)(?:\|(?P<alias>[^\]]*))?\]\]")
_CLOSING_PRESENTATION_WRAPPER_RE = re.compile(r"\s*</(?:div|p)>\s*", re.IGNORECASE)
_RELATIONSHIP_BLOCK_KINDS = frozenset(
    {
        BlockKind.BLOCKQUOTE,
        BlockKind.HEADING,
        BlockKind.ORDERED_LIST_ITEM,
        BlockKind.PARAGRAPH,
        BlockKind.TABLE,
        BlockKind.UNORDERED_LIST_ITEM,
    }
)
_BLOCK_BOUNDARY_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "dd",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "ul",
    }
)
_VOID_HTML_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)
_GITHUB_PROFILE_MARKER_KEY = "profile_cleanup"
_GITHUB_PROFILE_MARKER_VALUE = "github_centered_unwrapped_v1"
_PARSER_POSITIONAL_METADATA_KEYS = frozenset({"url_offsets", "inline_code_spans"})


@dataclass(frozen=True, slots=True)
class _RelationshipEvent:
    line: int
    column: int
    sequence: int
    target: str


@dataclass(frozen=True, slots=True)
class _TextReplacement:
    start: int
    end: int
    text: str


class _PresentationHTMLParser(HTMLParser):
    """Identify a centered root wrapper and render its visible structure."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root_seen = False
        self.root_centered = False
        self.root_valid = True
        self.root_centered_balance = 0
        self.text_parts: list[str] = []
        self.asset_labels: list[str] = []
        self._open_tags: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.casefold()
        is_centered = normalized_tag in {"div", "p"} and _has_center_alignment(attrs)
        is_root = not self._open_tags and not self.root_seen
        if not self._open_tags:
            if self.root_seen:
                self.root_valid = False
            else:
                self.root_seen = True
                self.root_centered = is_centered

        attributes = {name.casefold(): (value or "") for name, value in attrs}
        if normalized_tag == "img" and attributes.get("src"):
            self.asset_labels.append(attributes.get("alt") or attributes["src"])
        if normalized_tag == "br" or (normalized_tag in _BLOCK_BOUNDARY_TAGS and not is_root):
            self._append_boundary()

        if normalized_tag not in _VOID_HTML_TAGS:
            self._open_tags.append((normalized_tag, is_root))
            if is_root and is_centered:
                self.root_centered_balance += 1

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.casefold()
        for index in range(len(self._open_tags) - 1, -1, -1):
            open_tag, was_root = self._open_tags[index]
            if open_tag != normalized_tag:
                continue
            del self._open_tags[index:]
            if normalized_tag in _BLOCK_BOUNDARY_TAGS and not was_root:
                self._append_boundary()
            if was_root and self.root_centered:
                self.root_centered_balance -= 1
            return

    def handle_data(self, data: str) -> None:
        if not self._open_tags and data.strip():
            self.root_valid = False
        self.text_parts.append(data)

    @property
    def is_centered_root(self) -> bool:
        return self.root_seen and self.root_centered and self.root_valid

    @property
    def visible_text(self) -> str:
        lines = (
            re.sub(r"[\t\f\v ]+", " ", line).strip()
            for line in "".join(self.text_parts).splitlines()
        )
        return "\n".join(line for line in lines if line)

    def _append_boundary(self) -> None:
        if self.text_parts and not self.text_parts[-1].endswith("\n"):
            self.text_parts.append("\n")


def apply_profile(document: ParsedDocument, profile: str) -> ParsedDocument:
    """Apply exactly one supported source profile without mutating its input."""
    adapters: dict[str, ProfileAdapter] = {
        "academy_obsidian": _clean_academy_obsidian,
        "github_walkthrough": _clean_github_walkthrough,
        "htb_scrape": _clean_htb_scrape,
    }
    try:
        adapter = adapters[profile]
    except KeyError as error:
        raise ValueError(f"unsupported parser profile: {profile!r}") from error
    return adapter(document)


def _clean_htb_scrape(document: ParsedDocument) -> ParsedDocument:
    first_article_index = next(
        (
            index
            for index, block in enumerate(document.blocks)
            if block.kind is BlockKind.HEADING and block.level == 1
        ),
        None,
    )
    if first_article_index is None:
        return document

    article_blocks: list[ParsedBlock] = []
    for block in document.blocks[first_article_index:]:
        if article_blocks and _is_htb_article_boundary(block):
            break
        article_blocks.append(block)

    return _rebuild_document(document, tuple(article_blocks))


def _is_htb_article_boundary(block: ParsedBlock) -> bool:
    return (
        block.kind in _BOUNDARY_BLOCK_KINDS
        and _normalize_label(block.text) in _HTB_ARTICLE_BOUNDARIES
    )


def _clean_academy_obsidian(document: ParsedDocument) -> ParsedDocument:
    blocks: list[ParsedBlock] = []
    relationship_events: list[_RelationshipEvent] = []
    new_assets: list[ParsedAsset] = []
    sequence = 0
    changed = False

    for block in document.blocks:
        candidate_blocks = (block,)
        if block.kind is BlockKind.PARAGRAPH:
            candidate_blocks, metadata_events = _remove_note_metadata(block, sequence)
            changed = changed or candidate_blocks != (block,)
            relationship_events.extend(metadata_events)
            sequence += len(metadata_events)

        for candidate in candidate_blocks:
            rewritten, assets = _convert_obsidian_embeds(candidate)
            changed = changed or bool(assets)
            blocks.append(rewritten)
            new_assets.extend(assets)
            wiki_events = _wiki_relationship_events(rewritten, sequence)
            relationship_events.extend(wiki_events)
            sequence += len(wiki_events)

    missing_relationship = any(
        event.target not in document.relationships for event in relationship_events
    )
    if not changed and not missing_relationship:
        return document

    return _rebuild_document(
        document,
        tuple(blocks),
        extra_relationships=relationship_events,
        extra_assets=new_assets,
    )


def _remove_note_metadata(
    block: ParsedBlock,
    starting_sequence: int,
) -> tuple[tuple[ParsedBlock, ...], tuple[_RelationshipEvent, ...]]:
    raw_lines = block.text.splitlines(keepends=True)
    lines = tuple(_remove_line_ending(raw_line) for raw_line in raw_lines)
    if not any(_NOTE_METADATA_RE.fullmatch(line.strip()) for line in lines):
        return (block,), ()

    kept_blocks: list[ParsedBlock] = []
    relationship_events: list[_RelationshipEvent] = []
    sequence = starting_sequence
    text_offset = 0

    for line_offset, (raw_line, line) in enumerate(zip(raw_lines, lines, strict=True)):
        source_line = min(block.start_line + line_offset, block.end_line)
        line_block = _slice_block(
            block,
            text=line,
            text_start=text_offset,
            text_end=text_offset + len(line),
            source_line=source_line,
        )
        text_offset += len(raw_line)
        match = _NOTE_METADATA_RE.fullmatch(line.strip())
        if match is None:
            if line.strip():
                kept_blocks.append(line_block)
            continue

        label = re.sub(r"\s+", " ", match.group("label")).casefold()
        if label == "tags":
            continue

        line_events = [
            *_url_relationship_events(line_block, sequence),
            *_wiki_relationship_events(line_block, sequence),
        ]
        line_events.sort(key=lambda event: (event.column, event.sequence))
        for event in line_events:
            relationship_events.append(
                _RelationshipEvent(
                    line=event.line,
                    column=event.column,
                    sequence=sequence,
                    target=event.target,
                )
            )
            sequence += 1

    return tuple(kept_blocks), tuple(relationship_events)


def _convert_obsidian_embeds(
    block: ParsedBlock,
) -> tuple[ParsedBlock, tuple[ParsedAsset, ...]]:
    assets: list[ParsedAsset] = []
    replacements: list[_TextReplacement] = []
    inline_code_spans = _inline_code_spans(block)

    for match in _OBSIDIAN_EMBED_RE.finditer(block.text):
        if any(start <= match.start() and match.end() <= end for start, end in inline_code_spans):
            continue
        target = match.group("target").strip()
        alias = (match.group("alias") or "").strip() or None
        source_line = block.start_line + block.text[: match.start()].count("\n")
        assets.append(
            ParsedAsset(
                target=target,
                start_line=source_line,
                end_line=source_line,
                alt_text=alias,
                metadata={"source": "obsidian_embed"},
            )
        )
        replacements.append(_TextReplacement(match.start(), match.end(), alias or target))

    if not assets:
        return block, ()

    rewritten_text = _apply_text_replacements(block.text, replacements)
    embed_only = _OBSIDIAN_EMBED_RE.fullmatch(block.text.strip()) is not None
    kind = BlockKind.IMAGE if embed_only else block.kind
    rewritten_block = _copy_block(
        block,
        text=rewritten_text,
        metadata=_metadata_after_replacements(block, replacements),
    )
    metadata = _metadata_with_asset_targets(rewritten_block, assets)
    return (
        _copy_block(rewritten_block, kind=kind, metadata=metadata),
        tuple(assets),
    )


def _clean_github_walkthrough(document: ParsedDocument) -> ParsedDocument:
    blocks: list[ParsedBlock] = []
    open_centered_wrappers = 0

    for block in document.blocks:
        if block.metadata.get(_GITHUB_PROFILE_MARKER_KEY) == _GITHUB_PROFILE_MARKER_VALUE:
            blocks.append(block)
            continue
        if block.kind not in {
            BlockKind.HEADING,
            BlockKind.HTML,
            BlockKind.PARAGRAPH,
        }:
            blocks.append(block)
            continue
        parser = _parse_presentation_html(block.text)
        if parser.is_centered_root:
            open_centered_wrappers += parser.root_centered_balance
            rewritten = _unwrap_centered_block(
                block,
                parser.visible_text,
                tuple(parser.asset_labels),
            )
            if rewritten is not None:
                blocks.append(rewritten)
            continue

        if (
            open_centered_wrappers > 0
            and block.kind is BlockKind.HTML
            and _CLOSING_PRESENTATION_WRAPPER_RE.fullmatch(block.text)
        ):
            open_centered_wrappers -= 1
            continue

        blocks.append(block)

    return _rebuild_document(document, tuple(blocks))


def _parse_presentation_html(text: str) -> _PresentationHTMLParser:
    parser = _PresentationHTMLParser()
    parser.feed(text)
    parser.close()
    return parser


def _unwrap_centered_block(
    block: ParsedBlock,
    visible_text: str,
    asset_labels: tuple[str, ...],
) -> ParsedBlock | None:
    assets = _assets_named_by_block(block)
    if not visible_text and not assets:
        return None

    text = visible_text or " ".join(asset_labels) or " ".join(asset.target for asset in assets)
    kind = block.kind
    if block.kind is BlockKind.HTML:
        kind = BlockKind.IMAGE if assets and not visible_text else BlockKind.PARAGRAPH
    metadata = {
        key: value
        for key, value in block.metadata.items()
        if key not in _PARSER_POSITIONAL_METADATA_KEYS
    }
    metadata[_GITHUB_PROFILE_MARKER_KEY] = _GITHUB_PROFILE_MARKER_VALUE
    return _copy_block(block, kind=kind, text=text, metadata=metadata)


def _rebuild_document(
    document: ParsedDocument,
    blocks: tuple[ParsedBlock, ...],
    *,
    extra_relationships: Iterable[_RelationshipEvent] = (),
    extra_assets: Iterable[ParsedAsset] = (),
) -> ParsedDocument:
    relationships = _relationships_in_source_order(blocks, extra_relationships)
    assets = _assets_in_source_order(document, blocks, extra_assets)
    return ParsedDocument(
        source_id=document.source_id,
        path=document.path,
        blocks=blocks,
        assets=assets,
        relationships=relationships,
    )


def _relationships_in_source_order(
    blocks: tuple[ParsedBlock, ...],
    extras: Iterable[_RelationshipEvent],
) -> tuple[str, ...]:
    events = list(extras)
    sequence = max((event.sequence for event in events), default=-1) + 1
    for block in blocks:
        block_events = _url_relationship_events(block, sequence)
        events.extend(block_events)
        sequence += len(block_events)

    events.sort(key=lambda event: (event.line, event.column, event.sequence))
    return _unique_in_order(event.target for event in events)


def _assets_in_source_order(
    document: ParsedDocument,
    blocks: tuple[ParsedBlock, ...],
    extras: Iterable[ParsedAsset],
) -> tuple[ParsedAsset, ...]:
    retained = [
        asset
        for asset in document.assets
        if any(_block_represents_asset(block, asset) for block in blocks)
    ]
    ordered = [*retained, *extras]
    return tuple(
        asset
        for _, asset in sorted(
            enumerate(ordered),
            key=lambda item: (
                item[1].start_line,
                item[1].end_line,
                item[0],
            ),
        )
    )


def _block_represents_asset(block: ParsedBlock, asset: ParsedAsset) -> bool:
    return (
        block.start_line <= asset.end_line
        and asset.start_line <= block.end_line
        and asset.target in _metadata_values(block, "asset_targets", "asset_target")
    )


def _assets_named_by_block(block: ParsedBlock) -> tuple[ParsedAsset, ...]:
    targets = _metadata_values(block, "asset_targets", "asset_target")
    return tuple(
        ParsedAsset(
            target=target,
            start_line=block.start_line,
            end_line=block.end_line,
        )
        for target in targets
    )


def _metadata_values(
    block: ParsedBlock,
    plural_key: str,
    singular_key: str,
) -> tuple[str, ...]:
    serialized = block.metadata.get(plural_key)
    if serialized is not None:
        values = json.loads(serialized)
        if isinstance(values, list) and all(isinstance(value, str) for value in values):
            return tuple(values)
    singular = block.metadata.get(singular_key)
    return (singular,) if singular is not None else ()


def _metadata_with_asset_targets(
    block: ParsedBlock,
    assets: Iterable[ParsedAsset],
) -> dict[str, str]:
    metadata = dict(block.metadata)
    targets = (
        *_metadata_values(block, "asset_targets", "asset_target"),
        *(asset.target for asset in assets),
    )
    metadata["asset_targets"] = json.dumps(
        targets,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(targets) == 1:
        metadata["asset_target"] = targets[0]
    else:
        metadata.pop("asset_target", None)
    return metadata


def _slice_block(
    block: ParsedBlock,
    *,
    text: str,
    text_start: int,
    text_end: int,
    source_line: int,
) -> ParsedBlock:
    metadata = dict(block.metadata)
    spans = tuple(
        (max(start, text_start) - text_start, min(end, text_end) - text_start)
        for start, end in _inline_code_spans(block)
        if start < text_end and text_start < end
    )
    _set_inline_code_spans(metadata, spans)

    targets = _metadata_values(block, "urls", "url")
    offsets = _url_offsets(block)
    selected = tuple(
        (target, offset - text_start)
        for target, offset in zip(targets, offsets, strict=False)
        if text_start <= offset < text_end
    )
    _set_url_metadata(metadata, selected)
    return _copy_block(
        block,
        text=text,
        start_line=source_line,
        end_line=source_line,
        metadata=metadata,
    )


def _metadata_after_replacements(
    block: ParsedBlock,
    replacements: list[_TextReplacement],
) -> dict[str, str]:
    metadata = dict(block.metadata)
    spans = tuple(
        (
            _shift_offset(start, replacements),
            _shift_offset(end, replacements),
        )
        for start, end in _inline_code_spans(block)
    )
    _set_inline_code_spans(metadata, spans)

    targets = _metadata_values(block, "urls", "url")
    offsets = _url_offsets(block)
    if len(offsets) == len(targets):
        _set_url_metadata(
            metadata,
            tuple(
                (target, _shift_offset(offset, replacements))
                for target, offset in zip(targets, offsets, strict=True)
            ),
        )
    return metadata


def _set_inline_code_spans(
    metadata: dict[str, str],
    spans: tuple[tuple[int, int], ...],
) -> None:
    if spans:
        metadata["inline_code_spans"] = json.dumps(
            spans,
            separators=(",", ":"),
        )
    else:
        metadata.pop("inline_code_spans", None)


def _set_url_metadata(
    metadata: dict[str, str],
    relationships: tuple[tuple[str, int], ...],
) -> None:
    metadata.pop("urls", None)
    metadata.pop("url", None)
    metadata.pop("url_offsets", None)
    if not relationships:
        return
    targets = tuple(target for target, _ in relationships)
    offsets = tuple(offset for _, offset in relationships)
    metadata["urls"] = json.dumps(
        targets,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    metadata["url_offsets"] = json.dumps(offsets, separators=(",", ":"))
    if len(targets) == 1:
        metadata["url"] = targets[0]


def _apply_text_replacements(
    text: str,
    replacements: list[_TextReplacement],
) -> str:
    parts: list[str] = []
    cursor = 0
    for replacement in replacements:
        parts.append(text[cursor : replacement.start])
        parts.append(replacement.text)
        cursor = replacement.end
    parts.append(text[cursor:])
    return "".join(parts)


def _shift_offset(offset: int, replacements: list[_TextReplacement]) -> int:
    delta = 0
    for replacement in replacements:
        if replacement.end <= offset:
            delta += len(replacement.text) - (replacement.end - replacement.start)
            continue
        if replacement.start < offset < replacement.end:
            return replacement.start + delta
        break
    return offset + delta


def _remove_line_ending(text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith(("\n", "\r")):
        return text[:-1]
    return text


def _copy_block(
    block: ParsedBlock,
    *,
    kind: BlockKind | None = None,
    text: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    metadata: dict[str, str] | None = None,
) -> ParsedBlock:
    return ParsedBlock(
        kind=kind or block.kind,
        text=block.text if text is None else text,
        start_line=block.start_line if start_line is None else start_line,
        end_line=block.end_line if end_line is None else end_line,
        level=block.level,
        language=block.language,
        metadata=dict(block.metadata) if metadata is None else metadata,
    )


def _wiki_relationship_events(
    block: ParsedBlock,
    starting_sequence: int,
) -> tuple[_RelationshipEvent, ...]:
    if block.kind not in _RELATIONSHIP_BLOCK_KINDS:
        return ()
    return _wiki_events_from_text(
        block.text,
        block.start_line,
        starting_sequence,
        excluded_spans=_inline_code_spans(block),
    )


def _wiki_events_from_text(
    text: str,
    start_line: int,
    starting_sequence: int,
    *,
    excluded_spans: tuple[tuple[int, int], ...] = (),
) -> tuple[_RelationshipEvent, ...]:
    events: list[_RelationshipEvent] = []
    sequence = starting_sequence
    for match in _WIKI_LINK_RE.finditer(text):
        if any(start <= match.start() and match.end() <= end for start, end in excluded_spans):
            continue
        raw_target = match.group("target")
        target = raw_target.strip()
        if not target or target != raw_target:
            continue
        line, column = _text_position(text, match.start(), start_line)
        events.append(_RelationshipEvent(line, column, sequence, target))
        sequence += 1
    return tuple(events)


def _inline_code_spans(block: ParsedBlock) -> tuple[tuple[int, int], ...]:
    serialized = block.metadata.get("inline_code_spans")
    if serialized is None:
        return ()
    values = json.loads(serialized)
    if not isinstance(values, list):
        return ()
    spans: list[tuple[int, int]] = []
    for value in values:
        if (
            isinstance(value, list)
            and len(value) == 2
            and all(isinstance(item, int) for item in value)
        ):
            spans.append((value[0], value[1]))
    return tuple(spans)


def _url_relationship_events(
    block: ParsedBlock,
    starting_sequence: int,
) -> tuple[_RelationshipEvent, ...]:
    targets = _metadata_values(block, "urls", "url")
    if not targets:
        return ()

    stored_offsets = _url_offsets(block)
    if len(stored_offsets) == len(targets):
        literal_offsets: list[int | None] = list(stored_offsets)
    else:
        literal_offsets = []
        search_offset = 0
        for target in targets:
            offset = block.text.find(target, search_offset)
            literal_offsets.append(offset if offset >= 0 else None)
            if offset >= 0:
                search_offset = offset + len(target)

    events: list[_RelationshipEvent] = []
    for index, (target, offset) in enumerate(zip(targets, literal_offsets, strict=True)):
        if offset is not None:
            line, column = _text_position(block.text, offset, block.start_line)
        else:
            line, column = _best_effort_url_position(
                block,
                index,
                literal_offsets,
            )
        events.append(_RelationshipEvent(line, column, starting_sequence + index, target))
    return tuple(events)


def _url_offsets(block: ParsedBlock) -> tuple[int, ...]:
    serialized = block.metadata.get("url_offsets")
    if serialized is None:
        return ()
    values = json.loads(serialized)
    if not isinstance(values, list) or not all(isinstance(value, int) for value in values):
        return ()
    return tuple(values)


def _best_effort_url_position(
    block: ParsedBlock,
    index: int,
    literal_offsets: list[int | None],
) -> tuple[int, int]:
    next_offset = next(
        (offset for offset in literal_offsets[index + 1 :] if offset is not None),
        None,
    )
    if next_offset is not None:
        line, column = _text_position(block.text, next_offset, block.start_line)
        return line, column - 1

    previous_offset = next(
        (offset for offset in reversed(literal_offsets[:index]) if offset is not None),
        None,
    )
    if previous_offset is not None:
        line, column = _text_position(block.text, previous_offset, block.start_line)
        return line, column + 1
    return block.end_line, len(block.text) + index


def _text_position(text: str, offset: int, start_line: int) -> tuple[int, int]:
    prefix = text[:offset]
    line = start_line + prefix.count("\n")
    last_newline = prefix.rfind("\n")
    column = offset if last_newline < 0 else offset - last_newline - 1
    return line, column


def _has_center_alignment(attrs: list[tuple[str, str | None]]) -> bool:
    attributes = {name.casefold(): (value or "") for name, value in attrs}
    if attributes.get("align", "").strip().casefold() == "center":
        return True
    style = attributes.get("style", "")
    return any(
        name.strip().casefold() == "text-align" and value.strip().casefold() == "center"
        for declaration in style.split(";")
        if ":" in declaration
        for name, value in (declaration.split(":", maxsplit=1),)
    )


def _normalize_label(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def _unique_in_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
