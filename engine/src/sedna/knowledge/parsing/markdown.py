"""Loss-minimized CommonMark parsing with source-line provenance."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser

from markdown_it import MarkdownIt
from markdown_it.token import Token

from sedna.knowledge.parsing.models import (
    BlockKind,
    ParsedAsset,
    ParsedBlock,
    ParsedDocument,
)


@dataclass(frozen=True, slots=True)
class _InlinePayload:
    text: str
    links: tuple[str, ...] = ()
    assets: tuple[ParsedAsset, ...] = ()
    code_spans: tuple[tuple[int, int], ...] = ()
    link_offsets: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class _BlockPayload:
    block: ParsedBlock
    links: tuple[str, ...] = ()
    assets: tuple[ParsedAsset, ...] = ()


class _ImageHTMLParser(HTMLParser):
    """Collect image attributes without interpreting the surrounding HTML."""

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.images: list[dict[str, str]] = []
        self.links: list[str] = []
        self.link_offsets: list[int] = []
        self._html_length = len(html)
        self._line_starts = [0]
        self._line_starts.extend(
            index + 1 for index, character in enumerate(html) if character == "\n"
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.casefold(): value or "" for name, value in attrs}
        normalized_tag = tag.casefold()
        if normalized_tag == "img" and attributes.get("src"):
            self.images.append(attributes)
        elif normalized_tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
            self.link_offsets.append(self._absolute_offset(*self.getpos()))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def _absolute_offset(self, line: int, column: int) -> int:
        line_index = line - 1
        if not 0 <= line_index < len(self._line_starts):
            raise ValueError("HTML parser returned an invalid source line")
        offset = self._line_starts[line_index] + column
        if not 0 <= offset <= self._html_length:
            raise ValueError("HTML parser returned an invalid source offset")
        return offset


def parse_markdown(source_id: str, path: str, markdown: str) -> ParsedDocument:
    """Parse Markdown into ordered structural blocks with exact line spans.

    Markdown-it token maps use zero-based, half-open line ranges. Every emitted
    block and asset converts those maps to one-based, inclusive provenance.
    Cleanup is deliberately absent here: parser profiles own that later step.
    """
    tokens = MarkdownIt("commonmark").enable("table").parse(markdown)
    parsed_blocks = _parse_scope(tokens, 0, len(tokens), level=0)

    relationships = _unique_in_order(link for parsed in parsed_blocks for link in parsed.links)
    return ParsedDocument(
        source_id=source_id,
        path=path,
        blocks=tuple(parsed.block for parsed in parsed_blocks),
        assets=tuple(asset for parsed in parsed_blocks for asset in parsed.assets),
        relationships=relationships,
    )


def _parse_scope(
    tokens: list[Token],
    start: int,
    end: int,
    *,
    level: int,
    skip_paragraph_index: int | None = None,
) -> list[_BlockPayload]:
    """Flatten one token scope while retaining nested structural children."""
    parsed_blocks: list[_BlockPayload] = []
    index = start

    while index < end:
        token = tokens[index]
        if token.level != level:
            index += 1
            continue

        if token.type == "heading_open":
            close_index = _matching_close(tokens, index)
            parsed_blocks.append(_heading_block(token, tokens[index + 1 : close_index]))
            index = close_index + 1
            continue

        if token.type == "paragraph_open":
            close_index = _matching_close(tokens, index)
            if index != skip_paragraph_index:
                parsed_blocks.append(_paragraph_block(token, tokens[index + 1 : close_index]))
            index = close_index + 1
            continue

        if token.type in {"fence", "code_block"}:
            parsed_blocks.append(_code_block(token))
            index += 1
            continue

        if token.type == "table_open":
            close_index = _matching_close(tokens, index)
            parsed_blocks.append(_table_block(token, tokens[index + 1 : close_index]))
            index = close_index + 1
            continue

        if token.type in {"bullet_list_open", "ordered_list_open"}:
            close_index = _matching_close(tokens, index)
            parsed_blocks.extend(_list_blocks(tokens, index, close_index))
            index = close_index + 1
            continue

        if token.type == "blockquote_open":
            close_index = _matching_close(tokens, index)
            child_level = token.level + 1
            leading_payload, leading_paragraph_index = _leading_paragraph_payload(
                tokens,
                index + 1,
                close_index,
                level=child_level,
            )
            parsed_blocks.append(
                _make_block(
                    BlockKind.BLOCKQUOTE,
                    token,
                    leading_payload,
                )
            )
            parsed_blocks.extend(
                _parse_scope(
                    tokens,
                    index + 1,
                    close_index,
                    level=child_level,
                    skip_paragraph_index=leading_paragraph_index,
                )
            )
            index = close_index + 1
            continue

        if token.type == "html_block":
            parsed_blocks.append(_html_block(token))
            index += 1
            continue

        if token.type == "hr":
            start_line, end_line = _source_span(token)
            parsed_blocks.append(
                _BlockPayload(
                    ParsedBlock(
                        kind=BlockKind.THEMATIC_BREAK,
                        text=token.markup,
                        start_line=start_line,
                        end_line=end_line,
                    )
                )
            )
            index += 1
            continue

        index += 1

    return parsed_blocks


def _heading_block(open_token: Token, inner_tokens: list[Token]) -> _BlockPayload:
    payload = _tokens_payload(inner_tokens)
    level = int(open_token.tag.removeprefix("h"))
    return _make_block(BlockKind.HEADING, open_token, payload, level=level)


def _paragraph_block(open_token: Token, inner_tokens: list[Token]) -> _BlockPayload:
    payload = _tokens_payload(inner_tokens)
    children = tuple(
        child
        for token in inner_tokens
        if token.type == "inline"
        for child in (token.children or ())
    )
    image_only = bool(payload.assets) and _contains_only_wrapped_images(children)
    kind = BlockKind.IMAGE if image_only else BlockKind.PARAGRAPH
    return _make_block(kind, open_token, payload)


def _code_block(token: Token) -> _BlockPayload:
    start_line, end_line = _source_span(token)
    info = token.info.strip()
    language = info.split(maxsplit=1)[0] if info else None
    metadata: dict[str, str] = {}
    if info:
        metadata["info"] = info
    if token.type == "fence" and token.markup:
        metadata["fence"] = token.markup
    return _BlockPayload(
        ParsedBlock(
            kind=BlockKind.CODE,
            text=token.content.removesuffix("\n"),
            start_line=start_line,
            end_line=end_line,
            language=language,
            metadata=metadata,
        )
    )


def _table_block(open_token: Token, inner_tokens: list[Token]) -> _BlockPayload:
    rows: list[str] = []
    links: list[str] = []
    assets: list[ParsedAsset] = []
    code_spans: list[tuple[int, int]] = []
    link_offsets: list[int] = []
    current_cells: list[_InlinePayload] | None = None

    for token in inner_tokens:
        if token.type == "tr_open":
            current_cells = []
        elif token.type == "tr_close" and current_cells is not None:
            row_start = sum(len(row) + 1 for row in rows)
            cell_start = row_start
            for cell in current_cells:
                links.extend(cell.links)
                link_offsets.extend(cell_start + offset for offset in cell.link_offsets)
                assets.extend(cell.assets)
                code_spans.extend(
                    (cell_start + start, cell_start + end) for start, end in cell.code_spans
                )
                cell_start += len(cell.text) + 3
            rows.append(" | ".join(cell.text for cell in current_cells))
            current_cells = None
        elif token.type == "inline" and current_cells is not None:
            payload = _inline_payload(token.children or (), _source_span(token))
            current_cells.append(payload)

    payload = _InlinePayload(
        "\n".join(rows),
        tuple(links),
        tuple(assets),
        tuple(code_spans),
        tuple(link_offsets),
    )
    return _make_block(BlockKind.TABLE, open_token, payload)


def _list_blocks(tokens: list[Token], start: int, end: int) -> list[_BlockPayload]:
    blocks: list[_BlockPayload] = []
    list_token = tokens[start]
    item_kind = (
        BlockKind.UNORDERED_LIST_ITEM
        if list_token.type == "bullet_list_open"
        else BlockKind.ORDERED_LIST_ITEM
    )
    item_level = list_token.level + 1
    index = start + 1

    while index < end:
        token = tokens[index]
        if token.type == "list_item_open" and token.level == item_level:
            close_index = _matching_close(tokens, index)
            child_level = token.level + 1
            payload, leading_paragraph_index = _leading_paragraph_payload(
                tokens,
                index + 1,
                close_index,
                level=child_level,
            )
            blocks.append(_make_block(item_kind, token, payload))
            blocks.extend(
                _parse_scope(
                    tokens,
                    index + 1,
                    close_index,
                    level=child_level,
                    skip_paragraph_index=leading_paragraph_index,
                )
            )
            index = close_index + 1
            continue
        index += 1

    return blocks


def _leading_paragraph_payload(
    tokens: list[Token],
    start: int,
    end: int,
    *,
    level: int,
) -> tuple[_InlinePayload, int | None]:
    """Return only the first paragraph when it leads a container's direct children."""
    index = start
    while index < end:
        token = tokens[index]
        if token.level != level:
            index += 1
            continue
        if token.type == "paragraph_open":
            close_index = _matching_close(tokens, index)
            return _tokens_payload(tokens[index + 1 : close_index]), index
        return _InlinePayload(""), None
    return _InlinePayload(""), None


def _html_block(token: Token) -> _BlockPayload:
    span = _source_span(token)
    payload = _raw_html_payload(token.content.removesuffix("\n"), span)
    return _make_block(BlockKind.HTML, token, payload)


def _make_block(
    kind: BlockKind,
    source_token: Token,
    payload: _InlinePayload,
    *,
    level: int | None = None,
) -> _BlockPayload:
    start_line, end_line = _source_span(source_token)
    metadata = _target_metadata(
        payload.links,
        payload.assets,
        payload.code_spans,
        payload.link_offsets,
    )
    return _BlockPayload(
        ParsedBlock(
            kind=kind,
            text=payload.text,
            start_line=start_line,
            end_line=end_line,
            level=level,
            metadata=metadata,
        ),
        links=payload.links,
        assets=payload.assets,
    )


def _tokens_payload(tokens: list[Token]) -> _InlinePayload:
    text_parts: list[str] = []
    links: list[str] = []
    assets: list[ParsedAsset] = []
    code_spans: list[tuple[int, int]] = []
    link_offsets: list[int] = []
    output_length = 0
    for token in tokens:
        if token.type == "inline":
            payload = _inline_payload(token.children or (), _source_span(token))
        elif token.type in {"fence", "code_block"}:
            payload = _InlinePayload(token.content.removesuffix("\n"))
        elif token.type == "html_block":
            token_span = _source_span(token)
            payload = _raw_html_payload(token.content.removesuffix("\n"), token_span)
        else:
            continue
        payload_start = output_length
        if payload.text:
            if text_parts:
                output_length += 1
            payload_start = output_length
            code_spans.extend(
                (output_length + start, output_length + end) for start, end in payload.code_spans
            )
            text_parts.append(payload.text)
            output_length += len(payload.text)
        links.extend(payload.links)
        link_offsets.extend(payload_start + offset for offset in payload.link_offsets)
        assets.extend(payload.assets)
    return _InlinePayload(
        "\n".join(text_parts),
        tuple(links),
        tuple(assets),
        tuple(code_spans),
        tuple(link_offsets),
    )


def _inline_payload(children: list[Token], span: tuple[int, int]) -> _InlinePayload:
    text_parts: list[str] = []
    links: list[str] = []
    assets: list[ParsedAsset] = []
    code_spans: list[tuple[int, int]] = []
    link_offsets: list[int] = []
    output_length = 0

    for child in children:
        if child.type == "text":
            text_parts.append(child.content)
            output_length += len(child.content)
        elif child.type == "code_inline":
            code_spans.append((output_length, output_length + len(child.content)))
            text_parts.append(child.content)
            output_length += len(child.content)
        elif child.type in {"softbreak", "hardbreak"}:
            text_parts.append("\n")
            output_length += 1
        elif child.type == "link_open":
            href = child.attrGet("href")
            if href:
                links.append(href)
                link_offsets.append(output_length)
        elif child.type == "image":
            alt_text = _inline_visible_text(child.children or ()) or child.content
            target = child.attrGet("src")
            if target:
                assets.append(
                    ParsedAsset(
                        target=target,
                        alt_text=alt_text or None,
                        title=child.attrGet("title"),
                        start_line=span[0],
                        end_line=span[1],
                        metadata={"source": "markdown_image"},
                    )
                )
            text_parts.append(alt_text)
            output_length += len(alt_text)
        elif child.type == "html_inline":
            html_payload = _raw_html_payload(child.content, span)
            link_offsets.extend(output_length + offset for offset in html_payload.link_offsets)
            text_parts.append(html_payload.text)
            output_length += len(html_payload.text)
            links.extend(html_payload.links)
            assets.extend(html_payload.assets)

    return _InlinePayload(
        "".join(text_parts),
        tuple(links),
        tuple(assets),
        tuple(code_spans),
        tuple(link_offsets),
    )


def _inline_visible_text(children: list[Token]) -> str:
    return "".join(
        "\n" if child.type in {"softbreak", "hardbreak"} else child.content
        for child in children
        if child.type in {"text", "code_inline", "softbreak", "hardbreak"}
    )


def _contains_only_wrapped_images(children: tuple[Token, ...]) -> bool:
    for child in children:
        if child.type == "image":
            continue
        if child.type == "text" and not child.content.strip():
            continue
        if child.type in {"softbreak", "hardbreak"}:
            continue
        if child.nesting != 0 and not child.block:
            continue
        return False
    return True


def _raw_html_payload(html: str, span: tuple[int, int]) -> _InlinePayload:
    parser = _ImageHTMLParser(html)
    parser.feed(html)
    parser.close()
    assets = tuple(
        ParsedAsset(
            target=attributes["src"],
            alt_text=attributes.get("alt") or None,
            title=attributes.get("title") or None,
            start_line=span[0],
            end_line=span[1],
            metadata={"source": "html_image"},
        )
        for attributes in parser.images
    )
    return _InlinePayload(
        html,
        tuple(parser.links),
        assets,
        link_offsets=tuple(parser.link_offsets),
    )


def _target_metadata(
    links: tuple[str, ...],
    assets: tuple[ParsedAsset, ...],
    code_spans: tuple[tuple[int, int], ...],
    link_offsets: tuple[int, ...],
) -> dict[str, str]:
    metadata: dict[str, str] = {}
    if links:
        metadata["urls"] = _compact_json(links)
        if len(links) == 1:
            metadata["url"] = links[0]
        metadata["url_offsets"] = json.dumps(
            link_offsets,
            separators=(",", ":"),
        )
    targets = tuple(asset.target for asset in assets)
    if targets:
        metadata["asset_targets"] = _compact_json(targets)
        if len(targets) == 1:
            metadata["asset_target"] = targets[0]
    if code_spans:
        metadata["inline_code_spans"] = json.dumps(
            code_spans,
            separators=(",", ":"),
        )
    return metadata


def _compact_json(values: tuple[str, ...]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _source_span(token: Token) -> tuple[int, int]:
    if token.map is None:
        raise ValueError(f"Markdown token {token.type!r} has no source map")
    return token.map[0] + 1, token.map[1]


def _matching_close(tokens: list[Token], open_index: int) -> int:
    open_token = tokens[open_index]
    depth = 1
    for index in range(open_index + 1, len(tokens)):
        token = tokens[index]
        if token.type == open_token.type:
            depth += 1
        elif token.type == open_token.type.replace("_open", "_close"):
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unclosed Markdown token {open_token.type!r}")


def _unique_in_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
