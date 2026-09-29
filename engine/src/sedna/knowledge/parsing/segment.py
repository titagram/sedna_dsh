"""Heading-aware logical segmentation over immutable parsed Markdown blocks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sedna.knowledge.parsing.models import (
    BlockKind,
    LogicalSegment,
    ParsedBlock,
    ParsedDocument,
    SegmentAsset,
)
from sedna.knowledge.parsing.sanitize import (
    _contextual_hex_flag_values,
    _sanitize_searchable_text,
    sanitize_asset_target,
)

_COMMON_COMMAND_NAMES = frozenset(
    {
        "apt",
        "apt-get",
        "awk",
        "bash",
        "cat",
        "chmod",
        "chown",
        "cp",
        "curl",
        "docker",
        "echo",
        "env",
        "find",
        "git",
        "grep",
        "ip",
        "iptables",
        "ls",
        "mkdir",
        "mount",
        "mv",
        "nc",
        "netcat",
        "nmap",
        "ping",
        "pip",
        "pip3",
        "powershell",
        "python",
        "python3",
        "rm",
        "rpcclient",
        "run",
        "script",
        "set",
        "show",
        "smbclient",
        "snmpwalk",
        "ssh",
        "strace",
        "sudo",
        "tar",
        "tree",
        "unzip",
        "use",
        "wget",
        "whoami",
    }
)
_PROMPT_COMMAND_RE = re.compile(r"(?:[$#>]\s+)(?P<command>[^\r\n]+)$")
_KNOWN_OUTPUT_PREFIX_RE = re.compile(
    r"(?:find:|iptables\s+v\d|nmap\s+scan\s+report\b)",
    re.IGNORECASE,
)
_COMMAND_NAME_RE = re.compile(
    r"(?:(?:\./|/)?[A-Za-z0-9_.-]+/)*(?P<name>[A-Za-z][A-Za-z0-9_-]*)(?=$|\s)"
)


@dataclass(frozen=True, slots=True)
class _BlockView:
    index: int
    block: ParsedBlock
    heading_path: tuple[str, ...]
    searchable_text: str


class OversizedStructuralGroupError(ValueError):
    """A source block group cannot fit without breaking provenance or coherence."""


def segment_document(
    document: ParsedDocument,
    maximum_segment_chars: int = 12_000,
) -> tuple[LogicalSegment, ...]:
    """Group a parsed document without slicing source blocks or leaking flags.

    A heading owns blocks through the next heading at the same or a higher level.
    Oversized sections split only between atomic block groups. A heading and its
    first block stay together, as do an action immediately before a command code
    block, at most one following result code block, and an immediate conclusion.
    An indivisible group that exceeds the configured maximum is rejected with its
    exact block and line provenance instead of silently exceeding the limit or
    slicing a source block.
    """
    if maximum_segment_chars < 1:
        raise ValueError("maximum_segment_chars must be positive")
    if not document.blocks:
        return ()

    views = _block_views(document)
    segments: list[LogicalSegment] = []
    for section in _section_ranges(views):
        atomic_groups = _atomic_groups(views[section.start : section.stop])
        for packed_group in _pack_groups(atomic_groups, maximum_segment_chars):
            segments.append(_build_segment(document, packed_group))
    return tuple(segments)


def _block_views(document: ParsedDocument) -> tuple[_BlockView, ...]:
    heading_stack: list[tuple[int, str]] = []
    contextual_blocks: list[tuple[int, ParsedBlock, tuple[str, ...]]] = []

    for index, block in enumerate(document.blocks):
        if block.kind is BlockKind.HEADING:
            assert block.level is not None
            while heading_stack and heading_stack[-1][0] >= block.level:
                heading_stack.pop()
            heading_stack.append((block.level, block.text))

        heading_path = tuple(text for _, text in heading_stack)
        contextual_blocks.append((index, block, heading_path))

    known_hex_flags = frozenset(
        value
        for _, block, heading_path in contextual_blocks
        for value in _contextual_hex_flag_values(block.text, heading_path)
    )
    return tuple(
        _BlockView(
            index=index,
            block=block,
            heading_path=_sanitize_heading_path(heading_path, known_hex_flags),
            searchable_text=_sanitize_searchable_text(
                block.text,
                heading_path,
                known_hex_flags,
            ),
        )
        for index, block, heading_path in contextual_blocks
    )


def _sanitize_heading_path(
    heading_path: tuple[str, ...],
    known_hex_flags: frozenset[str],
) -> tuple[str, ...]:
    sanitized_path: list[str] = []
    for index, component in enumerate(heading_path):
        sanitized_component = _sanitize_searchable_text(
            component,
            heading_path[: index + 1],
            known_hex_flags,
        ).strip()
        if sanitized_component:
            sanitized_path.append(sanitized_component)
    return tuple(sanitized_path)


def _section_ranges(views: tuple[_BlockView, ...]) -> tuple[range, ...]:
    heading_positions = tuple(
        (position, view.block.level)
        for position, view in enumerate(views)
        if view.block.kind is BlockKind.HEADING
    )
    if not heading_positions:
        return (range(len(views)),) if views else ()

    first_heading_position, first_heading_level = heading_positions[0]
    assert first_heading_level is not None
    later_heading_levels = tuple(level for _, level in heading_positions[1:] if level is not None)
    title_child_levels = tuple(
        level for level in later_heading_levels if level > first_heading_level
    )
    title_is_container = (
        first_heading_level == 1
        and bool(title_child_levels)
        and all(level > first_heading_level for level in later_heading_levels)
    )
    if title_is_container:
        return _title_container_section_ranges(
            views,
            first_heading_position,
            min(title_child_levels),
        )

    sections: list[range] = []
    section_start = 0
    section_level: int | None = None

    for position, view in enumerate(views):
        if view.block.kind is not BlockKind.HEADING:
            continue
        assert view.block.level is not None

        if section_level is None:
            if position > section_start:
                sections.append(range(section_start, position))
            section_start = position
            section_level = view.block.level
        elif view.block.level <= section_level:
            sections.append(range(section_start, position))
            section_start = position
            section_level = view.block.level

    if section_start < len(views):
        sections.append(range(section_start, len(views)))
    return tuple(sections)


def _title_container_section_ranges(
    views: tuple[_BlockView, ...],
    title_position: int,
    child_section_level: int,
) -> tuple[range, ...]:
    sections: list[range] = []
    if title_position:
        sections.append(range(0, title_position))

    section_start = title_position
    for position in range(title_position + 1, len(views)):
        block = views[position].block
        if (
            block.kind is BlockKind.HEADING
            and block.level is not None
            and block.level <= child_section_level
        ):
            sections.append(range(section_start, position))
            section_start = position

    sections.append(range(section_start, len(views)))
    return tuple(sections)


def _atomic_groups(views: tuple[_BlockView, ...]) -> tuple[tuple[_BlockView, ...], ...]:
    if not views:
        return ()

    groups: list[tuple[_BlockView, ...]] = []
    position = 0
    while position < len(views):
        group_start = position
        current = views[position].block

        if current.kind is BlockKind.HEADING:
            position += 1
            if position < len(views) and views[position].block.kind is not BlockKind.HEADING:
                if views[position].block.kind is BlockKind.CODE:
                    position += 1
                    position = _consume_code_result(views, position)
                else:
                    position += 1
                    if position < len(views) and views[position].block.kind is BlockKind.CODE:
                        position += 1
                        position = _consume_code_result(views, position)
        elif current.kind is BlockKind.CODE:
            position += 1
            position = _consume_code_result(views, position)
        elif position + 1 < len(views) and views[position + 1].block.kind is BlockKind.CODE:
            position += 2
            position = _consume_code_result(views, position)
        else:
            position += 1

        groups.append(views[group_start:position])
    return tuple(groups)


def _consume_code_result(views: tuple[_BlockView, ...], position: int) -> int:
    if (
        position < len(views)
        and views[position].block.kind is BlockKind.CODE
        and not _looks_like_command_code(views[position].block)
    ):
        position += 1
    if position < len(views) and views[position].block.kind not in {
        BlockKind.HEADING,
        BlockKind.CODE,
    }:
        position += 1
    return position


def _looks_like_command_code(block: ParsedBlock) -> bool:
    first_line = next(
        (line.strip() for line in block.text.splitlines() if line.strip()),
        "",
    )
    if not first_line:
        return False
    if _KNOWN_OUTPUT_PREFIX_RE.match(first_line):
        return False
    prompt_match = _PROMPT_COMMAND_RE.search(first_line)
    if prompt_match is not None:
        first_line = prompt_match.group("command").strip()
    name_match = _COMMAND_NAME_RE.match(first_line.casefold())
    return name_match is not None and name_match.group("name") in _COMMON_COMMAND_NAMES


def _pack_groups(
    groups: tuple[tuple[_BlockView, ...], ...],
    maximum_segment_chars: int,
) -> tuple[tuple[_BlockView, ...], ...]:
    packed: list[tuple[_BlockView, ...]] = []
    current: tuple[_BlockView, ...] = ()

    for group in groups:
        group_length = _rendered_length(group)
        if group_length > maximum_segment_chars:
            raise _oversized_group_error(group, group_length, maximum_segment_chars)
        candidate = (*current, *group)
        if current and _rendered_length(candidate) > maximum_segment_chars:
            packed.append(current)
            current = group
        else:
            current = candidate

    if current:
        packed.append(current)
    return tuple(packed)


def _oversized_group_error(
    group: tuple[_BlockView, ...],
    rendered_length: int,
    maximum_segment_chars: int,
) -> OversizedStructuralGroupError:
    first = group[0]
    last = group[-1]
    block_label = (
        f"block {first.index}" if len(group) == 1 else f"blocks {first.index}-{last.index}"
    )
    start_line = min(view.block.start_line for view in group)
    end_line = max(view.block.end_line for view in group)
    return OversizedStructuralGroupError(
        f"indivisible structural {block_label} at lines {start_line}-{end_line} "
        f"renders to {rendered_length} characters, exceeding "
        f"maximum_segment_chars={maximum_segment_chars}; refusing to split "
        "source blocks or lose exact provenance"
    )


def _rendered_length(views: tuple[_BlockView, ...]) -> int:
    if not views:
        return 0
    return sum(len(view.searchable_text) for view in views) + 2 * (len(views) - 1)


def _build_segment(
    document: ParsedDocument,
    views: tuple[_BlockView, ...],
) -> LogicalSegment:
    block_indices = tuple(view.index for view in views)
    start_line = min(view.block.start_line for view in views)
    end_line = max(view.block.end_line for view in views)
    assets = tuple(
        SegmentAsset(
            asset_index=asset_index,
            target=sanitize_asset_target(asset.target),
            start_line=asset.start_line,
            end_line=asset.end_line,
        )
        for asset_index, asset in enumerate(document.assets)
        if asset.end_line >= start_line and asset.start_line <= end_line
    )
    return LogicalSegment(
        block_indices=block_indices,
        text="\n\n".join(view.searchable_text for view in views),
        start_line=start_line,
        end_line=end_line,
        heading_path=views[0].heading_path,
        assets=assets,
    )
