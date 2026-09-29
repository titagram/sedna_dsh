"""Deterministic and explainable classification of inventoried source documents."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import PurePosixPath

from markdown_it import MarkdownIt
from markdown_it.token import Token
from pydantic import BaseModel, ConfigDict, Field

from sedna.knowledge.inventory import SourceCandidate
from sedna.knowledge.schema import (
    DocumentType,
    IngestionStatus,
    KnowledgeRole,
    SourceQuality,
)

_ATX_HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_SETEXT_HEADING_RE = re.compile(r"(?m)^([^\n]+)\n\s*(?:={4,}|-{4,})\s*$")
_URL_RE = re.compile(r"https?://[^\s<>\])]+", re.IGNORECASE)
_HTB_FLAG_RE = re.compile(r"HTB\{[^}\r\n]+\}", re.IGNORECASE)
_FLAG_HEADING_RE = re.compile(r"(?ims)^\s{0,3}#{1,6}[^\n]*\bflag\b[^\n]*\n(?P<body>.{0,500})")
_HEX_32_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.IGNORECASE)
_USER_ROOT_FLAG_RE = re.compile(
    r"(?ims)^\s{0,3}(?:#{1,6}\s*)?(?:user|root)(?:\s+flag)?\s*:?\s*#*\s*$"
    r"\n(?P<body>.{0,160})"
)
_ACTION_LANGUAGE_RE = re.compile(
    r"\b(?:we|i)\s+(?:ran|run|used|started|added|enumerated|scanned|inspected|"
    r"tested|tried|executed|uploaded|connected|requested|checked|decoded|"
    r"extracted|opened|visited|submitted)\b|"
    r"\blet(?:'s| us)\b|"
    r"\bafter\s+(?:running|adding|enumerating|scanning|checking|uploading|"
    r"connecting|requesting|decoding|extracting)\b",
    re.IGNORECASE,
)
_RESULT_LANGUAGE_RE = re.compile(
    r"\b(?:we|i)\s+(?:found|discovered|observed|identified|obtained|received|"
    r"saw|got|confirmed)\b|"
    r"\b(?:the|our)\s+(?:scan|command|request|exploit|test|enumeration)\s+"
    r"(?:showed|revealed|returned|found|failed|succeeded|confirmed)\b|"
    r"\baccording to (?:the )?(?:scan )?results\b|"
    r"\bresults?\s+(?:showed|revealed|indicated|returned|confirmed|led)\b",
    re.IGNORECASE,
)
_WALKTHROUGH_LANGUAGE_RE = re.compile(
    r"\b(?:walkthrough|write[ -]?up|step[ -]?by[ -]?step|full guide)\b",
    re.IGNORECASE,
)
_TECHNICAL_PDF_RE = re.compile(r"\b(?:cheat[ -]?sheet|reference|handbook|manual)\b", re.IGNORECASE)
_NON_PROCEDURAL_HEADING_RE = re.compile(
    r"\b(?:flag|challenge overview|overview|objective|metadata|table of contents|"
    r"contents|difficulty|category)\b",
    re.IGNORECASE,
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


class ClassificationResult(BaseModel):
    """Immutable disposition and routing decision for one source document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    document_type: DocumentType
    knowledge_role: KnowledgeRole
    quality: SourceQuality
    parser_profile: str = Field(min_length=1)
    ingestion_status: IngestionStatus
    reasons: tuple[str, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class _DocumentSignals:
    headings: tuple[str, ...]
    substantive_heading_count: int
    code_block_count: int
    word_count: int
    table_line_count: int
    table_has_local_content: bool
    narrative_line_count: int
    has_flag: bool
    procedural: bool
    walkthrough_urls: tuple[str, ...]
    local_substance: bool
    reference_link_count: int


@dataclass(frozen=True, slots=True)
class _ContentSignals:
    local_text: str
    narrative_line_count: int
    code_block_count: int
    table_line_count: int
    table_has_local_content: bool
    reference_link_count: int


@dataclass(frozen=True, slots=True)
class _InlineSignals:
    local_text: str
    reference_link_count: int


@dataclass(frozen=True, slots=True)
class _WikiScanResult:
    local_text: str
    reference_link_count: int
    scanned_characters: int


class _HTMLContentParser(HTMLParser):
    """Collect visible non-anchor text and bounded link/image signals."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.local_parts: list[str] = []
        self.reference_link_count = 0
        self._linked_anchor_stack: list[bool] = []
        self._linked_anchor_depth = 0

    @property
    def suppresses_text(self) -> bool:
        return self._linked_anchor_depth > 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.casefold()
        attributes = {name.casefold(): value or "" for name, value in attrs}
        if normalized_tag == "a":
            linked = bool(attributes.get("href"))
            self._linked_anchor_stack.append(linked)
            if linked:
                self.reference_link_count += 1
                self._linked_anchor_depth += 1
        elif normalized_tag == "img" and _is_external_target(attributes.get("src", "")):
            self.reference_link_count += 1

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() == "a":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() != "a" or not self._linked_anchor_stack:
            return
        if self._linked_anchor_stack.pop():
            self._linked_anchor_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.suppresses_text:
            self.local_parts.append(data)

    def drain_local_text(self) -> str:
        text = "".join(self.local_parts)
        self.local_parts.clear()
        return text


def classify_document(candidate: SourceCandidate, text: str | None) -> ClassificationResult:
    """Classify a source using ordered structural and path-based rules.

    Reason codes intentionally expose the rule that won so a manifest or review
    report can explain every deterministic decision.
    """
    normalized_path = _classification_path(candidate)

    if candidate.suffix.casefold() == ".pdf":
        return _classify_pdf(candidate)

    if text is None or not text.strip():
        return _result(
            DocumentType.EXCLUDED,
            KnowledgeRole.REFERENCE,
            SourceQuality.UNUSABLE,
            "none",
            IngestionStatus.EXCLUDED,
            "empty",
        )

    signals = _collect_signals(text)

    # A real external walkthrough link is substance enough to distinguish a
    # stub from a generic flag dump, but the flag-only rule remains first for
    # documents that contain only official challenge metadata and a flag.
    if signals.has_flag and not signals.procedural and not signals.walkthrough_urls:
        return _result(
            DocumentType.EXCLUDED,
            KnowledgeRole.REFERENCE,
            SourceQuality.UNUSABLE,
            "none",
            IngestionStatus.EXCLUDED,
            "flag_only",
        )

    if (
        len(signals.walkthrough_urls) == 1
        and not signals.procedural
        and (signals.has_flag or signals.word_count < 100)
    ):
        return _result(
            DocumentType.EXTERNAL_STUB,
            KnowledgeRole.REFERENCE,
            SourceQuality.MINIMAL,
            "none",
            IngestionStatus.EXCLUDED,
            "external_walkthrough_only",
        )

    if _is_machine_path(normalized_path) and signals.procedural:
        quality = _walkthrough_quality(signals)
        return _result(
            DocumentType.MACHINE_WALKTHROUGH,
            KnowledgeRole.CASE_STUDY,
            quality,
            "github_walkthrough",
            IngestionStatus.ACCEPTED,
            "machine_path",
            "procedural_signals",
            f"quality_{quality.value}",
        )

    if _is_challenge_path(normalized_path) and signals.procedural:
        quality = _walkthrough_quality(signals)
        return _result(
            DocumentType.CHALLENGE_WALKTHROUGH,
            KnowledgeRole.CASE_STUDY,
            quality,
            "github_walkthrough",
            IngestionStatus.ACCEPTED,
            "challenge_path",
            "procedural_signals",
            f"quality_{quality.value}",
        )

    if _is_reference_family_path(normalized_path):
        if not signals.local_substance:
            if signals.reference_link_count:
                return _result(
                    DocumentType.EXTERNAL_STUB,
                    KnowledgeRole.REFERENCE,
                    SourceQuality.MINIMAL,
                    "none",
                    IngestionStatus.EXCLUDED,
                    "no_local_substance",
                    "link_navigation_only",
                )
            return _result(
                DocumentType.EXCLUDED,
                KnowledgeRole.REFERENCE,
                SourceQuality.UNUSABLE,
                "none",
                IngestionStatus.EXCLUDED,
                "no_local_substance",
            )

        parser_profile = (
            "htb_scrape"
            if normalized_path.startswith("01_information-gathering/")
            else "academy_obsidian"
        )
        if _is_table_dominant(signals):
            return _result(
                DocumentType.CHEATSHEET_REFERENCE,
                KnowledgeRole.REFERENCE,
                SourceQuality.PARTIAL,
                parser_profile,
                IngestionStatus.ACCEPTED,
                "reference_family_path",
                "table_dominant",
            )

        quality = _lesson_quality(signals)
        return _result(
            DocumentType.LESSON,
            KnowledgeRole.REFERENCE,
            quality,
            parser_profile,
            IngestionStatus.ACCEPTED,
            "reference_family_path",
            "narrative_dominant",
            f"quality_{quality.value}",
        )

    return _result(
        DocumentType.EXCLUDED,
        KnowledgeRole.REFERENCE,
        SourceQuality.MINIMAL,
        "none",
        IngestionStatus.QUARANTINED,
        "ambiguous",
        "no_deterministic_rule_matched",
    )


def _classify_pdf(candidate: SourceCandidate) -> ClassificationResult:
    filename = PurePosixPath(candidate.relative_path).name.replace("_", " ")
    if _TECHNICAL_PDF_RE.search(filename):
        return _result(
            DocumentType.CHEATSHEET_REFERENCE,
            KnowledgeRole.REFERENCE,
            SourceQuality.PARTIAL,
            "none",
            IngestionStatus.QUARANTINED,
            "technical_reference_pdf",
            "pdf_parser_unavailable",
        )
    return _result(
        DocumentType.EXCLUDED,
        KnowledgeRole.REFERENCE,
        SourceQuality.MINIMAL,
        "none",
        IngestionStatus.QUARANTINED,
        "ambiguous",
        "unsupported_pdf",
    )


def _collect_signals(text: str) -> _DocumentSignals:
    visible_text = _HTML_COMMENT_RE.sub("", text)
    content = _markdown_content_signals(visible_text)
    headings = tuple(
        _clean_heading(heading)
        for heading in (
            *_ATX_HEADING_RE.findall(visible_text),
            *_SETEXT_HEADING_RE.findall(visible_text),
        )
    )
    substantive_headings = tuple(heading for heading in headings if _is_substantive(heading))

    action_language = bool(_ACTION_LANGUAGE_RE.search(content.local_text))
    result_language = bool(_RESULT_LANGUAGE_RE.search(content.local_text))
    procedural = (len(substantive_headings) >= 2 and content.code_block_count >= 1) or (
        action_language and result_language
    )

    urls = tuple(url.rstrip(".,;:'\"") for url in _URL_RE.findall(visible_text))
    walkthrough_urls = tuple(url for url in urls if _url_is_external_walkthrough(visible_text, url))
    local_substance = bool(
        content.code_block_count or content.table_has_local_content or content.narrative_line_count
    )

    return _DocumentSignals(
        headings=headings,
        substantive_heading_count=len(substantive_headings),
        code_block_count=content.code_block_count,
        word_count=len(re.findall(r"\b[\w'-]+\b", content.local_text)),
        table_line_count=content.table_line_count,
        table_has_local_content=content.table_has_local_content,
        narrative_line_count=content.narrative_line_count,
        has_flag=_contains_final_flag(text),
        procedural=procedural,
        walkthrough_urls=walkthrough_urls,
        local_substance=local_substance,
        reference_link_count=content.reference_link_count,
    )


def _markdown_content_signals(text: str) -> _ContentSignals:
    tokens = MarkdownIt("commonmark").enable("table").parse(text)
    stack: list[str] = []
    local_parts: list[str] = []
    narrative_line_count = 0
    code_block_count = 0
    table_row_count = 0
    table_count = 0
    table_has_local_content = False
    reference_link_count = 0

    for token in tokens:
        if token.nesting == 1:
            if token.type == "tr_open":
                table_row_count += 1
            elif token.type == "table_open":
                table_count += 1
            stack.append(token.type)
            continue
        if token.nesting == -1:
            if stack:
                stack.pop()
            continue

        if token.type == "inline":
            inline = _inline_content_signals(tuple(token.children or ()))
            local_parts.append(inline.local_text)
            reference_link_count += inline.reference_link_count
            if "tbody_open" in stack and _contains_word(inline.local_text):
                table_has_local_content = True
            elif "table_open" not in stack and "heading_open" not in stack:
                narrative_line_count += sum(
                    _is_local_narrative_line(line) for line in inline.local_text.splitlines()
                )
        elif token.type in {"fence", "code_block"} and token.content.strip():
            code_block_count += 1
            local_parts.append(token.content)
        elif token.type == "html_block":
            html = _html_content_signals(token.content)
            local_parts.append(html.local_text)
            reference_link_count += html.reference_link_count
            narrative_line_count += sum(
                _is_local_narrative_line(line) for line in html.local_text.splitlines()
            )

    return _ContentSignals(
        local_text="\n".join(local_parts),
        narrative_line_count=narrative_line_count,
        code_block_count=code_block_count,
        table_line_count=table_row_count + table_count,
        table_has_local_content=table_has_local_content,
        reference_link_count=reference_link_count,
    )


def _inline_content_signals(children: tuple[Token, ...]) -> _InlineSignals:
    local_parts: list[str] = []
    reference_link_count = 0
    markdown_link_depth = 0
    html_parser = _HTMLContentParser()

    for child in children:
        if child.type == "link_open":
            reference_link_count += 1
            markdown_link_depth += 1
            continue
        if child.type == "link_close":
            markdown_link_depth = max(0, markdown_link_depth - 1)
            continue
        if child.type == "image":
            if _is_external_target(child.attrGet("src") or ""):
                reference_link_count += 1
            continue
        if child.type == "html_inline":
            html_parser.feed(child.content)
            html_text, text_links = _strip_text_references(html_parser.drain_local_text())
            reference_link_count += text_links
            if markdown_link_depth == 0:
                local_parts.append(html_text)
            continue
        if child.type in {"softbreak", "hardbreak"}:
            if markdown_link_depth == 0 and not html_parser.suppresses_text:
                local_parts.append("\n")
            continue
        if child.type == "code_inline":
            if markdown_link_depth == 0 and not html_parser.suppresses_text:
                local_parts.append(child.content)
            continue
        if child.type == "text" and markdown_link_depth == 0 and not html_parser.suppresses_text:
            local_text, text_links = _strip_text_references(child.content)
            local_parts.append(local_text)
            reference_link_count += text_links

    html_parser.close()
    trailing_text, text_links = _strip_text_references(html_parser.drain_local_text())
    local_parts.append(trailing_text)
    reference_link_count += text_links + html_parser.reference_link_count
    return _InlineSignals(
        local_text="".join(local_parts),
        reference_link_count=reference_link_count,
    )


def _html_content_signals(html: str) -> _InlineSignals:
    parser = _HTMLContentParser()
    parser.feed(html)
    parser.close()
    local_text, text_links = _strip_text_references(parser.drain_local_text())
    return _InlineSignals(
        local_text=local_text,
        reference_link_count=parser.reference_link_count + text_links,
    )


def _strip_text_references(text: str) -> tuple[str, int]:
    wiki = _scan_wiki_links(text)
    urls = _URL_RE.findall(wiki.local_text)
    return (
        _URL_RE.sub("", wiki.local_text),
        wiki.reference_link_count + len(urls),
    )


def _scan_wiki_links(text: str) -> _WikiScanResult:
    """Remove valid Obsidian wiki links with one bounded left-to-right scan."""
    local_parts: list[str] = []
    literal_start = 0
    opening: int | None = None
    position = 0
    reference_link_count = 0
    scanned_characters = 0

    while position < len(text):
        scanned_characters += 1
        if opening is None:
            if text.startswith("[[", position) and (position == 0 or text[position - 1] != "!"):
                local_parts.append(text[literal_start:position])
                opening = position
                position += 2
            else:
                position += 1
            continue

        if text[position] == "\n":
            local_parts.append(text[opening : position + 1])
            opening = None
            position += 1
            literal_start = position
        elif text.startswith("[[", position):
            local_parts.append(text[opening:position])
            opening = position
            position += 2
        elif text.startswith("]]", position):
            content = text[opening + 2 : position]
            target = content.partition("|")[0].strip()
            position += 2
            if target:
                reference_link_count += 1
            else:
                local_parts.append(text[opening:position])
            opening = None
            literal_start = position
        else:
            position += 1

    if opening is None:
        local_parts.append(text[literal_start:])
    else:
        local_parts.append(text[opening:])
    return _WikiScanResult(
        local_text="".join(local_parts),
        reference_link_count=reference_link_count,
        scanned_characters=scanned_characters,
    )


def _is_external_target(target: str) -> bool:
    return target.casefold().startswith(("http://", "https://"))


def _contains_word(text: str) -> bool:
    return bool(re.search(r"\w", text))


def _contains_final_flag(text: str) -> bool:
    if _HTB_FLAG_RE.search(text):
        return True
    flag_sections = (*_FLAG_HEADING_RE.finditer(text), *_USER_ROOT_FLAG_RE.finditer(text))
    return any(_HEX_32_RE.search(match.group("body")) for match in flag_sections)


def _url_is_external_walkthrough(text: str, url: str) -> bool:
    lowered_url = url.casefold()
    if "app.hackthebox.com/challenges" in lowered_url:
        return False
    start = text.find(url)
    context = text[max(0, start - 100) : start + len(url) + 100]
    return bool(_WALKTHROUGH_LANGUAGE_RE.search(f"{context} {url}"))


def _clean_heading(heading: str) -> str:
    return re.sub(r"<[^>]+>", " ", heading).strip()


def _is_substantive(heading: str) -> bool:
    normalized = re.sub(r"\s+", " ", heading).strip().casefold()
    return normalized not in {"user", "root"} and not _NON_PROCEDURAL_HEADING_RE.search(heading)


def _is_local_narrative_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.casefold().startswith(("tags:", "related to:", "see also:", "previous:", "next:")):
        return False
    if re.fullmatch(r"[-=* _]{3,}", stripped):
        return False
    return len(re.findall(r"\b[\w'-]+\b", stripped)) >= 5


def _is_table_dominant(signals: _DocumentSignals) -> bool:
    return (
        signals.table_has_local_content
        and signals.table_line_count >= 3
        and (
            signals.table_line_count >= signals.narrative_line_count
            or any("cheatsheet" in heading.casefold() for heading in signals.headings)
        )
    )


def _walkthrough_quality(signals: _DocumentSignals) -> SourceQuality:
    if signals.substantive_heading_count >= 3 and signals.code_block_count >= 2:
        return SourceQuality.COMPLETE
    if signals.word_count >= 200 and signals.code_block_count >= 1:
        return SourceQuality.COMPLETE
    return SourceQuality.PARTIAL


def _classification_path(candidate: SourceCandidate) -> str:
    """Retain corpus-family context when a nested file or folder is selected directly."""
    relative_path = PurePosixPath(candidate.relative_path).as_posix().casefold()
    physical_path = PurePosixPath(candidate.path).as_posix().casefold()
    for marker in (
        "write-ups/machines/",
        "write-ups/challanges/",
        "write-ups/challenges/",
        "write-ups/academy/",
        "01_information-gathering/",
    ):
        marker_offset = physical_path.find(marker)
        if marker_offset >= 0:
            return physical_path[marker_offset:]
    return relative_path


def _lesson_quality(signals: _DocumentSignals) -> SourceQuality:
    if signals.word_count >= 100 and len(signals.headings) >= 2:
        return SourceQuality.COMPLETE
    return SourceQuality.PARTIAL


def _is_machine_path(path: str) -> bool:
    return path.startswith("write-ups/machines/")


def _is_challenge_path(path: str) -> bool:
    return path.startswith("write-ups/challanges/") or path.startswith("write-ups/challenges/")


def _is_reference_family_path(path: str) -> bool:
    return path.startswith("write-ups/academy/") or path.startswith("01_information-gathering/")


def _result(
    document_type: DocumentType,
    knowledge_role: KnowledgeRole,
    quality: SourceQuality,
    parser_profile: str,
    ingestion_status: IngestionStatus,
    *reasons: str,
) -> ClassificationResult:
    return ClassificationResult(
        document_type=document_type,
        knowledge_role=knowledge_role,
        quality=quality,
        parser_profile=parser_profile,
        ingestion_status=ingestion_status,
        reasons=reasons,
    )
