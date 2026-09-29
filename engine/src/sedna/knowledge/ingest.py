"""Markdown-to-SQLite ingestion for the local Sedna knowledge base."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sedna.models import KnowledgeChunk, Phase
from sedna.store import SednaStore

_TITLE = re.compile(r"^(.+?)\n=+\s*$", re.MULTILINE)
_PREVIOUS = re.compile(r"^Previous\s*$", re.MULTILINE)


def ingest_markdown(
    path: str | Path,
    *,
    store: SednaStore,
    source_root: str | Path | None = None,
    maximum_chunk_chars: int = 3_500,
) -> list[KnowledgeChunk]:
    """Create legacy retrieval chunks from one Markdown article.

    Deprecated: this compatibility helper preserves the original SQLite-backed
    ``KnowledgeChunk`` workflow during migration. It is not used by the strategic
    ingestion pipeline; new integrations should start with ``IngestionPipeline``.
    """
    if maximum_chunk_chars < 1:
        raise ValueError("maximum_chunk_chars must be positive")

    markdown_path = Path(path)
    article_title, article_body = _extract_article(markdown_path.read_text(encoding="utf-8"))
    source_path = _source_path(markdown_path, source_root)
    phase = _phase_for_path(source_path)
    chunks: list[KnowledgeChunk] = []

    for index, content in enumerate(_split_paragraphs(article_body, maximum_chunk_chars), start=1):
        digest = hashlib.sha256(content.encode()).hexdigest()
        chunk_id = uuid5(NAMESPACE_URL, f"sedna:{source_path}:{index}:{digest}")
        existing = store.get(KnowledgeChunk, chunk_id)
        chunk = KnowledgeChunk(
            id=chunk_id,
            source_path=source_path,
            source_type="markdown",
            title=article_title if index == 1 else f"{article_title} ({index})",
            content=content,
            tags=("htb-academy",),
            phase=phase,
            created_at=existing.created_at if existing is not None else datetime.now(UTC),
        )
        store.save(chunk)
        chunks.append(chunk)
    return chunks


def _extract_article(markdown: str) -> tuple[str, str]:
    match = _TITLE.search(markdown)
    if match is None:
        raise ValueError("markdown does not contain a setext level-one title")

    title = match.group(1).strip()
    body = markdown[match.end() :]
    previous = _PREVIOUS.search(body)
    if previous is not None:
        body = body[: previous.start()]

    lines = [
        line.rstrip()
        for line in body.splitlines()
        if line.strip() != "* * *" and not line.lstrip().startswith("![")
    ]
    cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if not cleaned:
        raise ValueError("markdown article body is empty")
    return title, cleaned


def _split_paragraphs(content: str, maximum_chunk_chars: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for paragraph in re.split(r"\n{2,}", content):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        for part in _split_long_paragraph(paragraph, maximum_chunk_chars):
            candidate = part if not current else f"{current}\n\n{part}"
            if current and len(candidate) > maximum_chunk_chars:
                chunks.append(current)
                current = part
            else:
                current = candidate
    if current:
        chunks.append(current)
    return chunks


def _split_long_paragraph(paragraph: str, maximum_chunk_chars: int) -> list[str]:
    if len(paragraph) <= maximum_chunk_chars:
        return [paragraph]

    parts: list[str] = []
    remaining = paragraph
    while len(remaining) > maximum_chunk_chars:
        boundary = remaining.rfind(" ", 0, maximum_chunk_chars + 1)
        if boundary <= 0:
            boundary = maximum_chunk_chars
        parts.append(remaining[:boundary].strip())
        remaining = remaining[boundary:].strip()
    parts.append(remaining)
    return parts


def _source_path(path: Path, source_root: str | Path | None) -> str:
    if source_root is None:
        return path.name
    return path.relative_to(Path(source_root)).as_posix()


def _phase_for_path(source_path: str) -> Phase | None:
    if "information-gathering" in source_path:
        return Phase.RECON
    return None
