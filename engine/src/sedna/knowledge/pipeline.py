"""Deterministic orchestration from inventoried source to prepared knowledge."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path, PurePosixPath

from sedna.knowledge.classifier import ClassificationResult, classify_document
from sedna.knowledge.inventory import (
    SourceCandidate,
    stable_source_id,
    stable_source_namespace,
)
from sedna.knowledge.parsing import BlockKind, PreparedSource, parse_markdown
from sedna.knowledge.parsing.profiles import apply_profile
from sedna.knowledge.parsing.sanitize import EXCLUDED_FLAG, sanitize_searchable_text
from sedna.knowledge.parsing.segment import (
    OversizedStructuralGroupError,
    segment_document,
)
from sedna.knowledge.repository import CanonicalKnowledgeRepository, QuarantineRecord
from sedna.knowledge.schema import (
    AssetRef,
    DocumentManifest,
    DocumentType,
    ExtractionMetadata,
    IngestionStatus,
    KnowledgeRole,
    SourceQuality,
)

SCHEMA_VERSION = "1.2.0"
PARSER_ID = "markdown-it-commonmark"
PARSER_VERSION = "1"
EXTRACTOR_ID = "deterministic-foundation"
EXTRACTOR_VERSION = "5"
DEFAULT_LANGUAGE = "en"

_ATX_TITLE_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_SETEXT_TITLE_RE = re.compile(r"(?m)^([^\n]+)\n\s*(?:={4,}|-{4,})\s*$")
_TITLE_FLAG_CONTEXT_RE = re.compile(r"\b(?:flag|root|user)\b", re.IGNORECASE)
_STANDALONE_32_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]{32}(?![A-Za-z0-9])")


class CandidateIngestionError(ValueError):
    """A source-scoped failure that cannot safely produce a disposition."""

    def __init__(self, source_id: str, reason_code: str, message: str) -> None:
        super().__init__(f"{source_id}: {message}")
        self.source_id = source_id
        self.reason_code = reason_code


class SourceStructureError(ValueError):
    """A dedicated, source-caused structural parsing failure."""


def foundation_metadata() -> ExtractionMetadata:
    """Return the exact deterministic foundation versions used by this process."""
    return ExtractionMetadata(
        schema_version=SCHEMA_VERSION,
        parser_id=PARSER_ID,
        parser_version=PARSER_VERSION,
        extractor_id=EXTRACTOR_ID,
        extractor_version=EXTRACTOR_VERSION,
    )


class IngestionPipeline:
    """Prepare one inventoried source without ever writing beneath ``source_root``.

    Source-specific ``SourceStructureError`` failures are reviewable quarantines.
    Unexpected parser/profile failures are explicit ``CandidateIngestionError``
    failures so implementation defects are never disguised as bad input.
    """

    def __init__(
        self,
        source_root: Path,
        knowledge_root: Path,
        *,
        repository: CanonicalKnowledgeRepository | None = None,
        before_foundation_revision_change: Callable[[str], object] | None = None,
    ) -> None:
        requested_source_root = Path(source_root)
        self.source_root = requested_source_root.resolve(strict=True)
        if not self.source_root.is_dir():
            raise ValueError(f"source root is not a directory: {self.source_root}")

        resolved_knowledge = (
            Path(knowledge_root).resolve(strict=False)
            if repository is None
            else Path(repository.root)
        )
        if (
            resolved_knowledge == self.source_root
            or self.source_root in resolved_knowledge.parents
            or resolved_knowledge in self.source_root.parents
        ):
            raise ValueError("knowledge root must be outside the immutable source root")

        self._descriptor_lock = threading.Lock()
        self._owns_repository = repository is None
        if before_foundation_revision_change is not None and not callable(
            before_foundation_revision_change
        ):
            raise TypeError("before_foundation_revision_change must be callable")
        self._before_foundation_revision_change = before_foundation_revision_change
        self.source_namespace = stable_source_namespace(self.source_root)
        self._source_fd: int | None = os.open(
            self.source_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            source_status = os.fstat(self._source_fd)
            expected_status = os.stat(self.source_root, follow_symlinks=False)
            if not stat.S_ISDIR(source_status.st_mode) or (
                source_status.st_dev,
                source_status.st_ino,
            ) != (expected_status.st_dev, expected_status.st_ino):
                raise ValueError("source root changed while it was being opened")
            self.repository = (
                CanonicalKnowledgeRepository(resolved_knowledge)
                if repository is None
                else repository
            )
        except Exception:
            os.close(self._source_fd)
            self._source_fd = None
            raise

        self.extraction = foundation_metadata()
        self.last_outcome: str | None = None

    def __enter__(self) -> IngestionPipeline:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    def close(self) -> None:
        """Close the source and canonical repository descriptors idempotently."""
        descriptor_lock = getattr(self, "_descriptor_lock", None)
        if descriptor_lock is None:
            return
        with descriptor_lock:
            source_fd = self._source_fd
            if source_fd is not None:
                self._source_fd = None
                os.close(source_fd)
        repository = getattr(self, "repository", None)
        if repository is not None and getattr(self, "_owns_repository", False):
            repository.close()

    def prepare(
        self,
        candidate: SourceCandidate,
        *,
        force_reprepare: bool = False,
    ) -> PreparedSource | None:
        """Prepare one current candidate, optionally refreshing an accepted unchanged source.

        ``force_reprepare`` is deliberately narrow: it bypasses only the accepted
        foundation's unchanged short-circuit.  It does not reprocess excluded or
        foundation-quarantined sources and it never relaxes descriptor confinement.
        """
        self._ensure_open()
        self.last_outcome = None
        try:
            return self._prepare(candidate, force_reprepare=force_reprepare)
        except Exception:
            self.last_outcome = "failed"
            raise

    def _prepare(
        self,
        candidate: SourceCandidate,
        *,
        force_reprepare: bool,
    ) -> PreparedSource | None:
        source_bytes = self._verified_candidate_bytes(candidate)
        self._verify_current_asset_path_set(candidate)
        asset_refs = self._verified_asset_refs(candidate)
        existing = self._load_existing_manifest(candidate.source_id)
        if existing is not None:
            self._require_compatible_source_namespace(existing, candidate)
        if existing is not None and self._is_unchanged(existing, candidate, asset_refs):
            self._validate_incremental_state(existing)
            if existing.ingestion_status is not IngestionStatus.ACCEPTED:
                self.repository.resume_nonaccepted_projection_revision(
                    existing.source_id,
                    before_barrier_clear=self._before_foundation_revision_change,
                )
            if not force_reprepare or existing.ingestion_status is not IngestionStatus.ACCEPTED:
                self.last_outcome = "unchanged"
                return None

        if candidate.suffix.casefold() != ".md":
            classification = classify_document(candidate, None)
            return self._persist_quarantine(
                candidate,
                classification,
                asset_refs,
                title=self._safe_stem(candidate.relative_path),
                reason_code="unsupported_parser",
                message="No deterministic parser is available for this source format.",
            )

        try:
            text = source_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return self._persist_unclassified_quarantine(
                candidate,
                asset_refs,
                title=self._safe_stem(candidate.relative_path),
                reason_code="invalid_encoding",
                message="Markdown source is not valid UTF-8.",
            )

        classification = classify_document(candidate, text)
        preliminary_title = self._title_from_text(text, candidate.relative_path)
        if classification.ingestion_status is IngestionStatus.EXCLUDED:
            manifest = self._manifest(
                candidate,
                classification,
                asset_refs,
                title=preliminary_title,
            )
            self.repository.transition_source(
                manifest,
                None,
                before_foundation_revision_change=self._before_foundation_revision_change,
            )
            self.last_outcome = "excluded"
            return None

        if classification.ingestion_status is IngestionStatus.QUARANTINED:
            return self._persist_quarantine(
                candidate,
                classification,
                asset_refs,
                title=preliminary_title,
                reason_code=classification.reasons[0],
                message="The deterministic classifier could not accept this source.",
            )

        try:
            parsed = parse_markdown(candidate.source_id, candidate.relative_path, text)
        except SourceStructureError:
            return self._persist_quarantine(
                candidate,
                classification,
                asset_refs,
                title=preliminary_title,
                reason_code="structural_parse_error",
                message="The source could not be structurally parsed with its selected profile.",
            )
        except Exception as exc:
            raise CandidateIngestionError(
                candidate.source_id,
                "parser_failure",
                "structural parser failed unexpectedly",
            ) from exc

        try:
            profiled = apply_profile(parsed, classification.parser_profile)
        except Exception as exc:
            raise CandidateIngestionError(
                candidate.source_id,
                "profile_failure",
                "source profile failed unexpectedly",
            ) from exc

        try:
            segments = segment_document(profiled)
        except OversizedStructuralGroupError as exc:
            return self._persist_quarantine(
                candidate,
                classification,
                asset_refs,
                title=self._title_from_document(profiled, candidate.relative_path),
                reason_code="oversized_indivisible_block",
                message=str(exc),
            )
        except Exception as exc:
            raise CandidateIngestionError(
                candidate.source_id,
                "segmenter_failure",
                "logical segmenter failed unexpectedly",
            ) from exc

        title = self._title_from_document(profiled, candidate.relative_path)
        if not segments:
            return self._persist_quarantine(
                candidate,
                classification,
                asset_refs,
                title=title,
                reason_code="no_searchable_segments",
                message="The selected profile produced no searchable logical segments.",
            )

        manifest = self._manifest(
            candidate,
            classification,
            asset_refs,
            title=title,
        )
        try:
            prepared = PreparedSource(manifest=manifest, document=profiled, segments=segments)
        except ValueError as exc:
            raise CandidateIngestionError(
                candidate.source_id,
                "prepared_source_invariant",
                "prepared source violated the canonical consistency contract",
            ) from exc

        self.repository.transition_source(
            manifest,
            None,
            before_foundation_revision_change=self._before_foundation_revision_change,
        )
        self.last_outcome = "accepted"
        return prepared

    def _verified_candidate_bytes(self, candidate: SourceCandidate) -> bytes:
        relative_path = self._validated_relative_path(
            candidate.relative_path,
            candidate.source_id,
        )
        if candidate.source_id != stable_source_id(relative_path):
            raise CandidateIngestionError(
                candidate.source_id,
                "candidate_identity_mismatch",
                "source identity does not match its relative path",
            )
        if candidate.source_namespace not in {None, self.source_namespace}:
            raise CandidateIngestionError(
                candidate.source_id,
                "candidate_namespace_mismatch",
                "source namespace does not match its retained source root",
            )
        expected_path = self.source_root.joinpath(*PurePosixPath(relative_path).parts)
        if Path(candidate.path).resolve(strict=False) != expected_path.resolve(strict=False):
            raise CandidateIngestionError(
                candidate.source_id,
                "candidate_path_mismatch",
                "candidate path is not the declared path beneath source root",
            )
        if candidate.suffix.casefold() != PurePosixPath(relative_path).suffix.casefold():
            raise CandidateIngestionError(
                candidate.source_id,
                "candidate_suffix_mismatch",
                "candidate suffix does not match its relative path",
            )

        content = self._read_relative_file(relative_path, candidate.source_id)
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != candidate.size_bytes or digest != candidate.sha256:
            raise CandidateIngestionError(
                candidate.source_id,
                "stale_candidate",
                "source changed since inventory",
            )
        return content

    def _verified_asset_refs(self, candidate: SourceCandidate) -> tuple[AssetRef, ...]:
        refs: list[AssetRef] = []
        seen_paths: set[str] = set()
        for asset in candidate.assets:
            relative_path = self._validated_relative_path(
                asset.relative_path,
                candidate.source_id,
            )
            if relative_path in seen_paths:
                raise CandidateIngestionError(
                    candidate.source_id,
                    "duplicate_asset",
                    "asset inventory contains a duplicate relative path",
                )
            seen_paths.add(relative_path)
            expected_path = self.source_root.joinpath(*PurePosixPath(relative_path).parts)
            if Path(asset.path).resolve(strict=False) != expected_path.resolve(strict=False):
                raise CandidateIngestionError(
                    candidate.source_id,
                    "asset_path_mismatch",
                    "asset path is not beneath source root",
                )
            content = self._read_relative_file(relative_path, candidate.source_id)
            digest = hashlib.sha256(content).hexdigest()
            if len(content) != asset.size_bytes or digest != asset.sha256:
                raise CandidateIngestionError(
                    candidate.source_id,
                    "stale_asset",
                    "asset changed since inventory",
                )
            refs.append(AssetRef(path=relative_path, sha256=digest))
        return tuple(sorted(refs, key=lambda item: item.path))

    def _verify_current_asset_path_set(self, candidate: SourceCandidate) -> None:
        expected = frozenset(asset.relative_path for asset in candidate.assets)
        current = self._current_associated_asset_paths(candidate)
        if current != expected:
            raise CandidateIngestionError(
                candidate.source_id,
                "stale_asset_inventory",
                "associated asset path set changed since inventory",
            )

    def _current_associated_asset_paths(self, candidate: SourceCandidate) -> frozenset[str]:
        source_path = PurePosixPath(candidate.relative_path)
        root_fd = self._duplicate_source_root()
        directory_fds = [root_fd]
        current_fd = root_fd
        try:
            for part in source_path.parent.parts:
                try:
                    current_fd = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise CandidateIngestionError(
                        candidate.source_id,
                        "unsafe_source_path",
                        "source directory is not safely readable beneath source root",
                    ) from exc
                directory_fds.append(current_fd)

            prefix = source_path.parent.as_posix()
            if prefix == ".":
                prefix = ""
            return frozenset(
                self._walk_asset_paths(
                    current_fd,
                    prefix,
                    candidate.source_id,
                )
            )
        finally:
            for descriptor in reversed(directory_fds):
                os.close(descriptor)

    def _walk_asset_paths(
        self,
        directory_fd: int,
        prefix: str,
        source_id: str,
    ) -> tuple[str, ...]:
        paths: list[str] = []
        try:
            entries = tuple(sorted(os.scandir(directory_fd), key=lambda entry: entry.name))
        except OSError as exc:
            raise CandidateIngestionError(
                source_id,
                "unsafe_asset_inventory",
                "associated asset directory changed during verification",
            ) from exc
        for entry in entries:
            relative_path = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise CandidateIngestionError(
                    source_id,
                    "unsafe_asset_inventory",
                    "associated asset changed during verification",
                ) from exc
            if stat.S_ISDIR(status.st_mode):
                try:
                    child_fd = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise CandidateIngestionError(
                        source_id,
                        "unsafe_asset_inventory",
                        "associated asset directory is not safely readable",
                    ) from exc
                try:
                    paths.extend(self._walk_asset_paths(child_fd, relative_path, source_id))
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(status.st_mode):
                if entry.name == ".DS_Store":
                    continue
                if PurePosixPath(relative_path).suffix.casefold() in {".md", ".pdf"}:
                    continue
                paths.append(relative_path)
            else:
                raise CandidateIngestionError(
                    source_id,
                    "unsafe_asset_inventory",
                    "associated asset inventory contains a non-regular entry",
                )
        return tuple(paths)

    def _read_relative_file(self, relative_path: str, source_id: str) -> bytes:
        parts = PurePosixPath(relative_path).parts
        root_fd = self._duplicate_source_root()
        parent_fds: list[int] = [root_fd]
        current_fd = root_fd
        try:
            for part in parts[:-1]:
                try:
                    directory_fd = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise CandidateIngestionError(
                        source_id,
                        "unsafe_source_path",
                        "candidate path is not a safe regular file beneath source root",
                    ) from exc
                parent_fds.append(directory_fd)
                current_fd = directory_fd
            try:
                file_fd = os.open(
                    parts[-1],
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise CandidateIngestionError(
                    source_id,
                    "unsafe_source_path",
                    "candidate path is not a safe regular file beneath source root",
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise CandidateIngestionError(
                        source_id,
                        "unsafe_source_path",
                        "candidate path is not a safe regular file beneath source root",
                    )
                with os.fdopen(file_fd, "rb") as stream:
                    file_fd = -1
                    return stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            for descriptor in reversed(parent_fds):
                os.close(descriptor)

    @staticmethod
    def _validated_relative_path(relative_path: str, source_id: str) -> str:
        pure = PurePosixPath(relative_path)
        if (
            not relative_path
            or "\x00" in relative_path
            or "\\" in relative_path
            or pure.is_absolute()
            or pure.as_posix() != relative_path
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise CandidateIngestionError(
                source_id,
                "unsafe_relative_path",
                "candidate does not use a safe relative path",
            )
        return relative_path

    def _load_existing_manifest(self, source_id: str) -> DocumentManifest | None:
        try:
            return self.repository.load_manifest(source_id)
        except FileNotFoundError:
            return None

    def _is_unchanged(
        self,
        manifest: DocumentManifest,
        candidate: SourceCandidate,
        asset_refs: tuple[AssetRef, ...],
    ) -> bool:
        return (
            manifest.source_namespace == self.source_namespace
            and manifest.path == candidate.relative_path
            and manifest.sha256 == candidate.sha256
            and manifest.assets == asset_refs
            and manifest.extraction == self.extraction
            and self._sanitize_title(manifest.title) == manifest.title
        )

    def _require_compatible_source_namespace(
        self,
        manifest: DocumentManifest,
        candidate: SourceCandidate,
    ) -> None:
        """Reject a relative-path identity already owned by another source root."""
        if manifest.source_namespace is None:
            if manifest.path == candidate.relative_path and manifest.sha256 == candidate.sha256:
                return
            raise CandidateIngestionError(
                candidate.source_id,
                "legacy_source_namespace_collision",
                "legacy source ownership cannot be migrated from different content",
            )
        if manifest.source_namespace != self.source_namespace:
            raise CandidateIngestionError(
                candidate.source_id,
                "source_namespace_collision",
                "source identity is already owned by another source root",
            )

    def _validate_incremental_state(self, manifest: DocumentManifest) -> None:
        try:
            quarantine = self.repository.load_quarantine(manifest.source_id)
        except FileNotFoundError:
            quarantine = None
        except ValueError as exc:
            raise CandidateIngestionError(
                manifest.source_id,
                "canonical_state_mismatch",
                "stored quarantine record is invalid",
            ) from exc
        try:
            self.repository.validate_source_state(manifest, quarantine)
        except ValueError as exc:
            raise CandidateIngestionError(
                manifest.source_id,
                "canonical_state_mismatch",
                "manifest and quarantine disposition contracts disagree",
            ) from exc

    def _persist_unclassified_quarantine(
        self,
        candidate: SourceCandidate,
        asset_refs: tuple[AssetRef, ...],
        *,
        title: str,
        reason_code: str,
        message: str,
    ) -> None:
        manifest = DocumentManifest(
            source_id=candidate.source_id,
            source_namespace=self.source_namespace,
            path=candidate.relative_path,
            sha256=candidate.sha256,
            title=title,
            language=DEFAULT_LANGUAGE,
            document_type=DocumentType.EXCLUDED,
            knowledge_role=KnowledgeRole.REFERENCE,
            quality=SourceQuality.UNUSABLE,
            parser_profile="none",
            ingestion_status=IngestionStatus.QUARANTINED,
            extraction=self.extraction,
            assets=asset_refs,
            quality_reason_codes=(reason_code,),
            quarantine_reasons=(reason_code,),
        )
        self._write_quarantine_pair(manifest, reason_code, message)
        self.last_outcome = "quarantined"
        return None

    def _persist_quarantine(
        self,
        candidate: SourceCandidate,
        classification: ClassificationResult,
        asset_refs: tuple[AssetRef, ...],
        *,
        title: str,
        reason_code: str,
        message: str,
    ) -> None:
        manifest = self._manifest(
            candidate,
            classification,
            asset_refs,
            title=title,
            ingestion_status=IngestionStatus.QUARANTINED,
            quarantine_reasons=(reason_code,),
        )
        self._write_quarantine_pair(manifest, reason_code, message)
        self.last_outcome = "quarantined"
        return None

    def _write_quarantine_pair(
        self,
        manifest: DocumentManifest,
        reason_code: str,
        message: str,
    ) -> None:
        record = QuarantineRecord(
            quarantine_id=f"quarantine-{manifest.source_id}",
            source_id=manifest.source_id,
            reason_codes=(reason_code,),
            messages=(self._sanitize_title(message),),
            parser_profile=manifest.parser_profile,
            extraction=self.extraction,
        )
        self.repository.transition_source(
            manifest,
            record,
            before_foundation_revision_change=self._before_foundation_revision_change,
        )

    def _manifest(
        self,
        candidate: SourceCandidate,
        classification: ClassificationResult,
        asset_refs: tuple[AssetRef, ...],
        *,
        title: str,
        ingestion_status: IngestionStatus | None = None,
        quarantine_reasons: tuple[str, ...] = (),
    ) -> DocumentManifest:
        return DocumentManifest(
            source_id=candidate.source_id,
            source_namespace=self.source_namespace,
            path=candidate.relative_path,
            sha256=candidate.sha256,
            title=self._sanitize_title(title),
            language=DEFAULT_LANGUAGE,
            document_type=classification.document_type,
            knowledge_role=classification.knowledge_role,
            quality=classification.quality,
            parser_profile=classification.parser_profile,
            ingestion_status=ingestion_status or classification.ingestion_status,
            extraction=self.extraction,
            assets=asset_refs,
            quality_reason_codes=classification.reasons,
            quarantine_reasons=quarantine_reasons,
        )

    def _title_from_document(self, document: object, relative_path: str) -> str:
        blocks = getattr(document, "blocks", ())
        for block in blocks:
            if block.kind is BlockKind.HEADING and block.text.strip():
                return self._sanitize_title(block.text)
        return self._safe_stem(relative_path)

    def _title_from_text(self, text: str, relative_path: str) -> str:
        for pattern in (_ATX_TITLE_RE, _SETEXT_TITLE_RE):
            match = pattern.search(text)
            if match is not None and match.group(1).strip():
                return self._sanitize_title(match.group(1))
        return self._safe_stem(relative_path)

    def _safe_stem(self, relative_path: str) -> str:
        return self._sanitize_title(PurePosixPath(relative_path).stem)

    @staticmethod
    def _sanitize_title(text: str) -> str:
        sanitized = sanitize_searchable_text(text.strip(), (text.strip(),)).strip()
        if _TITLE_FLAG_CONTEXT_RE.search(sanitized):
            sanitized = _STANDALONE_32_HEX_RE.sub(EXCLUDED_FLAG, sanitized)
        return sanitized or "Untitled source"

    def _ensure_open(self) -> int:
        with self._descriptor_lock:
            if self._source_fd is None:
                raise RuntimeError("pipeline is closed")
            return self._source_fd

    def _duplicate_source_root(self) -> int:
        with self._descriptor_lock:
            if self._source_fd is None:
                raise RuntimeError("pipeline is closed")
            return os.dup(self._source_fd)


__all__ = [
    "CandidateIngestionError",
    "IngestionPipeline",
    "SourceStructureError",
    "foundation_metadata",
]
