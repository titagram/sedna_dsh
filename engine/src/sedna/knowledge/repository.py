"""Deterministic, atomic persistence for canonical ingestion records."""

from __future__ import annotations

import fcntl
import inspect
import json
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePath
from typing import Annotated, TypeVar
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.parsing.models import validate_prepared_source
from sedna.knowledge.schema import (
    DocumentManifest,
    ExtractionMetadata,
    SemanticKnowledgeBundle,
    SemanticQuarantineRecord,
    SemanticVerificationRecord,
    foundation_manifest_digest,
)
from sedna.knowledge.schema.execution import ExecutionExample
from sedna.knowledge.semantic.compiler import (
    EXECUTION_EXAMPLE_SCHEMA_VERSION,
    SEMANTIC_COMPILER_VERSION,
    SEMANTIC_SCHEMA_VERSION,
)
from sedna.knowledge.semantic.drafts import SemanticCompilationResult
from sedna.knowledge.semantic.prompts import (
    CRITIC_PROMPT_VERSION,
    EXTRACTOR_PROMPT_VERSION,
    REPAIR_PROMPT_VERSION,
)

_LEGACY_RETRIEVAL_SCHEMA_VERSION = "2.4.0"
_LEGACY_RETRIEVAL_COMPILER_VERSION = "8"
_LEGACY_RETRIEVAL_PROMPT_VERSION = "1"

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_MAX_SEMANTIC_INVENTORY_FILES = 100_000
_MAX_SEMANTIC_RECORD_BYTES = 64 * 1024 * 1024
_MAX_JOURNAL_PROMOTION_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_JOURNAL_PROMOTION_ASSET_BYTES = 8 * 1024 * 1024


def _validate_stable_id(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or Path(value).is_absolute()
    ):
        raise ValueError("identifier must be a safe path segment")
    return value


StableId = Annotated[str, Field(min_length=1), AfterValidator(_validate_stable_id)]
NonEmptyString = Annotated[str, Field(min_length=1)]


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(sorted(values))
    if len(set(normalized)) != len(normalized):
        raise ValueError("values must be unique")
    return normalized


class SemanticBundleEnumerationError(ValueError):
    """One canonical semantic source cannot safely participate in retrieval."""

    def __init__(self, source_id: str, reason_code: str, message: str) -> None:
        self.source_id = source_id
        self.reason_code = reason_code
        super().__init__(f"semantic source {source_id!r} {message}")


class SemanticSnapshotChangedError(RuntimeError):
    """The canonical semantic inventory changed before a guarded index commit."""


@dataclass(frozen=True, slots=True)
class SemanticRepositorySnapshot:
    """One lock-consistent verified semantic corpus and raw inventory revision."""

    bundles: tuple[SemanticKnowledgeBundle, ...]
    revision: str


@dataclass(frozen=True, slots=True)
class _ProjectionRevisionBarrier:
    """Durable proof that an index barrier must precede one foundation revision."""

    source_id: str
    previous_foundation_sha256: str
    target_foundation_sha256: str


class QuarantineRecord(BaseModel):
    """A reviewable explanation for why one source could not be prepared."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    quarantine_id: StableId
    source_id: StableId
    reason_codes: tuple[NonEmptyString, ...] = Field(min_length=1)
    messages: tuple[NonEmptyString, ...] = Field(min_length=1)
    parser_profile: NonEmptyString
    extraction: ExtractionMetadata

    @field_validator("reason_codes", "messages")
    @classmethod
    def normalize_explanations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Make semantically set-like explanations byte-stable."""
        return _sorted_unique(values)


class IngestionFailure(BaseModel):
    """One deterministic source-level failure included in a run report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: StableId
    reason_code: NonEmptyString
    message: NonEmptyString


class IngestionReport(BaseModel):
    """A complete deterministic accounting of a foundation ingestion run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: StableId
    extraction: ExtractionMetadata
    inventoried_source_ids: tuple[StableId, ...] = ()
    accepted_source_ids: tuple[StableId, ...] = ()
    excluded_source_ids: tuple[StableId, ...] = ()
    quarantined_source_ids: tuple[StableId, ...] = ()
    unchanged_source_ids: tuple[StableId, ...] = ()
    failures: tuple[IngestionFailure, ...] = ()
    warnings: tuple[NonEmptyString, ...] = ()

    @field_validator(
        "inventoried_source_ids",
        "accepted_source_ids",
        "excluded_source_ids",
        "quarantined_source_ids",
        "unchanged_source_ids",
        "warnings",
    )
    @classmethod
    def normalize_string_sets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize order and reject duplicate report entries."""
        return _sorted_unique(values)

    @field_validator("failures")
    @classmethod
    def normalize_failures(
        cls, values: tuple[IngestionFailure, ...]
    ) -> tuple[IngestionFailure, ...]:
        """Keep failures stable regardless of source traversal order."""
        ordered = tuple(
            sorted(values, key=lambda item: (item.source_id, item.reason_code, item.message))
        )
        if len({item.source_id for item in ordered}) != len(ordered):
            raise ValueError("each failed source must appear once")
        return ordered

    @model_validator(mode="after")
    def validate_complete_accounting(self) -> IngestionReport:
        """Require each inventoried source to have exactly one run outcome."""
        outcome_ids = (
            self.accepted_source_ids
            + self.excluded_source_ids
            + self.quarantined_source_ids
            + self.unchanged_source_ids
            + tuple(failure.source_id for failure in self.failures)
        )
        if len(outcome_ids) != len(set(outcome_ids)) or set(outcome_ids) != set(
            self.inventoried_source_ids
        ):
            raise ValueError("every inventoried source must have exactly one outcome")
        return self


class CanonicalKnowledgeRepository:
    """Persist canonical JSON through a retained, resolved root descriptor.

    Write methods return the nominal canonical ``Path`` beneath the original resolved
    root pathname. IO remains bound to the retained directory when that pathname is
    renamed or replaced, so a returned path is a location hint rather than an identity
    handle in that exceptional case.

    A supplied ``root_fd`` is duplicated rather than adopted; the caller retains ownership.
    That guarded mode requires an existing nominal root with the same physical identity and
    never creates path components before the match is established.

    Source transitions use POSIX ``flock`` locks opened relative to the retained
    root.  The locks are advisory, but every transition entry point participates;
    their open-file-description lifetime also releases locks after process death.
    Construction fails closed on platforms without these POSIX semantics.
    """

    _DIRECTORIES = frozenset(
        {
            "manifests",
            "quarantine",
            "ingestion_reports",
            "semantic_bundles",
            "semantic_compilation_guards",
            "promotion_publication_guards",
            "semantic_verification",
            "semantic_quarantine",
            "transactions",
        }
    )
    _SEMANTIC_DIRECTORIES = (
        "semantic_bundles",
        "semantic_verification",
        "semantic_quarantine",
    )

    def __init__(self, root: Path, *, root_fd: int | None = None) -> None:
        self._descriptor_lock = threading.RLock()
        self._promotion_guard_local = threading.local()
        self._root_fd: int | None = None
        self._require_safe_primitives()
        requested_root = Path(root)
        if "\x00" in os.fspath(requested_root):
            raise ValueError("repository root must not contain NUL")
        if root_fd is None:
            requested_root.mkdir(parents=True, exist_ok=True)
        self.root = requested_root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError(f"repository root is not a directory: {self.root}")
        expected = os.stat(self.root, follow_symlinks=False)
        retained_root_fd = (
            os.open(self.root, self._directory_open_flags()) if root_fd is None else os.dup(root_fd)
        )
        try:
            actual = os.fstat(retained_root_fd)
            if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
                expected.st_dev,
                expected.st_ino,
            ):
                raise ValueError("repository root changed while it was being opened")
        except Exception:
            os.close(retained_root_fd)
            raise
        self._root_fd = retained_root_fd
        try:
            self._recover_pending_transactions()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> CanonicalKnowledgeRepository:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    def close(self) -> None:
        """Release the retained root descriptor; repeated calls are harmless."""
        descriptor_lock = getattr(self, "_descriptor_lock", None)
        if descriptor_lock is None:
            return
        with descriptor_lock:
            root_fd = self._root_fd
            if root_fd is not None:
                self._root_fd = None
                os.close(root_fd)

    def write_manifest(self, manifest: DocumentManifest) -> Path:
        """Persist one source manifest and return its nominal canonical path."""
        return self._write_model("manifests", manifest.source_id, manifest)

    def write_quarantine(self, record: QuarantineRecord) -> Path:
        """Persist one quarantine explanation and return its nominal canonical path."""
        return self._write_model("quarantine", record.source_id, record)

    def write_ingestion_report(self, report: IngestionReport) -> Path:
        """Persist one deterministic report and return its nominal canonical path."""
        return self._write_model("ingestion_reports", report.run_id, report)

    def write_semantic_result(self, result: SemanticCompilationResult) -> None:
        """Durably apply one verified or quarantined semantic source disposition."""
        if not isinstance(result, SemanticCompilationResult):
            raise TypeError("result must be a SemanticCompilationResult")
        result = SemanticCompilationResult.model_validate(
            result.model_dump(mode="json", warnings="error")
        )
        if result.disposition in {"failed", "unchanged"}:
            return

        verification = result.verification
        if verification is None:
            raise ValueError("terminal semantic result requires verification")
        source_id = verification.source_id
        source_sha256 = verification.source_sha256
        _validate_stable_id(source_id)
        if result.disposition == "verified":
            bundle = result.bundle
            if (
                bundle is None
                or bundle.source_id != source_id
                or bundle.source_sha256 != source_sha256
            ):
                raise ValueError("semantic bundle and verification identities must match")
        else:
            quarantine = result.quarantine
            if (
                quarantine is None
                or quarantine.source_id != source_id
                or quarantine.source_sha256 != source_sha256
            ):
                raise ValueError("semantic quarantine and verification identities must match")

        with (
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            snapshots = {
                directory: self._read_optional_bytes(directory, source_id)
                for directory in self._SEMANTIC_DIRECTORIES
            }
            self._write_semantic_transition_journal(source_id, snapshots)
            try:
                self._write_model("semantic_verification", source_id, verification)
                if result.disposition == "verified":
                    self._write_model("semantic_bundles", source_id, result.bundle)
                    self._delete_record("semantic_quarantine", source_id)
                else:
                    self._write_model("semantic_quarantine", source_id, result.quarantine)
                    self._delete_record("semantic_bundles", source_id)
                self._fsync_directories(self._SEMANTIC_DIRECTORIES)
                self._delete_semantic_transition_journal(source_id)
            except BaseException as original_error:
                rollback_errors = self._restore_semantic_snapshots(source_id, snapshots)
                if not rollback_errors:
                    try:
                        self._delete_semantic_transition_journal(source_id)
                    except BaseException as rollback_error:
                        rollback_errors.append(rollback_error)
                for rollback_error in rollback_errors:
                    original_error.add_note(
                        "semantic transition rollback remains recoverable: "
                        f"{type(rollback_error).__name__}: {rollback_error}"
                    )
                raise

    def invalidate_failed_semantic_result(self, prepared: PreparedSource) -> bool:
        """Remove stale semantics after a failed compile for the current accepted source.

        Callers must hold :meth:`semantic_compilation_guard` for ``prepared`` so a concurrent
        compiler or foundation transition cannot invalidate a newer source state.
        """
        prepared = validate_prepared_source(prepared)
        source_id = prepared.manifest.source_id
        with (
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            try:
                manifest = self.load_manifest(source_id)
            except FileNotFoundError:
                return False
            if manifest.ingestion_status.value != "accepted" or manifest != prepared.manifest:
                return False
            self._invalidate_semantic_state(source_id, prepared.manifest.sha256)
            return True

    def open_index_directory(self) -> int:
        """Return a descriptor for the disposable index directory beneath this root."""
        directory = "indexes"
        with self._descriptor_lock:
            root_fd = self._ensure_open()
            with suppress(FileExistsError):
                os.mkdir(directory, mode=0o755, dir_fd=root_fd)
            try:
                directory_fd = os.open(
                    directory,
                    self._directory_open_flags(),
                    dir_fd=root_fd,
                )
            except OSError as error:
                raise ValueError("repository index directory is unavailable") from error
        try:
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise ValueError("repository index target is not a directory")
            return directory_fd
        except Exception:
            os.close(directory_fd)
            raise

    def assert_root_identity(self) -> None:
        """Reject a replaced root pathname instead of mixing it with retained descriptors."""
        with self._descriptor_lock:
            root_fd = self._ensure_open()
            retained = os.fstat(root_fd)
            try:
                current = os.stat(self.root, follow_symlinks=False)
            except FileNotFoundError as error:
                raise RuntimeError("repository root identity changed") from error
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (
            retained.st_dev,
            retained.st_ino,
        ):
            raise RuntimeError("repository root identity changed")

    def load_semantic_bundle(self, source_id: str) -> SemanticKnowledgeBundle:
        """Load a strictly validated verified semantic bundle."""
        return self._load_semantic_component(source_id, "bundle")

    def load_execution_examples(
        self,
        source_id: str,
        *,
        parent_artifact_id: str,
        example_ids: tuple[str, ...] | None = None,
    ) -> tuple[ExecutionExample, ...]:
        """Load bundle-owned examples for one exact parent, sorted by example ID.

        Uses the descriptor-relative bundle loader only; it never searches command
        text and never falls back to filesystem paths.
        """
        _validate_stable_id(source_id)
        for identifier in (parent_artifact_id,) + tuple(example_ids or ()):
            _validate_stable_id(identifier)
        bundle = self.load_semantic_bundle(source_id)
        selected = tuple(
            example
            for example in bundle.execution_examples
            if example.parent_artifact_id == parent_artifact_id
        )
        ordered = tuple(sorted(selected, key=lambda example: example.example_id))
        if example_ids is not None and set(example_ids) != {
            example.example_id for example in ordered
        }:
            raise ValueError("example_ids must exactly match the parent's execution examples")
        return ordered

    def load_semantic_verification(self, source_id: str) -> SemanticVerificationRecord:
        """Load a strictly validated semantic verification record."""
        return self._load_semantic_component(source_id, "verification")

    def load_semantic_quarantine(self, source_id: str) -> SemanticQuarantineRecord:
        """Load a strictly validated semantic quarantine record."""
        return self._load_semantic_component(source_id, "quarantine")

    def iter_semantic_bundles(self) -> Iterator[SemanticKnowledgeBundle]:
        """Return a sorted snapshot iterator of current verified semantic bundles.

        Enumeration and every record load remain descriptor-relative.  Valid quarantined
        dispositions are omitted; any unsafe, incomplete, corrupt, or stale verified state
        fails the complete enumeration before a caller can consume a partial corpus.
        """
        return iter(self.semantic_bundle_snapshot().bundles)

    def semantic_bundle_snapshot(self) -> SemanticRepositorySnapshot:
        """Return verified bundles and a revision from one shared inventory lock."""
        with self._semantic_inventory_lock(exclusive=False):
            return self._semantic_bundle_snapshot_locked()

    def retrieval_read_revision(self) -> str:
        """Return a lock-free-from-index token that rejects transitional reads.

        Callers must not retain an index lock while invoking this method.  Comparing
        tokens around one index read catches a complete canonical transition, while
        the pending-journal checks reject every still-open projection barrier.
        """
        with self._semantic_inventory_lock(exclusive=False):
            self._require_no_pending_semantic_transactions()
            entries, _ = self._semantic_inventory_entries()
            self._require_no_pending_semantic_transactions()
            return self._semantic_inventory_revision(entries)

    @contextmanager
    def semantic_snapshot_guard(self, expected_revision: str) -> Iterator[None]:
        """Verify and hold one semantic revision stable through an external commit."""
        if (
            type(expected_revision) is not str
            or len(expected_revision) != 64
            or any(character not in "0123456789abcdef" for character in expected_revision)
        ):
            raise ValueError("semantic snapshot revision must be a lowercase SHA-256 digest")
        with self._semantic_inventory_lock(exclusive=False):
            self._require_semantic_inventory_revision(expected_revision)
            try:
                yield
            finally:
                self._require_semantic_inventory_revision(expected_revision)

    def _require_semantic_inventory_revision(self, expected_revision: str) -> None:
        try:
            self._require_no_pending_semantic_transactions()
            entries, _ = self._semantic_inventory_entries()
            self._require_no_pending_semantic_transactions()
        except Exception as error:
            raise SemanticSnapshotChangedError(
                "canonical semantic inventory became unsafe during index commit"
            ) from error
        if self._semantic_inventory_revision(entries) != expected_revision:
            raise SemanticSnapshotChangedError(
                "canonical semantic inventory changed during index commit"
            )

    def _semantic_bundle_snapshot_locked(self) -> SemanticRepositorySnapshot:
        self._require_no_pending_semantic_transactions()
        entries, source_ids = self._semantic_inventory_entries()
        bundles: list[SemanticKnowledgeBundle] = []
        for source_id in source_ids:
            try:
                with self._source_transition_lock(source_id):
                    bundle, verification, quarantine = self._load_semantic_state(source_id)
                    self._require_semantic_foundation_state(
                        source_id,
                        bundle=bundle,
                        verification=verification,
                        quarantine=quarantine,
                    )
                if bundle is None:
                    # A complete quarantine pair is canonical but deliberately not retrievable.
                    if verification is not None and quarantine is not None:
                        self._require_current_retrieval_quarantine(quarantine)
                        continue
                    raise ValueError("semantic state does not contain a verified bundle")
                self._require_current_retrieval_bundle(bundle)
            except SemanticBundleEnumerationError:
                raise
            except (OSError, RuntimeError, ValueError) as exc:
                raise SemanticBundleEnumerationError(
                    source_id,
                    "invalid_semantic_record",
                    f"is invalid for retrieval: {exc}",
                ) from exc
            bundles.append(bundle)
        final_entries, _ = self._semantic_inventory_entries()
        self._require_no_pending_semantic_transactions()
        if final_entries != entries:
            raise SemanticBundleEnumerationError(
                "<repository>",
                "semantic_inventory_changed",
                "changed during canonical enumeration",
            )
        return SemanticRepositorySnapshot(
            bundles=tuple(bundles),
            revision=self._semantic_inventory_revision(entries),
        )

    def _require_no_pending_semantic_transactions(self) -> None:
        pending = self._pending_semantic_transaction_journals()
        if pending:
            source_id, journal_name = pending[0]
            raise SemanticBundleEnumerationError(
                source_id,
                "pending_semantic_transaction",
                f"has unresolved canonical transaction journal {journal_name!r}",
            )

    def _pending_semantic_transaction_journals(self) -> tuple[tuple[str, str], ...]:
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return ()
        try:
            names: list[tuple[str, str]] = []
            entry_count = 0
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > _MAX_SEMANTIC_INVENTORY_FILES:
                        raise SemanticBundleEnumerationError(
                            "<repository>",
                            "semantic_transaction_inventory_too_large",
                            "exceeds the bounded transaction journal inventory",
                        )
                    source_id: str | None = None
                    if entry.name.endswith(".semantic-transaction.json"):
                        source_id = entry.name[: -len(".semantic-transaction.json")]
                    elif entry.name.endswith(".semantic-invalidation.json"):
                        source_id = entry.name[: -len(".semantic-invalidation.json")]
                    elif entry.name.endswith(".projection-revision.json"):
                        source_id = entry.name[: -len(".projection-revision.json")]
                    elif entry.name.endswith(".transaction.json"):
                        source_id = entry.name[: -len(".transaction.json")]
                    if source_id is not None:
                        names.append((source_id, entry.name))

            checked: list[tuple[str, str]] = []
            for source_id, name in sorted(names):
                try:
                    _validate_stable_id(source_id)
                    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError("transaction journal is not a regular file")
                    journal_fd = os.open(name, self._file_read_flags(), dir_fd=directory_fd)
                except (OSError, ValueError) as error:
                    raise SemanticBundleEnumerationError(
                        source_id or "<empty>",
                        "unsafe_semantic_transaction_journal",
                        f"has unsafe pending transaction journal {name!r}",
                    ) from error
                try:
                    opened = os.fstat(journal_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or self._semantic_file_identity(opened)
                        != self._semantic_file_identity(before)
                        or self._semantic_file_identity(opened)
                        != self._semantic_file_identity(after)
                    ):
                        raise SemanticBundleEnumerationError(
                            source_id,
                            "unsafe_semantic_transaction_journal",
                            f"changed pending transaction journal {name!r}",
                        )
                except OSError as error:
                    raise SemanticBundleEnumerationError(
                        source_id,
                        "unsafe_semantic_transaction_journal",
                        f"could not safely inspect pending transaction journal {name!r}",
                    ) from error
                finally:
                    os.close(journal_fd)
                checked.append((source_id, name))
            return tuple(checked)
        finally:
            os.close(directory_fd)

    def load_current_semantic_result(
        self,
        prepared: PreparedSource,
        *,
        semantic_schema_version: str = SEMANTIC_SCHEMA_VERSION,
        extractor_prompt_version: str = EXTRACTOR_PROMPT_VERSION,
        critic_prompt_version: str = CRITIC_PROMPT_VERSION,
        repair_prompt_version: str = REPAIR_PROMPT_VERSION,
        compiler_version: str = SEMANTIC_COMPILER_VERSION,
        execution_example_schema_version: str = EXECUTION_EXAMPLE_SCHEMA_VERSION,
        pin_models: bool = False,
        extractor_model_id: str | None = None,
        critic_model_id: str | None = None,
    ) -> SemanticCompilationResult | None:
        """Atomically load one current, cross-validated verified semantic pair."""
        prepared = validate_prepared_source(prepared)
        if pin_models and (not extractor_model_id or not critic_model_id):
            raise ValueError("model-pinned currentness requires both model identifiers")
        source_id = prepared.manifest.source_id
        self._target("semantic_bundles", source_id)
        with (
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            try:
                bundle, verification, quarantine = self._load_semantic_state(source_id)
                foundation_manifest = self.load_manifest(source_id)
                self._require_semantic_foundation_state(
                    source_id,
                    bundle=bundle,
                    verification=verification,
                    quarantine=quarantine,
                    foundation=foundation_manifest,
                )
            except (FileNotFoundError, ValueError):
                return None
            if verification is None:
                return None

            foundation = prepared.manifest.extraction
            manifest = (
                bundle.compilation_manifest
                if bundle is not None
                else quarantine.compilation_manifest
                if quarantine is not None
                else None
            )
            if manifest is None:
                return None
            current = (
                foundation_manifest == prepared.manifest
                and verification.source_id == source_id
                and verification.source_sha256 == prepared.manifest.sha256
                and manifest.foundation_schema_version == foundation.schema_version
                and manifest.foundation_parser_id == foundation.parser_id
                and manifest.foundation_parser_version == foundation.parser_version
                and manifest.foundation_extraction == foundation
                and (
                    bundle.schema_version == semantic_schema_version
                    if bundle is not None
                    else quarantine is not None
                    and quarantine.semantic_schema_version == semantic_schema_version
                )
                and manifest.extractor_prompt_version == extractor_prompt_version
                and manifest.critic_prompt_version == critic_prompt_version
                and manifest.repair_prompt_version == repair_prompt_version
                and manifest.compiler_version == compiler_version
                and (
                    not manifest.emitted_execution_example_ids
                    or manifest.execution_example_schema_version == execution_example_schema_version
                )
            )
            if pin_models:
                current = current and (
                    manifest.extractor_model_id == extractor_model_id
                    and manifest.critic_model_id == critic_model_id
                )
            if not current:
                return None
            if bundle is None:
                if quarantine is None or verification.adjudication != "quarantined":
                    return None
                return SemanticCompilationResult(
                    disposition="unchanged",
                    verification=verification,
                    quarantine=quarantine,
                )
            if quarantine is not None or verification.adjudication != "verified":
                return None
            return SemanticCompilationResult(
                disposition="unchanged",
                bundle=bundle,
                verification=verification,
            )

    @contextmanager
    def semantic_compilation_guard(self, source_id: str) -> Iterator[None]:
        """Serialize check, compile, and persistence for one semantic source."""
        with self._source_operation_guard("semantic_compilation_guards", source_id):
            yield

    @contextmanager
    def promotion_publication_guard(self, source_id: str) -> Iterator[None]:
        """Serialize promotion publication and revocation for one source."""
        _validate_stable_id(source_id)
        held_source_ids = getattr(self._promotion_guard_local, "source_ids", None)
        if held_source_ids is None:
            held_source_ids = set()
            self._promotion_guard_local.source_ids = held_source_ids
        if source_id in held_source_ids:
            yield
            return
        with self._source_operation_guard("promotion_publication_guards", source_id):
            held_source_ids.add(source_id)
            try:
                yield
            finally:
                held_source_ids.remove(source_id)

    @contextmanager
    def _source_operation_guard(self, directory: str, source_id: str) -> Iterator[None]:
        _validate_stable_id(source_id)
        label = directory.removesuffix("s").replace("_", " ")
        directory_fd = self._open_child_directory(directory, create=True)
        lock_fd = -1
        try:
            try:
                lock_fd = os.open(
                    f"{source_id}.lock",
                    self._lock_open_flags(),
                    0o600,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ValueError(f"{label} is not a confined regular file: {exc}") from exc
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise ValueError(f"{label} is not a regular file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            if lock_fd >= 0:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            os.close(directory_fd)

    def semantic_result_is_current(
        self,
        prepared: PreparedSource,
        *,
        semantic_schema_version: str = SEMANTIC_SCHEMA_VERSION,
        extractor_prompt_version: str = EXTRACTOR_PROMPT_VERSION,
        critic_prompt_version: str = CRITIC_PROMPT_VERSION,
        repair_prompt_version: str = REPAIR_PROMPT_VERSION,
        compiler_version: str = SEMANTIC_COMPILER_VERSION,
        execution_example_schema_version: str = EXECUTION_EXAMPLE_SCHEMA_VERSION,
        pin_models: bool = False,
        extractor_model_id: str | None = None,
        critic_model_id: str | None = None,
    ) -> bool:
        """Return whether verified canonical semantics match all configured inputs."""
        return (
            self.load_current_semantic_result(
                prepared,
                semantic_schema_version=semantic_schema_version,
                extractor_prompt_version=extractor_prompt_version,
                critic_prompt_version=critic_prompt_version,
                repair_prompt_version=repair_prompt_version,
                compiler_version=compiler_version,
                execution_example_schema_version=execution_example_schema_version,
                pin_models=pin_models,
                extractor_model_id=extractor_model_id,
                critic_model_id=critic_model_id,
            )
            is not None
        )

    def quarantine_exists(self, source_id: str) -> bool:
        """Return whether a regular quarantine record exists for ``source_id``."""
        return self._record_exists("quarantine", source_id)

    def delete_quarantine(self, source_id: str) -> bool:
        """Delete one stale quarantine record, returning whether it existed."""
        return self._delete_record("quarantine", source_id)

    def load_quarantine(self, source_id: str) -> QuarantineRecord:
        """Load and strictly validate one quarantine record and its identities."""
        target, filename = self._target("quarantine", source_id)
        try:
            directory_fd = self._open_child_directory("quarantine", create=False)
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"quarantine not found for source_id {source_id!r}: {target}"
            ) from exc
        try:
            try:
                file_fd = os.open(filename, self._file_read_flags(), dir_fd=directory_fd)
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"quarantine not found for source_id {source_id!r}: {target}"
                ) from exc
            except OSError as exc:
                raise ValueError(
                    f"invalid quarantine for source_id {source_id!r}: {target}"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError("quarantine target is not a regular file")
                with os.fdopen(file_fd, mode="r", encoding="utf-8") as stream:
                    file_fd = -1
                    payload = json.load(stream)
                record = QuarantineRecord.model_validate(payload)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ValueError(
                    f"invalid quarantine for source_id {source_id!r}: {target}; {exc}"
                ) from exc
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)

        expected_quarantine_id = f"quarantine-{source_id}"
        if record.source_id != source_id or record.quarantine_id != expected_quarantine_id:
            raise ValueError(
                f"invalid quarantine for source_id {source_id!r}: {target}; "
                "record identity does not match requested source"
            )
        return record

    def transition_source(
        self,
        manifest: DocumentManifest,
        quarantine: QuarantineRecord | None,
        *,
        before_foundation_revision_change: Callable[[str], object] | None = None,
    ) -> None:
        """Durably commit one source disposition or recover its previous bytes."""
        with self.promotion_publication_guard(manifest.source_id):
            self._transition_source_under_publication_guard(
                manifest,
                quarantine,
                before_foundation_revision_change=before_foundation_revision_change,
            )

    def _transition_source_under_publication_guard(
        self,
        manifest: DocumentManifest,
        quarantine: QuarantineRecord | None,
        *,
        before_foundation_revision_change: Callable[[str], object] | None = None,
    ) -> None:
        """Apply a source transition while its promotion publication guard is held."""
        self.validate_source_state(manifest, quarantine)
        if before_foundation_revision_change is not None and not callable(
            before_foundation_revision_change
        ):
            raise TypeError("before_foundation_revision_change must be callable")
        source_id = manifest.source_id
        target_revision = foundation_manifest_digest(manifest)
        barrier_expected_revision: str | None = None
        with (
            self.semantic_compilation_guard(source_id),
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            try:
                current_manifest = self.load_manifest(source_id)
            except FileNotFoundError:
                current_manifest = None
            self._require_journal_promotion_lineage(manifest, current_manifest)
            current_revision = (
                None if current_manifest is None else foundation_manifest_digest(current_manifest)
            )
            pending_barrier = self._read_projection_revision_barrier(source_id)
            if pending_barrier is not None:
                if before_foundation_revision_change is None:
                    raise RuntimeError("pending projection revision requires index invalidation")
                if current_revision is None or current_revision not in {
                    pending_barrier.previous_foundation_sha256,
                    pending_barrier.target_foundation_sha256,
                }:
                    raise RuntimeError(
                        "pending projection revision does not match canonical foundation"
                    )
                barrier_expected_revision = current_revision
                if pending_barrier.target_foundation_sha256 != target_revision:
                    self._write_projection_revision_barrier(
                        _ProjectionRevisionBarrier(
                            source_id=source_id,
                            previous_foundation_sha256=current_revision,
                            target_foundation_sha256=target_revision,
                        )
                    )
            elif (
                before_foundation_revision_change is not None
                and current_manifest is not None
                and current_manifest != manifest
            ):
                barrier_expected_revision = foundation_manifest_digest(current_manifest)
                self._write_projection_revision_barrier(
                    _ProjectionRevisionBarrier(
                        source_id=source_id,
                        previous_foundation_sha256=barrier_expected_revision,
                        target_foundation_sha256=target_revision,
                    )
                )
            if barrier_expected_revision is None:
                self._transition_source_locked(manifest, quarantine)
                return

        # Lock order is deliberate: the external disposable index is acquired only
        # after every repository lock, including the compilation guard, is released.
        # The durable marker makes every concurrent canonical snapshot and rebuild
        # fail closed until the source transition commits.
        barrier_callback = before_foundation_revision_change
        if barrier_callback is None:
            raise RuntimeError("pending projection revision requires index invalidation")
        if barrier_callback(source_id) is not True:
            raise RuntimeError("source projection absence could not be proven")

        with (
            self.semantic_compilation_guard(source_id),
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            pending_barrier = self._read_projection_revision_barrier(source_id)
            try:
                current_manifest = self.load_manifest(source_id)
            except FileNotFoundError as error:
                raise RuntimeError(
                    "canonical foundation disappeared during projection invalidation"
                ) from error
            if (
                pending_barrier is None
                or pending_barrier.target_foundation_sha256 != target_revision
                or foundation_manifest_digest(current_manifest) != barrier_expected_revision
            ):
                raise RuntimeError("canonical foundation changed during projection invalidation")
            self._transition_source_locked(manifest, quarantine)
            self._delete_projection_revision_barrier(source_id)

    @staticmethod
    def _require_journal_promotion_lineage(
        target: DocumentManifest,
        current: DocumentManifest | None,
    ) -> None:
        """Protect the stable promotion identity from collisions, reuse, and rollback."""
        if target.source_namespace != "journal-promotion":
            if current is not None and current.source_namespace == "journal-promotion":
                raise ValueError("journal-promotion identity cannot change namespace")
            return
        match = re.fullmatch(
            r"engagements/([0-9a-f-]{36})/promotion/sources/promotion-v([1-9][0-9]*)\.md",
            target.path,
        )
        if match is None:
            raise ValueError("journal-promotion path does not match its stable lineage")
        try:
            engagement_id = UUID(match.group(1))
        except ValueError as error:
            raise ValueError("journal-promotion path has an invalid engagement identity") from error
        identity = uuid5(NAMESPACE_URL, f"sedna:journal-promotion:{engagement_id}")
        expected_source_id = f"source-{identity}"
        if target.source_id != expected_source_id:
            raise ValueError("journal-promotion source identity does not match its engagement")
        target_revision = int(match.group(2))
        expected_provenance_path = target.path.removesuffix(".md") + ".provenance.json"
        if len(target.assets) != 1 or target.assets[0].path != expected_provenance_path:
            raise ValueError("journal-promotion source and provenance paths must be an exact pair")
        if current is None:
            return
        if current.source_namespace != "journal-promotion":
            raise ValueError("journal-promotion identity collision with legacy foundation")
        current_match = re.fullmatch(
            r"engagements/([0-9a-f-]{36})/promotion/sources/promotion-v([1-9][0-9]*)\.md",
            current.path,
        )
        if current_match is None or current_match.group(1) != match.group(1):
            raise ValueError("journal-promotion current foundation has a conflicting lineage")
        current_revision = int(current_match.group(2))
        if target_revision < current_revision:
            raise ValueError("journal-promotion revision rollback is forbidden")
        if target_revision == current_revision:
            if (
                current.ingestion_status.value == "excluded"
                and target.ingestion_status.value == "accepted"
            ):
                raise ValueError("journal-promotion excluded revision cannot be reaccepted")
            immutable_fields = (
                "source_id",
                "source_namespace",
                "path",
                "sha256",
                "title",
                "language",
                "document_type",
                "knowledge_role",
                "parser_profile",
                "extraction",
                "assets",
                "warnings",
            )
            if any(getattr(target, field) != getattr(current, field) for field in immutable_fields):
                raise ValueError(
                    "journal-promotion same revision changed immutable source material"
                )

    def resume_nonaccepted_projection_revision(
        self,
        source_id: str,
        *,
        before_barrier_clear: Callable[[str], object] | None,
    ) -> bool:
        """Finish a committed terminal revision only after fencing its projection safely.

        A nonaccepted source has no semantic compilation to force on an unchanged
        learning run.  This explicit recovery path therefore consumes only a marker
        whose exact target is already canonical, while retaining the marker across
        every failed validation or index-invalidation attempt.
        """
        _validate_stable_id(source_id)
        if before_barrier_clear is not None and not callable(before_barrier_clear):
            raise TypeError("before_barrier_clear must be callable")
        with (
            self.semantic_compilation_guard(source_id),
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            pending_barrier = self._read_projection_revision_barrier(source_id)
            if pending_barrier is None:
                return False
            self._require_current_nonaccepted_projection_target(
                source_id,
                pending_barrier,
            )
        if before_barrier_clear is None:
            raise RuntimeError("pending projection revision requires index invalidation")

        # The disposable index must never be acquired beneath repository locks.
        # True proves either source absence or a durable global rebuild barrier.
        if before_barrier_clear(source_id) is not True:
            raise RuntimeError("source projection absence could not be proven")

        with (
            self.semantic_compilation_guard(source_id),
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            current_barrier = self._read_projection_revision_barrier(source_id)
            if current_barrier != pending_barrier:
                raise RuntimeError("projection revision changed during index invalidation")
            self._require_current_nonaccepted_projection_target(
                source_id,
                pending_barrier,
            )
            self._delete_projection_revision_barrier(source_id)
        return True

    def _require_current_nonaccepted_projection_target(
        self,
        source_id: str,
        barrier: _ProjectionRevisionBarrier,
    ) -> None:
        """Validate the canonical terminal target while its repository locks are held."""
        try:
            manifest = self.load_manifest(source_id)
        except FileNotFoundError as error:
            raise RuntimeError("projection revision target foundation is missing") from error
        if (
            manifest.ingestion_status.value == "accepted"
            or foundation_manifest_digest(manifest) != barrier.target_foundation_sha256
        ):
            raise RuntimeError("projection revision is not at its canonical terminal target")
        try:
            quarantine = self.load_quarantine(source_id)
        except FileNotFoundError:
            quarantine = None
        self.validate_source_state(manifest, quarantine)
        if self._load_semantic_state(source_id) != (None, None, None):
            raise RuntimeError("nonaccepted projection revision retains semantic state")

    def _transition_source_locked(
        self,
        manifest: DocumentManifest,
        quarantine: QuarantineRecord | None,
    ) -> None:
        """Apply one source transition while inventory and source locks are held."""
        source_id = manifest.source_id
        try:
            current_manifest = self.load_manifest(source_id)
        except FileNotFoundError:
            current_manifest = None
        old_manifest = self._read_optional_bytes("manifests", source_id)
        old_quarantine = self._read_optional_bytes("quarantine", source_id)
        foundation_changed = current_manifest != manifest
        semantic_snapshots: dict[str, bytes | None] | None = None
        if manifest.ingestion_status.value != "accepted" or foundation_changed:
            semantic_snapshots = {
                directory: self._read_optional_bytes(directory, source_id)
                for directory in self._SEMANTIC_DIRECTORIES
            }
            self._write_semantic_transition_journal(source_id, semantic_snapshots)
            try:
                for directory in self._SEMANTIC_DIRECTORIES:
                    self._delete_record(directory, source_id)
                self._fsync_directories(self._SEMANTIC_DIRECTORIES)
            except BaseException as original_error:
                rollback_errors = self._restore_semantic_snapshots(
                    source_id,
                    semantic_snapshots,
                )
                if rollback_errors:
                    for rollback_error in rollback_errors:
                        original_error.add_note(
                            "semantic invalidation rollback remains recoverable: "
                            f"{type(rollback_error).__name__}: {rollback_error}"
                        )
                else:
                    self._delete_semantic_transition_journal(source_id)
                raise
        self._write_transition_journal(source_id, old_manifest, old_quarantine)
        try:
            if quarantine is None:
                self.delete_quarantine(source_id)
            else:
                self.write_quarantine(quarantine)
            self.write_manifest(manifest)
        except BaseException as original_error:
            rollback_errors: list[BaseException] = []
            if semantic_snapshots is not None:
                rollback_errors.extend(
                    self._restore_semantic_snapshots(source_id, semantic_snapshots)
                )
                if not rollback_errors:
                    try:
                        self._delete_semantic_transition_journal(source_id)
                    except BaseException as rollback_error:
                        rollback_errors.append(rollback_error)
            rollback_errors.extend(
                self._restore_source_snapshots(
                    source_id,
                    old_manifest,
                    old_quarantine,
                )
            )
            if not rollback_errors:
                try:
                    self._delete_transition_journal(source_id)
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
            for rollback_error in rollback_errors:
                original_error.add_note(
                    "transition rollback remains recoverable: "
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
            raise
        if semantic_snapshots is not None:
            self._delete_semantic_transition_journal(source_id)
        self._delete_transition_journal(source_id)

    def load_manifest(self, source_id: str) -> DocumentManifest:
        """Load and validate one manifest, with path-specific errors."""
        target, filename = self._target("manifests", source_id)
        try:
            directory_fd = self._open_child_directory("manifests", create=False)
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"manifest not found for source_id {source_id!r}: {target}"
            ) from exc
        try:
            try:
                file_fd = os.open(
                    filename,
                    self._file_read_flags(),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"manifest not found for source_id {source_id!r}: {target}"
                ) from exc
            except OSError as exc:
                raise ValueError(f"invalid manifest for source_id {source_id!r}: {target}") from exc

            try:
                file_status = os.fstat(file_fd)
                if not stat.S_ISREG(file_status.st_mode):
                    raise ValueError("manifest target is not a regular file")
                with os.fdopen(file_fd, mode="r", encoding="utf-8") as stream:
                    file_fd = -1
                    payload = json.load(stream)
                manifest = DocumentManifest.model_validate(payload)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ValueError(
                    f"invalid manifest for source_id {source_id!r}: {target}; {exc}"
                ) from exc
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)

        if manifest.source_id != source_id:
            raise ValueError(
                f"invalid manifest for source_id {source_id!r}: {target}; "
                f"record contains source_id {manifest.source_id!r}"
            )
        return manifest

    def _load_semantic_component(
        self,
        source_id: str,
        component: str,
    ) -> SemanticKnowledgeBundle | SemanticVerificationRecord | SemanticQuarantineRecord:
        directory = {
            "bundle": "semantic_bundles",
            "verification": "semantic_verification",
            "quarantine": "semantic_quarantine",
        }[component]
        target, _ = self._target(directory, source_id)
        with (
            self._semantic_inventory_lock(exclusive=True),
            self._source_transition_lock(source_id),
        ):
            self._recover_source(source_id)
            bundle, verification, quarantine = self._load_semantic_state(source_id)
        record = {
            "bundle": bundle,
            "verification": verification,
            "quarantine": quarantine,
        }[component]
        if record is None:
            raise FileNotFoundError(
                f"semantic {component} not found for source_id {source_id!r}: {target}"
            )
        return record

    def _load_semantic_state(
        self,
        source_id: str,
    ) -> tuple[
        SemanticKnowledgeBundle | None,
        SemanticVerificationRecord | None,
        SemanticQuarantineRecord | None,
    ]:
        bundle = self._read_optional_model(
            "semantic_bundles", source_id, SemanticKnowledgeBundle, "semantic bundle"
        )
        verification = self._read_optional_model(
            "semantic_verification",
            source_id,
            SemanticVerificationRecord,
            "semantic verification",
        )
        quarantine = self._read_optional_model(
            "semantic_quarantine",
            source_id,
            SemanticQuarantineRecord,
            "semantic quarantine",
        )
        if bundle is None and verification is None and quarantine is None:
            return None, None, None

        records = tuple(
            record for record in (bundle, verification, quarantine) if record is not None
        )
        if any(record.source_id != source_id for record in records):
            raise ValueError(
                f"invalid semantic state for source_id {source_id!r}: record identity mismatch"
            )
        hashes = {record.source_sha256 for record in records}
        if len(hashes) != 1:
            raise ValueError(
                f"invalid semantic state for source_id {source_id!r}: record identity mismatch"
            )
        if bundle is not None:
            if (
                verification is None
                or quarantine is not None
                or verification.adjudication != "verified"
            ):
                raise ValueError(
                    f"invalid semantic state for source_id {source_id!r}: "
                    "bundle and verification disposition mismatch"
                )
            if verification.critic_call.model != bundle.compilation_manifest.critic_model_id:
                raise ValueError(
                    f"invalid semantic state for source_id {source_id!r}: "
                    "critic model identity mismatch"
                )
            if verification.repair_count != bundle.compilation_manifest.repair_count:
                raise ValueError(
                    f"invalid semantic state for source_id {source_id!r}: "
                    "repair count attribution mismatch"
                )
        elif quarantine is not None:
            if verification is None or verification.adjudication != "quarantined":
                raise ValueError(
                    f"invalid semantic state for source_id {source_id!r}: "
                    "quarantine and verification disposition mismatch"
                )
            manifest = quarantine.compilation_manifest
            if manifest is not None and (
                manifest.source_id != source_id
                or manifest.source_sha256 != quarantine.source_sha256
                or manifest.critic_model_id != verification.critic_call.model
                or manifest.repair_count != verification.repair_count
                or manifest.disposition != "quarantined"
            ):
                raise ValueError(
                    f"invalid semantic state for source_id {source_id!r}: "
                    "quarantine compilation identity mismatch"
                )
        else:
            raise ValueError(
                f"invalid semantic state for source_id {source_id!r}: orphan verification"
            )
        return bundle, verification, quarantine

    def _require_semantic_foundation_state(
        self,
        source_id: str,
        *,
        bundle: SemanticKnowledgeBundle | None,
        verification: SemanticVerificationRecord | None,
        quarantine: SemanticQuarantineRecord | None,
        foundation: DocumentManifest | None = None,
    ) -> None:
        """Bind every semantic disposition to its exact accepted foundation manifest."""
        if bundle is None and verification is None and quarantine is None:
            return
        if foundation is None:
            try:
                foundation = self.load_manifest(source_id)
            except FileNotFoundError as error:
                raise ValueError("semantic state has no foundation manifest") from error
        if foundation.ingestion_status.value != "accepted":
            raise ValueError("semantic state foundation manifest is not accepted")
        if foundation.source_namespace == "journal-promotion":
            self._require_journal_promotion_physical_state(foundation)
        semantic_manifest = (
            bundle.compilation_manifest
            if bundle is not None
            else quarantine.compilation_manifest
            if quarantine is not None
            else None
        )
        if semantic_manifest is None or verification is None:
            raise ValueError("semantic state lacks foundation compilation attribution")
        extraction = foundation.extraction
        if (
            verification.source_sha256 != foundation.sha256
            or semantic_manifest.source_sha256 != foundation.sha256
            or semantic_manifest.foundation_schema_version != extraction.schema_version
            or semantic_manifest.foundation_parser_id != extraction.parser_id
            or semantic_manifest.foundation_parser_version != extraction.parser_version
            or semantic_manifest.foundation_extraction != extraction
            or semantic_manifest.foundation_manifest_sha256
            != foundation_manifest_digest(foundation)
        ):
            raise ValueError("semantic state does not match its current foundation manifest")

    def require_journal_promotion_physical_state(self, foundation: DocumentManifest) -> None:
        """Revalidate an accepted promotion foundation immediately before persistence."""
        foundation = DocumentManifest.model_validate(
            foundation.model_dump(mode="json", warnings="error")
        )
        if foundation.source_namespace != "journal-promotion":
            raise ValueError("physical promotion validation requires journal-promotion namespace")
        if foundation.ingestion_status.value != "accepted":
            raise ValueError("physical promotion validation requires an accepted foundation")
        self._require_journal_promotion_physical_state(foundation)

    def _require_journal_promotion_physical_state(
        self,
        foundation: DocumentManifest,
    ) -> None:
        """Rehash one promotion source and every bound asset through the retained root."""
        physical = ((foundation.path, foundation.sha256, _MAX_JOURNAL_PROMOTION_SOURCE_BYTES),)
        physical += tuple(
            (asset.path, asset.sha256, _MAX_JOURNAL_PROMOTION_ASSET_BYTES)
            for asset in foundation.assets
        )
        for relative_path, expected_sha256, byte_limit in physical:
            payload = self._read_confined_physical_file(relative_path, byte_limit=byte_limit)
            if sha256(payload).hexdigest() != expected_sha256:
                raise ValueError("journal-promotion physical artifact digest mismatch")

    def _read_confined_physical_file(self, relative_path: str, *, byte_limit: int) -> bytes:
        """Boundedly read a regular root-relative file without following any symlink."""
        path = PurePath(relative_path)
        if (
            type(relative_path) is not str
            or not relative_path
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("journal-promotion physical artifact path is not confined")
        with self._descriptor_lock:
            current_fd = os.dup(self._ensure_open())
        file_fd = -1
        try:
            for part in path.parts[:-1]:
                next_fd = os.open(part, self._directory_open_flags(), dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            name = path.parts[-1]
            before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_size > byte_limit:
                raise ValueError(
                    "journal-promotion physical artifact is not a bounded regular file"
                )
            file_fd = os.open(name, self._file_read_flags(), dir_fd=current_fd)
            opened = os.fstat(file_fd)
            if not stat.S_ISREG(opened.st_mode) or self._semantic_file_identity(
                opened
            ) != self._semantic_file_identity(before):
                raise ValueError("journal-promotion physical artifact changed while opening")
            chunks: list[bytes] = []
            size = 0
            while chunk := os.read(file_fd, min(1024 * 1024, byte_limit + 1 - size)):
                size += len(chunk)
                if size > byte_limit:
                    raise ValueError("journal-promotion physical artifact exceeds its byte limit")
                chunks.append(chunk)
            final = os.fstat(file_fd)
            after = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if self._semantic_file_identity(opened) != self._semantic_file_identity(
                final
            ) or self._semantic_file_identity(opened) != self._semantic_file_identity(after):
                raise ValueError("journal-promotion physical artifact changed while reading")
            return b"".join(chunks)
        except OSError as error:
            raise ValueError("journal-promotion physical artifact is unavailable") from error
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            os.close(current_fd)

    def _semantic_inventory_entries(
        self,
    ) -> tuple[tuple[tuple[str, str, str, int], ...], tuple[str, ...]]:
        entries: list[tuple[str, str, str, int]] = []
        source_ids: set[str] = set()
        for directory in self._SEMANTIC_DIRECTORIES:
            try:
                directory_fd = self._open_child_directory(directory, create=False)
            except FileNotFoundError:
                continue
            try:
                names: list[str] = []
                entry_count = 0
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        entry_count += 1
                        if entry_count > _MAX_SEMANTIC_INVENTORY_FILES:
                            raise SemanticBundleEnumerationError(
                                "<repository>",
                                "semantic_inventory_too_large",
                                "exceeds the bounded semantic file inventory",
                            )
                        if entry.name.endswith(".json"):
                            names.append(entry.name)
                names.sort()
                for name in names:
                    if not name.endswith(".json"):
                        continue
                    source_id = name[:-5]
                    try:
                        _validate_stable_id(source_id)
                    except ValueError as exc:
                        raise SemanticBundleEnumerationError(
                            source_id or "<empty>",
                            "unsafe_semantic_filename",
                            "has an unsafe canonical filename",
                        ) from exc
                    try:
                        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if not stat.S_ISREG(before.st_mode):
                            raise ValueError("semantic record is not a regular file")
                        file_fd = os.open(name, self._file_read_flags(), dir_fd=directory_fd)
                    except (OSError, ValueError) as exc:
                        raise SemanticBundleEnumerationError(
                            source_id,
                            "unsafe_semantic_record",
                            f"has an unsafe {directory} record",
                        ) from exc
                    try:
                        opened = os.fstat(file_fd)
                        if not stat.S_ISREG(opened.st_mode) or self._semantic_file_identity(
                            opened
                        ) != self._semantic_file_identity(before):
                            raise SemanticBundleEnumerationError(
                                source_id,
                                "unsafe_semantic_record",
                                f"has a non-regular {directory} record",
                            )
                        chunks: list[bytes] = []
                        size = 0
                        while chunk := os.read(file_fd, 1024 * 1024):
                            size += len(chunk)
                            if size > _MAX_SEMANTIC_RECORD_BYTES:
                                raise SemanticBundleEnumerationError(
                                    source_id,
                                    "semantic_record_too_large",
                                    f"has an oversized {directory} record",
                                )
                            chunks.append(chunk)
                        payload = b"".join(chunks)
                        final = os.fstat(file_fd)
                        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if self._semantic_file_identity(opened) != self._semantic_file_identity(
                            final
                        ) or self._semantic_file_identity(opened) != self._semantic_file_identity(
                            after
                        ):
                            raise SemanticBundleEnumerationError(
                                source_id,
                                "semantic_record_changed",
                                f"changed while reading {directory}",
                            )
                    except OSError as exc:
                        raise SemanticBundleEnumerationError(
                            source_id,
                            "unsafe_semantic_record",
                            f"could not read {directory} safely",
                        ) from exc
                    finally:
                        os.close(file_fd)
                    entries.append((directory, name, sha256(payload).hexdigest(), len(payload)))
                    source_ids.add(source_id)
            finally:
                os.close(directory_fd)
        for source_id in sorted(source_ids):
            try:
                payload = self._read_optional_bytes("manifests", source_id)
            except (OSError, ValueError) as exc:
                raise SemanticBundleEnumerationError(
                    source_id,
                    "unsafe_foundation_record",
                    "has an unsafe current foundation manifest",
                ) from exc
            if payload is not None:
                entries.append(
                    (
                        "manifests",
                        f"{source_id}.json",
                        sha256(payload).hexdigest(),
                        len(payload),
                    )
                )
        return tuple(sorted(entries)), tuple(sorted(source_ids))

    @staticmethod
    def _semantic_file_identity(status: os.stat_result) -> tuple[object, ...]:
        return (
            status.st_mode,
            status.st_dev,
            status.st_ino,
            status.st_nlink,
            status.st_uid,
            status.st_gid,
            status.st_size,
            getattr(status, "st_mtime_ns", status.st_mtime),
            getattr(status, "st_ctime_ns", status.st_ctime),
        )

    @staticmethod
    def _semantic_inventory_revision(
        entries: tuple[tuple[str, str, str, int], ...],
    ) -> str:
        payload = json.dumps(
            entries,
            ensure_ascii=True,
            sort_keys=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        return sha256(payload.encode("ascii")).hexdigest()

    @staticmethod
    def _require_current_retrieval_bundle(bundle: SemanticKnowledgeBundle) -> None:
        if CanonicalKnowledgeRepository._is_current_or_legacy_bundle(bundle):
            return
        raise SemanticBundleEnumerationError(
            bundle.source_id,
            "stale_semantic_record",
            "is not current and must be semantically recompiled",
        )

    @staticmethod
    def _is_current_or_legacy_bundle(bundle: SemanticKnowledgeBundle) -> bool:
        """Retrieval accepts the current contract or exactly the legacy strategic contract."""
        manifest = bundle.compilation_manifest
        if (
            bundle.schema_version == SEMANTIC_SCHEMA_VERSION
            and manifest.compiler_version == SEMANTIC_COMPILER_VERSION
            and manifest.extractor_prompt_version == EXTRACTOR_PROMPT_VERSION
            and manifest.critic_prompt_version == CRITIC_PROMPT_VERSION
            and manifest.repair_prompt_version == REPAIR_PROMPT_VERSION
        ):
            return True
        return (
            bundle.schema_version == _LEGACY_RETRIEVAL_SCHEMA_VERSION
            and manifest.compiler_version == _LEGACY_RETRIEVAL_COMPILER_VERSION
            and manifest.extractor_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.critic_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.repair_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.execution_example_schema_version is None
            and not manifest.emitted_execution_example_ids
            and not bundle.execution_examples
        )

    @staticmethod
    def _require_current_retrieval_quarantine(quarantine: SemanticQuarantineRecord) -> None:
        manifest = quarantine.compilation_manifest
        current = (
            quarantine.semantic_schema_version == SEMANTIC_SCHEMA_VERSION
            and manifest is not None
            and manifest.compiler_version == SEMANTIC_COMPILER_VERSION
            and manifest.extractor_prompt_version == EXTRACTOR_PROMPT_VERSION
            and manifest.critic_prompt_version == CRITIC_PROMPT_VERSION
            and manifest.repair_prompt_version == REPAIR_PROMPT_VERSION
        )
        legacy = (
            quarantine.semantic_schema_version == _LEGACY_RETRIEVAL_SCHEMA_VERSION
            and manifest is not None
            and manifest.compiler_version == _LEGACY_RETRIEVAL_COMPILER_VERSION
            and manifest.extractor_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.critic_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.repair_prompt_version == _LEGACY_RETRIEVAL_PROMPT_VERSION
            and manifest.execution_example_schema_version is None
            and not manifest.emitted_execution_example_ids
        )
        if current or legacy:
            return
        raise SemanticBundleEnumerationError(
            quarantine.source_id,
            "stale_semantic_record",
            "is not current and must be semantically recompiled",
        )

    def _read_optional_model(
        self,
        directory: str,
        source_id: str,
        model_type: type[_ModelT],
        record_name: str,
    ) -> _ModelT | None:
        target, _ = self._target(directory, source_id)
        try:
            raw = self._read_optional_bytes(directory, source_id)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"invalid {record_name} for source_id {source_id!r}: {target}; {exc}"
            ) from exc
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
            return model_type.model_validate(payload)
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                f"invalid {record_name} for source_id {source_id!r}: {target}; {exc}"
            ) from exc

    def _write_model(self, directory: str, record_id: str, model: BaseModel) -> Path:
        target, filename = self._target(directory, record_id)
        payload = (
            json.dumps(
                model.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        )
        directory_fd = self._open_child_directory(directory, create=True)
        try:
            self._atomic_write(directory_fd, filename, payload)
        finally:
            os.close(directory_fd)
        return target

    def _record_exists(self, directory: str, record_id: str) -> bool:
        self._target(directory, record_id)
        try:
            directory_fd = self._open_child_directory(directory, create=False)
        except FileNotFoundError:
            return False
        try:
            try:
                file_fd = os.open(
                    f"{record_id}.json",
                    self._file_read_flags(),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise ValueError(f"invalid {directory} record for source_id {record_id!r}") from exc
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError(f"invalid {directory} record for source_id {record_id!r}")
                return True
            finally:
                os.close(file_fd)
        finally:
            os.close(directory_fd)

    def _delete_record(self, directory: str, record_id: str) -> bool:
        _, filename = self._target(directory, record_id)
        try:
            directory_fd = self._open_child_directory(directory, create=False)
        except FileNotFoundError:
            return False
        try:
            try:
                os.unlink(filename, dir_fd=directory_fd)
            except FileNotFoundError:
                return False
            os.fsync(directory_fd)
            return True
        finally:
            os.close(directory_fd)

    def _read_optional_bytes(self, directory: str, record_id: str) -> bytes | None:
        self._target(directory, record_id)
        try:
            directory_fd = self._open_child_directory(directory, create=False)
        except FileNotFoundError:
            return None
        try:
            try:
                file_fd = os.open(
                    f"{record_id}.json",
                    self._file_read_flags(),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError(f"{directory} target is not a regular file")
                with os.fdopen(file_fd, mode="rb") as stream:
                    file_fd = -1
                    return stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)

    def _restore_snapshot(
        self,
        directory: str,
        record_id: str,
        payload: bytes | None,
    ) -> None:
        if payload is None:
            self._delete_record(directory, record_id)
            return
        directory_fd = self._open_child_directory(directory, create=True)
        try:
            self._atomic_write_bytes(directory_fd, f"{record_id}.json", payload)
        finally:
            os.close(directory_fd)

    def _restore_source_snapshots(
        self,
        source_id: str,
        manifest: bytes | None,
        quarantine: bytes | None,
    ) -> list[BaseException]:
        errors: list[BaseException] = []
        for directory, payload in (
            ("manifests", manifest),
            ("quarantine", quarantine),
        ):
            try:
                self._restore_snapshot(directory, source_id, payload)
            except BaseException as exc:
                errors.append(exc)
        return errors

    def _restore_semantic_snapshots(
        self,
        source_id: str,
        snapshots: dict[str, bytes | None],
    ) -> list[BaseException]:
        errors: list[BaseException] = []
        for directory in self._SEMANTIC_DIRECTORIES:
            try:
                self._restore_snapshot(directory, source_id, snapshots[directory])
            except BaseException as exc:
                errors.append(exc)
        if not errors:
            try:
                self._fsync_directories(self._SEMANTIC_DIRECTORIES)
            except BaseException as exc:
                errors.append(exc)
        return errors

    def _invalidate_semantic_state(self, source_id: str, source_sha256: str) -> None:
        """Durably delete stale semantics with roll-forward-only crash recovery."""
        self._write_semantic_invalidation_journal(source_id, source_sha256)
        try:
            for directory in self._SEMANTIC_DIRECTORIES:
                self._delete_record(directory, source_id)
            self._fsync_directories(self._SEMANTIC_DIRECTORIES)
            self._delete_semantic_invalidation_journal(source_id)
        except BaseException as original_error:
            original_error.add_note(
                "semantic invalidation remains pending and will roll forward on repository reopen"
            )
            raise

    def _fsync_directories(self, directories: Iterable[str]) -> None:
        for directory in directories:
            directory_fd = self._open_child_directory(directory, create=True)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    @contextmanager
    def _semantic_inventory_lock(self, *, exclusive: bool) -> Iterator[None]:
        with self._descriptor_lock:
            root_fd = self._ensure_open()
            lock_fd = os.dup(root_fd)
            try:
                retained = os.fstat(root_fd)
                duplicated = os.fstat(lock_fd)
                retained_identity = (retained.st_dev, retained.st_ino)
                if (
                    not stat.S_ISDIR(retained.st_mode)
                    or not stat.S_ISDIR(duplicated.st_mode)
                    or retained_identity != (duplicated.st_dev, duplicated.st_ino)
                ):
                    raise RuntimeError("semantic inventory lock lost repository root identity")
                fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                yield
            finally:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    @contextmanager
    def _source_transition_lock(self, source_id: str) -> Iterator[None]:
        _validate_stable_id(source_id)
        directory_fd = self._open_child_directory("transactions", create=True)
        lock_fd = -1
        try:
            lock_fd = os.open(
                f"{source_id}.lock",
                self._lock_open_flags(),
                0o600,
                dir_fd=directory_fd,
            )
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise ValueError("source transition lock is not a regular file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            if lock_fd >= 0:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            os.close(directory_fd)

    def _recover_pending_transactions(self) -> None:
        with self._semantic_inventory_lock(exclusive=True):
            try:
                directory_fd = self._open_child_directory("transactions", create=False)
            except FileNotFoundError:
                return
            try:
                names = tuple(sorted(os.listdir(directory_fd)))
            finally:
                os.close(directory_fd)
            foundation_suffix = ".transaction.json"
            semantic_suffix = ".semantic-transaction.json"
            invalidation_suffix = ".semantic-invalidation.json"
            source_ids: set[str] = set()
            for name in names:
                if name.endswith(invalidation_suffix):
                    source_ids.add(name[: -len(invalidation_suffix)])
                elif name.endswith(semantic_suffix):
                    source_ids.add(name[: -len(semantic_suffix)])
                elif name.endswith(foundation_suffix):
                    source_ids.add(name[: -len(foundation_suffix)])
            for source_id in sorted(source_ids):
                _validate_stable_id(source_id)
                with self._source_transition_lock(source_id):
                    self._recover_source(source_id)

    def _recover_source(self, source_id: str) -> None:
        self._recover_foundation_source(source_id)
        self._recover_semantic_source(source_id)
        self._recover_semantic_invalidation(source_id)

    def _recover_foundation_source(self, source_id: str) -> None:
        journal = self._read_transition_journal(source_id)
        if journal is None:
            return
        manifest, quarantine = journal
        errors = self._restore_source_snapshots(source_id, manifest, quarantine)
        if errors:
            error = OSError(f"could not recover interrupted transition for {source_id!r}")
            for recovery_error in errors:
                error.add_note(f"{type(recovery_error).__name__}: {recovery_error}")
            raise error from errors[0]
        self._delete_transition_journal(source_id)

    def _recover_semantic_source(self, source_id: str) -> None:
        snapshots = self._read_semantic_transition_journal(source_id)
        if snapshots is None:
            return
        errors = self._restore_semantic_snapshots(source_id, snapshots)
        if errors:
            error = OSError(f"could not recover interrupted semantic transition for {source_id!r}")
            for recovery_error in errors:
                error.add_note(f"{type(recovery_error).__name__}: {recovery_error}")
            raise error from errors[0]
        self._delete_semantic_transition_journal(source_id)

    def _recover_semantic_invalidation(self, source_id: str) -> None:
        source_sha256 = self._read_semantic_invalidation_journal(source_id)
        if source_sha256 is None:
            return
        del source_sha256  # A hash mismatch still fails closed by deleting stale semantic state.
        for directory in self._SEMANTIC_DIRECTORIES:
            self._delete_record(directory, source_id)
        self._fsync_directories(self._SEMANTIC_DIRECTORIES)
        self._delete_semantic_invalidation_journal(source_id)

    def _write_transition_journal(
        self,
        source_id: str,
        manifest: bytes | None,
        quarantine: bytes | None,
    ) -> None:
        payload = (
            json.dumps(
                {
                    "manifest_hex": None if manifest is None else manifest.hex(),
                    "quarantine_hex": None if quarantine is None else quarantine.hex(),
                    "source_id": source_id,
                    "version": 1,
                },
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        directory_fd = self._open_child_directory("transactions", create=True)
        try:
            self._atomic_write_bytes(
                directory_fd,
                f"{source_id}.transaction.json",
                payload,
            )
        finally:
            os.close(directory_fd)

    def _read_transition_journal(
        self,
        source_id: str,
    ) -> tuple[bytes | None, bytes | None] | None:
        _validate_stable_id(source_id)
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return None
        filename = f"{source_id}.transaction.json"
        try:
            try:
                file_fd = os.open(
                    filename,
                    self._file_read_flags(),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError("transition journal is not a regular file")
                with os.fdopen(file_fd, mode="rb") as stream:
                    file_fd = -1
                    raw = stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "manifest_hex",
                "quarantine_hex",
                "source_id",
                "version",
            }:
                raise ValueError("unexpected transition journal fields")
            if (
                payload["source_id"] != source_id
                or type(payload["version"]) is not int
                or payload["version"] != 1
            ):
                raise ValueError("transition journal identity or version mismatch")
            manifest = self._decode_optional_hex(payload["manifest_hex"])
            quarantine = self._decode_optional_hex(payload["quarantine_hex"])
        except (TypeError, UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid interrupted transition journal for {source_id!r}") from exc
        return manifest, quarantine

    @staticmethod
    def _decode_optional_hex(value: object) -> bytes | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("snapshot must be hexadecimal text or null")
        return bytes.fromhex(value)

    def _delete_transition_journal(self, source_id: str) -> None:
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return
        try:
            try:
                os.unlink(
                    f"{source_id}.transaction.json",
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _write_semantic_transition_journal(
        self,
        source_id: str,
        snapshots: dict[str, bytes | None],
    ) -> None:
        _validate_stable_id(source_id)
        if set(snapshots) != set(self._SEMANTIC_DIRECTORIES):
            raise ValueError("semantic transition snapshots are incomplete")
        payload = (
            json.dumps(
                {
                    "kind": "semantic",
                    "snapshots": {
                        directory: (
                            None if snapshots[directory] is None else snapshots[directory].hex()
                        )
                        for directory in self._SEMANTIC_DIRECTORIES
                    },
                    "source_id": source_id,
                    "version": 1,
                },
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        directory_fd = self._open_child_directory("transactions", create=True)
        try:
            self._atomic_write_bytes(
                directory_fd,
                f"{source_id}.semantic-transaction.json",
                payload,
            )
        finally:
            os.close(directory_fd)

    def _read_semantic_transition_journal(
        self,
        source_id: str,
    ) -> dict[str, bytes | None] | None:
        _validate_stable_id(source_id)
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return None
        filename = f"{source_id}.semantic-transaction.json"
        try:
            try:
                file_fd = os.open(filename, self._file_read_flags(), dir_fd=directory_fd)
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError("semantic transition journal is not a regular file")
                with os.fdopen(file_fd, mode="rb") as stream:
                    file_fd = -1
                    raw = stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "kind",
                "snapshots",
                "source_id",
                "version",
            }:
                raise ValueError("unexpected semantic transition journal fields")
            if (
                payload["kind"] != "semantic"
                or payload["source_id"] != source_id
                or type(payload["version"]) is not int
                or payload["version"] != 1
                or not isinstance(payload["snapshots"], dict)
                or set(payload["snapshots"]) != set(self._SEMANTIC_DIRECTORIES)
            ):
                raise ValueError("semantic transition journal identity or version mismatch")
            return {
                directory: self._decode_optional_hex(payload["snapshots"][directory])
                for directory in self._SEMANTIC_DIRECTORIES
            }
        except (TypeError, UnicodeError, ValueError) as exc:
            raise ValueError(
                f"invalid interrupted semantic transition journal for {source_id!r}"
            ) from exc

    def _delete_semantic_transition_journal(self, source_id: str) -> None:
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return
        try:
            try:
                os.unlink(
                    f"{source_id}.semantic-transaction.json",
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _write_semantic_invalidation_journal(self, source_id: str, source_sha256: str) -> None:
        _validate_stable_id(source_id)
        if (
            not isinstance(source_sha256, str)
            or len(source_sha256) != 64
            or any(character not in "0123456789abcdef" for character in source_sha256)
        ):
            raise ValueError("semantic invalidation journal requires a SHA-256 source hash")
        payload = (
            json.dumps(
                {
                    "kind": "semantic_invalidation",
                    "source_id": source_id,
                    "source_sha256": source_sha256,
                    "version": 1,
                },
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        directory_fd = self._open_child_directory("transactions", create=True)
        try:
            self._atomic_write_bytes(
                directory_fd,
                f"{source_id}.semantic-invalidation.json",
                payload,
            )
        finally:
            os.close(directory_fd)

    def _read_semantic_invalidation_journal(self, source_id: str) -> str | None:
        _validate_stable_id(source_id)
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return None
        filename = f"{source_id}.semantic-invalidation.json"
        try:
            try:
                file_fd = os.open(filename, self._file_read_flags(), dir_fd=directory_fd)
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError("semantic invalidation journal is not a regular file")
                with os.fdopen(file_fd, mode="rb") as stream:
                    file_fd = -1
                    raw = stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "kind",
                "source_id",
                "source_sha256",
                "version",
            }:
                raise ValueError("unexpected semantic invalidation journal fields")
            source_sha256 = payload["source_sha256"]
            if (
                payload["kind"] != "semantic_invalidation"
                or payload["source_id"] != source_id
                or type(payload["version"]) is not int
                or payload["version"] != 1
                or not isinstance(source_sha256, str)
                or len(source_sha256) != 64
                or any(character not in "0123456789abcdef" for character in source_sha256)
            ):
                raise ValueError("semantic invalidation journal identity or version mismatch")
            return source_sha256
        except (TypeError, UnicodeError, ValueError) as exc:
            raise ValueError(
                f"invalid interrupted semantic invalidation journal for {source_id!r}"
            ) from exc

    def _delete_semantic_invalidation_journal(self, source_id: str) -> None:
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return
        try:
            try:
                os.unlink(
                    f"{source_id}.semantic-invalidation.json",
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _write_projection_revision_barrier(
        self,
        barrier: _ProjectionRevisionBarrier,
    ) -> None:
        """Persist the rebuild-visible barrier before touching the disposable index."""
        _validate_stable_id(barrier.source_id)
        for revision in (
            barrier.previous_foundation_sha256,
            barrier.target_foundation_sha256,
        ):
            if (
                not isinstance(revision, str)
                or len(revision) != 64
                or any(character not in "0123456789abcdef" for character in revision)
            ):
                raise ValueError("projection revision barrier requires foundation digests")
        payload = (
            json.dumps(
                {
                    "kind": "projection_revision",
                    "previous_foundation_sha256": barrier.previous_foundation_sha256,
                    "source_id": barrier.source_id,
                    "target_foundation_sha256": barrier.target_foundation_sha256,
                    "version": 1,
                },
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        directory_fd = self._open_child_directory("transactions", create=True)
        try:
            self._atomic_write_bytes(
                directory_fd,
                f"{barrier.source_id}.projection-revision.json",
                payload,
            )
        finally:
            os.close(directory_fd)

    def _read_projection_revision_barrier(
        self,
        source_id: str,
    ) -> _ProjectionRevisionBarrier | None:
        """Load one exact pending foundation/index ordering barrier."""
        _validate_stable_id(source_id)
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return None
        filename = f"{source_id}.projection-revision.json"
        try:
            try:
                file_fd = os.open(filename, self._file_read_flags(), dir_fd=directory_fd)
            except FileNotFoundError:
                return None
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise ValueError("projection revision barrier is not a regular file")
                with os.fdopen(file_fd, mode="rb") as stream:
                    file_fd = -1
                    raw = stream.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        finally:
            os.close(directory_fd)
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "kind",
                "previous_foundation_sha256",
                "source_id",
                "target_foundation_sha256",
                "version",
            }:
                raise ValueError("unexpected projection revision barrier fields")
            barrier = _ProjectionRevisionBarrier(
                source_id=payload["source_id"],
                previous_foundation_sha256=payload["previous_foundation_sha256"],
                target_foundation_sha256=payload["target_foundation_sha256"],
            )
            if (
                payload["kind"] != "projection_revision"
                or barrier.source_id != source_id
                or type(payload["version"]) is not int
                or payload["version"] != 1
            ):
                raise ValueError("projection revision barrier identity or version mismatch")
            for revision in (
                barrier.previous_foundation_sha256,
                barrier.target_foundation_sha256,
            ):
                if (
                    not isinstance(revision, str)
                    or len(revision) != 64
                    or any(character not in "0123456789abcdef" for character in revision)
                ):
                    raise ValueError("projection revision barrier digest is invalid")
            return barrier
        except (KeyError, TypeError, UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid projection revision barrier for {source_id!r}") from exc

    def _delete_projection_revision_barrier(self, source_id: str) -> None:
        """Remove the barrier only after both index invalidation and canonical commit."""
        try:
            directory_fd = self._open_child_directory("transactions", create=False)
        except FileNotFoundError:
            return
        try:
            try:
                os.unlink(
                    f"{source_id}.projection-revision.json",
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def validate_source_state(
        manifest: DocumentManifest,
        quarantine: QuarantineRecord | None,
    ) -> None:
        """Validate the complete canonical disposition pair for one source."""
        is_quarantined = manifest.ingestion_status.value == "quarantined"
        if is_quarantined != (quarantine is not None):
            raise ValueError("quarantined manifests require exactly one quarantine record")
        if quarantine is None:
            if manifest.quarantine_reasons:
                raise ValueError("non-quarantined manifest cannot contain quarantine reasons")
            return
        if (
            quarantine.source_id != manifest.source_id
            or quarantine.quarantine_id != f"quarantine-{manifest.source_id}"
            or quarantine.parser_profile != manifest.parser_profile
            or quarantine.extraction != manifest.extraction
            or quarantine.reason_codes != tuple(sorted(manifest.quarantine_reasons))
        ):
            raise ValueError("manifest and quarantine record contracts do not match")

    def _target(self, directory: str, record_id: str) -> tuple[Path, str]:
        self._ensure_open()
        _validate_stable_id(record_id)
        if directory not in self._DIRECTORIES:
            raise ValueError(f"unsupported canonical directory: {directory!r}")
        relative_target = PurePath(directory, f"{record_id}.json")
        self._validate_relative_target(relative_target)
        return self.root.joinpath(*relative_target.parts), relative_target.name

    @staticmethod
    def _validate_relative_target(relative_target: PurePath) -> None:
        text = os.fspath(relative_target)
        if (
            relative_target.is_absolute()
            or "\x00" in text
            or any(part in {"", ".", ".."} for part in relative_target.parts)
            or any("/" in part or "\\" in part for part in relative_target.parts)
        ):
            raise ValueError("target must be a safe relative path")

    def _open_child_directory(self, directory: str, *, create: bool) -> int:
        if directory not in self._DIRECTORIES:
            raise ValueError(f"unsupported canonical directory: {directory!r}")
        with self._descriptor_lock:
            root_fd = self._ensure_open()
            if create:
                with suppress(FileExistsError):
                    os.mkdir(directory, mode=0o755, dir_fd=root_fd)
            try:
                directory_fd = os.open(
                    directory,
                    self._directory_open_flags(),
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise ValueError(
                    f"repository directory may resolve outside repository root: {directory!r}"
                ) from exc
        try:
            directory_status = os.fstat(directory_fd)
            if not stat.S_ISDIR(directory_status.st_mode):
                raise ValueError(f"repository child is not a directory: {directory!r}")
        except Exception:
            os.close(directory_fd)
            raise
        return directory_fd

    @staticmethod
    def _atomic_write(directory_fd: int, filename: str, payload: str) -> None:
        CanonicalKnowledgeRepository._atomic_write_bytes(
            directory_fd,
            filename,
            payload.encode("utf-8"),
        )

    @staticmethod
    def _atomic_write_bytes(directory_fd: int, filename: str, payload: bytes) -> None:
        temporary_name: str | None = None
        try:
            for _ in range(32):
                candidate = f".{filename}.{secrets.token_hex(16)}.tmp"
                try:
                    temporary_fd = os.open(
                        candidate,
                        CanonicalKnowledgeRepository._file_create_flags(),
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            else:
                raise FileExistsError("could not allocate a unique temporary file")

            try:
                with os.fdopen(
                    temporary_fd,
                    mode="wb",
                ) as stream:
                    temporary_fd = -1
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if temporary_fd >= 0:
                    os.close(temporary_fd)

            os.replace(
                temporary_name,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = None
            os.fsync(directory_fd)
        finally:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)

    @staticmethod
    def _directory_open_flags() -> int:
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _file_read_flags() -> int:
        return os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _file_create_flags() -> int:
        return os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    @staticmethod
    def _lock_open_flags() -> int:
        return os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    def _ensure_open(self) -> int:
        if self._root_fd is None:
            raise RuntimeError("repository is closed")
        return self._root_fd

    @staticmethod
    def _require_safe_primitives() -> None:
        required_constants = ("O_DIRECTORY", "O_NONBLOCK", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required_constants):
            raise RuntimeError("platform lacks safe descriptor-relative filesystem support")
        if any(function not in os.supports_dir_fd for function in (os.open, os.mkdir, os.unlink)):
            raise RuntimeError("platform lacks safe descriptor-relative filesystem support")
        replace_parameters = inspect.signature(os.replace).parameters
        if not {"src_dir_fd", "dst_dir_fd"}.issubset(replace_parameters):
            raise RuntimeError("platform lacks safe descriptor-relative replace support")
        if not hasattr(fcntl, "flock"):
            raise RuntimeError("platform lacks POSIX source-transition locking")


__all__ = [
    "CanonicalKnowledgeRepository",
    "IngestionFailure",
    "IngestionReport",
    "QuarantineRecord",
    "SemanticBundleEnumerationError",
    "SemanticRepositorySnapshot",
    "SemanticSnapshotChangedError",
]
