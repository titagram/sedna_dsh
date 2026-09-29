"""Host-LLM composition root for local Sedna knowledge services."""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from sedna.knowledge.learning import DocumentLearningService
from sedna.knowledge.repository import CanonicalKnowledgeRepository
from sedna.knowledge.retrieval.maintenance import RetrievalMaintenanceService
from sedna.knowledge.retrieval.service import KnowledgeRetrievalService
from sedna.knowledge.retrieval.sqlite import SQLiteRetrievalIndex
from sedna.knowledge.semantic.compiler import SemanticCompiler
from sedna.knowledge.semantic.llm import HadesLlmAdapter, HostStructuredLlm
from sedna.knowledge.semantic.service import SemanticIngestionService

if TYPE_CHECKING:
    from sedna.engagement.lifecycle import EngagementLifecycleService
    from sedna.engagement.promotion.adapter import PromotionRecoveryCoordinator
    from sedna.engagement.reporting.service import ReportClosureFinalizer, ReportManagementService
    from sedna.engagement.repository import EngagementJournalRepository
    from sedna.engagement.service import EngagementJournalService
    from sedna.planning.service import PlanningService


@dataclass(slots=True)
class HadesKnowledgeRuntime:
    """Own the repository and disposable index used by host-backed learning."""

    learning: DocumentLearningService
    retrieval: KnowledgeRetrievalService
    maintenance: RetrievalMaintenanceService
    planning: PlanningService
    _repository: CanonicalKnowledgeRepository
    _index: SQLiteRetrievalIndex
    _journal: EngagementJournalService
    _journal_repository: EngagementJournalRepository
    journal: EngagementJournalService | None = None
    reporting: ReportManagementService | None = None
    report_finalizer: ReportClosureFinalizer | None = None
    engagements: EngagementLifecycleService | None = None
    promotion: PromotionRecoveryCoordinator | None = None
    _closed: bool = field(default=False, init=False, repr=False)
    _index_closed: bool = field(default=False, init=False, repr=False)
    _repository_closed: bool = field(default=False, init=False, repr=False)
    _journal_closed: bool = field(default=False, init=False, repr=False)
    _close_lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    @classmethod
    def create(
        cls,
        host_llm: object,
        knowledge_root: Path,
        *,
        external_source_path: Path | None = None,
    ) -> HadesKnowledgeRuntime:
        """Create an owned local runtime using only the host structured-completion facade."""
        from uuid import uuid4

        from sedna.engagement.lifecycle import (
            EngagementLifecycleService,
            TerminalSettlementCoordinator,
        )
        from sedna.engagement.promotion.adapter import (
            JournalPromotionAdapter,
            PromotionCommitCapability,
            PromotionRecoveryCoordinator,
        )
        from sedna.engagement.promotion.compiler import CasePromotionCompiler
        from sedna.engagement.promotion.input import PromotionInputProjector
        from sedna.engagement.promotion.llm import PromotionLlmAdapter
        from sedna.engagement.reporting.service import (
            ReportClosureFinalizer,
            ReportManagementService,
        )
        from sedna.engagement.repository import EngagementJournalRepository
        from sedna.engagement.service import EngagementJournalService
        from sedna.engagement.sources import SharedSourceRegistry
        from sedna.planning.llm import PlanningLlmAdapter
        from sedna.planning.service import PlanningService

        host = _require_structured_host(host_llm)
        repository: CanonicalKnowledgeRepository | None = None
        index: SQLiteRetrievalIndex | None = None
        journal_repository: EngagementJournalRepository | None = None
        index_parent_fd = -1
        guarded_root_fd = -1
        source_root_fd = -1
        guarded_source_root: Path | None = None
        try:
            if external_source_path is None:
                journal_repository = EngagementJournalRepository(knowledge_root)
                repository = CanonicalKnowledgeRepository(Path(knowledge_root))
            else:
                guarded_source_root, source_root_fd = _open_source_root_guard(external_source_path)
                requested_root = Path(knowledge_root).resolve(strict=False)
                _require_external_paths(guarded_source_root, requested_root)
                _assert_directory_identity(
                    guarded_source_root, source_root_fd, "learning source root"
                )
                journal_repository = EngagementJournalRepository(requested_root)
                guarded_knowledge_root, guarded_root_fd = _open_external_knowledge_root(
                    knowledge_root,
                    guarded_source_root,
                    source_root_fd,
                )
                repository = CanonicalKnowledgeRepository(
                    guarded_knowledge_root,
                    root_fd=guarded_root_fd,
                )
                os.close(guarded_root_fd)
                guarded_root_fd = -1
                _assert_guarded_roots(repository, guarded_source_root, source_root_fd)
            adapter = HadesLlmAdapter(host)
            compiler = SemanticCompiler(adapter, clock=lambda: datetime.now(UTC))
            semantic = SemanticIngestionService(repository, compiler)
            if guarded_source_root is not None:
                _assert_guarded_roots(repository, guarded_source_root, source_root_fd)
            index_parent_fd = repository.open_index_directory()
            index = SQLiteRetrievalIndex(
                repository.root / "indexes" / "retrieval.sqlite",
                parent_fd=index_parent_fd,
            )
            os.close(index_parent_fd)
            index_parent_fd = -1
            repository.assert_root_identity()
            if guarded_source_root is not None:
                _assert_guarded_roots(repository, guarded_source_root, source_root_fd)
                os.close(source_root_fd)
                source_root_fd = -1
            maintenance = RetrievalMaintenanceService(repository, index)
            opening_audit = maintenance.audit()
            if not opening_audit.succeeded or opening_audit.rebuild_required:
                index.mark_rebuild_required()
            learning = DocumentLearningService(
                knowledge_root=repository.root,
                semantic_service=semantic,
                maintenance=maintenance,
                repository=repository,
            )
            retrieval = KnowledgeRetrievalService(
                index,
                revision_guard=repository.retrieval_read_revision,
                execution_example_loader=repository.load_execution_examples,
            )
            journal = EngagementJournalService(
                journal_repository,
                clock=lambda: datetime.now(UTC),
                uuid_factory=uuid4,
            )
            report_finalizer = ReportClosureFinalizer(
                journal,
                journal_repository._issue_report_commit_capability(),
            )
            terminal_settlement = TerminalSettlementCoordinator(
                journal=journal,
                proof_closure=journal._issue_proof_closure_capability(),
                finalizer=report_finalizer,
            )
            source_registry = SharedSourceRegistry(journal_repository)
            planning = PlanningService(
                journal=journal,
                llm=PlanningLlmAdapter(host),
                clock=lambda: datetime.now(UTC),
                canonical_revision=repository.retrieval_read_revision,
                source_registry_digest=lambda: source_registry.planner_snapshot().registry_sha256,
                retrieval=retrieval,
                source_registry=source_registry,
                terminal_settlement_port=terminal_settlement,
            )
            reporting = ReportManagementService(
                journal=journal,
                planning=planning,
                finalizer=report_finalizer,
            )
            promotion_adapter = JournalPromotionAdapter(
                PromotionCommitCapability(journal_repository._issue_promotion_journal_writer()),
                inputs=PromotionInputProjector(),
                compiler=CasePromotionCompiler(PromotionLlmAdapter(host)),
                semantic=semantic,
                maintenance=maintenance,
                evidence_reader=journal_repository.read_evidence_slice,
            )
            promotion = PromotionRecoveryCoordinator(journal=journal, adapter=promotion_adapter)
            engagements = EngagementLifecycleService(
                journal=journal,
                planning=planning,
                closure_finalizer=report_finalizer,
                lifecycle_commits=journal._issue_lifecycle_commit_capability(),
                promotion_recovery=promotion,
                promotion_revocation=promotion_adapter,
            )
            return cls(
                learning=learning,
                retrieval=retrieval,
                maintenance=maintenance,
                planning=planning,
                promotion=promotion,
                journal=journal,
                reporting=reporting,
                report_finalizer=report_finalizer,
                engagements=engagements,
                _repository=repository,
                _index=index,
                _journal=journal,
                _journal_repository=journal_repository,
            )
        except BaseException:
            if index_parent_fd >= 0:
                os.close(index_parent_fd)
            if guarded_root_fd >= 0:
                os.close(guarded_root_fd)
            if source_root_fd >= 0:
                os.close(source_root_fd)
            _close_owned(journal_repository, index, repository)
            raise

    def __enter__(self) -> HadesKnowledgeRuntime:
        with self._close_lock:
            if self._closed:
                raise RuntimeError("knowledge runtime is closed")
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        """Serialize close attempts and retry only resources whose prior close failed."""
        with self._close_lock:
            if self._closed:
                return
            failure: BaseException | None = None
            if not self._journal_closed:
                try:
                    self._journal_repository.close()
                    self._journal_closed = True
                except BaseException as error:
                    failure = error
            if not self._index_closed:
                try:
                    self._index.close()
                    self._index_closed = True
                except BaseException as error:
                    if failure is None:
                        failure = error
            if not self._repository_closed:
                try:
                    self._repository.close()
                    self._repository_closed = True
                except BaseException as error:
                    if failure is None:
                        failure = error
            if self._journal_closed and self._index_closed and self._repository_closed:
                self._closed = True
            if failure is not None:
                raise failure


class _BoundStructuredHost:
    """One immutable structured-completion callable captured during runtime preflight."""

    def __init__(self, complete_structured: Callable[..., object]) -> None:
        self._complete_structured = complete_structured

    def complete_structured(self, **kwargs: object) -> object:
        return self._complete_structured(**kwargs)


def _open_source_root_guard(source_path: Path) -> tuple[Path, int]:
    requested = Path(source_path)
    try:
        requested_status = os.stat(requested, follow_symlinks=False)
    except OSError as error:
        raise ValueError("learning source path is unavailable") from error
    if stat.S_ISDIR(requested_status.st_mode):
        requested_root = requested
    elif stat.S_ISREG(requested_status.st_mode):
        requested_root = requested.parent
    else:
        raise ValueError("learning source path must be a regular file or directory")
    resolved_root = requested_root.resolve(strict=True)
    descriptor = os.open(resolved_root, _directory_open_flags())
    try:
        _assert_directory_identity(resolved_root, descriptor, "learning source root")
        return resolved_root, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_external_knowledge_root(
    knowledge_root: Path,
    source_root: Path,
    source_root_fd: int,
) -> tuple[Path, int]:
    try:
        resolved_root = Path(knowledge_root).resolve(strict=False)
    except (OSError, ValueError) as error:
        raise ValueError("knowledge root is unavailable") from error
    _require_external_paths(source_root, resolved_root)
    _assert_directory_identity(source_root, source_root_fd, "learning source root")
    descriptor = _open_or_create_directory(
        resolved_root,
        forbidden_root_fd=source_root_fd,
    )
    try:
        _assert_directory_identity(source_root, source_root_fd, "learning source root")
        _require_external_paths(source_root, resolved_root)
        return resolved_root, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_or_create_directory(path: Path, *, forbidden_root_fd: int | None = None) -> int:
    flags = _directory_open_flags()
    descriptor = os.open(path.anchor, flags)
    try:
        _require_distinct_root_descriptor(descriptor, forbidden_root_fd)
        for component in path.parts[1:]:
            try:
                child_fd = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o755, dir_fd=descriptor)
                child_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child_fd
            _require_distinct_root_descriptor(descriptor, forbidden_root_fd)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("knowledge root is not a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_distinct_root_descriptor(descriptor: int, forbidden_root_fd: int | None) -> None:
    if forbidden_root_fd is None:
        return
    current = os.fstat(descriptor)
    forbidden = os.fstat(forbidden_root_fd)
    if (current.st_dev, current.st_ino) == (forbidden.st_dev, forbidden.st_ino):
        raise ValueError("knowledge root must remain outside the learning source root")


def _assert_guarded_roots(
    repository: CanonicalKnowledgeRepository,
    source_root: Path,
    source_root_fd: int,
) -> None:
    _assert_directory_identity(source_root, source_root_fd, "learning source root")
    repository.assert_root_identity()
    _require_external_paths(source_root, repository.root)


def _assert_directory_identity(path: Path, descriptor: int, label: str) -> None:
    retained = os.fstat(descriptor)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError(f"{label} identity changed") from error
    if (
        not stat.S_ISDIR(retained.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (
            retained.st_dev,
            retained.st_ino,
        )
        != (current.st_dev, current.st_ino)
    ):
        raise RuntimeError(f"{label} identity changed")


def _require_external_paths(source_root: Path, knowledge_root: Path) -> None:
    if (
        source_root == knowledge_root
        or knowledge_root.is_relative_to(source_root)
        or source_root.is_relative_to(knowledge_root)
    ):
        raise ValueError("knowledge root must remain outside the learning source root")


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _require_structured_host(host_llm: object) -> HostStructuredLlm:
    """Fail closed unless the host exposes the sole allowed semantic LLM entry point."""
    try:
        complete_structured = host_llm.complete_structured  # type: ignore[attr-defined]
    except Exception:
        complete_structured = None
    if not callable(complete_structured):
        raise TypeError("host_llm must provide callable complete_structured")
    return cast(HostStructuredLlm, _BoundStructuredHost(complete_structured))


def _close_owned(
    journal_repository: EngagementJournalRepository | None,
    index: SQLiteRetrievalIndex | None,
    repository: CanonicalKnowledgeRepository | None,
) -> None:
    """Attempt both owned closes once, preserving the first close failure."""
    failure: BaseException | None = None
    for resource in (journal_repository, index, repository):
        if resource is None:
            continue
        try:
            resource.close()
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise failure


__all__ = ["HadesKnowledgeRuntime"]
