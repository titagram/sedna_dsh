"""Sealed promotion-to-journal adapter.

This module is the only promotion layer allowed to hold the repository-issued
promotion writer.  The repository receives canonical bytes and data-only
identities; it does not import promotion models.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from hashlib import sha256
from typing import Any, Literal, Protocol, TypeVar, cast
from uuid import UUID, uuid5

from sedna.engagement.models import ExecutionLaneKey, JournalRevision, PromotionSourceId, Sha256Hex
from sedna.engagement.promotion.models import (
    PROMOTION_COMPILER_VERSION,
    CommittedPromotionSource,
    PromotionClaimOwnership,
    PromotionClaimRequest,
    PromotionClaimResult,
    PromotionCleanupReceipt,
    PromotionDraft,
    PromotionIndexFailureReceipt,
    PromotionIndexPendingReceipt,
    PromotionPublicationReceipt,
    PromotionResult,
    PromotionSemanticReceipt,
    RenderedPromotionSource,
)
from sedna.engagement.promotion.prompts import (
    PROMOTION_CRITIC_PROMPT_VERSION,
    PROMOTION_EXTRACTOR_PROMPT_VERSION,
    PROMOTION_REPAIR_PROMPT_VERSION,
)
from sedna.engagement.promotion.render import (
    PROMOTION_RENDERER_VERSION,
    PromotionRenderIdentity,
    promotion_source_id,
    render_promotion_source,
)
from sedna.engagement.promotion.sanitize import assert_semantic_promotion_safe
from sedna.engagement.promotion.source import (
    build_nonaccepted_promotion_manifest,
    build_promotion_prepared_source,
)
from sedna.engagement.repository import _PromotionJournalWriter
from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.retrieval.maintenance import (
    MaintenanceIssueCode,
    RetrievalMaintenanceReport,
    RetrievalMaintenanceService,
)
from sedna.knowledge.schema import foundation_manifest_digest
from sedna.knowledge.semantic import SemanticAcceptanceProfile, SemanticIngestionService
from sedna.knowledge.semantic.compiler import SEMANTIC_COMPILER_VERSION
from sedna.knowledge.semantic.drafts import SemanticCompilationResult
from sedna.knowledge.semantic.prompts import (
    CRITIC_PROMPT_VERSION,
    EXTRACTOR_PROMPT_VERSION,
    REPAIR_PROMPT_VERSION,
)

MAX_PROMOTION_INDEX_RETRIES = 3


@dataclass(frozen=True, slots=True, repr=False)
class RevocationAbsenceProof:
    """Repository-bound proof that a promotion's physical state is absent."""

    engagement_id: UUID
    verification_event_id: UUID
    attempt_id: UUID | None
    purpose: Literal["direct_empty", "request_cleanup"]
    request_event_id: UUID | None
    source_id: PromotionSourceId | None
    removed_case_ids: tuple[str, ...]
    canonical_state: Literal["absent", "excluded"]
    canonical_revision: Sha256Hex | None
    index_generation: int
    index_audit_sha256: Sha256Hex
    guard_nonce: UUID
    _issuer_token: object = field(repr=False, compare=False)
    operation_nonce: object = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class PromotionSourceCommitResult:
    source: CommittedPromotionSource
    event_id: UUID
    created: bool


@dataclass(frozen=True)
class PromotionMutationResult:
    event_id: UUID
    revision: JournalRevision
    created: bool = True


ReceiptIssuer = Callable[..., object]
ReceiptAuthenticator = Callable[[object, type], None]
ReceiptValidator = Callable[[object, type, str], None]
TReceipt = TypeVar("TReceipt")


class _ReceiptNonce(Protocol):
    operation_nonce: object


class _ReceiptLedger:
    """Authenticate exact in-memory receipt payloads and one-shot operation uses."""

    __slots__ = ("_records", "_token", "_uses")

    def __init__(self, token: object) -> None:
        self._token = token
        self._records: dict[object, tuple[type, tuple[object, ...]]] = {}
        self._uses: dict[object, set[str]] = {}

    @staticmethod
    def _payload(receipt: object) -> tuple[object, ...]:
        return tuple(
            getattr(receipt, item.name)
            for item in fields(receipt)
            if item.name not in {"_issuer_token", "operation_nonce"}
        )

    def issue(self, receipt_type: type[TReceipt], **values: object) -> TReceipt:
        nonce = object()
        receipt = cast(Any, receipt_type)(
            _issuer_token=self._token,
            operation_nonce=nonce,
            **values,
        )
        self._records[nonce] = (receipt_type, self._payload(receipt))
        self._uses[nonce] = set()
        return cast(TReceipt, receipt)

    def authenticate(self, receipt: object, expected_type: type) -> None:
        nonce = getattr(receipt, "operation_nonce", None)
        record = self._records.get(nonce)
        if (
            type(receipt) is not expected_type
            or getattr(receipt, "_issuer_token", None) is not self._token
            or record != (expected_type, self._payload(receipt))
        ):
            raise ValueError("invalid promotion receipt payload binding")

    def consume(self, receipt: object, expected_type: type, action: str) -> None:
        self.require_available(receipt, expected_type, action)
        nonce = cast(_ReceiptNonce, receipt).operation_nonce
        self._uses[nonce].add(action)

    def require_available(self, receipt: object, expected_type: type, action: str) -> None:
        self.authenticate(receipt, expected_type)
        nonce = cast(_ReceiptNonce, receipt).operation_nonce
        if action in self._uses[nonce]:
            raise ValueError("promotion receipt operation nonce was already consumed")


class PromotionCommitCapability:
    """Package-private sealed authority for promotion transactions."""

    __slots__ = ("_issuer_token", "_receipt_ledger", "_writer")

    def __init__(self, writer: _PromotionJournalWriter) -> None:
        if type(writer) is not _PromotionJournalWriter:
            raise ValueError("promotion capability requires a repository-issued writer")
        writer._require_holder()
        self._writer = writer
        self._issuer_token = object()
        self._receipt_ledger = _ReceiptLedger(self._issuer_token)

    def claim(
        self,
        engagement_id: UUID,
        request: PromotionClaimRequest,
        *,
        expected_revision: JournalRevision,
    ) -> PromotionClaimResult:
        request = PromotionClaimRequest.model_validate(
            request.model_dump(mode="python", warnings="error")
        )
        result = self._writer.claim(
            engagement_id,
            request=request.model_dump(mode="json", warnings="error"),
            expected_revision=expected_revision,
        )
        ownership = None
        if result.disposition in {"created", "resumed"}:
            assert result.event is not None and result.attempt is not None
            ownership = PromotionClaimOwnership(
                attempt_id=result.attempt.attempt_id,
                claim_event_id=result.event.event_id,
                _issuer_token=self._issuer_token,
            )
        return PromotionClaimResult(
            disposition=result.disposition,
            attempt=result.attempt,
            claim_event_id=result.event.event_id if result.event is not None else None,
            revision=result.revision,
            ownership=ownership,
        )

    def request_cancellation(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        attempt_id: UUID,
        operation: Literal["reject", "reopen"],
        reopen_reason: str,
        proof_rejection: object | None,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        method = getattr(self._writer, "request_cancellation", None)
        if method is None:
            raise ValueError("promotion cancellation is not available")
        result = method(
            engagement_id,
            lane=lane,
            attempt_id=attempt_id,
            operation=operation,
            reopen_reason=reopen_reason,
            proof_rejection=proof_rejection,
            expected_revision=expected_revision,
        )
        return PromotionMutationResult(event_id=result.event_id, revision=result.revision)

    def request_revocation(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        attempt_id: UUID,
        operation: Literal["reject", "reopen"],
        reopen_reason: str,
        proof_rejection: object | None,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        method = getattr(self._writer, "request_revocation", None)
        if method is None:
            raise ValueError("promotion revocation is not available")
        result = method(
            engagement_id,
            lane=lane,
            attempt_id=attempt_id,
            operation=operation,
            reopen_reason=reopen_reason,
            proof_rejection=proof_rejection,
            expected_revision=expected_revision,
        )
        return PromotionMutationResult(event_id=result.event_id, revision=result.revision)

    def commit_superseded_and_promoted(
        self,
        engagement_id: UUID,
        *,
        replacement: PromotionPublicationReceipt,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        self._require_receipt(replacement, PromotionPublicationReceipt, "commit_superseded")
        method = getattr(self._writer, "commit_superseded_and_promoted", None)
        if method is None:
            raise ValueError("promotion supersession is not available")
        result = method(engagement_id, replacement=replacement, expected_revision=expected_revision)
        self._consume_receipt(replacement, PromotionPublicationReceipt, "commit_superseded")
        return PromotionMutationResult(event_id=result.event_id, revision=result.revision)

    def commit_candidate(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        promotion_revision: int,
        draft: PromotionDraft,
        repair_count: int,
        ownership: PromotionClaimOwnership,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._issuer_token
            or ownership.attempt_id != attempt_id
        ):
            raise ValueError("invalid promotion claim ownership")
        if type(promotion_revision) is not int or promotion_revision < 1:
            raise ValueError("invalid promotion revision")
        draft = PromotionDraft.model_validate(draft.model_dump(mode="python", warnings="error"))
        candidate_bytes = json.dumps(
            draft.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        result = self._writer.commit_candidate(
            engagement_id,
            attempt_id=attempt_id,
            promotion_revision=promotion_revision,
            candidate_bytes=candidate_bytes,
            candidate_sha256=sha256(candidate_bytes).hexdigest(),
            repair_count=repair_count,
            expected_revision=expected_revision,
        )
        return PromotionMutationResult(
            event_id=result.event.event_id,
            revision=result.revision,
            created=result.created,
        )

    def load_candidate(
        self,
        engagement_id: UUID,
        *,
        ownership: PromotionClaimOwnership,
    ) -> PromotionDraft:
        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._issuer_token
        ):
            raise ValueError("invalid promotion claim ownership")
        candidate_bytes = self._writer.load_candidate(
            engagement_id,
            attempt_id=ownership.attempt_id,
            claim_event_id=ownership.claim_event_id,
        )
        return PromotionDraft.model_validate_json(candidate_bytes)

    def terminate(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        promotion_revision: int,
        disposition: Literal["quarantined", "failed", "abandoned", "cancelled"],
        reason_code: str,
        cleanup_receipt: PromotionCleanupReceipt | None,
        ownership: PromotionClaimOwnership,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._issuer_token
            or ownership.attempt_id != attempt_id
        ):
            raise ValueError("invalid promotion claim ownership")
        source_id = canonical_revision = None
        if cleanup_receipt is not None:
            try:
                self._require_receipt(cleanup_receipt, PromotionCleanupReceipt, "terminate_cleanup")
            except ValueError:
                raise ValueError("invalid promotion cleanup receipt") from None
            if (
                cleanup_receipt.attempt_id != attempt_id
                or cleanup_receipt.promotion_revision != promotion_revision
            ):
                raise ValueError("invalid promotion cleanup receipt")
            source_id = cleanup_receipt.source_id
            canonical_revision = cleanup_receipt.canonical_revision
        result = self._writer.terminate(
            engagement_id,
            attempt_id=attempt_id,
            promotion_revision=promotion_revision,
            disposition=disposition,
            reason_code=reason_code,
            cleanup_source_id=source_id,
            cleanup_canonical_revision=canonical_revision,
            claim_event_id=ownership.claim_event_id,
            expected_revision=expected_revision,
        )
        if cleanup_receipt is not None:
            self._consume_receipt(
                cleanup_receipt,
                PromotionCleanupReceipt,
                "terminate_cleanup",
            )
        return PromotionMutationResult(
            event_id=result.events[0].event_id,
            revision=result.revision,
        )

    def commit_source(
        self,
        engagement_id: UUID,
        rendered: RenderedPromotionSource,
        *,
        ownership: PromotionClaimOwnership,
        expected_revision: JournalRevision,
    ) -> PromotionSourceCommitResult:
        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._issuer_token
            or ownership.attempt_id != rendered.provenance.attempt_id
        ):
            raise ValueError("invalid promotion claim ownership")
        rendered = RenderedPromotionSource.model_validate(
            rendered.model_dump(mode="python", warnings="error")
        )
        if rendered.provenance.engagement_id != engagement_id:
            raise ValueError("promotion source does not belong to the engagement")
        provenance_bytes = json.dumps(
            rendered.provenance.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        committed = self._writer.commit_source(
            engagement_id,
            attempt_id=rendered.provenance.attempt_id,
            source_id=rendered.source_id,
            promotion_revision=rendered.promotion_revision,
            source_bytes=rendered.markdown.encode("utf-8"),
            source_sha256=rendered.source_sha256,
            provenance_bytes=provenance_bytes,
            provenance_sha256=rendered.provenance_sha256,
            verified_revision=rendered.provenance.verified_revision,
            verification_event_id=rendered.provenance.verification_event_id,
            expected_revision=expected_revision,
        )
        return PromotionSourceCommitResult(
            source=CommittedPromotionSource(
                **rendered.model_dump(mode="python"),
                committed_revision=committed.revision,
            ),
            event_id=committed.event.event_id,
            created=committed.created,
        )

    def _receipt_service(
        self,
        semantic: SemanticIngestionService,
        maintenance: RetrievalMaintenanceService,
    ) -> _PromotionReceiptService:
        """Bind receipt issuance to exact trusted service instances and their operations."""
        if type(semantic) is not SemanticIngestionService:
            raise TypeError("semantic must be an exact SemanticIngestionService")
        if type(maintenance) is not RetrievalMaintenanceService:
            raise TypeError("maintenance must be an exact RetrievalMaintenanceService")
        if semantic._repository is not maintenance.repository:
            raise ValueError("promotion receipt services must share one canonical repository")
        return _PromotionReceiptService(
            semantic,
            maintenance,
            self._receipt_ledger.issue,
            self._receipt_ledger.authenticate,
            self._receipt_ledger.consume,
            self._issuer_token,
        )

    def _require_receipt(self, receipt: object, expected_type: type, action: str) -> None:
        if (
            type(receipt) is not expected_type
            or getattr(receipt, "_issuer_token", None) is not self._issuer_token
        ):
            raise ValueError("invalid promotion receipt")
        self._receipt_ledger.require_available(receipt, expected_type, action)

    def _consume_receipt(self, receipt: object, expected_type: type, action: str) -> None:
        self._receipt_ledger.consume(receipt, expected_type, action)

    @staticmethod
    def _mutation(result) -> PromotionMutationResult:
        return PromotionMutationResult(
            event_id=result.events[0].event_id,
            revision=result.revision,
        )

    def commit_semantic(
        self,
        engagement_id: UUID,
        receipt: PromotionSemanticReceipt,
        *,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        self._require_receipt(receipt, PromotionSemanticReceipt, "commit_semantic")
        mutation = self._mutation(
            self._writer.commit_semantic(
                engagement_id,
                attempt_id=receipt.attempt_id,
                promotion_revision=receipt.promotion_revision,
                source_id=receipt.source_id,
                foundation_manifest_sha256=receipt.foundation_manifest_sha256,
                artifact_ids=receipt.artifact_ids,
                expected_revision=expected_revision,
            )
        )
        self._consume_receipt(receipt, PromotionSemanticReceipt, "commit_semantic")
        return mutation

    def commit_index_pending(
        self,
        engagement_id: UUID,
        receipt: PromotionIndexPendingReceipt,
        *,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        self._require_receipt(receipt, PromotionIndexPendingReceipt, "commit_index_pending")
        mutation = self._mutation(
            self._writer.commit_index_pending(
                engagement_id,
                attempt_id=receipt.attempt_id,
                promotion_revision=receipt.promotion_revision,
                source_id=receipt.source_id,
                expected_canonical_revision=receipt.expected_canonical_revision,
                expected_revision=expected_revision,
            )
        )
        self._consume_receipt(receipt, PromotionIndexPendingReceipt, "commit_index_pending")
        return mutation

    def commit_index_retry(
        self,
        engagement_id: UUID,
        receipt: PromotionIndexFailureReceipt,
        *,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        self._require_receipt(receipt, PromotionIndexFailureReceipt, "commit_index_retry")
        mutation = self._mutation(
            self._writer.commit_index_retry(
                engagement_id,
                attempt_id=receipt.attempt_id,
                promotion_revision=receipt.promotion_revision,
                retry_count=receipt.retry_count,
                reason_code=receipt.reason_code,
                expected_revision=expected_revision,
            )
        )
        self._consume_receipt(receipt, PromotionIndexFailureReceipt, "commit_index_retry")
        return mutation

    def commit_promoted(
        self,
        engagement_id: UUID,
        receipt: PromotionPublicationReceipt,
        *,
        expected_revision: JournalRevision,
    ) -> PromotionMutationResult:
        self._require_receipt(receipt, PromotionPublicationReceipt, "commit_promoted")
        mutation = self._mutation(
            self._writer.commit_promoted(
                engagement_id,
                attempt_id=receipt.attempt_id,
                promotion_revision=receipt.promotion_revision,
                source_id=receipt.source_id,
                case_ids=receipt.case_ids,
                expected_revision=expected_revision,
            )
        )
        self._consume_receipt(receipt, PromotionPublicationReceipt, "commit_promoted")
        return mutation

    def load_state(self, engagement_id: UUID):
        """Recover publication progress exclusively from the durable journal."""

        return self._writer.load_snapshot(engagement_id).state.promotion

    def active_attempt(
        self,
        engagement_id: UUID,
        *,
        ownership: PromotionClaimOwnership,
        expected_stages: set[str],
    ) -> tuple[Any, JournalRevision]:
        """Recheck the exact owned durable stage before one physical mutation."""

        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._issuer_token
        ):
            raise ValueError("invalid promotion claim ownership")
        return self._writer.authenticate_claim(
            engagement_id,
            attempt_id=ownership.attempt_id,
            claim_event_id=ownership.claim_event_id,
            expected_stages=expected_stages,
        )


class _PromotionReceiptService:
    """Mint journal receipts only from completed canonical service operations."""

    __slots__ = (
        "_authenticate",
        "_issue",
        "_maintenance",
        "_semantic",
        "_token",
        "_validate",
    )

    def __init__(
        self,
        semantic: SemanticIngestionService,
        maintenance: RetrievalMaintenanceService,
        issue: ReceiptIssuer,
        authenticate: ReceiptAuthenticator,
        validate: ReceiptValidator,
        token: object,
    ) -> None:
        self._semantic = semantic
        self._maintenance = maintenance
        self._issue = issue
        self._authenticate = authenticate
        self._validate = validate
        self._token = token

    def persist_semantic(
        self,
        prepared: PreparedSource,
        compilation: SemanticCompilationResult,
        *,
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
    ) -> tuple[SemanticCompilationResult, PromotionSemanticReceipt]:
        """Persist one service-issued compilation and attest only the verified result."""
        self._require_ownership(ownership)
        persisted = self._semantic.persist_compilation(
            prepared,
            compilation,
            acceptance_profile=SemanticAcceptanceProfile.JOURNAL_PROMOTION,
        )
        bundle = persisted.bundle
        if persisted.disposition != "verified" or bundle is None:
            raise ValueError("journal promotion semantic persistence was not verified")
        self._require_current(prepared)
        receipt = self._issue(
            PromotionSemanticReceipt,
            attempt_id=ownership.attempt_id,
            promotion_revision=promotion_revision,
            source_id=prepared.manifest.source_id,
            foundation_manifest_sha256=foundation_manifest_digest(prepared.manifest),
            artifact_ids=bundle.compilation_manifest.emitted_artifact_ids,
        )
        assert type(receipt) is PromotionSemanticReceipt
        return persisted, receipt

    def canonical_currentness(
        self,
        prepared: PreparedSource,
        semantic_receipt: PromotionSemanticReceipt,
        *,
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
    ) -> PromotionIndexPendingReceipt:
        """Attest the exact canonical snapshot containing the persisted promotion."""
        self._require_prior_receipt(
            semantic_receipt,
            PromotionSemanticReceipt,
            prepared,
            ownership,
            promotion_revision,
        )
        snapshot, _bundle = self._require_current_snapshot(prepared, semantic_receipt.artifact_ids)
        self._validate(semantic_receipt, PromotionSemanticReceipt, "canonical_currentness")
        receipt = self._issue(
            PromotionIndexPendingReceipt,
            attempt_id=ownership.attempt_id,
            promotion_revision=promotion_revision,
            source_id=prepared.manifest.source_id,
            expected_canonical_revision=snapshot.revision,
        )
        assert type(receipt) is PromotionIndexPendingReceipt
        return receipt

    def recover_semantic(
        self,
        prepared: PreparedSource,
        *,
        artifact_ids: tuple[str, ...],
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
    ) -> PromotionSemanticReceipt:
        """Re-attest only event-bound canonical semantics after a runtime restart."""

        self._require_ownership(ownership)
        _snapshot, bundle = self._require_current_snapshot(prepared, artifact_ids)
        receipt = self._issue(
            PromotionSemanticReceipt,
            attempt_id=ownership.attempt_id,
            promotion_revision=promotion_revision,
            source_id=prepared.manifest.source_id,
            foundation_manifest_sha256=foundation_manifest_digest(prepared.manifest),
            artifact_ids=bundle.compilation_manifest.emitted_artifact_ids,
        )
        assert type(receipt) is PromotionSemanticReceipt
        return receipt

    def exclude_foundation(
        self,
        prepared: PreparedSource,
        *,
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
        reason: str,
    ) -> PromotionCleanupReceipt:
        """Exclude a committed foundation and prove retrieval absence before termination."""

        self._require_ownership(ownership)
        current = self._semantic._repository.load_manifest(prepared.manifest.source_id)
        excluded = build_nonaccepted_promotion_manifest(current, reason=cast(Any, reason))
        if current != excluded:
            self._semantic._repository.transition_source(
                excluded,
                None,
                before_foundation_revision_change=self._maintenance.barrier_source_revision,
            )
        report = self._maintenance.rebuild()
        if not report.succeeded or report.rebuild_required:
            raise ValueError("promotion foundation cleanup could not prove index absence")
        snapshot = self._semantic._repository.semantic_bundle_snapshot()
        if any(bundle.source_id == prepared.manifest.source_id for bundle in snapshot.bundles):
            raise ValueError("excluded promotion foundation remains semantically retrievable")
        receipt = self._issue(
            PromotionCleanupReceipt,
            attempt_id=ownership.attempt_id,
            promotion_revision=promotion_revision,
            source_id=prepared.manifest.source_id,
            canonical_revision=foundation_manifest_digest(excluded),
        )
        assert type(receipt) is PromotionCleanupReceipt
        return receipt

    def rebuild_index(
        self,
        prepared: PreparedSource,
        pending_receipt: PromotionIndexPendingReceipt,
        *,
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
        retry_count: int,
    ) -> tuple[
        RetrievalMaintenanceReport,
        PromotionIndexFailureReceipt | PromotionPublicationReceipt,
    ]:
        """Return a failure or publication receipt from this exact rebuild invocation."""
        self._require_prior_receipt(
            pending_receipt,
            PromotionIndexPendingReceipt,
            prepared,
            ownership,
            promotion_revision,
        )
        if type(retry_count) is not int or retry_count < 1:
            raise ValueError("retry_count must be a positive integer")
        snapshot, _bundle = self._require_current_snapshot(prepared)
        if snapshot.revision != pending_receipt.expected_canonical_revision:
            raise ValueError("canonical revision changed before promotion index rebuild")
        self._validate(pending_receipt, PromotionIndexPendingReceipt, "rebuild_index")
        report = self._maintenance.rebuild()
        if not report.succeeded or report.rebuild_required:
            unavailable = any(
                issue.code is MaintenanceIssueCode.INDEX_UNAVAILABLE for issue in report.issues
            )
            receipt = self._issue(
                PromotionIndexFailureReceipt,
                attempt_id=ownership.attempt_id,
                promotion_revision=promotion_revision,
                retry_count=retry_count,
                reason_code="index_unavailable" if unavailable else "index_rebuild_failed",
            )
            assert type(receipt) is PromotionIndexFailureReceipt
            return report, receipt
        snapshot, bundle = self._require_current_snapshot(prepared)
        if snapshot.revision != pending_receipt.expected_canonical_revision:
            raise ValueError("canonical revision changed during promotion index rebuild")
        receipt = self._issue(
            PromotionPublicationReceipt,
            attempt_id=ownership.attempt_id,
            promotion_revision=promotion_revision,
            source_id=prepared.manifest.source_id,
            case_ids=tuple(item.case_id for item in bundle.cases),
        )
        assert type(receipt) is PromotionPublicationReceipt
        return report, receipt

    def _require_ownership(self, ownership: PromotionClaimOwnership) -> None:
        if (
            type(ownership) is not PromotionClaimOwnership
            or ownership._issuer_token is not self._token
        ):
            raise ValueError("invalid promotion claim ownership")

    def _require_prior_receipt(
        self,
        receipt: object,
        receipt_type: type,
        prepared: PreparedSource,
        ownership: PromotionClaimOwnership,
        promotion_revision: int,
    ) -> None:
        self._require_ownership(ownership)
        if (
            type(receipt) is not receipt_type
            or getattr(receipt, "_issuer_token", None) is not self._token
            or getattr(receipt, "attempt_id", None) != ownership.attempt_id
            or getattr(receipt, "promotion_revision", None) != promotion_revision
            or getattr(receipt, "source_id", prepared.manifest.source_id)
            != prepared.manifest.source_id
        ):
            raise ValueError("promotion receipt does not match its trusted operation chain")
        self._authenticate(receipt, receipt_type)

    def _require_current(self, prepared: PreparedSource) -> None:
        self._semantic._repository.require_journal_promotion_physical_state(prepared.manifest)
        if not self._semantic.is_current(prepared):
            raise ValueError("journal promotion semantic state is not current")

    def _require_current_snapshot(
        self,
        prepared: PreparedSource,
        artifact_ids: tuple[str, ...] | None = None,
    ):
        self._require_current(prepared)
        snapshot = self._semantic._repository.semantic_bundle_snapshot()
        matches = tuple(
            bundle for bundle in snapshot.bundles if bundle.source_id == prepared.manifest.source_id
        )
        if len(matches) != 1:
            raise ValueError("canonical promotion bundle is unavailable")
        bundle = matches[0]
        if (
            artifact_ids is not None
            and bundle.compilation_manifest.emitted_artifact_ids != artifact_ids
        ):
            raise ValueError("canonical promotion artifacts do not match semantic persistence")
        return snapshot, bundle


class RevocationLifecycleCommitCapability:
    """Sealed bridge for cleanup plus lifecycle settlement events.

    The concrete repository/runtime composition may provide the corresponding
    writer operation; keeping this bridge separate prevents callers from
    submitting arbitrary mixed event batches.
    """

    __slots__ = ("_writer", "_issuer_token", "_proof_ledger")

    def __init__(
        self,
        writer: _PromotionJournalWriter,
        issuer_token: object,
        proof_ledger: _ReceiptLedger,
    ) -> None:
        if type(writer) is not _PromotionJournalWriter:
            raise ValueError("revocation capability requires a repository-issued writer")
        writer._require_holder()
        self._writer = writer
        self._issuer_token = issuer_token
        self._proof_ledger = proof_ledger

    def _require_absence_proof(
        self,
        engagement_id: UUID,
        request_event_id: UUID | None,
        absence_proof: RevocationAbsenceProof,
        purpose: Literal["direct_empty", "request_cleanup"],
    ) -> None:
        if (
            type(absence_proof) is not RevocationAbsenceProof
            or absence_proof.engagement_id != engagement_id
            or absence_proof.purpose != purpose
            or absence_proof.request_event_id != request_event_id
            or (absence_proof.canonical_state == "excluded")
            != (absence_proof.canonical_revision is not None)
            or (
                absence_proof.canonical_state == "absent"
                and (absence_proof.source_id is not None or absence_proof.removed_case_ids)
            )
            or (absence_proof.canonical_state == "excluded" and absence_proof.source_id is None)
        ):
            raise ValueError("invalid repository-bound revocation absence proof")
        self._proof_ledger.require_available(
            absence_proof,
            RevocationAbsenceProof,
            "revocation_cleanup",
        )

    def _consume_absence_proof(self, absence_proof: RevocationAbsenceProof) -> None:
        self._proof_ledger.consume(
            absence_proof,
            RevocationAbsenceProof,
            "revocation_cleanup",
        )

    def commit_cleanup_reject_and_reopen(
        self,
        engagement_id: UUID,
        request_event_id: UUID,
        absence_proof: RevocationAbsenceProof,
        expected_revision: JournalRevision,
    ) -> Any:
        self._require_absence_proof(
            engagement_id,
            request_event_id,
            absence_proof,
            "request_cleanup",
        )
        method = getattr(self._writer, "commit_cleanup_reject_and_reopen", None)
        if method is None:
            raise ValueError("revocation cleanup is not available")
        result = method(
            engagement_id,
            request_event_id=request_event_id,
            absence_proof=absence_proof,
            expected_revision=expected_revision,
        )
        self._consume_absence_proof(absence_proof)
        return result

    def commit_cleanup_and_reopen(
        self,
        engagement_id: UUID,
        request_event_id: UUID,
        absence_proof: RevocationAbsenceProof,
        expected_revision: JournalRevision,
    ) -> Any:
        self._require_absence_proof(
            engagement_id,
            request_event_id,
            absence_proof,
            "request_cleanup",
        )
        method = getattr(self._writer, "commit_cleanup_and_reopen", None)
        if method is None:
            raise ValueError("revocation cleanup is not available")
        result = method(
            engagement_id,
            request_event_id=request_event_id,
            absence_proof=absence_proof,
            expected_revision=expected_revision,
        )
        self._consume_absence_proof(absence_proof)
        return result

    def commit_empty_reject_and_reopen(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        reason: str,
        proof_rejection: object,
        absence_proof: RevocationAbsenceProof,
        expected_revision: JournalRevision,
    ) -> Any:
        self._require_absence_proof(engagement_id, None, absence_proof, "direct_empty")
        method = getattr(self._writer, "commit_empty_reject_and_reopen", None)
        if method is None:
            raise ValueError("empty revocation cleanup is not available")
        result = method(
            engagement_id,
            lane=lane,
            reason=reason,
            proof_rejection=proof_rejection,
            absence_proof=absence_proof,
            expected_revision=expected_revision,
        )
        self._consume_absence_proof(absence_proof)
        return result

    def commit_empty_and_reopen(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        reason: str,
        absence_proof: RevocationAbsenceProof,
        expected_revision: JournalRevision,
    ) -> Any:
        self._require_absence_proof(engagement_id, None, absence_proof, "direct_empty")
        method = getattr(self._writer, "commit_empty_and_reopen", None)
        if method is None:
            raise ValueError("empty revocation cleanup is not available")
        result = method(
            engagement_id,
            lane=lane,
            reason=reason,
            absence_proof=absence_proof,
            expected_revision=expected_revision,
        )
        self._consume_absence_proof(absence_proof)
        return result


class JournalPromotionAdapter:
    """Sole orchestration authority for guarded canonical/index publication."""

    def __init__(
        self,
        capability: PromotionCommitCapability,
        *,
        inputs: Any,
        compiler: Any,
        semantic: SemanticIngestionService,
        maintenance: RetrievalMaintenanceService,
        evidence_reader: Callable[..., object],
    ) -> None:
        if type(capability) is not PromotionCommitCapability:
            raise TypeError("capability must be an exact PromotionCommitCapability")
        if not callable(evidence_reader):
            raise TypeError("evidence_reader must be callable")
        self._capability = capability
        self._inputs = inputs
        self._compiler = compiler
        self._semantic = semantic
        self._maintenance = maintenance
        self._evidence_reader = evidence_reader
        self._receipts = capability._receipt_service(semantic, maintenance)
        self._revocation_commits = RevocationLifecycleCommitCapability(
            capability._writer,
            capability._issuer_token,
            capability._receipt_ledger,
        )

    @staticmethod
    def _claim_request(
        revision: JournalRevision, verification_event_id: UUID
    ) -> PromotionClaimRequest:
        return PromotionClaimRequest(
            verified_revision=revision,
            verification_event_id=verification_event_id,
            compiler_version=PROMOTION_COMPILER_VERSION,
            extractor_prompt_version=PROMOTION_EXTRACTOR_PROMPT_VERSION,
            critic_prompt_version=PROMOTION_CRITIC_PROMPT_VERSION,
            repair_prompt_version=PROMOTION_REPAIR_PROMPT_VERSION,
            renderer_version=PROMOTION_RENDERER_VERSION,
            semantic_compiler_version=SEMANTIC_COMPILER_VERSION,
            semantic_prompt_versions=(
                EXTRACTOR_PROMPT_VERSION,
                CRITIC_PROMPT_VERSION,
                REPAIR_PROMPT_VERSION,
            ),
        )

    @staticmethod
    def _completed(snapshot: Any, verification_event_id: UUID) -> PromotionResult | None:
        for attempt in reversed(snapshot.state.promotion.recent_terminal_attempts):
            if (
                attempt.verification_event_id == verification_event_id
                and attempt.disposition == "promoted"
            ):
                return PromotionResult(
                    disposition="unchanged",
                    attempt_id=attempt.attempt_id,
                    promotion_revision=attempt.promotion_revision,
                    source_id=attempt.source_id,
                    case_ids=attempt.case_ids,
                    journal_revision=snapshot.revision,
                )
        return None

    def _require_stage_fence(
        self,
        engagement_id: UUID,
        *,
        verification_event_id: UUID,
        attempt_id: UUID,
        promotion_revision: int,
    ) -> tuple[Any, JournalRevision]:
        writer = getattr(self._capability, "_writer", None)
        if writer is None:
            # Recovery tests and dependency-neutral embedders may expose only
            # the narrow capability methods; their caller already owns the
            # journal fence.
            return self._capability, cast(JournalRevision, promotion_revision)
        snapshot = writer.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        if snapshot.state.status.value != "closed_verified":
            raise ValueError("promotion verification fence is no longer valid")
        if active is None or active.attempt_id != attempt_id:
            raise ValueError("promotion claim is no longer active")
        if active.promotion_revision != promotion_revision:
            raise ValueError("promotion claim is no longer active")
        if active.verification_event_id != verification_event_id or active.stage in {
            "cancellation_requested",
            "revocation_requested",
            "revoked",
            "superseded",
        }:
            raise ValueError("promotion verification fence is no longer valid")
        return active, snapshot.revision

    @staticmethod
    def _direct_empty_replay_guard(
        snapshot: Any,
        *,
        lane: ExecutionLaneKey,
        expected_revision: JournalRevision,
        operation: Literal["reject", "reopen"],
        reason: str,
        proof_rejection: object | None,
    ) -> UUID | None:
        """Authenticate the exact direct-empty tail eligible for response-loss replay."""

        if snapshot.state.status.value != "active" or snapshot.revision == expected_revision:
            return None
        event_count = 2 if operation == "reject" else 1
        if (
            expected_revision.sequence < 1
            or len(snapshot.events) != expected_revision.sequence + event_count
            or not any(binding.lane == lane for binding in snapshot.state.bound_lanes)
        ):
            return None
        verified = snapshot.events[expected_revision.sequence - 1]
        if (
            verified.sequence != expected_revision.sequence
            or verified.event_hash != expected_revision.event_hash
            or getattr(verified.type, "value", verified.type) != "engagement_verified"
        ):
            return None
        reopened = snapshot.events[-1]
        reopened_payload = reopened.payload
        reopen_key = reopened.idempotency_key
        if (
            getattr(reopened.type, "value", reopened.type) != "engagement_reopened"
            or getattr(reopened_payload, "reason", None) != reason
            or getattr(reopened_payload, "prior_status", None) != "closed_verified"
            or getattr(reopened_payload, "proof_revalidation", None)
            != ("retain_rejections" if operation == "reject" else "invalidate_all")
            or reopened.system_correlation is None
            or reopened.system_correlation.source != "lifecycle"
            or reopened.system_correlation.operation_id != verified.event_id
            or not isinstance(reopen_key, str)
        ):
            return None
        prefix = f"direct-empty:{operation}:"
        suffix = ":reopen"
        if not reopen_key.startswith(prefix) or not reopen_key.endswith(suffix):
            return None
        try:
            guard_nonce = UUID(reopen_key[len(prefix) : -len(suffix)])
        except ValueError:
            return None
        if operation == "reopen":
            return guard_nonce if proof_rejection is None else None
        receipt = cast(Any, proof_rejection)
        rejected = snapshot.events[-2]
        rejected_payload = rejected.payload
        if (
            proof_rejection is None
            or getattr(receipt, "engagement_id", None) != snapshot.engagement_id
            or getattr(receipt, "authoritative_revision", None) != expected_revision
            or getattr(rejected.type, "value", rejected.type) != "flag_rejected"
            or getattr(rejected_payload, "flag_event_id", None) != receipt.proof_event_id
            or getattr(rejected_payload, "rejected_value_sha256", None)
            != receipt.rejected_value_sha256
            or getattr(rejected_payload, "reason", None) != reason
            or rejected.system_correlation is None
            or rejected.system_correlation.source != "lifecycle"
            or rejected.system_correlation.operation_id != receipt.proof_event_id
            or rejected.idempotency_key != f"{prefix}{guard_nonce}:proof-rejection"
        ):
            return None
        return guard_nonce

    def revoke_after_settlement(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        expected_revision: JournalRevision,
        operation: Literal["reject", "reopen"],
        reason: str,
        proof_rejection: object | None = None,
    ) -> Any:
        """Enter the repository-owned revocation saga after lifecycle settlement."""

        if operation not in {"reject", "reopen"}:
            raise ValueError("invalid promotion revocation operation")
        if not isinstance(reason, str) or not reason or len(reason) > 2048:
            raise ValueError("invalid promotion revocation reason")
        snapshot = self._capability._writer.load_snapshot(engagement_id)
        direct_empty_replay_guard = self._direct_empty_replay_guard(
            snapshot,
            lane=lane,
            expected_revision=expected_revision,
            operation=operation,
            reason=reason,
            proof_rejection=proof_rejection,
        )
        direct_empty_response_retry = direct_empty_replay_guard is not None
        if not direct_empty_response_retry and (
            snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_verified"
        ):
            raise ValueError("promotion revocation expected revision is stale")
        active = snapshot.state.promotion.active_attempt
        recovering_request = active is not None and active.stage in {
            "cancellation_requested",
            "revocation_requested",
        }
        if operation == "reopen" and proof_rejection is not None:
            raise ValueError("promotion reopen forbids a settled proof receipt")
        if operation == "reject" and proof_rejection is None and not recovering_request:
            raise ValueError("promotion rejection requires its settled proof receipt")
        current_verification = next(
            (
                event
                for event in reversed(snapshot.events)
                if getattr(event.type, "value", event.type) == "engagement_verified"
            ),
            None,
        )
        if current_verification is None:
            raise ValueError("promotion revocation requires verified lineage")
        if active is None:
            current_terminal = next(
                (
                    attempt
                    for attempt in reversed(snapshot.state.promotion.recent_terminal_attempts)
                    if attempt.verification_event_id == current_verification.event_id
                ),
                None,
            )
            lineage = snapshot.state.promotion.latest_successful_publication
            if (
                lineage is not None
                and current_terminal is not None
                and current_terminal.attempt_id == lineage.attempt_id
                and current_terminal.stage == "promoted"
            ):
                active = current_terminal
            if active is None:
                if current_terminal is not None and not (
                    current_terminal.stage == "terminated"
                    and current_terminal.cleanup_canonical_revision is None
                ):
                    raise ValueError("current promotion attempt is not direct-empty")
                source_id = promotion_source_id(engagement_id)
                with self._semantic._repository.promotion_publication_guard(source_id):
                    if direct_empty_response_retry:
                        proof = self._prove_revocation_absence(
                            engagement_id=engagement_id,
                            active=current_terminal,
                            request_event_id=None,
                            verification_event_id=current_verification.event_id,
                            purpose="direct_empty",
                            guard_nonce=direct_empty_replay_guard,
                            allow_cleanup=False,
                        )
                    else:
                        proof = self._prove_revocation_absence(
                            engagement_id=engagement_id,
                            active=current_terminal,
                            request_event_id=None,
                            verification_event_id=current_verification.event_id,
                            purpose="direct_empty",
                        )
                    if operation == "reject":
                        committed = self._revocation_commits.commit_empty_reject_and_reopen(
                            engagement_id,
                            lane,
                            reason,
                            proof_rejection,
                            proof,
                            expected_revision,
                        )
                    else:
                        committed = self._revocation_commits.commit_empty_and_reopen(
                            engagement_id,
                            lane,
                            reason,
                            proof,
                            expected_revision,
                        )
                from sedna.engagement.service import EngagementMutationResult

                return EngagementMutationResult(
                    snapshot=self._capability._writer.load_snapshot(engagement_id),
                    created_event_ids=committed.created_event_ids,
                    existing_event_ids=committed.existing_event_ids,
                )
        if active.stage in {"cancellation_requested", "revocation_requested"}:
            request_event_id = (
                active.cancellation_request_event_id
                if active.stage == "cancellation_requested"
                else active.revocation_request_event_id
            )
            request_event = next(
                (event for event in snapshot.events if event.event_id == request_event_id),
                None,
            )
            intent = (
                None
                if request_event is None
                else getattr(request_event.payload, "lifecycle_intent", None)
            )
            if (
                request_event_id is None
                or intent is None
                or intent.operation != operation
                or intent.lane != lane
                or intent.reopen_reason != reason
            ):
                raise ValueError("promotion revocation recovery intent does not match")
            assert request_event is not None
            requested = PromotionMutationResult(
                event_id=request_event_id,
                revision=snapshot.revision,
                created=False,
            )
            proof_active = (
                active.model_copy(update={"stage": request_event.payload.stage})
                if active.stage == "cancellation_requested"
                else active
            )
        else:
            request = (
                self._capability.request_revocation
                if active.stage == "promoted"
                else self._capability.request_cancellation
            )
            requested = request(
                engagement_id,
                lane=lane,
                attempt_id=active.attempt_id,
                operation=operation,
                reopen_reason=reason,
                proof_rejection=proof_rejection,
                expected_revision=expected_revision,
            )
            proof_active = active
        source_id = (
            promotion_source_id(engagement_id)
            if proof_active.source_id is None
            else proof_active.source_id
        )
        with self._semantic._repository.promotion_publication_guard(source_id):
            proof = self._prove_revocation_absence(
                engagement_id=engagement_id,
                active=proof_active,
                request_event_id=requested.event_id,
                verification_event_id=active.verification_event_id,
                purpose="request_cleanup",
            )
            if operation == "reject":
                committed = self._revocation_commits.commit_cleanup_reject_and_reopen(
                    engagement_id,
                    requested.event_id,
                    proof,
                    requested.revision,
                )
            else:
                committed = self._revocation_commits.commit_cleanup_and_reopen(
                    engagement_id,
                    requested.event_id,
                    proof,
                    requested.revision,
                )
        from sedna.engagement.service import EngagementMutationResult

        return EngagementMutationResult(
            snapshot=self._capability._writer.load_snapshot(engagement_id),
            created_event_ids=committed.created_event_ids,
            existing_event_ids=committed.existing_event_ids,
        )

    def _prove_revocation_absence(
        self,
        *,
        engagement_id: UUID,
        active: Any | None,
        request_event_id: UUID | None,
        verification_event_id: UUID,
        purpose: Literal["direct_empty", "request_cleanup"],
        guard_nonce: UUID | None = None,
        allow_cleanup: bool = True,
    ) -> RevocationAbsenceProof:
        source_id = (
            promotion_source_id(engagement_id)
            if active is None or active.source_id is None
            else active.source_id
        )
        repository = self._semantic._repository
        canonical_state: Literal["absent", "excluded"] = "absent"
        canonical_revision = None
        try:
            manifest = repository.load_manifest(source_id)
        except FileNotFoundError:
            indexed = self._maintenance.index.snapshot_state()
            if any(state.source_id == source_id for state in indexed.source_states):
                if not allow_cleanup:
                    raise ValueError(
                        "direct-empty replay physical state no longer matches"
                    ) from None
                if self._maintenance.invalidate_source_projection(source_id) is not True:
                    raise ValueError("promotion revocation could not prove index absence") from None
            report = self._maintenance.audit()
        else:
            if not allow_cleanup:
                raise ValueError("direct-empty replay physical state no longer matches")
            excluded = build_nonaccepted_promotion_manifest(
                manifest,
                reason="verification_revoked",
            )
            accepted_foundation = active is not None and active.stage in {
                "semantic_committed",
                "index_pending",
                "retry_failed",
                "promoted",
                "revocation_requested",
                "revoked",
                "superseded",
            }
            if not accepted_foundation:
                if manifest != excluded:
                    raise ValueError("prior promotion lineage remains accepted")
                report = self._maintenance.audit()
            elif manifest != excluded:
                repository.transition_source(
                    excluded,
                    None,
                    before_foundation_revision_change=self._maintenance.barrier_source_revision,
                )
                report = self._maintenance.rebuild()
            else:
                report = self._maintenance.audit()
            if accepted_foundation:
                canonical_state = "excluded"
                canonical_revision = foundation_manifest_digest(excluded)
        if not report.succeeded or report.rebuild_required:
            raise ValueError("promotion revocation could not prove canonical/index absence")
        semantic = repository.semantic_bundle_snapshot()
        if any(bundle.source_id == source_id for bundle in semantic.bundles):
            raise ValueError("revoked promotion remains semantically retrievable")
        index = self._maintenance.index.snapshot_state()
        if any(state.source_id == source_id for state in index.source_states):
            raise ValueError("revoked promotion remains indexed")
        audit_sha256 = sha256(
            json.dumps(
                index.audit.model_dump(mode="json", warnings="error"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        attempt_id = None if active is None else active.attempt_id
        guard_nonce = guard_nonce or uuid5(
            engagement_id,
            ":".join(
                (
                    "revocation-absence",
                    str(verification_event_id),
                    "none" if attempt_id is None else str(attempt_id),
                    purpose,
                    "none" if request_event_id is None else str(request_event_id),
                    canonical_state,
                    "none" if canonical_revision is None else canonical_revision,
                    str(index.generation),
                    audit_sha256,
                )
            ),
        )
        return cast(
            RevocationAbsenceProof,
            self._capability._receipt_ledger.issue(
                RevocationAbsenceProof,
                engagement_id=engagement_id,
                verification_event_id=verification_event_id,
                attempt_id=attempt_id,
                purpose=purpose,
                request_event_id=request_event_id,
                source_id=source_id if canonical_state == "excluded" else None,
                removed_case_ids=(
                    tuple(active.case_ids)
                    if active is not None and canonical_state == "excluded"
                    else ()
                ),
                canonical_state=canonical_state,
                canonical_revision=canonical_revision,
                index_generation=index.generation,
                index_audit_sha256=audit_sha256,
                guard_nonce=guard_nonce,
            ),
        )

    def promote_verified(
        self,
        engagement_id: UUID,
        *,
        expected_revision: JournalRevision,
        verification_event_id: UUID,
        verified_revision: JournalRevision | None = None,
    ) -> PromotionResult:
        """Publish an exact verified snapshot or coalesce with its durable attempt."""

        snapshot = self._capability._writer.load_snapshot(engagement_id)
        completed = self._completed(snapshot, verification_event_id)
        if completed is not None:
            return completed
        prior_publication = getattr(snapshot.state.promotion, "latest_successful_publication", None)
        active = getattr(snapshot.state.promotion, "active_attempt", None)
        fixed_verified_revision = verified_revision or expected_revision
        resumable = (
            active is not None
            and active.verification_event_id == verification_event_id
            and active.verified_revision == fixed_verified_revision
        )
        if snapshot.revision != expected_revision and not resumable:
            raise ValueError("promotion expected revision is stale")
        projection_events = tuple(
            event for event in snapshot.events if event.sequence <= fixed_verified_revision.sequence
        )
        projection_snapshot = snapshot.model_copy(
            update={"events": projection_events, "revision": fixed_verified_revision}
        )
        projection = self._inputs.project(
            projection_snapshot,
            verification_event_id=verification_event_id,
            evidence_reader=self._evidence_reader,
        )
        claim = self._capability.claim(
            engagement_id,
            self._claim_request(fixed_verified_revision, verification_event_id),
            expected_revision=snapshot.revision if resumable else expected_revision,
        )
        if claim.disposition == "retry_exhausted":
            return PromotionResult(disposition="retry_exhausted", journal_revision=claim.revision)
        attempt = claim.attempt
        if attempt is None:
            raise ValueError("promotion claim did not return an attempt")
        if claim.disposition == "existing":
            return PromotionResult(
                disposition="in_progress",
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
                source_id=attempt.source_id,
                case_ids=attempt.case_ids,
                journal_revision=claim.revision,
            )
        ownership = claim.ownership
        if ownership is None:
            raise ValueError("created promotion claim has no ownership")
        return self._run_owned(
            engagement_id,
            fixed_verified_revision,
            verification_event_id,
            projection,
            attempt,
            ownership,
            claim.revision,
            prior_publication,
        )

    def _run_owned(
        self,
        engagement_id: UUID,
        verified_revision: JournalRevision,
        verification_event_id: UUID,
        projection: Any,
        attempt: Any,
        ownership: PromotionClaimOwnership,
        revision: JournalRevision,
        prior_publication: Any | None = None,
    ) -> PromotionResult:
        if attempt.stage == "requested":
            self._require_stage_fence(
                engagement_id,
                verification_event_id=verification_event_id,
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
            )
            compiled = self._compiler.compile(
                projection.safe_input,
                inventory=projection.inventory,
            )
            _fenced, revision = self._require_stage_fence(
                engagement_id,
                verification_event_id=verification_event_id,
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
            )
            if compiled.disposition != "verified" or compiled.draft is None:
                disposition = "quarantined" if compiled.disposition == "quarantined" else "failed"
                mutation = self._capability.terminate(
                    engagement_id,
                    attempt_id=attempt.attempt_id,
                    promotion_revision=attempt.promotion_revision,
                    disposition=disposition,
                    reason_code=compiled.failure_code or "semantic_failure",
                    cleanup_receipt=None,
                    ownership=ownership,
                    expected_revision=revision,
                )
                return PromotionResult(
                    disposition=disposition,
                    attempt_id=attempt.attempt_id,
                    promotion_revision=attempt.promotion_revision,
                    journal_revision=mutation.revision,
                    reason_code=compiled.failure_code,
                )
            draft = compiled.draft
            candidate = self._capability.commit_candidate(
                engagement_id,
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
                draft=draft,
                repair_count=compiled.repair_count,
                ownership=ownership,
                expected_revision=revision,
            )
            revision = candidate.revision
        else:
            draft = self._capability.load_candidate(engagement_id, ownership=ownership)
        rendered = render_promotion_source(
            draft,
            context=projection.safe_input,
            inventory=projection.inventory,
            identity=PromotionRenderIdentity(
                engagement_id=engagement_id,
                attempt_id=attempt.attempt_id,
                verification_event_id=verification_event_id,
                verified_revision=verified_revision,
                source_id=promotion_source_id(engagement_id),
                promotion_revision=attempt.promotion_revision,
            ),
        )
        _fenced, revision = self._require_stage_fence(
            engagement_id,
            verification_event_id=verification_event_id,
            attempt_id=attempt.attempt_id,
            promotion_revision=attempt.promotion_revision,
        )
        source = self._capability.commit_source(
            engagement_id,
            rendered,
            ownership=ownership,
            expected_revision=revision,
        )
        return self._publish_owned(
            engagement_id,
            projection,
            attempt,
            ownership,
            source.source,
            prior_publication,
        )

    def _publish_owned(
        self,
        engagement_id: UUID,
        projection: Any,
        attempt: Any,
        ownership: PromotionClaimOwnership,
        source: CommittedPromotionSource,
        prior_publication: Any | None = None,
    ) -> PromotionResult:
        prepared = build_promotion_prepared_source(source)
        active, revision = self._capability.active_attempt(
            engagement_id,
            ownership=ownership,
            expected_stages={
                "source_committed",
                "semantic_committed",
                "index_pending",
                "retry_failed",
            },
        )
        if (
            active.stage == "retry_failed"
            and active.index_retry_count >= MAX_PROMOTION_INDEX_RETRIES
        ):
            return self._recover_index_exhaustion(
                engagement_id,
                prepared,
                attempt,
                ownership,
            )
        semantic_candidate = None
        if active.stage == "source_committed":
            with self._semantic._repository.promotion_publication_guard(
                prepared.manifest.source_id
            ):
                self._capability.active_attempt(
                    engagement_id,
                    ownership=ownership,
                    expected_stages={"source_committed"},
                )
                self._semantic._repository.transition_source(
                    prepared.manifest,
                    None,
                    before_foundation_revision_change=self._maintenance.barrier_source_revision,
                )
            semantic_candidate = self._semantic.compile_candidate(
                prepared,
                acceptance_profile=SemanticAcceptanceProfile.JOURNAL_PROMOTION,
            )
        if semantic_candidate is not None and semantic_candidate.disposition not in {
            "verified",
            "unchanged",
        }:
            reason = (
                "required_case_missing"
                if semantic_candidate.failure_code == "required_case_missing"
                else (
                    "semantic_quarantined"
                    if semantic_candidate.disposition == "quarantined"
                    else "semantic_failure"
                )
            )
            return self._terminate_foundation(
                engagement_id,
                prepared,
                attempt,
                ownership,
                revision,
                reason=reason,
                disposition=(
                    "quarantined" if semantic_candidate.disposition == "quarantined" else "failed"
                ),
            )
        try:
            if semantic_candidate is not None:
                assert_semantic_promotion_safe(semantic_candidate, projection.inventory)
        except ValueError:
            return self._terminate_foundation(
                engagement_id,
                prepared,
                attempt,
                ownership,
                revision,
                reason="unsafe_material",
                disposition="failed",
            )
        if semantic_candidate is not None:
            with self._semantic._repository.promotion_publication_guard(
                prepared.manifest.source_id
            ):
                _active, revision = self._capability.active_attempt(
                    engagement_id,
                    ownership=ownership,
                    expected_stages={"source_committed"},
                )
                _persisted, semantic_receipt = self._receipts.persist_semantic(
                    prepared,
                    semantic_candidate,
                    ownership=ownership,
                    promotion_revision=attempt.promotion_revision,
                )
                semantic_event = self._capability.commit_semantic(
                    engagement_id,
                    semantic_receipt,
                    expected_revision=revision,
                )
                revision = semantic_event.revision
        else:
            semantic_receipt = self._receipts.recover_semantic(
                prepared,
                artifact_ids=active.artifact_ids,
                ownership=ownership,
                promotion_revision=attempt.promotion_revision,
            )
        if active.stage in {"source_committed", "semantic_committed"}:
            with self._semantic._repository.promotion_publication_guard(
                prepared.manifest.source_id
            ):
                _active, revision = self._capability.active_attempt(
                    engagement_id,
                    ownership=ownership,
                    expected_stages={"semantic_committed"},
                )
                pending_receipt = self._receipts.canonical_currentness(
                    prepared,
                    semantic_receipt,
                    ownership=ownership,
                    promotion_revision=attempt.promotion_revision,
                )
                pending_event = self._capability.commit_index_pending(
                    engagement_id,
                    pending_receipt,
                    expected_revision=revision,
                )
                revision = pending_event.revision
        else:
            pending_receipt = self._receipts.canonical_currentness(
                prepared,
                semantic_receipt,
                ownership=ownership,
                promotion_revision=attempt.promotion_revision,
            )
        active, revision = self._capability.active_attempt(
            engagement_id,
            ownership=ownership,
            expected_stages={"index_pending", "retry_failed"},
        )
        retry_count = active.index_retry_count + 1
        with self._semantic._repository.promotion_publication_guard(prepared.manifest.source_id):
            _active, revision = self._capability.active_attempt(
                engagement_id,
                ownership=ownership,
                expected_stages={"index_pending", "retry_failed"},
            )
            _report, publication = self._receipts.rebuild_index(
                prepared,
                pending_receipt,
                ownership=ownership,
                promotion_revision=attempt.promotion_revision,
                retry_count=retry_count,
            )
            if type(publication) is PromotionIndexFailureReceipt:
                if retry_count >= MAX_PROMOTION_INDEX_RETRIES:
                    retry = self._capability.commit_index_retry(
                        engagement_id,
                        publication,
                        expected_revision=revision,
                    )
                    cleanup = self._receipts.exclude_foundation(
                        prepared,
                        ownership=ownership,
                        promotion_revision=attempt.promotion_revision,
                        reason="index_retry_exhausted",
                    )
                    terminated = self._capability.terminate(
                        engagement_id,
                        attempt_id=attempt.attempt_id,
                        promotion_revision=attempt.promotion_revision,
                        disposition="failed",
                        reason_code="index_retry_exhausted",
                        cleanup_receipt=cleanup,
                        ownership=ownership,
                        expected_revision=retry.revision,
                    )
                    return PromotionResult(
                        disposition="failed",
                        attempt_id=attempt.attempt_id,
                        promotion_revision=attempt.promotion_revision,
                        source_id=prepared.manifest.source_id,
                        journal_revision=terminated.revision,
                        reason_code="index_retry_exhausted",
                    )
                retry = self._capability.commit_index_retry(
                    engagement_id,
                    publication,
                    expected_revision=revision,
                )
                return PromotionResult(
                    disposition="retrying",
                    attempt_id=attempt.attempt_id,
                    promotion_revision=attempt.promotion_revision,
                    source_id=prepared.manifest.source_id,
                    journal_revision=retry.revision,
                    reason_code=publication.reason_code,
                )
            publication = cast(PromotionPublicationReceipt, publication)
            if prior_publication is not None and prior_publication.attempt_id != attempt.attempt_id:
                promoted = self._capability.commit_superseded_and_promoted(
                    engagement_id,
                    replacement=publication,
                    expected_revision=revision,
                )
            else:
                promoted = self._capability.commit_promoted(
                    engagement_id,
                    publication,
                    expected_revision=revision,
                )
            return PromotionResult(
                disposition="promoted",
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
                source_id=prepared.manifest.source_id,
                case_ids=publication.case_ids,
                journal_revision=promoted.revision,
            )

    def _recover_index_exhaustion(
        self,
        engagement_id: UUID,
        prepared: PreparedSource,
        attempt: Any,
        ownership: PromotionClaimOwnership,
    ) -> PromotionResult:
        with self._semantic._repository.promotion_publication_guard(prepared.manifest.source_id):
            active, revision = self._capability.active_attempt(
                engagement_id,
                ownership=ownership,
                expected_stages={"retry_failed"},
            )
            if active.index_retry_count != MAX_PROMOTION_INDEX_RETRIES:
                raise ValueError("promotion retry exhaustion fence no longer matches")
            cleanup = self._receipts.exclude_foundation(
                prepared,
                ownership=ownership,
                promotion_revision=attempt.promotion_revision,
                reason="index_retry_exhausted",
            )
            terminated = self._capability.terminate(
                engagement_id,
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
                disposition="failed",
                reason_code="index_retry_exhausted",
                cleanup_receipt=cleanup,
                ownership=ownership,
                expected_revision=revision,
            )
        return PromotionResult(
            disposition="failed",
            attempt_id=attempt.attempt_id,
            promotion_revision=attempt.promotion_revision,
            source_id=prepared.manifest.source_id,
            journal_revision=terminated.revision,
            reason_code="index_retry_exhausted",
        )

    def _terminate_foundation(
        self,
        engagement_id: UUID,
        prepared: PreparedSource,
        attempt: Any,
        ownership: PromotionClaimOwnership,
        revision: JournalRevision,
        *,
        reason: str,
        disposition: Literal["quarantined", "failed"],
    ) -> PromotionResult:
        del revision
        _active, current_revision = self._capability.active_attempt(
            engagement_id,
            ownership=ownership,
            expected_stages={"source_committed"},
        )
        with self._semantic._repository.promotion_publication_guard(prepared.manifest.source_id):
            cleanup = self._receipts.exclude_foundation(
                prepared,
                ownership=ownership,
                promotion_revision=attempt.promotion_revision,
                reason=reason,
            )
            mutation = self._capability.terminate(
                engagement_id,
                attempt_id=attempt.attempt_id,
                promotion_revision=attempt.promotion_revision,
                disposition=disposition,
                reason_code=reason,
                cleanup_receipt=cleanup,
                ownership=ownership,
                expected_revision=current_revision,
            )
        return PromotionResult(
            disposition=disposition,
            attempt_id=attempt.attempt_id,
            promotion_revision=attempt.promotion_revision,
            source_id=prepared.manifest.source_id,
            journal_revision=mutation.revision,
            reason_code=reason,
        )


class PromotionRecoveryCoordinator:
    """Resume or coalesce promotion from the durable verified journal state."""

    def __init__(self, *, journal: Any, adapter: JournalPromotionAdapter) -> None:
        self._journal = journal
        self._adapter = adapter

    def resume_for_engagement(self, engagement_id: UUID) -> PromotionResult:
        snapshot = self._journal.load_snapshot(engagement_id)
        verification = next(
            (
                event
                for event in reversed(snapshot.events)
                if getattr(event.type, "value", event.type) == "engagement_verified"
            ),
            None,
        )
        if verification is None:
            raise ValueError("promotion recovery requires a verified engagement")
        active = snapshot.state.promotion.active_attempt
        if active is not None and active.stage in {
            "cancellation_requested",
            "revocation_requested",
        }:
            request_event_id = (
                active.cancellation_request_event_id
                if active.stage == "cancellation_requested"
                else active.revocation_request_event_id
            )
            request = next(
                (
                    event
                    for event in reversed(snapshot.events)
                    if event.event_id == request_event_id
                ),
                None,
            )
            if request is None:
                return PromotionResult(
                    disposition="failed",
                    attempt_id=active.attempt_id,
                    promotion_revision=active.promotion_revision,
                    source_id=active.source_id,
                    journal_revision=snapshot.revision,
                    reason_code="promotion_revocation_recovery_failed",
                )
            intent = request.payload.lifecycle_intent
            try:
                completed = self._adapter.revoke_after_settlement(
                    engagement_id,
                    lane=intent.lane,
                    expected_revision=snapshot.revision,
                    operation=intent.operation,
                    reason=intent.reopen_reason,
                    proof_rejection=None,
                )
            except Exception:
                return PromotionResult(
                    disposition="failed",
                    attempt_id=active.attempt_id,
                    promotion_revision=active.promotion_revision,
                    source_id=active.source_id,
                    journal_revision=snapshot.revision,
                    reason_code="promotion_revocation_recovery_failed",
                )
            return PromotionResult(
                disposition="revoked",
                attempt_id=active.attempt_id,
                promotion_revision=active.promotion_revision,
                source_id=active.source_id,
                journal_revision=completed.snapshot.revision,
            )
        verified_revision = (
            active.verified_revision
            if active is not None and active.verification_event_id == verification.event_id
            else JournalRevision(
                sequence=verification.sequence,
                event_hash=verification.event_hash,
            )
        )
        try:
            return self._adapter.promote_verified(
                engagement_id,
                expected_revision=snapshot.revision,
                verification_event_id=verification.event_id,
                verified_revision=verified_revision,
            )
        except Exception:
            return PromotionResult(
                disposition="failed",
                journal_revision=snapshot.revision,
                reason_code="promotion_recovery_failed",
            )

    def recover_after_verification(self, engagement_id: UUID) -> None:
        self.resume_for_engagement(engagement_id)
