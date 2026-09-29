"""One-source orchestration for semantic compilation and canonical persistence."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import TYPE_CHECKING

from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.parsing.models import validate_prepared_source
from sedna.knowledge.semantic.compiler import (
    SEMANTIC_COMPILER_VERSION,
    SEMANTIC_SCHEMA_VERSION,
    SemanticCompiler,
)
from sedna.knowledge.semantic.drafts import (
    CANONICAL_COMPILATION_FAILURE_MESSAGES,
    CompilationFailureCode,
    SemanticCompilationResult,
)
from sedna.knowledge.semantic.prompts import (
    CRITIC_PROMPT_VERSION,
    EXTRACTOR_PROMPT_VERSION,
    REPAIR_PROMPT_VERSION,
)

if TYPE_CHECKING:
    from sedna.knowledge.repository import CanonicalKnowledgeRepository


class SemanticAcceptanceProfile(StrEnum):
    """Closed semantic acceptance policies for canonical source classes."""

    DEFAULT = "default"
    JOURNAL_PROMOTION = "journal_promotion"


@dataclass(frozen=True, slots=True)
class _IssuedJournalPromotionCompilation:
    """One service-holder-authenticated candidate awaiting guarded persistence."""

    prepared: PreparedSource
    result: SemanticCompilationResult
    profile: SemanticAcceptanceProfile


class SemanticIngestionService:
    """Compile and persist one prepared source, reusing current verified state."""

    def __init__(
        self,
        repository: CanonicalKnowledgeRepository,
        compiler: SemanticCompiler,
    ) -> None:
        self._repository = repository
        self._compiler = compiler
        self._issuance_lock = Lock()
        self._issued_journal_promotion_compilations: dict[
            int, _IssuedJournalPromotionCompilation
        ] = {}

    def compile_and_store(
        self,
        prepared: PreparedSource,
        *,
        acceptance_profile: SemanticAcceptanceProfile = SemanticAcceptanceProfile.DEFAULT,
    ) -> SemanticCompilationResult:
        """Return current canonical semantics or compile and persist one stale source."""
        try:
            profile = SemanticAcceptanceProfile(acceptance_profile)
        except ValueError:
            return self._failure("invalid_input")
        if profile is SemanticAcceptanceProfile.JOURNAL_PROMOTION:
            candidate = self.compile_candidate(prepared, acceptance_profile=profile)
            return self.persist_compilation(prepared, candidate, acceptance_profile=profile)
        try:
            prepared = validate_prepared_source(prepared)
        except (TypeError, ValueError):
            return SemanticCompilationResult(
                disposition="failed",
                failure_code="invalid_input",
                failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES["invalid_input"],
            )
        if prepared.manifest.source_namespace == "journal-promotion":
            return self._failure("invalid_input")
        source_id = prepared.manifest.source_id
        with self._repository.semantic_compilation_guard(source_id):
            current = self._repository.load_current_semantic_result(
                prepared,
                semantic_schema_version=SEMANTIC_SCHEMA_VERSION,
                extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
                critic_prompt_version=CRITIC_PROMPT_VERSION,
                repair_prompt_version=REPAIR_PROMPT_VERSION,
                compiler_version=SEMANTIC_COMPILER_VERSION,
            )
            if current is not None:
                accepted = self._apply_acceptance_profile(prepared, current, acceptance_profile)
                if accepted.disposition == "failed":
                    self._repository.invalidate_failed_semantic_result(prepared)
                return accepted
            result = self._compiler.compile(prepared)
            result = self._apply_acceptance_profile(prepared, result, acceptance_profile)
            if result.disposition in {"verified", "quarantined"}:
                try:
                    manifest = self._repository.load_manifest(source_id)
                except (FileNotFoundError, ValueError):
                    return self._failure("internal_failure")
                if manifest.ingestion_status.value != "accepted" or manifest != prepared.manifest:
                    return self._failure("internal_failure")
                if result.disposition == "quarantined":
                    result = self._with_quarantine_manifest(prepared, result)
                try:
                    self._repository.write_semantic_result(result)
                except Exception:
                    with suppress(Exception):
                        self._repository.invalidate_failed_semantic_result(prepared)
                    return self._failure("internal_failure")
            elif result.disposition == "failed":
                try:
                    self._repository.invalidate_failed_semantic_result(prepared)
                except Exception:
                    return self._failure("internal_failure")
            return result

    def compile_candidate(
        self,
        prepared: PreparedSource,
        *,
        acceptance_profile: SemanticAcceptanceProfile | str = SemanticAcceptanceProfile.DEFAULT,
    ) -> SemanticCompilationResult:
        """Compile and validate one candidate without acquiring a persistence guard."""
        try:
            profile = SemanticAcceptanceProfile(acceptance_profile)
            prepared = validate_prepared_source(prepared)
        except (TypeError, ValueError):
            return self._failure("invalid_input")
        if (
            prepared.manifest.source_namespace == "journal-promotion"
            and profile is not SemanticAcceptanceProfile.JOURNAL_PROMOTION
        ):
            return self._failure("invalid_input")
        result = self._compiler.compile(prepared)
        result = self._apply_acceptance_profile(prepared, result, profile)
        if profile is SemanticAcceptanceProfile.JOURNAL_PROMOTION:
            issued = _IssuedJournalPromotionCompilation(
                prepared=prepared,
                result=result,
                profile=profile,
            )
            with self._issuance_lock:
                self._issued_journal_promotion_compilations[id(result)] = issued
        return result

    def persist_compilation(
        self,
        prepared: PreparedSource,
        result: SemanticCompilationResult,
        *,
        acceptance_profile: SemanticAcceptanceProfile | str = SemanticAcceptanceProfile.DEFAULT,
    ) -> SemanticCompilationResult:
        """Persist a precompiled candidate under the short semantic commit guard."""
        try:
            profile = SemanticAcceptanceProfile(acceptance_profile)
            prepared = validate_prepared_source(prepared)
            if (
                prepared.manifest.source_namespace == "journal-promotion"
                and profile is not SemanticAcceptanceProfile.JOURNAL_PROMOTION
            ):
                return self._failure("invalid_input")
            if profile is SemanticAcceptanceProfile.JOURNAL_PROMOTION:
                with self._issuance_lock:
                    issued = self._issued_journal_promotion_compilations.pop(id(result), None)
                if (
                    issued is None
                    or issued.result is not result
                    or issued.prepared != prepared
                    or issued.profile is not profile
                ):
                    return self._failure("invalid_input")
            result = SemanticCompilationResult.model_validate(
                result.model_dump(mode="json", warnings="error")
            )
        except (AttributeError, TypeError, ValueError):
            return self._failure("invalid_input")
        source_id = prepared.manifest.source_id
        with self._repository.semantic_compilation_guard(source_id):
            if profile is SemanticAcceptanceProfile.JOURNAL_PROMOTION:
                try:
                    self._repository.require_journal_promotion_physical_state(prepared.manifest)
                except (OSError, TypeError, ValueError):
                    return self._failure("internal_failure")
            current = self._repository.load_current_semantic_result(
                prepared,
                semantic_schema_version=SEMANTIC_SCHEMA_VERSION,
                extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
                critic_prompt_version=CRITIC_PROMPT_VERSION,
                repair_prompt_version=REPAIR_PROMPT_VERSION,
                compiler_version=SEMANTIC_COMPILER_VERSION,
            )
            if current is not None:
                accepted = self._apply_acceptance_profile(prepared, current, acceptance_profile)
                if accepted.disposition == "failed":
                    self._repository.invalidate_failed_semantic_result(prepared)
                return accepted
            result = self._apply_acceptance_profile(prepared, result, acceptance_profile)
            if result.disposition in {"verified", "quarantined"}:
                try:
                    manifest = self._repository.load_manifest(source_id)
                except (FileNotFoundError, ValueError):
                    return self._failure("internal_failure")
                if manifest.ingestion_status.value != "accepted" or manifest != prepared.manifest:
                    return self._failure("internal_failure")
                if result.disposition == "quarantined":
                    result = self._with_quarantine_manifest(prepared, result)
                try:
                    self._repository.write_semantic_result(result)
                except Exception:
                    with suppress(Exception):
                        self._repository.invalidate_failed_semantic_result(prepared)
                    return self._failure("internal_failure")
            elif result.disposition == "failed":
                try:
                    self._repository.invalidate_failed_semantic_result(prepared)
                except Exception:
                    return self._failure("internal_failure")
            return result

    @staticmethod
    def _failure(code: CompilationFailureCode) -> SemanticCompilationResult:
        return SemanticCompilationResult(
            disposition="failed",
            failure_code=code,
            failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES[code],
        )

    @staticmethod
    def _apply_acceptance_profile(
        prepared: PreparedSource,
        result: SemanticCompilationResult,
        acceptance_profile: SemanticAcceptanceProfile | str,
    ) -> SemanticCompilationResult:
        profile = SemanticAcceptanceProfile(acceptance_profile)
        if profile is SemanticAcceptanceProfile.DEFAULT:
            return result
        if prepared.manifest.source_namespace != "journal-promotion":
            return SemanticCompilationResult(
                disposition="failed",
                failure_code="invalid_input",
                failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES["invalid_input"],
            )
        if result.bundle is not None and result.bundle.cases:
            return result
        if result.disposition in {"verified", "unchanged"}:
            return SemanticCompilationResult(
                disposition="failed",
                failure_code="required_case_missing",
                failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES["required_case_missing"],
            )
        return result

    def is_current(self, prepared: PreparedSource) -> bool:
        """Check semantic currentness against this service's exact compiler contract."""
        try:
            prepared = validate_prepared_source(prepared)
        except (TypeError, ValueError):
            return False
        return self._repository.semantic_result_is_current(
            prepared,
            semantic_schema_version=SEMANTIC_SCHEMA_VERSION,
            extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
            critic_prompt_version=CRITIC_PROMPT_VERSION,
            repair_prompt_version=REPAIR_PROMPT_VERSION,
            compiler_version=SEMANTIC_COMPILER_VERSION,
        )

    def invalidate_failed_result(self, prepared: PreparedSource) -> bool:
        """Fail closed after an unexpected caller-visible semantic processing exception."""
        prepared = validate_prepared_source(prepared)
        with self._repository.semantic_compilation_guard(prepared.manifest.source_id):
            return self._repository.invalidate_failed_semantic_result(prepared)

    @staticmethod
    def _with_quarantine_manifest(
        prepared: PreparedSource,
        result: SemanticCompilationResult,
    ) -> SemanticCompilationResult:
        quarantine = result.quarantine
        if quarantine is not None and quarantine.compilation_manifest is not None:
            return result
        return SemanticCompilationResult(
            disposition="failed",
            failure_code="internal_failure",
            failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES["internal_failure"],
        )


__all__ = ["SemanticAcceptanceProfile", "SemanticIngestionService"]
