"""Bounded extraction, criticism, and one-repair promotion compiler."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from sedna.engagement.models import EvidenceId
from sedna.engagement.promotion.llm import (
    PromotionLlmAdapter,
    PromotionLlmError,
    SafePromotionCriticRequest,
    SafePromotionExtractRequest,
    SafePromotionRepairRequest,
)
from sedna.engagement.promotion.models import (
    PromotionCompilationResult,
    PromotionCriticVerdict,
    PromotionDraft,
    PromotionInput,
    PromotionSecretInventory,
)
from sedna.engagement.promotion.prompts import (
    PROMOTION_CRITIC_PROMPT,
    PROMOTION_EXTRACTOR_PROMPT,
    PROMOTION_REPAIR_PROMPT,
)
from sedna.engagement.promotion.sanitize import assert_promotion_safe

PromotionDraftFailureCode = Literal[
    "invalid_structured_response",
    "invalid_provenance",
    "unsafe_material",
]


class PromotionDraftValidationError(ValueError):
    """Closed local draft-validation failure with no model material."""

    def __init__(self, code: PromotionDraftFailureCode) -> None:
        self.code: PromotionDraftFailureCode = code
        super().__init__(code)


class CasePromotionCompiler:
    """Compile a symbolized source using one extractor and at most one repair."""

    def __init__(self, llm: PromotionLlmAdapter) -> None:
        self._llm = llm

    def compile(
        self,
        source: PromotionInput,
        *,
        inventory: PromotionSecretInventory,
    ) -> PromotionCompilationResult:
        try:
            source = PromotionInput.model_validate(
                source.model_dump(mode="python", warnings="error")
            )
        except Exception:
            return self._failed("invalid_structured_response", repair_count=0)
        try:
            assert_promotion_safe(source, inventory)
        except ValueError:
            return self._failed("unsafe_material", repair_count=0)

        try:
            extracted = self._llm.complete(
                PromotionDraft,
                instructions=PROMOTION_EXTRACTOR_PROMPT,
                payload=SafePromotionExtractRequest(source=source),
                purpose="sedna.promotion.extract",
            ).parsed
            extracted = self._validated_draft(extracted, source, inventory)
            initial = self._critic(source, extracted, inventory)
        except PromotionLlmError as error:
            return self._failed(self._closed_llm_code(error), repair_count=0)
        except PromotionDraftValidationError as error:
            return self._failed(error.code, repair_count=0)

        if initial.accepted:
            return PromotionCompilationResult(
                disposition="verified",
                draft=extracted,
                critic=initial,
                repair_count=0,
            )

        try:
            repaired = self._llm.complete(
                PromotionDraft,
                instructions=PROMOTION_REPAIR_PROMPT,
                payload=SafePromotionRepairRequest(
                    source=source,
                    draft=extracted,
                    critic=initial,
                ),
                purpose="sedna.promotion.repair",
            ).parsed
            repaired = self._validated_draft(repaired, source, inventory)
            final = self._critic(source, repaired, inventory)
        except PromotionLlmError as error:
            return self._failed(self._closed_llm_code(error), repair_count=1)
        except PromotionDraftValidationError as error:
            return self._failed(error.code, repair_count=1)

        if not final.accepted:
            return PromotionCompilationResult(
                disposition="quarantined",
                critic=final,
                repair_count=1,
                failure_code="critic_rejected",
            )
        return PromotionCompilationResult(
            disposition="verified",
            draft=repaired,
            critic=final,
            repair_count=1,
        )

    def _critic(
        self,
        source: PromotionInput,
        draft: PromotionDraft,
        inventory: PromotionSecretInventory,
    ) -> PromotionCriticVerdict:
        verdict = self._llm.complete(
            PromotionCriticVerdict,
            instructions=PROMOTION_CRITIC_PROMPT,
            payload=SafePromotionCriticRequest(source=source, draft=draft),
            purpose="sedna.promotion.critic",
        ).parsed
        try:
            verdict = PromotionCriticVerdict.model_validate(
                verdict.model_dump(mode="python", warnings="error")
            )
        except Exception:
            raise PromotionDraftValidationError("invalid_structured_response") from None
        valid_ordinals = {step.ordinal for step in draft.steps}
        if any(
            ordinal not in valid_ordinals
            for finding in verdict.findings
            for ordinal in finding.step_ordinals
        ):
            raise PromotionDraftValidationError("invalid_provenance")
        try:
            assert_promotion_safe(verdict, inventory)
        except ValueError:
            raise PromotionDraftValidationError("unsafe_material") from None
        return verdict

    @staticmethod
    def _validated_draft(
        draft: PromotionDraft,
        source: PromotionInput,
        inventory: PromotionSecretInventory,
    ) -> PromotionDraft:
        try:
            draft = PromotionDraft.model_validate(draft.model_dump(mode="python", warnings="error"))
        except Exception:
            raise PromotionDraftValidationError("invalid_structured_response") from None

        allowed_events = {source.verification_event_id}
        allowed_evidence: set[EvidenceId] = set()
        for lane in (source.context, source.decisions, source.outcomes, source.alternatives):
            for item in lane:
                allowed_events.update(item.event_ids)
                allowed_evidence.update(item.evidence_ids)

        event_ids: set[UUID] = set()
        evidence_ids: set[EvidenceId] = set()
        claims = (
            draft.starting_access,
            *draft.applicability,
            *draft.alternate_paths,
            *draft.transferable_properties,
            *draft.non_transferable_properties,
            draft.generalizability_basis,
            draft.verified_outcome,
        )
        for item in (*claims, *draft.steps):
            event_ids.update(item.event_ids)
            evidence_ids.update(item.evidence_ids)
        if not event_ids <= allowed_events or not evidence_ids <= allowed_evidence:
            raise PromotionDraftValidationError("invalid_provenance")
        material = (*source.decisions, *source.outcomes)
        draft_items = (*claims, *draft.steps)
        candidates = tuple(
            tuple(
                index
                for index, draft_item in enumerate(draft_items)
                if set(source_item.event_ids) <= set(draft_item.event_ids)
                and set(source_item.evidence_ids) <= set(draft_item.evidence_ids)
            )
            for source_item in material
        )
        matched_material_by_draft_item: dict[int, int] = {}

        def match(material_index: int, visited: set[int]) -> bool:
            for draft_index in candidates[material_index]:
                if draft_index in visited:
                    continue
                visited.add(draft_index)
                previous = matched_material_by_draft_item.get(draft_index)
                if previous is None or match(previous, visited):
                    matched_material_by_draft_item[draft_index] = material_index
                    return True
            return False

        if any(not match(index, set()) for index in range(len(material))):
            raise PromotionDraftValidationError("invalid_provenance")
        try:
            assert_promotion_safe(draft, inventory)
        except ValueError:
            raise PromotionDraftValidationError("unsafe_material") from None
        return draft

    @staticmethod
    def _closed_llm_code(
        error: PromotionLlmError,
    ) -> Literal["transport_failure", "invalid_structured_response"]:
        if error.reason_code == "transport_failure":
            return "transport_failure"
        return "invalid_structured_response"

    @staticmethod
    def _failed(
        code: Literal[
            "transport_failure",
            "invalid_structured_response",
            "invalid_provenance",
            "unsafe_material",
        ],
        *,
        repair_count: int,
    ) -> PromotionCompilationResult:
        return PromotionCompilationResult(
            disposition="failed",
            repair_count=repair_count,
            failure_code=code,
        )


__all__ = ["CasePromotionCompiler", "PromotionDraftValidationError"]
