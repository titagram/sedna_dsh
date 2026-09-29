"""Bounded orchestration for semantic extraction, criticism, and repair."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from sedna.knowledge.parsing import PreparedSource
from sedna.knowledge.parsing.models import validate_prepared_source
from sedna.knowledge.schema import (
    DecisionRule,
    KnowledgeCase,
    ReferenceArtifact,
    VerificationStatus,
    foundation_manifest_digest,
)
from sedna.knowledge.schema.execution import ExecutionExample
from sedna.knowledge.schema.semantic import (
    CANONICAL_FINDING_MESSAGES,
    SemanticCallMetadata,
    SemanticCompilationManifest,
    SemanticKnowledgeBundle,
    SemanticQuarantineRecord,
    SemanticVerificationRecord,
    VerificationFinding,
)
from sedna.knowledge.semantic.drafts import (
    CANONICAL_COMPILATION_FAILURE_MESSAGES,
    CompilationFailureCode,
    CriticVerdict,
    SemanticCompilationResult,
    SemanticDraftBundle,
)
from sedna.knowledge.semantic.llm import (
    HadesLlmAdapter,
    SafeCriticRequestPayload,
    SafePreparedSourcePayload,
    SafeRepairRequestPayload,
    SemanticLlmError,
    StructuredResult,
    build_safe_source_payload,
)
from sedna.knowledge.semantic.materialize import (
    CanonicalArtifact,
    materialize_semantic_content,
    validate_segment_accounting,
)
from sedna.knowledge.semantic.prompts import (
    CRITIC_PROMPT,
    CRITIC_PROMPT_VERSION,
    EXTRACTOR_PROMPT,
    EXTRACTOR_PROMPT_VERSION,
    REPAIR_PROMPT,
    REPAIR_PROMPT_VERSION,
)

SEMANTIC_SCHEMA_VERSION = "2.5.0"
SEMANTIC_COMPILER_VERSION = "9"
EXECUTION_EXAMPLE_SCHEMA_VERSION = "1"


class SemanticCompiler:
    """Compile one prepared source with one extractor, critic, and bounded repair pass."""

    def __init__(
        self,
        llm: HadesLlmAdapter,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._llm = llm
        self._clock = clock

    def compile(self, prepared: PreparedSource) -> SemanticCompilationResult:
        """Return a verified bundle, explainable quarantine, or response-free failure."""
        calls: list[SemanticCallMetadata] = []
        try:
            started_at = self._now()
        except Exception:
            return self._failed("internal_failure", calls)
        try:
            prepared = self._validated_prepared(prepared)
            source = build_safe_source_payload(prepared)
        except (TypeError, ValueError):
            return self._failed("invalid_input", calls)

        try:
            extracted = self._extract(source)
            calls.append(self._call_metadata(extracted, "sedna.semantic.extract"))
            extracted.parsed.validate_against_segment_count(len(source.segments))
            validate_segment_accounting(prepared, extracted.parsed)

            initial_critic = self._critic(source, extracted.parsed)
            calls.append(self._call_metadata(initial_critic, "sedna.semantic.critic"))
            initial_critic.parsed.validate_against_segment_count(len(source.segments))
            if initial_critic.parsed.accepted:
                return self._verified(
                    prepared,
                    extracted,
                    extracted.parsed,
                    initial_critic,
                    repair_count=0,
                    started_at=started_at,
                    calls=tuple(calls),
                )

            repaired = self._repair(source, extracted.parsed, initial_critic.parsed)
            calls.append(self._call_metadata(repaired, "sedna.semantic.repair"))
            repaired.parsed.validate_against_segment_count(len(source.segments))
            validate_segment_accounting(prepared, repaired.parsed)
            final_critic = self._critic(source, repaired.parsed)
            calls.append(self._call_metadata(final_critic, "sedna.semantic.critic"))
            final_critic.parsed.validate_against_segment_count(len(source.segments))
            if not final_critic.parsed.accepted:
                return self._quarantined(
                    prepared,
                    final_critic,
                    repair_count=1,
                    started_at=started_at,
                    calls=tuple(calls),
                )
            return self._verified(
                prepared,
                extracted,
                repaired.parsed,
                final_critic,
                repair_count=1,
                started_at=started_at,
                calls=tuple(calls),
            )
        except SemanticLlmError as error:
            return self._failed(error.reason_code, calls)
        except (TypeError, ValueError):
            return self._failed("invalid_structured_response", calls)
        except Exception:
            return self._failed("internal_failure", calls)

    def _extract(self, source: SafePreparedSourcePayload) -> StructuredResult[SemanticDraftBundle]:
        return self._llm.complete(
            SemanticDraftBundle,
            instructions=EXTRACTOR_PROMPT,
            payload=source,
            purpose="sedna.semantic.extract",
        )

    def _critic(
        self,
        source: SafePreparedSourcePayload,
        drafts: SemanticDraftBundle,
    ) -> StructuredResult[CriticVerdict]:
        return self._llm.complete(
            CriticVerdict,
            instructions=CRITIC_PROMPT,
            payload=SafeCriticRequestPayload(source=source, drafts=drafts),
            purpose="sedna.semantic.critic",
        )

    def _repair(
        self,
        source: SafePreparedSourcePayload,
        drafts: SemanticDraftBundle,
        critic: CriticVerdict,
    ) -> StructuredResult[SemanticDraftBundle]:
        return self._llm.complete(
            SemanticDraftBundle,
            instructions=REPAIR_PROMPT,
            payload=SafeRepairRequestPayload(source=source, drafts=drafts, critic=critic),
            purpose="sedna.semantic.repair",
        )

    def _verified(
        self,
        prepared: PreparedSource,
        extraction: StructuredResult[SemanticDraftBundle],
        final_drafts: SemanticDraftBundle,
        critic: StructuredResult[CriticVerdict],
        *,
        repair_count: int,
        started_at: datetime,
        calls: tuple[SemanticCallMetadata, ...],
    ) -> SemanticCompilationResult:
        try:
            content = materialize_semantic_content(
                prepared,
                final_drafts,
                self._call_metadata(extraction, "sedna.semantic.extract"),
                VerificationStatus.VERIFIED,
            )
            artifacts = content.artifacts
            execution_examples = content.execution_examples
        except (TypeError, ValueError):
            return self._canonical_material_quarantine(
                prepared,
                critic,
                repair_count,
                started_at,
                calls,
            )
        except Exception:
            return self._failed("materialization_failure", calls)
        try:
            verification = self._verification(
                prepared,
                critic,
                "verified",
                repair_count,
            )
            bundle = self._bundle(
                prepared,
                extraction,
                critic,
                artifacts,
                execution_examples=execution_examples,
                repair_count=repair_count,
                started_at=started_at,
            )
        except Exception:
            return self._failed("internal_failure", calls)
        return SemanticCompilationResult(
            disposition="verified",
            bundle=bundle,
            verification=verification,
            calls=calls,
        )

    def _quarantined(
        self,
        prepared: PreparedSource,
        critic: StructuredResult[CriticVerdict],
        *,
        repair_count: int,
        started_at: datetime,
        calls: tuple[SemanticCallMetadata, ...],
    ) -> SemanticCompilationResult:
        verdict = critic.parsed
        try:
            extractor = calls[0]
            completed_at = self._now()
            return SemanticCompilationResult(
                disposition="quarantined",
                verification=self._verification(
                    prepared,
                    critic,
                    "quarantined",
                    repair_count,
                ),
                quarantine=SemanticQuarantineRecord(
                    source_id=prepared.manifest.source_id,
                    source_sha256=prepared.manifest.sha256,
                    reason_codes=tuple(finding.code for finding in verdict.findings),
                    messages=tuple(finding.message for finding in verdict.findings),
                    segment_indexes=self._finding_indexes(verdict.findings),
                    recorded_at=completed_at,
                    semantic_schema_version=SEMANTIC_SCHEMA_VERSION,
                    compilation_manifest=SemanticCompilationManifest(
                        source_id=prepared.manifest.source_id,
                        source_sha256=prepared.manifest.sha256,
                        foundation_schema_version=prepared.manifest.extraction.schema_version,
                        foundation_parser_id=prepared.manifest.extraction.parser_id,
                        foundation_parser_version=prepared.manifest.extraction.parser_version,
                        foundation_extraction=prepared.manifest.extraction,
                        foundation_manifest_sha256=foundation_manifest_digest(prepared.manifest),
                        compiler_version=SEMANTIC_COMPILER_VERSION,
                        extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
                        critic_prompt_version=CRITIC_PROMPT_VERSION,
                        repair_prompt_version=REPAIR_PROMPT_VERSION,
                        extractor_model_id=extractor.model,
                        critic_model_id=critic.model,
                        disposition="quarantined",
                        repair_count=repair_count,
                        started_at=started_at,
                        completed_at=completed_at,
                    ),
                ),
                calls=calls,
            )
        except Exception:
            return self._failed("internal_failure", calls)

    def _canonical_material_quarantine(
        self,
        prepared: PreparedSource,
        critic: StructuredResult[CriticVerdict],
        repair_count: int,
        started_at: datetime,
        calls: tuple[SemanticCallMetadata, ...],
    ) -> SemanticCompilationResult:
        try:
            extractor = calls[0]
            completed_at = self._now()
            finding = VerificationFinding(
                code="unsafe_material",
                severity="material",
                message=CANONICAL_FINDING_MESSAGES["unsafe_material"],
            )
            return SemanticCompilationResult(
                disposition="quarantined",
                verification=SemanticVerificationRecord(
                    source_id=prepared.manifest.source_id,
                    source_sha256=prepared.manifest.sha256,
                    critic_call=self._call_metadata(critic, "sedna.semantic.critic"),
                    repair_count=repair_count,
                    findings=(*critic.parsed.findings, finding),
                    adjudication="quarantined",
                    recorded_at=completed_at,
                ),
                quarantine=SemanticQuarantineRecord(
                    source_id=prepared.manifest.source_id,
                    source_sha256=prepared.manifest.sha256,
                    reason_codes=("unsafe_material",),
                    messages=(CANONICAL_FINDING_MESSAGES["unsafe_material"],),
                    recorded_at=completed_at,
                    semantic_schema_version=SEMANTIC_SCHEMA_VERSION,
                    compilation_manifest=SemanticCompilationManifest(
                        source_id=prepared.manifest.source_id,
                        source_sha256=prepared.manifest.sha256,
                        foundation_schema_version=prepared.manifest.extraction.schema_version,
                        foundation_parser_id=prepared.manifest.extraction.parser_id,
                        foundation_parser_version=prepared.manifest.extraction.parser_version,
                        foundation_extraction=prepared.manifest.extraction,
                        foundation_manifest_sha256=foundation_manifest_digest(prepared.manifest),
                        compiler_version=SEMANTIC_COMPILER_VERSION,
                        extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
                        critic_prompt_version=CRITIC_PROMPT_VERSION,
                        repair_prompt_version=REPAIR_PROMPT_VERSION,
                        extractor_model_id=extractor.model,
                        critic_model_id=critic.model,
                        disposition="quarantined",
                        repair_count=repair_count,
                        started_at=started_at,
                        completed_at=completed_at,
                    ),
                ),
                calls=calls,
            )
        except Exception:
            return self._failed("internal_failure", calls)

    def _verification(
        self,
        prepared: PreparedSource,
        critic: StructuredResult[CriticVerdict],
        adjudication: str,
        repair_count: int,
    ) -> SemanticVerificationRecord:
        return SemanticVerificationRecord(
            source_id=prepared.manifest.source_id,
            source_sha256=prepared.manifest.sha256,
            critic_call=self._call_metadata(critic, "sedna.semantic.critic"),
            repair_count=repair_count,
            findings=critic.parsed.findings,
            adjudication=adjudication,  # type: ignore[arg-type]
            recorded_at=self._now(),
        )

    def _bundle(
        self,
        prepared: PreparedSource,
        extraction: StructuredResult[SemanticDraftBundle],
        critic: StructuredResult[CriticVerdict],
        artifacts: tuple[CanonicalArtifact, ...],
        *,
        execution_examples: tuple[ExecutionExample, ...] = (),
        repair_count: int,
        started_at: datetime,
    ) -> SemanticKnowledgeBundle:
        references = tuple(
            sorted(
                (artifact for artifact in artifacts if isinstance(artifact, ReferenceArtifact)),
                key=lambda artifact: artifact.artifact_id,
            )
        )
        cases = tuple(
            sorted(
                (artifact for artifact in artifacts if isinstance(artifact, KnowledgeCase)),
                key=lambda artifact: artifact.case_id,
            )
        )
        guidance = tuple(
            sorted(
                (artifact for artifact in artifacts if isinstance(artifact, DecisionRule)),
                key=lambda artifact: artifact.rule_id,
            )
        )
        emitted_example_ids = tuple(sorted(example.example_id for example in execution_examples))
        emitted_ids = tuple(
            sorted(
                (
                    *(reference.artifact_id for reference in references),
                    *(knowledge_case.case_id for knowledge_case in cases),
                    *(step.step_id for knowledge_case in cases for step in knowledge_case.steps),
                    *(rule.rule_id for rule in guidance),
                )
            )
        )
        return SemanticKnowledgeBundle(
            schema_version=SEMANTIC_SCHEMA_VERSION,
            source_id=prepared.manifest.source_id,
            source_sha256=prepared.manifest.sha256,
            compilation_manifest=SemanticCompilationManifest(
                source_id=prepared.manifest.source_id,
                source_sha256=prepared.manifest.sha256,
                foundation_schema_version=prepared.manifest.extraction.schema_version,
                foundation_parser_id=prepared.manifest.extraction.parser_id,
                foundation_parser_version=prepared.manifest.extraction.parser_version,
                foundation_extraction=prepared.manifest.extraction,
                foundation_manifest_sha256=foundation_manifest_digest(prepared.manifest),
                compiler_version=SEMANTIC_COMPILER_VERSION,
                extractor_prompt_version=EXTRACTOR_PROMPT_VERSION,
                critic_prompt_version=CRITIC_PROMPT_VERSION,
                repair_prompt_version=REPAIR_PROMPT_VERSION,
                execution_example_schema_version=(
                    EXECUTION_EXAMPLE_SCHEMA_VERSION if emitted_example_ids else None
                ),
                emitted_execution_example_ids=emitted_example_ids,
                extractor_model_id=extraction.model,
                critic_model_id=critic.model,
                disposition="verified",
                repair_count=repair_count,
                emitted_artifact_ids=emitted_ids,
                started_at=started_at,
                completed_at=self._now(),
            ),
            references=references,
            cases=cases,
            guidance=guidance,
            execution_examples=execution_examples,
        )

    @staticmethod
    def _call_metadata(
        result: StructuredResult[object],
        purpose: str,
    ) -> SemanticCallMetadata:
        return SemanticCallMetadata(
            purpose=purpose,
            provider=result.provider,
            model=result.model,
            agent_id=result.agent_id,
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
        )

    @staticmethod
    def _finding_indexes(findings: tuple[VerificationFinding, ...]) -> tuple[int, ...]:
        return tuple(sorted({index for finding in findings for index in finding.segment_indexes}))

    @staticmethod
    def _validated_prepared(prepared: PreparedSource) -> PreparedSource:
        return validate_prepared_source(prepared)

    def _failed(
        self,
        failure_code: CompilationFailureCode,
        calls: Sequence[SemanticCallMetadata],
    ) -> SemanticCompilationResult:
        return SemanticCompilationResult(
            disposition="failed",
            failure_code=failure_code,
            failure_message=CANONICAL_COMPILATION_FAILURE_MESSAGES[failure_code],
            calls=tuple(calls),
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return a timezone-aware UTC datetime")
        return now.astimezone(UTC)


__all__ = ["SEMANTIC_SCHEMA_VERSION", "SemanticCompiler"]
