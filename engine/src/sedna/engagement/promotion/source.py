"""Strict semantic-source construction from committed promotion bytes."""

from typing import Literal

from sedna.engagement.promotion.models import (
    PROMOTION_COMPILER_VERSION,
    PROMOTION_SOURCE_SCHEMA_VERSION,
    CommittedPromotionSource,
)
from sedna.knowledge.parsing import PreparedSource, parse_markdown
from sedna.knowledge.parsing.models import validate_prepared_source
from sedna.knowledge.parsing.segment import segment_document
from sedna.knowledge.pipeline import PARSER_ID, PARSER_VERSION
from sedna.knowledge.schema import (
    AssetRef,
    DocumentManifest,
    DocumentType,
    ExtractionMetadata,
    IngestionStatus,
    KnowledgeRole,
    SourceQuality,
)

PromotionFoundationExclusionReason = Literal[
    "index_retry_exhausted",
    "verification_revoked",
    "unsafe_material",
    "required_case_missing",
    "semantic_quarantined",
    "semantic_failure",
    "promotion_stage_too_large",
    "canonical_unavailable",
    "recovery_conflict",
    "lease_abandoned",
    "promotion_asset_invalid",
]
_PROMOTION_FOUNDATION_EXCLUSION_REASONS = frozenset(PromotionFoundationExclusionReason.__args__)


def build_promotion_prepared_source(committed: CommittedPromotionSource) -> PreparedSource:
    """Parse only the immutable event-bound source represented by ``committed``."""
    committed = CommittedPromotionSource.model_validate_json(
        committed.model_dump_json(warnings="error")
    )
    document = parse_markdown(
        committed.source_id,
        committed.source_relative_path,
        committed.markdown,
    )
    segments = segment_document(document)
    manifest = DocumentManifest(
        source_id=committed.source_id,
        source_namespace="journal-promotion",
        path=committed.source_relative_path,
        sha256=committed.source_sha256,
        title=committed.title,
        language="en",
        document_type=DocumentType.MACHINE_WALKTHROUGH,
        knowledge_role=KnowledgeRole.CASE_STUDY,
        quality=SourceQuality.COMPLETE,
        parser_profile="journal_promotion",
        ingestion_status=IngestionStatus.ACCEPTED,
        extraction=ExtractionMetadata(
            schema_version=PROMOTION_SOURCE_SCHEMA_VERSION,
            parser_id=PARSER_ID,
            parser_version=PARSER_VERSION,
            extractor_id="journal-promotion-renderer",
            extractor_version="1",
            prompt_id="sedna.promotion.compile",
            prompt_version=PROMOTION_COMPILER_VERSION,
        ),
        assets=(
            AssetRef(
                path=committed.provenance_relative_path,
                sha256=committed.provenance_sha256,
            ),
        ),
    )
    return validate_prepared_source(
        PreparedSource(manifest=manifest, document=document, segments=segments)
    )


def build_nonaccepted_promotion_manifest(
    current: DocumentManifest,
    *,
    reason: PromotionFoundationExclusionReason,
) -> DocumentManifest:
    """Deterministically exclude one committed promotion foundation without changing lineage."""
    current = DocumentManifest.model_validate(current.model_dump(mode="json", warnings="error"))
    if current.source_namespace != "journal-promotion":
        raise ValueError("nonaccepted promotion manifest requires journal-promotion namespace")
    if reason not in _PROMOTION_FOUNDATION_EXCLUSION_REASONS:
        raise ValueError("unknown promotion foundation exclusion reason")
    return DocumentManifest.model_validate(
        current.model_copy(
            update={
                "ingestion_status": IngestionStatus.EXCLUDED,
                "quality": SourceQuality.UNUSABLE,
                "quality_reason_codes": (reason,),
                "emitted_artifact_ids": (),
                "quarantine_reasons": (),
            }
        ).model_dump(mode="json", warnings="error")
    )
