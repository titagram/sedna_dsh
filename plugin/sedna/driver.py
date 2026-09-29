#!/usr/bin/env python3
"""Sedna bridge driver — the Python half of the `sedna-bridge` DSH plugin.

Reads ONE JSON request object on stdin and writes ONE JSON response object on
stdout.  Nothing else goes to stdout (imports and library chatter are kept off
it) so the Node plugin can parse the result without guessing.

    echo '{"op":"retrieve","args":{...}}' | driver.py

Supported ops (all of them construct Sedna services from the knowledge root
alone; none needs a host LLM facade):

    retrieve     KnowledgeRetrievalService over the disposable SQLite index
    artifact     one canonical artifact by retrieval artifact id
    maintenance  audit or rebuild of the disposable index
    engagements  list | inspect | create | resume | abandon engagement journals
    record_decision  append one custom strategy decision to an engagement journal

`create`, `resume`, `abandon` and `record_decision` are the WRITE ops. They bind
or require an execution lane, supplied explicitly by the caller (`session_id`;
this driver has no trusted session context of its own to infer one from).
`create_engagement` / `resume_engagement` / `abandon_engagement` are LLM-free:
they append journal events, they do not plan.

`record_decision` is the only WRITE op: it appends to the engagement's
append-only journal and is bound to the calling execution lane. It is LLM-free —
`EngagementJournalService.record_decision` is a journal mutation, not a planning
call — but the lane must already be bound to the engagement, which today only
`manage_engagement(create|resume)` can do from Hermes. Until lane binding is
bridged too, expect a refusal on engagements that Hermes created.

Configuration is read from `config.json` beside this file, or from the
environment (SEDNA_SRC / SEDNA_KB_ROOT / SEDNA_PYTHON), and defaults to the tree
Hermes actually runs plus the shared knowledge root.

Output discipline: this driver never echoes raw request payloads back.  It
returns bounded labels and structured fields only, so nothing private (flags,
credentials, keys, cookies) can be forwarded into a session transcript by
accident.  Sedna itself redacts flag literals at ingestion time.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def _load_config() -> dict:
    config = {}
    try:
        config = json.loads((HERE / "config.json").read_text())
    except Exception:
        config = {}
    return config


CONFIG = _load_config()
SEDNA_SRC = os.environ.get("SEDNA_SRC") or CONFIG.get(
    "sednaSrc", str(pathlib.Path.home() / ".hermes" / "plugins" / "sedna" / "src")
)
KB_ROOT = pathlib.Path(
    os.environ.get("SEDNA_KB_ROOT")
    or CONFIG.get("knowledgeRoot", str(pathlib.Path.home() / ".hermes" / "knowledge" / "sedna"))
)

if SEDNA_SRC not in sys.path:
    sys.path.insert(0, SEDNA_SRC)


# --------------------------------------------------------------------------- #
# services
# --------------------------------------------------------------------------- #


def _index():
    from sedna.knowledge.retrieval.sqlite import SQLiteRetrievalIndex

    return SQLiteRetrievalIndex(KB_ROOT / "indexes" / "retrieval.sqlite")


def _repository():
    from sedna.knowledge.repository import CanonicalKnowledgeRepository

    return CanonicalKnowledgeRepository(KB_ROOT)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _bounded(value: object, limit: int = 400) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


_LABEL_FIELDS = (
    "summary",
    "statement",
    "intent",
    "rule",
    "action_intent",
    "rationale",
    "selected_action",
    "assessment",
    "description",
    "title",
    "name",
    "purpose",
    "text",
)

# Fields that may hold the readable text themselves when the label field is a
# nested object (e.g. `selected_action` / `action_intent` are structured).
_NESTED_TEXT_FIELDS = ("intent", "action", "summary", "statement", "description", "text", "value")


def _label(artifact: object) -> str:
    """First non-empty human-readable field of a canonical artifact."""
    try:
        dumped = artifact.model_dump()  # type: ignore[attr-defined]
    except Exception:
        dumped = artifact if isinstance(artifact, dict) else {}
    for field in _LABEL_FIELDS:
        value = dumped.get(field)
        if isinstance(value, str) and value.strip():
            return _bounded(value)
        if isinstance(value, dict):
            for nested in _NESTED_TEXT_FIELDS:
                inner = value.get(nested)
                if isinstance(inner, str) and inner.strip():
                    return _bounded(inner)
        if isinstance(value, (list, tuple)) and value:
            first = value[0]
            if isinstance(first, str) and first.strip():
                return _bounded(first)
    return ""


def _artifact_identity(artifact: object) -> str:
    try:
        dumped = artifact.model_dump()  # type: ignore[attr-defined]
    except Exception:
        dumped = artifact if isinstance(artifact, dict) else {}
    kind = dumped.get("artifact_type")
    return str(getattr(kind, "value", kind) or "")


def _lane_items(lane: object) -> list[dict]:
    """A lane is a sequence of candidates; tolerate an object exposing `.items`."""
    if lane is None:
        return []
    candidates = lane if isinstance(lane, (list, tuple)) else getattr(lane, "items", ()) or ()
    items = []
    for candidate in candidates:
        artifact = getattr(candidate, "artifact", None)
        items.append(
            {
                "artifact_id": str(getattr(candidate, "artifact_id", "")),
                "artifact_type": _artifact_identity(artifact),
                "label": _label(artifact),
            }
        )
    return items


def _validated_target(value: str):
    from sedna.knowledge.retrieval.models import ValidatedTarget

    return ValidatedTarget(value=value)


def _lane(args: dict):
    """Build the calling lane from explicit caller-supplied identity.

    This driver has no trusted runtime session context, so the lane is taken from
    the request rather than inferred: inventing an identity would write a lie into
    an append-only journal that outlives the mistake.
    """
    from sedna.engagement.models import ExecutionLaneKey, HostKind

    session_id = args.get("session_id")
    if not session_id:
        raise ValueError("a write action requires a session_id (the calling lane's identity)")
    return ExecutionLaneKey.from_host(
        host_kind=HostKind(str(args.get("host_kind", "other"))),
        session_id=str(session_id),
        task_id=args.get("task_id"),
    )


def _lane_dict(lane) -> dict:
    return {
        "host_kind": str(lane.host_kind),
        "session_id": _bounded(lane.session_id, 80),
        "task_id": _bounded(lane.task_id, 80),
    }


def _scope(args: dict):
    from sedna.knowledge.retrieval.models import (
        AuthorizationScope,
        AuthorizationState,
        ValidatedTarget,
    )

    targets = tuple(
        ValidatedTarget(value=str(item)) for item in (args.get("exact_targets") or ())
    )
    if not targets:
        raise ValueError("a write action requires exact_targets (the declared authorized scope)")
    return AuthorizationScope(
        state=AuthorizationState(args.get("authorization_state", "unknown")),
        exact_targets=targets,
    )


def _mutation_summary(payload: dict, fallback_id: object = "") -> dict:
    snapshot = payload.get("snapshot") or {}
    state = snapshot.get("state") or {}
    status = state.get("status")
    return {
        "engagement_id": str(snapshot.get("engagement_id", fallback_id)),
        "display_name": _bounded((snapshot.get("manifest") or {}).get("display_name"), 120),
        "status": str(getattr(status, "value", status) or ""),
        "revision_sequence": (snapshot.get("revision") or {}).get("sequence"),
        "created_events": len(payload.get("created_event_ids") or ()),
        "existing_events": len(payload.get("existing_event_ids") or ()),
    }


# --------------------------------------------------------------------------- #
# operations
# --------------------------------------------------------------------------- #


def op_retrieve(args: dict) -> dict:
    from sedna.knowledge.retrieval.models import (
        AuthorizationScope,
        AuthorizationState,
        CurrentSituation,
        RetrievalQuery,
    )
    from sedna.knowledge.retrieval.service import KnowledgeRetrievalService

    target_raw = args.get("target")
    if not target_raw:
        raise ValueError("retrieve requires a target")

    exact = tuple(_validated_target(item) for item in (args.get("exact_targets") or ()))
    situation = CurrentSituation(
        target=_validated_target(str(target_raw)),
        authorization=AuthorizationScope(
            state=AuthorizationState(args.get("authorization_state", "unknown")),
            exact_targets=exact,
        ),
        terms=tuple(args.get("observed_terms") or ()),
        services=tuple(args.get("observed_services") or ()),
    )
    query = RetrievalQuery(
        situation=situation,
        terms=tuple(args.get("query_terms") or ()),
        synonyms=tuple(args.get("query_synonyms") or ()),
        max_candidates=int(args.get("max_candidates", 32)),
        lane_limit=int(args.get("lane_limit", 5)),
    )

    index = _index()
    try:
        result = KnowledgeRetrievalService(index).retrieve(query)
        gap = getattr(result, "knowledge_gap", None)
        return {
            "knowledge_gap": (
                None
                if gap is None
                else {
                    "code": str(getattr(getattr(gap, "code", None), "value", getattr(gap, "code", ""))),
                    "retryable": bool(getattr(gap, "retryable", False)),
                }
            ),
            "references": _lane_items(result.references),
            "case_steps": _lane_items(result.case_steps),
            "negative_cases": _lane_items(result.negative_cases),
            "decision_guidance": _lane_items(result.decision_guidance),
            "rejected_candidates": len(getattr(result, "rejected_candidates", ()) or ()),
        }
    finally:
        try:
            index.close()
        except Exception:
            pass


def op_artifact(args: dict) -> dict:
    artifact_id = args.get("artifact_id")
    if not artifact_id:
        raise ValueError("artifact requires an artifact_id")
    index = _index()
    try:
        artifact = index.get_artifact(str(artifact_id))
        if artifact is None:
            return {"found": False, "artifact_id": str(artifact_id)}
        try:
            payload = artifact.model_dump(mode="json")
        except Exception:
            payload = json.loads(json.dumps(artifact, default=str))
        return {"found": True, "artifact_id": str(artifact_id), "artifact": payload}
    finally:
        try:
            index.close()
        except Exception:
            pass


def op_maintenance(args: dict) -> dict:
    from sedna.knowledge.retrieval.maintenance import RetrievalMaintenanceService
    from sedna.knowledge.retrieval.sqlite import SQLiteRetrievalIndex

    operation = str(args.get("operation", "audit"))
    if operation not in {"audit", "rebuild"}:
        raise ValueError("maintenance operation must be audit or rebuild")

    index = SQLiteRetrievalIndex(KB_ROOT / "indexes" / "retrieval.sqlite")
    repository = _repository()
    try:
        service = RetrievalMaintenanceService(repository, index)
        report = service.rebuild() if operation == "rebuild" else service.audit()
        try:
            payload = report.model_dump(mode="json")
        except Exception:
            payload = json.loads(json.dumps(report, default=str))
        return {"operation": operation, "report": payload}
    finally:
        for closer in (index.close, repository.close):
            try:
                closer()
            except Exception:
                pass


def op_engagements(args: dict) -> dict:
    from sedna.engagement.service import EngagementJournalService

    action = str(args.get("action", "list"))
    with EngagementJournalService.open(KB_ROOT) as service:
        if action == "list":
            page = service.list_engagements(limit=int(args.get("limit", 50)))
            items = []
            for item in getattr(page, "items", ()) or ():
                try:
                    dumped = item.model_dump(mode="json")
                except Exception:
                    dumped = json.loads(json.dumps(item, default=str))
                items.append(
                    {
                        "engagement_id": str(dumped.get("engagement_id", "")),
                        "display_name": _bounded(dumped.get("display_name"), 120),
                        "status": str(dumped.get("status", "")),
                        "objective": _bounded(dumped.get("objective"), 240),
                    }
                )
            return {"action": "list", "count": len(items), "engagements": items}

        if action == "inspect":
            from uuid import UUID

            raw = args.get("engagement_id")
            if not raw:
                raise ValueError("inspect requires an engagement_id")
            snapshot = service.inspect_engagement(UUID(str(raw)))
            try:
                dumped = snapshot.model_dump(mode="json")
            except Exception:
                dumped = json.loads(json.dumps(snapshot, default=str))
            manifest = dumped.get("manifest") or {}
            state = dumped.get("state") or {}
            status = state.get("status")
            revision = state.get("revision") or {}
            lanes = []
            for binding in state.get("bound_lanes") or ():
                lane = (binding or {}).get("lane") or {}
                lanes.append(
                    {
                        "host_kind": str(lane.get("host_kind", "")),
                        "session_id": _bounded(lane.get("session_id"), 80),
                        "task_id": _bounded(lane.get("task_id"), 80),
                    }
                )
            return {
                "action": "inspect",
                "engagement_id": str(dumped.get("engagement_id", raw)),
                "display_name": _bounded(manifest.get("display_name"), 120),
                "status": str(getattr(status, "value", status) or ""),
                "objective": _bounded(manifest.get("initial_objective"), 240),
                "event_count": len(dumped.get("events") or ()),
                "revision_sequence": revision.get("sequence"),
                "journal_healthy": state.get("journal_healthy"),
                "closure_ready": state.get("closure_ready"),
                "bound_lanes": lanes,
            }

        if action in {"create", "resume", "abandon"}:
            from uuid import UUID

            lane = _lane(args)

            # Measured 2026-09-20: unlike record_decision (lane-gated, fails
            # closed), resume/abandon are NOT gated on the lane being bound to
            # the target engagement -- a lane never bound to anything abandoned
            # an arbitrary engagement successfully. The bridge therefore asks for
            # an explicit confirmation rather than turning an administrative
            # action into a one-call accident. It is a deliberate-call guard, not
            # a security boundary: it cannot make Sedna stricter than Sedna is.
            if action in {"resume", "abandon"} and not args.get("confirm"):
                raise ValueError(
                    f"{action} is not lane-gated by Sedna: any lane can resume or abandon any "
                    "engagement, including one it was never bound to. Pass confirm=true to "
                    "record the call as deliberate."
                )
            try:
                binding = _bounded(service.resolve_lane_binding(lane), 200)
            except Exception as error:
                binding = f"unresolved: {type(error).__name__}: {_bounded(error, 160)}"

            if action == "create":
                display_name = str(args.get("display_name") or "").strip()
                objective = str(args.get("objective") or "").strip()
                if not display_name or not objective:
                    raise ValueError("create requires display_name and objective")
                result = service.create_engagement(
                    display_name=display_name,
                    objective=objective,
                    scope=_scope(args),
                    lane=lane,
                )
            elif action == "resume":
                raw = args.get("engagement_id")
                result = service.resume_engagement(
                    lane=lane,
                    engagement_id=UUID(str(raw)) if raw else None,
                    display_name=(str(args["display_name"]) if args.get("display_name") else None),
                    scope=(_scope(args) if args.get("exact_targets") else None),
                )
            else:
                raw = args.get("engagement_id")
                if not raw:
                    raise ValueError("abandon requires an engagement_id")
                reason = str(args.get("reason") or "").strip()
                if not reason:
                    raise ValueError("abandon requires a reason")
                result = service.abandon_engagement(UUID(str(raw)), lane=lane, reason=reason)

            try:
                payload = result.model_dump(mode="json")
            except Exception:
                payload = json.loads(json.dumps(result, default=str))
            return {
                "action": action,
                "lane": _lane_dict(lane),
                "lane_binding": binding,
                "result": _mutation_summary(payload, args.get("engagement_id", "")),
            }

        raise ValueError("engagements action must be list, inspect, create, resume or abandon")


def op_record_decision(args: dict) -> dict:
    """Append one custom strategy decision to an engagement journal.

    The lane is explicit rather than inferred: this driver has no trusted runtime
    session context, and inventing one would put a lie into the journal. A DSH
    caller supplies its own session identity, and the journal's lane binding is
    what decides whether the write is allowed.
    """
    from uuid import UUID

    from sedna.engagement.models import ExecutionLaneKey, HostKind
    from sedna.engagement.service import EngagementJournalService

    raw_engagement = args.get("engagement_id")
    if not raw_engagement:
        raise ValueError("record_decision requires an engagement_id")
    session_id = args.get("session_id")
    if not session_id:
        raise ValueError("record_decision requires a session_id (the calling lane's identity)")

    strategy = args.get("strategy")
    rationale = args.get("rationale")
    if strategy and not rationale:
        raise ValueError("a custom strategy requires a rationale")

    lane = ExecutionLaneKey.from_host(
        host_kind=HostKind(str(args.get("host_kind", "other"))),
        session_id=str(session_id),
        task_id=args.get("task_id"),
    )

    with EngagementJournalService.open(KB_ROOT) as service:
        try:
            binding = _bounded(service.resolve_lane_binding(lane), 200)
        except Exception as error:
            binding = f"unresolved: {type(error).__name__}: {_bounded(error, 160)}"
        result = service.record_decision(
            UUID(str(raw_engagement)),
            lane=lane,
            strategy=strategy,
            rationale=rationale,
        )
        try:
            payload = result.model_dump(mode="json")
        except Exception:
            payload = json.loads(json.dumps(result, default=str))
        snapshot = payload.get("snapshot") or {}
        snapshot_state = snapshot.get("state") or {}
        snapshot_status = snapshot_state.get("status")
        return {
            "lane": {
                "host_kind": str(lane.host_kind),
                "session_id": _bounded(lane.session_id, 80),
                "task_id": _bounded(lane.task_id, 80),
            },
            "lane_binding": binding,
            "result": {
                "engagement_id": str(snapshot.get("engagement_id", raw_engagement)),
                "display_name": _bounded((snapshot.get("manifest") or {}).get("display_name"), 120),
                "status": str(getattr(snapshot_status, "value", snapshot_status) or ""),
                "revision_sequence": (snapshot.get("revision") or {}).get("sequence"),
                "created_events": len(payload.get("created_event_ids") or ()),
                "existing_events": len(payload.get("existing_event_ids") or ()),
            },
        }


def op_ingest(args: dict) -> dict:
    """Learn a source into the knowledge base, and report what happened to it.

    Growing the base is the half of the promise the seed cannot keep: the volume is preserved
    by construction, but until this exists nothing shipped here could add to it.

    The shape is deliberate. A caller hands over a path *inside the inbox* and gets back the
    engine's own report -- what it accepted, what it quarantined and the codes that say why.
    That matters because a source is classified by its physical path, and from the outside the
    verdict is not guessable: the failure mode is a file that is accepted silently into
    quarantine and never becomes knowledge, which looks exactly like success.

    The model is called only for a real run. `check` stops before extraction and answers the
    layout question alone, so an operator can confirm a file will be accepted before paying
    for a semantic pass.
    """
    from pathlib import Path

    from sedna.knowledge.hades_runtime import HadesKnowledgeRuntime
    from sedna.knowledge.semantic.ollama_host import OllamaHost

    source_raw = args.get("source")
    if not source_raw:
        raise ValueError("ingest requires a source path inside the inbox")
    source = Path(str(source_raw)).expanduser()
    if not source.exists():
        raise ValueError("ingest source does not exist: " + str(source))

    inbox = Path(os.environ.get("SEDNA_INBOX", "/inbox")).resolve()
    resolved = source.resolve()
    if inbox not in resolved.parents and resolved != inbox:
        raise ValueError("ingest source must be inside the inbox: " + str(inbox))

    if bool(args.get("check")):
        # The deterministic half of the pipeline, run on its own. Inventory and preparation
        # decide whether a source is eligible -- the family it belongs to, its path, its
        # structure -- and neither of them calls a model. This is the answer to "will this be
        # accepted", one step before paying for extraction.
        #
        # It is not a simulation: preparation records the source's foundation state, which is
        # exactly what a later ingest would build on. What it does not do is spend a model call
        # on a file that was never going to be accepted.
        from sedna.knowledge.classifier import classify_document
        from sedna.knowledge.inventory import discover_sources
        from sedna.knowledge.pipeline import IngestionPipeline

        root = resolved if resolved.is_dir() else resolved.parent
        only = None if resolved.is_dir() else resolved.name
        repository = _repository()
        try:
            with IngestionPipeline(root, KB_ROOT, repository=repository) as pipeline:
                found = [
                    candidate
                    for candidate in discover_sources(root)
                    if only is None or candidate.relative_path == only
                ]
                entries = []
                for candidate in found:
                    entry = {"relative_path": candidate.relative_path}
                    try:
                        prepared = pipeline.prepare(candidate)
                        entry["outcome"] = pipeline.last_outcome or (
                            "accepted" if prepared is not None else None
                        )
                        # "unchanged" is a source the engine already holds: it was not
                        # re-prepared, but reporting it as ineligible reads as a rejection.
                        entry["eligible"] = prepared is not None or (
                            pipeline.last_outcome == "unchanged"
                        )
                    except Exception as error:
                        entry["outcome"] = "failed"
                        entry["eligible"] = False
                        entry["error"] = f"{type(error).__name__}: {_bounded(error)}"
                    if entry["outcome"] in {"quarantined", "excluded"}:
                        # The pipeline records *that* a source was refused; the classifier
                        # knows why. Asking it directly is what turns a silent quarantine
                        # into something an operator can act on.
                        try:
                            text = None
                            candidate_path = root / candidate.relative_path
                            if candidate_path.suffix.casefold() == ".md":
                                text = candidate_path.read_text(errors="replace")
                            verdict = classify_document(candidate, text)
                            try:
                                entry["classification"] = verdict.model_dump(mode="json")
                            except Exception:
                                entry["classification"] = json.loads(
                                    json.dumps(verdict, default=str)
                                )
                        except Exception as error:
                            entry["classification_error"] = type(error).__name__
                    entries.append(entry)
                return {
                    "source": str(resolved),
                    "checked_only": True,
                    "candidate_count": len(entries),
                    "entries": entries,
                    "note": (
                        "deterministic preparation only: nothing was sent to a model. An eligible "
                        "source is not yet knowledge -- run the same operation without check to "
                        "extract and verify it."
                    ),
                }
        finally:
            repository.close()

    # The host adapter is the engine's own. Its API mode is auto-detected from the URL, and
    # that detection is load-bearing: an endpoint containing `/v1` or `ollama.com` takes the
    # OpenAI-compatible path, where a hosted model may ignore the JSON schema and return prose
    # -- which the engine then reads as "no JSON object" and reports as a failed extraction,
    # not as a broken provider. A native endpoint (no `/v1`) uses Ollama's own JSON mode.
    host = OllamaHost()
    runtime = HadesKnowledgeRuntime.create(host, KB_ROOT, external_source_path=resolved)
    try:
        before = runtime.maintenance.audit()
        report = runtime.learning.learn(resolved)
        try:
            payload = report.model_dump(mode="json")
        except Exception:
            payload = json.loads(json.dumps(report, default=str))

        after = runtime.maintenance.audit()
        rebuilt = False
        if getattr(after, "rebuild_required", False):
            runtime.maintenance.rebuild()
            rebuilt = True
            after = runtime.maintenance.audit()

        return {
            "source": str(resolved),
            "report": payload,
            "canonical_sources_before": getattr(before, "canonical_source_count", None),
            "canonical_sources_after": getattr(after, "canonical_source_count", None),
            "index_rebuilt": rebuilt,
            "reachable_now": not getattr(after, "rebuild_required", True),
        }
    finally:
        try:
            runtime.close()
        except Exception:
            pass


OPERATIONS = {
    "retrieve": op_retrieve,
    "artifact": op_artifact,
    "maintenance": op_maintenance,
    "ingest": op_ingest,
    "engagements": op_engagements,
    "record_decision": op_record_decision,
}


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except Exception as error:
        print(json.dumps({"ok": False, "error": {"code": "invalid_request", "message": str(error)}}))
        return 0

    op = request.get("op")
    args = request.get("args") or {}
    handler = OPERATIONS.get(op)
    if handler is None:
        print(json.dumps({"ok": False, "error": {"code": "unknown_operation", "message": str(op)}}))
        return 0

    try:
        data = handler(args)
    except Exception as error:  # fail closed: one JSON error object, never a traceback
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {"code": type(error).__name__, "message": _bounded(error)},
                }
            )
        )
        return 0

    print(json.dumps({"ok": True, "data": data}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
