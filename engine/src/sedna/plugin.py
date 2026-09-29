"""Safe Hades tool registration for Sedna execution and strategic knowledge."""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sedna.engagement.hades_adapter import HadesEngagementAdapter
from sedna.engagement.models import ExecutionLaneKey, HostKind, PromotionSagaInProgressError
from sedna.knowledge.hades_runtime import HadesKnowledgeRuntime
from sedna.knowledge.retrieval import (
    AuthorizationScope,
    AuthorizationState,
    CurrentSituation,
    KnowledgeRetrievalService,
    RetrievalQuery,
    SituationFacet,
    ValidatedTarget,
)
from sedna.planning import (
    MAX_PLANNING_RESULT_BYTES,
    PlanningResult,
    PlanningRuntimeFactory,
    PlanningSettlementPortFactory,
)
from sedna.planning.retrieval import HindsightCandidateContext
from sedna.runners import ToolRunner, nmap_service_scan, nmap_tcp_discovery

_MAX_PATH_LENGTH = 4096
_MAX_TARGET_LENGTH = 2048
_MAX_SCOPE_VALUE_LENGTH = 2048
_MAX_TERM_LENGTH = 512
_MAX_FACET_NAMESPACE_LENGTH = 128
_MAX_FACET_KEY_LENGTH = 128
_MAX_FACET_VALUE_LENGTH = 2048
_MAX_SITUATION_ITEMS = 64
_MAX_QUERY_TERMS = 32

BoundedPath = Annotated[str, Field(min_length=1, max_length=_MAX_PATH_LENGTH)]
BoundedTarget = Annotated[str, Field(min_length=1, max_length=_MAX_TARGET_LENGTH)]
BoundedScopeValue = Annotated[str, Field(min_length=1, max_length=_MAX_SCOPE_VALUE_LENGTH)]
BoundedTerm = Annotated[str, Field(min_length=1, max_length=_MAX_TERM_LENGTH)]
BoundedFacetNamespace = Annotated[
    str,
    Field(min_length=1, max_length=_MAX_FACET_NAMESPACE_LENGTH),
]
BoundedFacetKey = Annotated[str, Field(min_length=1, max_length=_MAX_FACET_KEY_LENGTH)]
BoundedFacetValue = Annotated[str, Field(min_length=1, max_length=_MAX_FACET_VALUE_LENGTH)]
InputModelT = TypeVar("InputModelT", bound=BaseModel)
ToolErrorCode = Literal[
    "artifact_lookup_failed",
    "artifact_not_found",
    "invalid_input",
    "knowledge_root_required",
    "knowledge_runtime_unavailable",
    "learning_failed",
    "maintenance_failed",
    "retrieval_failed",
    "structured_llm_unavailable",
    "engagement_binding_required",
    "evidence_budget_exhausted",
    "interpretation_incomplete",
    "interpretation_failed",
    "settlement_unavailable",
    "journal_unavailable",
    "planning_failed",
    "result_too_large",
]


class _ToolInput(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        revalidate_instances="always",
        strict=True,
    )


class _RuntimeInput(_ToolInput):
    knowledge_root: BoundedPath | None = None


class _LearnLocalInput(_RuntimeInput):
    source_path: BoundedPath


class _AuthorizationInput(_ToolInput):
    state: AuthorizationState
    exact_targets: tuple[BoundedTarget, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    cidrs: tuple[BoundedScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    hostnames: tuple[BoundedScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    url_origins: tuple[BoundedScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    generic_ids: tuple[BoundedScopeValue, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)


class _FacetInput(_ToolInput):
    namespace: BoundedFacetNamespace
    key: BoundedFacetKey
    value: BoundedFacetValue
    confidence: float = Field(ge=0.0, le=1.0)


class _PrimitiveInput(_ToolInput):
    kind: BoundedFacetKey
    source: BoundedTerm | None = None
    transforms: tuple[BoundedTerm, ...] = Field(default=(), max_length=16)
    sink: BoundedTerm | None = None
    persistence: BoundedTerm | None = None
    trust_boundary: BoundedTerm | None = None
    preconditions: tuple[BoundedTerm, ...] = Field(default=(), max_length=16)
    candidate_classes: tuple[BoundedTerm, ...] = Field(default=(), max_length=16)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class _RetrieveInput(_RuntimeInput):
    target: BoundedTarget
    authorization: _AuthorizationInput
    observed_terms: tuple[BoundedTerm, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    observed_facts: tuple[_FacetInput, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    observed_primitives: tuple[_PrimitiveInput, ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    observed_access: tuple[BoundedTerm, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    observed_services: tuple[BoundedTerm, ...] = Field(default=(), max_length=_MAX_SITUATION_ITEMS)
    observed_hypotheses: tuple[BoundedTerm, ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    tried_outcomes: tuple[tuple[BoundedTerm, BoundedTerm], ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    unresolved_questions: tuple[BoundedTerm, ...] = Field(
        default=(), max_length=_MAX_SITUATION_ITEMS
    )
    query_terms: tuple[BoundedTerm, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    query_synonyms: tuple[BoundedTerm, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    query_facets: tuple[_FacetInput, ...] = Field(default=(), max_length=_MAX_QUERY_TERMS)
    max_candidates: int = Field(default=32, ge=1, le=100)
    lane_limit: int = Field(default=5, ge=1, le=20)


class _ArtifactInput(_RuntimeInput):
    artifact_id: Annotated[str, Field(min_length=1, max_length=2048)]


class _MaintenanceInput(_RuntimeInput):
    operation: Literal["audit", "rebuild"]


class _PlanNextInput(_ToolInput):
    max_proposals: int = Field(default=5, ge=3, le=8)
    hindsight_candidates: tuple[HindsightCandidateContext, ...] = Field(default=(), max_length=16)


class _ToolErrorResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    ok: Literal[False] = False
    error: ToolErrorCode


class _ToolBoundaryError(RuntimeError):
    def __init__(self, code: ToolErrorCode) -> None:
        self.code = code
        super().__init__(code)


class _PrebackendOnlyIndex:
    """A tripwire proving invalid/unauthorized queries do not touch a backend."""

    def search_candidates(self, *_: object, **__: object) -> tuple[()]:
        raise AssertionError("pre-backend retrieval attempted an index search")

    def get_artifact(self, *_: object, **__: object) -> None:
        raise AssertionError("pre-backend retrieval attempted an artifact lookup")


class _BoundStructuredHost:
    """Immutable host callable captured once at the plugin boundary."""

    def __init__(self, complete_structured: Callable[..., object]) -> None:
        self._complete_structured = complete_structured

    def complete_structured(self, **kwargs: object) -> object:
        return self._complete_structured(**kwargs)


def register(ctx: Any) -> None:
    """Register the implemented Nmap and local strategic-knowledge operations."""
    ctx.register_tool(
        name="sedna_nmap_tcp_discovery",
        toolset="plugin_sedna",
        schema={
            "name": "sedna_nmap_tcp_discovery",
            "description": (
                "Run an unprivileged TCP discovery scan against an authorized HTB target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                    "top_ports": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 65535,
                    },
                    "timeout": {"type": "number", "default": 120, "minimum": 1, "maximum": 600},
                },
                "required": ["target"],
            },
        },
        handler=_tcp_discovery_handler,
    )
    ctx.register_tool(
        name="sedna_nmap_service_scan",
        toolset="plugin_sedna",
        schema={
            "name": "sedna_nmap_service_scan",
            "description": (
                "Identify services on explicitly enumerated ports of an authorized HTB target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                    "ports": {
                        "type": "string",
                        "description": "Ports/ranges, e.g. 22,80,443 or 8000-8010",
                    },
                    "timeout": {"type": "number", "default": 120, "minimum": 1, "maximum": 600},
                },
                "required": ["target", "ports"],
            },
        },
        handler=_service_scan_handler,
    )
    _register_knowledge_tool(
        ctx,
        name="sedna_learn_local",
        description=(
            "Classify, verify, and index one local Markdown/PDF file or one local folder "
            "using the host structured LLM."
        ),
        input_model=_LearnLocalInput,
        handler=_learn_local_handler,
    )
    _register_knowledge_tool(
        ctx,
        name="sedna_retrieve_knowledge",
        description=(
            "Retrieve source-backed strategic knowledge for an explicitly authorized, "
            "typed current situation."
        ),
        input_model=_RetrieveInput,
        handler=_retrieve_handler,
    )
    _register_knowledge_tool(
        ctx,
        name="sedna_get_knowledge_artifact",
        description="Load one exact canonical knowledge artifact by its retrieval artifact ID.",
        input_model=_ArtifactInput,
        handler=_get_artifact_handler,
    )
    _register_knowledge_tool(
        ctx,
        name="sedna_knowledge_maintenance",
        description="Audit or rebuild the disposable knowledge retrieval index.",
        input_model=_MaintenanceInput,
        handler=_maintenance_handler,
    )

    def root_resolver() -> Path:
        return _knowledge_root(ctx, None)

    planning_runtime_factory = _planning_runtime_factory(ctx)
    ctx.register_tool(
        name="sedna_plan_next",
        toolset="plugin_sedna",
        schema={
            "name": "sedna_plan_next",
            "description": "Settle pending evidence and return the validated planning frontier.",
            "parameters": _PlanNextInput.model_json_schema(),
        },
        handler=_bind_plan_context(
            root_resolver=root_resolver,
            planning_runtime_factory=planning_runtime_factory,
        ),
    )
    HadesEngagementAdapter(
        ctx,
        root_resolver=root_resolver,
        settlement_port_factory=PlanningSettlementPortFactory(planning_runtime_factory),
        runtime_factory=planning_runtime_factory,
    ).register()


def _register_knowledge_tool(
    ctx: Any,
    *,
    name: str,
    description: str,
    input_model: type[BaseModel],
    handler: Callable[..., str],
) -> None:
    ctx.register_tool(
        name=name,
        toolset="plugin_sedna",
        schema={
            "name": name,
            "description": description,
            "parameters": input_model.model_json_schema(),
        },
        handler=_bind_context(handler, ctx),
    )


def _bind_context(handler: Callable[..., str], ctx: Any) -> Callable[..., str]:
    def bound(args: object, **_: Any) -> str:
        return handler(args, ctx=ctx)

    return bound


def _bind_plan_context(
    *,
    root_resolver: Callable[[], Path],
    planning_runtime_factory: PlanningRuntimeFactory,
) -> Callable[..., str]:
    def bound(args: object, **kwargs: Any) -> str:
        return _plan_next_handler(
            args,
            root_resolver=root_resolver,
            planning_runtime_factory=planning_runtime_factory,
            **kwargs,
        )

    return bound


def _planning_runtime_factory(ctx: Any) -> PlanningRuntimeFactory:
    @contextmanager
    def open_runtime(resolved_root: Path) -> Any:
        host = _structured_host(ctx)
        try:
            runtime = HadesKnowledgeRuntime.create(host, resolved_root)
        except Exception as error:
            raise _ToolBoundaryError("knowledge_runtime_unavailable") from error
        try:
            yield runtime
        finally:
            runtime.close()

    return open_runtime


def _plan_next_handler(
    args: object,
    *,
    root_resolver: Callable[[], Path],
    planning_runtime_factory: PlanningRuntimeFactory,
    session_id: str | None = None,
    task_id: str | None = None,
    **_: Any,
) -> str:
    if not session_id or not task_id:
        return _json_error("engagement_binding_required")
    try:
        request = _validate_input(_PlanNextInput, args)
        lane = ExecutionLaneKey.from_host(
            host_kind=HostKind.HADES,
            session_id=session_id,
            task_id=task_id,
        )
        root = root_resolver()
        with planning_runtime_factory(root) as runtime:
            result = runtime.planning.plan_next(
                lane,
                max_proposals=request.max_proposals,
                hindsight_candidates=request.hindsight_candidates,
            )
        return _serialize_planning_result(result)
    except _ToolBoundaryError as error:
        return _json_error(error.code)
    except PromotionSagaInProgressError:
        return _json_payload(
            {
                "ok": False,
                "error": {"code": "promotion_saga_in_progress", "retryable": True},
            }
        )
    except ValidationError:
        return _json_error("invalid_input")
    except Exception:
        return _json_error("planning_failed")


def _learn_local_handler(args: object, *, ctx: Any) -> str:
    try:
        request = _validate_input(_LearnLocalInput, args)
        source_path = Path(request.source_path)
        with _runtime_for_context(
            ctx,
            request.knowledge_root,
            source_path=source_path,
        ) as runtime:
            return _json_model(runtime.learning.learn(source_path))
    except _ToolBoundaryError as error:
        return _json_error(error.code)
    except ValidationError:
        return _json_error("invalid_input")
    except Exception:
        return _json_error("learning_failed")


def _retrieve_handler(args: object, *, ctx: Any) -> str:
    try:
        request = _validate_input(_RetrieveInput, args)
        query = _build_query(request)
        if (
            not query.situation.target.is_valid
            or query.situation.authorization.state is not AuthorizationState.AUTHORIZED
        ):
            service = KnowledgeRetrievalService(_PrebackendOnlyIndex())  # type: ignore[arg-type]
            return _json_model(service.retrieve(query))
        with _runtime_for_context(ctx, request.knowledge_root) as runtime:
            return _json_model(runtime.retrieval.retrieve(query))
    except _ToolBoundaryError as error:
        return _json_error(error.code)
    except ValidationError:
        return _json_error("invalid_input")
    except Exception:
        return _json_error("retrieval_failed")


def _get_artifact_handler(args: object, *, ctx: Any) -> str:
    try:
        request = _validate_input(_ArtifactInput, args)
        with _runtime_for_context(ctx, request.knowledge_root) as runtime:
            artifact = runtime.retrieval.get_artifact(request.artifact_id)
            if artifact is None:
                return _json_error("artifact_not_found")
            return _json_model(artifact)
    except _ToolBoundaryError as error:
        return _json_error(error.code)
    except ValidationError:
        return _json_error("invalid_input")
    except Exception:
        return _json_error("artifact_lookup_failed")


def _maintenance_handler(args: object, *, ctx: Any) -> str:
    try:
        request = _validate_input(_MaintenanceInput, args)
        with _runtime_for_context(ctx, request.knowledge_root) as runtime:
            operation = (
                runtime.maintenance.audit
                if request.operation == "audit"
                else runtime.maintenance.rebuild
            )
            return _json_model(operation())
    except _ToolBoundaryError as error:
        return _json_error(error.code)
    except ValidationError:
        return _json_error("invalid_input")
    except Exception:
        return _json_error("maintenance_failed")


def _validate_input(model: type[InputModelT], args: object) -> InputModelT:
    if type(args) is not dict:
        raise _ToolBoundaryError("invalid_input")
    try:
        encoded = json.dumps(args, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise _ToolBoundaryError("invalid_input") from error
    return model.model_validate_json(encoded)


def _build_query(request: _RetrieveInput) -> RetrievalQuery:
    target = ValidatedTarget.parse(request.target)
    authorization = (
        AuthorizationScope(state=AuthorizationState.UNKNOWN)
        if not target.is_valid
        else AuthorizationScope(
            state=request.authorization.state,
            exact_targets=tuple(
                ValidatedTarget.parse(value) for value in request.authorization.exact_targets
            ),
            cidrs=request.authorization.cidrs,
            hostnames=request.authorization.hostnames,
            url_origins=request.authorization.url_origins,
            generic_ids=request.authorization.generic_ids,
        )
    )
    facts = tuple(
        SituationFacet.model_validate(facet.model_dump(mode="json"))
        for facet in request.observed_facts
    )
    primitive_facets = tuple(
        SituationFacet(
            namespace="code_intel",
            key=primitive.kind,
            value="; ".join(
                part
                for part in (
                    f"kind={primitive.kind}",
                    f"source={primitive.source}" if primitive.source else "",
                    f"transforms={','.join(primitive.transforms)}" if primitive.transforms else "",
                    f"sink={primitive.sink}" if primitive.sink else "",
                    f"persistence={primitive.persistence}" if primitive.persistence else "",
                    f"trust_boundary={primitive.trust_boundary}"
                    if primitive.trust_boundary
                    else "",
                )
                if part
            ),
            confidence=primitive.confidence,
        )
        for primitive in request.observed_primitives
    )
    primitive_terms = tuple(
        dict.fromkeys(
            term
            for primitive in request.observed_primitives
            for term in (
                primitive.kind,
                primitive.source,
                *primitive.transforms,
                primitive.sink,
                primitive.persistence,
                primitive.trust_boundary,
                *primitive.preconditions,
            )
            if term is not None
        )
    )[:_MAX_QUERY_TERMS]
    primitive_classes = tuple(
        dict.fromkeys(
            candidate
            for primitive in request.observed_primitives
            for candidate in primitive.candidate_classes
        )
    )[:_MAX_QUERY_TERMS]
    query_facets = tuple(
        SituationFacet.model_validate(facet.model_dump(mode="json"))
        for facet in request.query_facets
    )
    return RetrievalQuery(
        situation=CurrentSituation(
            target=target,
            authorization=authorization,
            terms=tuple(dict.fromkeys((*request.observed_terms, *primitive_terms)))[
                :_MAX_SITUATION_ITEMS
            ],
            facts=(*facts, *primitive_facets)[:_MAX_SITUATION_ITEMS],
            access=request.observed_access,
            services=request.observed_services,
            hypotheses=request.observed_hypotheses,
            tried_outcomes=request.tried_outcomes,
            unresolved_questions=request.unresolved_questions,
        ),
        terms=tuple(dict.fromkeys((*request.query_terms, *primitive_terms)))[:_MAX_QUERY_TERMS],
        synonyms=tuple(dict.fromkeys((*request.query_synonyms, *primitive_classes)))[
            :_MAX_QUERY_TERMS
        ],
        facets=query_facets,
        max_candidates=request.max_candidates,
        lane_limit=request.lane_limit,
    )


def _runtime_for_context(
    ctx: Any,
    explicit_knowledge_root: str | None,
    *,
    source_path: Path | None = None,
) -> HadesKnowledgeRuntime:
    host = _structured_host(ctx)
    knowledge_root = _knowledge_root(ctx, explicit_knowledge_root)
    if source_path is not None:
        _require_external_knowledge_root(source_path, knowledge_root)
    try:
        return HadesKnowledgeRuntime.create(
            host,
            knowledge_root,
            external_source_path=source_path,
        )
    except Exception as error:
        raise _ToolBoundaryError("knowledge_runtime_unavailable") from error


def _structured_host(ctx: Any) -> object:
    # Opt-in to the local Codex CLI host for semantic extraction, bypassing
    # Hermes' auxiliary LLM routing (which may 402 on an exhausted fallback
    # provider like OpenRouter). Enabled only when SEDNA_CODEX_LLM=1 and the
    # codex binary is available; otherwise fail closed through the host facade.
    if os.environ.get("SEDNA_OLLAMA_LLM", "") == "1":
        try:
            from sedna.knowledge.semantic.ollama_host import OllamaHost
        except Exception:
            raise _ToolBoundaryError("structured_llm_unavailable") from None
        return OllamaHost()
    if os.environ.get("SEDNA_CODEX_LLM", "") == "1":
        try:
            from sedna.knowledge.semantic.codex_host import CodexCliHost
        except Exception:
            raise _ToolBoundaryError("structured_llm_unavailable") from None
        return CodexCliHost()
    try:
        host = ctx.llm
        complete_structured = host.complete_structured
    except Exception as error:
        raise _ToolBoundaryError("structured_llm_unavailable") from error
    if not callable(complete_structured):
        raise _ToolBoundaryError("structured_llm_unavailable")
    return _BoundStructuredHost(complete_structured)


def _validated_root(value: object, *, error_code: ToolErrorCode) -> Path:
    if type(value) is not str and not isinstance(value, Path):
        raise _ToolBoundaryError(error_code)
    rendered = str(value)
    if not rendered or len(rendered) > _MAX_PATH_LENGTH or "\x00" in rendered:
        raise _ToolBoundaryError(error_code)
    return Path(rendered)


def _platform_hades_home(
    platform: str,
    environment: Mapping[str, str],
    user_home: Path,
) -> Path:
    if platform == "win32":
        local = environment.get("LOCALAPPDATA")
        return (Path(local) if local else user_home / "AppData" / "Local") / "hades"
    return user_home / ".hades"


def _default_knowledge_root() -> Path:
    try:
        module = importlib.import_module("hermes_constants")
    except ModuleNotFoundError as error:
        if error.name != "hermes_constants":
            raise _ToolBoundaryError("knowledge_runtime_unavailable") from error
        home: object = _platform_hades_home(sys.platform, os.environ, Path.home())
    except ImportError as error:
        raise _ToolBoundaryError("knowledge_runtime_unavailable") from error
    else:
        resolver = getattr(module, "get_hermes_home", None)
        if not callable(resolver):
            raise _ToolBoundaryError("knowledge_runtime_unavailable")
        try:
            home = resolver()
        except Exception as error:
            raise _ToolBoundaryError("knowledge_runtime_unavailable") from error
    home_path = _validated_root(home, error_code="knowledge_runtime_unavailable")
    if not home_path.is_absolute():
        raise _ToolBoundaryError("knowledge_runtime_unavailable")
    return home_path / "knowledge" / "sedna"


def _knowledge_root(ctx: Any, explicit: str | None) -> Path:
    if explicit is not None:
        root = _validated_root(explicit, error_code="invalid_input")
        if not root.is_absolute():
            raise _ToolBoundaryError("invalid_input")
        return root
    try:
        configured = ctx.sedna_knowledge_root
    except AttributeError:
        return _default_knowledge_root()
    except Exception as error:
        raise _ToolBoundaryError("knowledge_runtime_unavailable") from error
    root = _validated_root(configured, error_code="invalid_input")
    if not root.is_absolute():
        raise _ToolBoundaryError("invalid_input")
    return root


def _require_external_knowledge_root(source_path: Path, knowledge_root: Path) -> None:
    try:
        resolved_source = source_path.resolve(strict=False)
        selected_root = resolved_source if resolved_source.is_dir() else resolved_source.parent
        resolved_knowledge = knowledge_root.resolve(strict=False)
    except (OSError, ValueError) as error:
        raise _ToolBoundaryError("invalid_input") from error
    if (
        resolved_knowledge == selected_root
        or resolved_knowledge.is_relative_to(selected_root)
        or selected_root.is_relative_to(resolved_knowledge)
    ):
        raise _ToolBoundaryError("invalid_input")


def _json_model(model: BaseModel) -> str:
    canonical = type(model).model_validate(model.model_dump(mode="json"))
    return _json_payload(canonical.model_dump(mode="json"))


def _serialize_planning_result(result: object) -> str:
    try:
        payload = result.model_dump(mode="json")  # type: ignore[attr-defined]
        canonical = PlanningResult.model_validate(payload)
    except Exception as error:
        raise _ToolBoundaryError("planning_failed") from error
    safe_payload = canonical.model_dump(mode="json")
    if canonical.status == "gap" and canonical.gap is not None:
        safe_payload["gap"].pop("pending_ranges", None)
    encoded = _json_payload(safe_payload)
    if len(encoded.encode("utf-8")) > MAX_PLANNING_RESULT_BYTES:
        raise _ToolBoundaryError("result_too_large")
    return encoded


def _json_error(code: ToolErrorCode) -> str:
    return _json_model(_ToolErrorResult(error=code))


def _json_payload(payload: object) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _tcp_discovery_handler(args: dict[str, Any], **_: Any) -> str:
    try:
        command = nmap_tcp_discovery(args["target"], top_ports=int(args.get("top_ports", 1000)))
        return _run(command, float(args.get("timeout", 120)))
    except (KeyError, TypeError, ValueError) as error:
        return json.dumps({"ok": False, "error": str(error)})


def _service_scan_handler(args: dict[str, Any], **_: Any) -> str:
    try:
        command = nmap_service_scan(args["target"], args["ports"])
        return _run(command, float(args.get("timeout", 120)))
    except (KeyError, TypeError, ValueError) as error:
        return json.dumps({"ok": False, "error": str(error)})


def _run(arguments: list[str], timeout: float) -> str:
    result = ToolRunner.default().run("nmap", arguments, timeout=timeout)
    return json.dumps(
        {
            "ok": result.returncode == 0 and not result.timed_out,
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
        }
    )
