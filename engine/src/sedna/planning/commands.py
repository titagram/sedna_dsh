"""Structured, scope-bound command suggestion contracts."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.engagement import ScopeReference
from sedna.knowledge.schema.execution import ExecutionExample, PlaceholderKind

if TYPE_CHECKING:
    from sedna.planning.models import SecretReference

_PLACEHOLDER = re.compile(r"\{\{([a-z][a-z0-9_]{0,63})\}\}")
_RUNTIME_NUMERIC_LITERAL = re.compile(r"(?<![\w./:-])\d{1,5}(?![\w./:-])")
_RAW_NETWORK_LITERAL = re.compile(
    r"(?:https?://[^\s{}]+|\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b)",
    re.IGNORECASE,
)


class CommandOrigin(StrEnum):
    SOURCE_EXAMPLE = "source_example"
    MODEL_GENERATED = "model_generated"
    HOST_ADAPTED = "host_adapted"


class CommandBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    placeholder_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    source: Literal[
        "scope_reference", "secret_reference", "host_supplied", "unresolved_source_case"
    ]
    reference_id: str | None = None

    @model_validator(mode="after")
    def _reference_policy(self) -> Self:
        reference_required = self.source in {"scope_reference", "secret_reference"}
        if reference_required != (self.reference_id is not None):
            raise ValueError("command_binding_reference_policy")
        return self


class CommandSuggestionDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    origin: Literal[CommandOrigin.SOURCE_EXAMPLE, CommandOrigin.MODEL_GENERATED]
    command_template: Annotated[str, Field(min_length=1, max_length=8192)]
    placeholder_kinds: tuple[PlaceholderKind, ...]
    bindings: tuple[CommandBinding, ...] = ()
    source_example_id: str | None = None
    capability_hint: Annotated[str, Field(min_length=1, max_length=512)] = "manual-command"
    purpose: Annotated[str, Field(min_length=1, max_length=2048)] = "Validate the proposal."
    knowledge_refs: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    validation_note: Annotated[str, Field(min_length=1, max_length=2048)] = (
        "Review and validate before execution."
    )

    @model_validator(mode="after")
    def _template_binding_policy(self) -> Self:
        literal_segments = _PLACEHOLDER.split(self.command_template)[::2]
        if any(_RAW_NETWORK_LITERAL.search(segment) for segment in literal_segments):
            raise ValueError("command_raw_target_literal")
        if any(_RUNTIME_NUMERIC_LITERAL.search(segment) for segment in literal_segments):
            raise ValueError("command_runtime_value_literal")
        raw_token_count = self.command_template.count("{{") + self.command_template.count("}}")
        names = _PLACEHOLDER.findall(self.command_template)
        if raw_token_count != 2 * len(names):
            raise ValueError("command_placeholder_token_invalid")
        if len(names) != len(set(names)):
            raise ValueError("command_placeholders_not_unique")
        if len(names) != len(self.placeholder_kinds):
            raise ValueError("command_placeholder_kind_count")
        binding_names = tuple(binding.placeholder_name for binding in self.bindings)
        if len(binding_names) != len(set(binding_names)):
            raise ValueError("command_bindings_not_unique")
        if set(binding_names) - set(names):
            raise ValueError("command_binding_unknown_placeholder")
        is_source = self.origin is CommandOrigin.SOURCE_EXAMPLE
        if is_source != (self.source_example_id is not None):
            raise ValueError("command_origin_example_policy")
        return self


class CommandSuggestion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    command_id: UUID
    origin: CommandOrigin
    command_template: str
    placeholder_kinds: tuple[PlaceholderKind, ...]
    bindings: tuple[CommandBinding, ...]
    rendered_preview: str
    requires_validation: Literal[True] = True
    source_example_id: str | None = None
    capability_hint: str
    purpose: str
    knowledge_refs: tuple[str, ...] = ()
    validation_note: str


def validate_command_suggestion(
    draft: CommandSuggestionDraft,
    *,
    scope_references: tuple[ScopeReference, ...],
    secret_references: tuple[SecretReference, ...],
    execution_examples: tuple[ExecutionExample, ...],
) -> CommandSuggestion:
    """Resolve only declared scope/secret bindings into a non-executable preview."""
    scope_by_id = {reference.reference_id: reference for reference in scope_references}
    secret_labels = {reference.label for reference in secret_references}
    if draft.origin is CommandOrigin.SOURCE_EXAMPLE:
        matching_examples = tuple(
            example
            for example in execution_examples
            if example.example_id == draft.source_example_id
        )
        if len(matching_examples) != 1:
            raise ValueError("command_source_example_not_exact")
        example = matching_examples[0]
        example_kinds = tuple(placeholder.kind for placeholder in example.placeholders)
        if (
            example.command_template != draft.command_template
            or example_kinds != draft.placeholder_kinds
        ):
            raise ValueError("command_source_example_not_exact")
    replacements: dict[str, str] = {}
    placeholder_names = _PLACEHOLDER.findall(draft.command_template)
    for ordinal, name in enumerate(placeholder_names):
        kind = draft.placeholder_kinds[ordinal]
        binding = next((item for item in draft.bindings if item.placeholder_name == name), None)
        if kind is PlaceholderKind.TARGET:
            has_invalid_target_binding = (
                binding is None
                or binding.source != "scope_reference"
                or binding.reference_id is None
            )
            if has_invalid_target_binding:
                raise ValueError("command_target_binding_required")
            assert binding is not None and binding.reference_id is not None
            scope = scope_by_id.get(binding.reference_id)
            if scope is None:
                raise ValueError("command_scope_reference_not_authorized")
            replacements[name] = scope.value
        elif kind is PlaceholderKind.SOURCE_CASE_CREDENTIAL:
            if binding is not None and binding.source != "unresolved_source_case":
                raise ValueError("command_source_case_credential_binding")
            replacements[name] = f"{{{{{name}}}}}"
        elif kind is PlaceholderKind.CREDENTIAL_REF:
            has_unknown_secret_reference = (
                binding is None
                or binding.source != "secret_reference"
                or binding.reference_id not in secret_labels
            )
            if has_unknown_secret_reference:
                raise ValueError("command_secret_reference_not_current")
            replacements[name] = f"{{{{{name}}}}}"
        elif binding is not None and binding.source == "unresolved_source_case":
            replacements[name] = f"{{{{{name}}}}}"
        else:
            replacements[name] = f"{{{{{name}}}}}"
    return CommandSuggestion(
        command_id=uuid4(),
        origin=draft.origin,
        command_template=draft.command_template,
        placeholder_kinds=draft.placeholder_kinds,
        bindings=draft.bindings,
        rendered_preview=render_command_preview(draft.command_template, replacements),
        source_example_id=draft.source_example_id,
        capability_hint=draft.capability_hint,
        purpose=draft.purpose,
        knowledge_refs=draft.knowledge_refs,
        validation_note=draft.validation_note,
    )


def render_command_preview(template: str, replacements: dict[str, str]) -> str:
    """Render display-only substitutions; callers retain structured bindings as authority."""
    return _PLACEHOLDER.sub(
        lambda match: replacements.get(match.group(1), match.group(0)),
        template,
    )
