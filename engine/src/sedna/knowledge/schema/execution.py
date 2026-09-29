"""Strict canonical and draft execution-example contracts for M6B planning."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.schema.common import (
    ExtractionMetadata,
    SearchableNonEmptyString,
    SourceRef,
    _reject_final_flag_material,
)
from sedna.knowledge.schema.context import ApplicabilityContext

MAX_EXECUTION_COMMAND_CHARS = 8192
_PLACEHOLDER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TEMPLATE_TOKEN = re.compile(r"\{\{\s*([a-z][a-z0-9_]{0,63})\s*\}\}")
_PLATFORM_MARKERS: dict[str, tuple[str, ...]] = {
    "os_family": ("linux", "windows", "macos", "darwin", "freebsd"),
    "cpu_architecture": ("x86_64", "amd64", "aarch64", "arm64", "i386", "armv7"),
    "execution_environment": ("docker", "container", "wsl", "kubernetes", "k8s"),
}


class PlaceholderKind(StrEnum):
    TARGET = "target"
    PORT = "port"
    USERNAME = "username"
    CREDENTIAL_REF = "credential_ref"
    SOURCE_CASE_CREDENTIAL = "source_case_credential"
    WORDLIST = "wordlist"
    PATH = "path"
    VALUE = "value"


class PlaceholderBindingPolicy(StrEnum):
    AUTHORIZED_SCOPE = "authorized_scope"
    HOST_SUPPLIED = "host_supplied"
    NEVER_AUTO_BIND = "never_auto_bind"


class ExecutionPlaceholder(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    kind: PlaceholderKind
    binding_policy: PlaceholderBindingPolicy
    role: SearchableNonEmptyString

    @model_validator(mode="after")
    def validate_binding_policy(self) -> Self:
        if (
            self.kind is PlaceholderKind.TARGET
            and self.binding_policy is not PlaceholderBindingPolicy.AUTHORIZED_SCOPE
        ):
            raise ValueError("target placeholders require authorized_scope")
        if (
            self.kind is PlaceholderKind.SOURCE_CASE_CREDENTIAL
            and self.binding_policy is not PlaceholderBindingPolicy.NEVER_AUTO_BIND
        ):
            raise ValueError("source-case credentials can never request automatic binding")
        return self


class ExecutionCondition(BaseModel):
    """A source-cited prerequisite assertion for an execution example."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    statement: SearchableNonEmptyString
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)


class ExecutionPlatformConstraint(BaseModel):
    """A closed OS/architecture/environment assertion with source citations."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    dimension: Literal[
        "os_family",
        "os_version",
        "cpu_architecture",
        "execution_environment",
    ]
    relation: Literal["required", "compatible", "incompatible"]
    value: SearchableNonEmptyString
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)


class ExecutionExample(BaseModel):
    """A canonical, bundle-owned, non-searchable executable example."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal["1"] = "1"
    example_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")]
    parent_artifact_id: Annotated[str, Field(min_length=1, max_length=512)]
    command_template: Annotated[str, Field(min_length=1, max_length=8192)]
    placeholders: tuple[ExecutionPlaceholder, ...]
    capability_hint: SearchableNonEmptyString
    purpose: SearchableNonEmptyString
    observed_role: SearchableNonEmptyString
    prerequisites: tuple[ExecutionCondition, ...] = ()
    applicability: ApplicabilityContext = Field(default_factory=ApplicabilityContext)
    platform_constraints: tuple[ExecutionPlatformConstraint, ...] = ()
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)
    extraction: ExtractionMetadata
    requires_validation: Literal[True] = True

    @model_validator(mode="after")
    def validate_example(self) -> Self:
        _validate_command_template(self.command_template)
        ordered = _ordered_placeholders(self.placeholders)
        object.__setattr__(self, "placeholders", ordered)
        declared = {placeholder.name for placeholder in ordered}
        tokens = set(_TEMPLATE_TOKEN.findall(self.command_template))
        if tokens != declared:
            raise ValueError("template placeholders must exactly cover the declared placeholders")
        _validate_platform_prose(
            self.purpose,
            self.capability_hint,
            self.observed_role,
            self.platform_constraints,
        )
        constraint_entries = {
            (constraint.dimension, constraint.relation, constraint.value)
            for constraint in self.platform_constraints
        }
        if len(constraint_entries) != len(self.platform_constraints):
            raise ValueError(
                "platform constraints must be unique by dimension, relation, and value"
            )
        return self


def _validate_command_template(template: str) -> None:
    # Allow whitespace control characters that legitimately appear in multi-line
    # shell command templates (\n newline, \t tab, \r carriage return) but reject
    # all other control characters (NUL, ESC, etc.) which are never valid in a
    # command template.
    for character in template:
        code = ord(character)
        if code < 32 and code not in (9, 10, 13) or code == 127:
            raise ValueError("command template must not contain control characters")
    _reject_final_flag_material(template)


def _ordered_placeholders(
    placeholders: tuple[ExecutionPlaceholder, ...],
) -> tuple[ExecutionPlaceholder, ...]:
    names = [placeholder.name for placeholder in placeholders]
    if len(set(names)) != len(names):
        raise ValueError("placeholder names must be unique")
    return tuple(sorted(placeholders, key=lambda placeholder: placeholder.name))


def _validate_platform_prose(
    purpose: str,
    capability_hint: str,
    observed_role: str,
    constraints: tuple[ExecutionPlatformConstraint, ...],
) -> None:
    """Reject an asserted OS/architecture/environment hidden only in prose."""
    text = f"{purpose} {capability_hint} {observed_role}".casefold()
    constrained = {constraint.dimension for constraint in constraints}
    for dimension, markers in _PLATFORM_MARKERS.items():
        if (
            any(re.search(rf"\b{re.escape(marker)}\b", text) for marker in markers)
            and dimension not in constrained
        ):
            raise ValueError(f"platform constraint {dimension} is asserted only in prose")
