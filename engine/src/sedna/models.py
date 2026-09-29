"""Sedna data models — Pydantic v2."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    PORT = "port"
    SERVICE = "service"
    VULN = "vuln"
    CREDENTIAL = "credential"
    LOOT = "loot"
    TECHNIQUE = "technique"
    NOTE = "note"


class Phase(StrEnum):
    RECON = "recon"
    ENUM = "enum"
    FOOTHOLD = "foothold"
    PRIVESC = "privesc"
    POSTEX = "postex"
    CLEANUP = "cleanup"


class Machine(BaseModel):
    """Target machine (HTB, CTF, lab, etc.)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str
    ip: str
    platform: str = "linux"  # linux, windows, mixed
    os: str | None = None
    difficulty: str | None = None  # easy, medium, hard, insane
    tags: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    """A single finding/evidence item."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    machine_id: UUID
    type: FindingType
    severity: Severity = Severity.INFO
    phase: Phase
    title: str
    description: str
    tool: str
    raw_output: str | None = None
    evidence_refs: tuple[str, ...] = ()  # file paths, screenshot paths, etc.
    tags: tuple[str, ...] = ()
    cve: str | None = None
    cvss: float | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Credential(BaseModel):
    """Discovered credential."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    machine_id: UUID
    username: str
    password: str | None = None
    hash: str | None = None
    hash_type: str | None = None
    source: str  # tool/module that found it
    service: str  # smb, ssh, rdp, web, db, etc.
    privileged: bool = False
    validated: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Loot(BaseModel):
    """Flag, file, or high-value data."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    machine_id: UUID
    kind: str  # user_flag, root_flag, file, screenshot, config, db_dump
    path: str | None = None
    content: str | None = None
    description: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Engagement(BaseModel):
    """Active engagement session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    machine_id: UUID
    phase: Phase = Phase.RECON
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    notes: str = ""
    objectives: tuple[str, ...] = ()
    completed_objectives: tuple[str, ...] = ()


class KnowledgeChunk(BaseModel):
    """Processed knowledge base chunk for retrieval."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    source_path: str
    source_type: str  # markdown, pdf, cheatsheet, technique, tool_ref, checklist
    title: str
    content: str
    summary: str | None = None
    tags: tuple[str, ...] = ()
    tool_refs: tuple[str, ...] = ()  # nmap, gobuster, sqlmap, etc.
    technique_refs: tuple[str, ...] = ()  # MITRE ATT&CK, custom
    phase: Phase | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Technique(BaseModel):
    """Attack technique with MITRE mapping."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    mitre_id: str | None = None  # T1003, T1059, etc.
    tactic: str | None = None  # credential-access, execution, etc.
    platforms: tuple[str, ...] = ()  # linux, windows, macos
    prerequisites: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolRef(BaseModel):
    """Tool reference card."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str
    category: str  # recon, enum, vuln, exploit, privesc, postex
    description: str
    install: str | None = None
    common_flags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SearchHit(BaseModel):
    """Compact result returned by the local full-text index."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    kind: str
    title: str
    snippet: str
    rank: float
