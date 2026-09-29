"""Deterministic inert Markdown rendering for private reports."""

from __future__ import annotations

import html
import re

from sedna.engagement.reporting.models import (
    MAX_REPORT_MARKDOWN_BYTES,
    OperationalReport,
    ReportCapturedOutput,
    ReportToolExecution,
)

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+.!|>-])")


def _escaped(value: str) -> str:
    return _MARKDOWN_SPECIAL.sub(r"\\\1", html.escape(value, quote=False))


def _code_block(value: str, language: str = "text") -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{value}\n{fence}"


def _inline_code(value: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {value} {fence}"


def _items(values: tuple[str, ...], *, empty: str = "None recorded.") -> str:
    if not values:
        return empty
    return "\n".join(f"- {_escaped(value)}" for value in values)


def _output(value: ReportCapturedOutput) -> str:
    if value.disposition == "inline":
        assert value.inline_text is not None
        return _code_block(value.inline_text)
    if value.disposition == "absent":
        assert value.absence_reason is not None
        return f"Output absent: {_escaped(value.absence_reason)}."
    assert value.evidence is not None
    evidence = value.evidence
    return "\n".join(
        (
            f"Evidence: {_inline_code(evidence.relative_path)}",
            f"SHA-256: {_inline_code(evidence.sha256)}",
            f"Media type: {_escaped(evidence.media_type)}",
            f"Representation: {_escaped(evidence.representation)}",
        )
    )


def _execution(value: ReportToolExecution) -> str:
    pieces = [
        f"**Tool:** {_escaped(value.tool_name)} ({_escaped(value.call_id)})",
        f"Outcome: {_escaped(value.outcome)}",
    ]
    if value.suggested_commands:
        pieces.extend(
            (
                "Suggested commands:",
                *(_code_block(item, "shell") for item in value.suggested_commands),
            )
        )
    if value.executed_command is not None:
        pieces.extend(("Executed command:", _code_block(value.executed_command, "shell")))
    pieces.extend(("Captured output:", _output(value.output)))
    return "\n\n".join(pieces)


def _render_sessions(report: OperationalReport) -> str:
    sessions = "\n".join(
        f"- {_escaped(item.session_id)}: {_escaped(item.started_at.isoformat())}"
        + (f" to {_escaped(item.ended_at.isoformat())}" if item.ended_at else "")
        for item in report.sessions
    )
    timeline = "\n".join(
        f"- Event ({item.confidence:.2f}): {_escaped(item.summary)}" for item in report.timeline
    )
    return "\n".join(value for value in (sessions, timeline) if value) or "None recorded."


def _render_observations(report: OperationalReport) -> str:
    lines = [
        *(
            f"- Observation ({item.confidence:.2f}): {_escaped(item.summary)}"
            for item in report.observations
        ),
        *(
            f"- Hypothesis [{_escaped(item.status)}]: {_escaped(item.statement)}"
            for item in report.hypotheses
        ),
    ]
    return "\n".join(lines) if lines else "None recorded."


def _render_decisions(report: OperationalReport) -> str:
    lines = [
        *(
            f"- Strategy: {_escaped(item.strategy)} — {_escaped(item.rationale)}"
            for item in report.decisions
        ),
        *(
            f"- Frontier {_escaped(item.strategy_key)}: {item.score} — {_escaped(item.reason)}"
            for item in report.frontier_changes
        ),
    ]
    return "\n".join(lines) if lines else "None recorded."


def _render_executions(report: OperationalReport) -> str:
    values = (*report.tool_executions, *report.failed_attempts)
    return "\n\n".join(_execution(item) for item in values) if values else "None recorded."


def _render_secrets(report: OperationalReport) -> str:
    if not report.secrets:
        return "None recorded."
    return "\n\n".join(
        f"- {_escaped(item.kind)} / {_escaped(item.label)}:\n{_code_block(item.value)}"
        for item in report.secrets
    )


def _render_sources(report: OperationalReport) -> str:
    lines = [
        f"- {_escaped(item.locator)}"
        + (f"; query: {_escaped(item.query)}" if item.query is not None else "")
        + f" — {_escaped(item.assessment)}"
        for item in report.sources
    ]
    for execution in (*report.tool_executions, *report.failed_attempts):
        if execution.output.evidence is not None:
            evidence = execution.output.evidence
            lines.append(
                f"- {_inline_code(evidence.relative_path)} ({_inline_code(evidence.sha256)})"
            )
    return "\n".join(lines) if lines else "None recorded."


def _render_overflow(report: OperationalReport) -> str:
    if not report.overflow:
        return ""
    return "\n".join(
        f"- {_escaped(item.section)}: {item.omitted_count} events omitted "
        f"(sequences {item.first_omitted_sequence}–{item.last_omitted_sequence}); "
        f"event digest {_inline_code(item.omitted_event_digest)}"
        for item in report.overflow
    )


def _render_completion(report: OperationalReport) -> str:
    return "\n".join(
        (
            f"Objective satisfied: {'yes' if report.completion.objective_satisfied else 'no'}",
            "Final access:",
            _items(report.completion.final_access),
            "Unresolved issues:",
            _items(report.completion.unresolved_issues),
        )
    )


def render_operational_report(report: OperationalReport) -> str:
    """Render validated report data without activating any dynamic Markdown."""

    report = OperationalReport.model_validate(report.model_dump(mode="json", warnings="error"))
    sections = [
        "# Sedna operational report",
        "\n".join(
            (
                f"- Engagement: {_escaped(report.display_name)}",
                f"- Report revision: {report.report_revision}",
                f"- Journal revision: {report.journal_revision.sequence}",
            )
        ),
        "## Scope and objective",
        _code_block(report.objective),
        _items(report.scope),
        "## Session timeline",
        _render_sessions(report),
        "## Observations and hypotheses",
        _render_observations(report),
        "## Decisions and frontier changes",
        _render_decisions(report),
        "## Commands, outputs, and failed attempts",
        _render_executions(report),
        "## Credentials and flags",
        _render_secrets(report),
        "## Evidence and sources",
        _render_sources(report),
        "## Completion and unresolved issues",
        _render_completion(report),
        _render_overflow(report),
    ]
    rendered = "\n\n".join(sections).rstrip() + "\n"
    if len(rendered.encode("utf-8")) > MAX_REPORT_MARKDOWN_BYTES:
        raise ValueError("report Markdown exceeds immutable report budget")
    return rendered


__all__ = ["render_operational_report"]
