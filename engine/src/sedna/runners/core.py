"""Subprocess runner that never invokes a shell."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolResult:
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


class ToolRunner:
    """Execute only explicit, absolute-path allowlisted programs."""

    def __init__(self, allowed_tools: Mapping[str, str | Path]) -> None:
        self._allowed_tools = {
            name: str(Path(executable).resolve()) for name, executable in allowed_tools.items()
        }
        if any(not Path(executable).is_file() for executable in self._allowed_tools.values()):
            raise ValueError("allowed tool paths must exist and be regular files")

    @classmethod
    def default(cls) -> ToolRunner:
        executable = shutil.which("nmap")
        return cls({"nmap": executable} if executable else {})

    @property
    def available_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._allowed_tools))

    def run(self, tool: str, arguments: Sequence[str], *, timeout: float = 120) -> ToolResult:
        if tool not in self._allowed_tools:
            raise ValueError(f"tool is not allowed: {tool}")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if any(not isinstance(argument, str) for argument in arguments):
            raise TypeError("tool arguments must be strings")

        command = (self._allowed_tools[tool], *arguments)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            return ToolResult(
                command=command,
                returncode=None,
                stdout=_as_text(error.stdout),
                stderr=_as_text(error.stderr),
                timed_out=True,
            )

        return ToolResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _as_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""
