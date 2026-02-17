"""Common error types for azs."""

from __future__ import annotations


class CliError(Exception):
    """User-facing command error."""


class CommandError(Exception):
    """Subprocess command error."""

    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = stderr.strip() or stdout.strip() or f"Command failed with exit code {returncode}"
        super().__init__(message)
