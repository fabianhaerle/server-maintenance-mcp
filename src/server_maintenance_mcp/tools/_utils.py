"""Shared utilities for tool modules."""

from __future__ import annotations

import re
import subprocess


_SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.@-]+$")


def validate_service_name(name: str) -> str:
    """Validate a systemd service/unit name to prevent command injection."""
    if not name or not isinstance(name, str):
        raise ValueError("Service name must be a non-empty string")
    if not _SERVICE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid service name: {name!r}. "
            "Only alphanumeric, dot, dash, at-sign, and underscore allowed."
        )
    if len(name) > 256:
        raise ValueError("Service name too long (max 256 characters)")
    return name


def run_command(
    args: list[str],
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str]:
    """Run a command with no shell, return CompletedProcess.

    Args are passed as a list — never shell=True — so command injection
    via service names or patterns is not possible.
    """
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
