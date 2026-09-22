"""Log file reading tools with path validation and redaction."""

from __future__ import annotations

import re

from fastmcp import FastMCP

from server_maintenance_mcp.config import ServerConfig
from server_maintenance_mcp.security.paths import PathGuard, PathValidationError
from server_maintenance_mcp.security.redaction import redact_output


_VALID_LOG_LEVELS = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}


def register(mcp: FastMCP, config: ServerConfig) -> None:
    """Register log-reading tools on the given FastMCP instance."""

    path_guard = PathGuard(allowed_dirs=config.allowed_log_dirs)
    max_lines = config.max_log_lines
    default_lines = config.default_log_lines

    @mcp.tool
    @redact_output
    async def read_log(
        path: str,
        lines: int | None = None,
        level: str | None = None,
    ) -> str:
        """Read the tail of a log file.

        The path must be within an allowed log directory (default: /var/log).
        Credential and key files are always blocked. Output is redacted to
        remove passwords, tokens, private keys, and other secrets.

        Args:
            path: Absolute path to the log file (e.g. /var/log/nginx/error.log).
            lines: Number of trailing lines to return. Defaults to configured
                   default (100), capped at max (1000).
            level: Optional syslog severity filter. Only lines matching this
                   level or higher severity are returned. One of: emerg, alert,
                   crit, err, warning, notice, info, debug.

        Returns:
            The requested log lines, with secrets redacted. [REDACTED] appears
            in place of any detected credential or key.
        """
        n = lines if lines is not None else default_lines
        n = max(1, min(n, max_lines))

        if level is not None:
            level = level.lower().strip()
            if level not in _VALID_LOG_LEVELS:
                valid = ", ".join(sorted(_VALID_LOG_LEVELS))
                return f"Error: invalid level '{level}'. Valid levels: {valid}"

        try:
            validated_path = path_guard.validate(path)
        except PathValidationError as e:
            return f"Error: {e}"

        try:
            with open(validated_path, "r", errors="replace") as f:
                all_lines = f.readlines()
        except PermissionError:
            return f"Error: permission denied reading {path}"
        except OSError as e:
            return f"Error reading file: {e}"

        if not all_lines:
            return f"File '{path}' is empty."

        tail = all_lines[-n:]

        if level:
            priority_order = list(_VALID_LOG_LEVELS)
            level_idx = priority_order.index(level)
            allowed_levels = set(priority_order[: level_idx + 1])
            tail = [
                line
                for line in tail
                if any(lvl in line.lower() for lvl in allowed_levels)
            ]

        if not tail:
            return f"No lines matching level '{level}' in last {n} lines of {path}."

        return "".join(tail)

    @mcp.tool
    @redact_output
    async def search_logs(
        path: str,
        pattern: str,
        lines: int | None = None,
    ) -> str:
        """Search for a regex pattern in a log file.

        The path must be within an allowed log directory. Output is redacted.

        Args:
            path: Absolute path to the log file.
            pattern: Regular expression pattern to search for (case-insensitive).
                     Keep patterns simple to avoid ReDoS. Max 200 characters.
            lines: Maximum number of matching lines to return. Defaults to
                   configured default (100), capped at max (1000).

        Returns:
            Matching log lines, with secrets redacted.
        """
        if not pattern or not isinstance(pattern, str):
            return "Error: pattern must be a non-empty string"
        if len(pattern) > 200:
            return "Error: pattern too long (max 200 characters)"

        n = lines if lines is not None else default_lines
        n = max(1, min(n, max_lines))

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return f"Error: invalid regex pattern: {e}"

        try:
            validated_path = path_guard.validate(path)
        except PathValidationError as e:
            return f"Error: {e}"

        try:
            with open(validated_path, "r", errors="replace") as f:
                all_lines = f.readlines()
        except PermissionError:
            return f"Error: permission denied reading {path}"
        except OSError as e:
            return f"Error reading file: {e}"

        matches = []
        for line in all_lines:
            if regex.search(line):
                matches.append(line)
                if len(matches) >= n:
                    break

        if not matches:
            return f"No lines matching pattern '{pattern}' in {path}."

        return f"Found {len(matches)} match(es):\n" + "".join(matches)
