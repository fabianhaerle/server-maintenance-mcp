"""Output redaction: scrubs credentials, keys, and secrets from tool output."""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec, TypeVar

_P = ParamSpec("_P")
_R = TypeVar("_R")

_REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "aws_secret_key_long",
        re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ),
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    ),
    (
        "slack_token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "gitlab_token",
        re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    ),
    (
        "google_api_key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    ),
    (
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+"),
    ),
    (
        "basic_auth_header",
        re.compile(r"(?i)Basic\s+[A-Za-z0-9+/=]{16,}"),
    ),
    (
        "password_assignment",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
            r"auth[_-]?token|private[_-]?key|client[_-]?secret)"
            r"\s*[:=]\s*"
            r"(?!\$\{|\{\{)"
            r"[^\s;,}'\"<>]+",
        ),
    ),
    (
        "credentialed_connection_string",
        re.compile(
            r"(?:postgresql|postgres|mysql|mongodb|redis|amqp|mqtt|"
            r"ftp|sftp)://"
            r"[^\s:/@]+:[^\s@/]+@"
        ),
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
    (
        "stripe_key",
        re.compile(r"(?:pk|sk)_(?:test_)?live_[A-Za-z0-9]{24,}"),
    ),
    (
        "generic_hex_secret",
        re.compile(
            r"(?i)(?:secret|token|key|password|passwd|pwd)"
            r"[_-]?(?:value|hash|digest)?"
            r"\s*[:=]\s*"
            r"(?:0x)?[0-9a-fA-F]{32,64}\b",
        ),
    ),
]

_COMPILED_PATTERNS = [p for _, p in _PATTERNS]


class Redactor:
    """Applies all redaction patterns to a string, returning the scrubbed result."""

    def __init__(self, patterns: list[tuple[str, re.Pattern[str]]] | None = None):
        self._patterns = patterns if patterns is not None else _PATTERNS

    def redact(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text

        for _, pattern in self._patterns:
            text = pattern.sub(_REDACTED, text)

        return text


_default_redactor = Redactor()


def redact(text: str) -> str:
    """Redact sensitive data from a string using the default Redactor."""
    return _default_redactor.redact(text)


def redact_output(
    func: Callable[_P, Awaitable[_R] | _R],
) -> Callable[_P, Awaitable[_R] | _R]:
    """Decorator that redacts string output from tool functions."""

    @functools.wraps(func)
    def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        result = func(*args, **kwargs)
        return _apply_redaction(result)

    @functools.wraps(func)
    async def async_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        result = await func(*args, **kwargs)
        return _apply_redaction(result)

    if inspect.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper


def _apply_redaction(result: Any) -> Any:
    if isinstance(result, str):
        return _default_redactor.redact(result)
    if isinstance(result, list):
        return [_apply_redaction(item) for item in result]
    if isinstance(result, dict):
        return {k: _apply_redaction(v) for k, v in result.items()}
    return result
