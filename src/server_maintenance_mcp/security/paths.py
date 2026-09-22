"""Path validation: ensures file-reading tools can only access allowed log
directories and never touch credential/key files."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path


_FORBIDDEN_DIRS = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.gnupg"),
    os.path.expanduser("~/.kube"),
    os.path.expanduser("~/.docker"),
    os.path.expanduser("~/.config/gcloud"),
    "/etc/ssh",
    "/etc/ssl/private",
    "/root/.ssh",
]

_FORBIDDEN_FILES = [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
]

_FORBIDDEN_GLOBS = [
    "*.env",
    ".*env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "*credential*",
    "*secret*",
    "*password*",
    "authorized_keys",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    "docker-compose*.yml",
    "docker-compose*.yaml",
]


class PathValidationError(Exception):
    """Raised when a path is rejected by PathGuard."""


class PathGuard:
    """Validates file paths against allow/forbidden rules.

    - Path must resolve to a real file inside one of the allowed directories.
    - Symlinks are resolved before checking (prevents symlink escapes).
    - Hard-coded forbidden dirs/files/globs always take precedence.
    """

    def __init__(self, allowed_dirs: list[str]):
        self._allowed_dirs = [str(Path(d).resolve()) for d in allowed_dirs]
        self._forbidden_dirs = [str(Path(d)) for d in _FORBIDDEN_DIRS]
        self._forbidden_files = [str(Path(f)) for f in _FORBIDDEN_FILES]
        self._forbidden_globs = list(_FORBIDDEN_GLOBS)

    def validate(self, path_str: str) -> Path:
        """Validate and return the resolved path, or raise PathValidationError."""
        if not path_str or not isinstance(path_str, str):
            raise PathValidationError("Path must be a non-empty string")

        try:
            candidate = Path(path_str).expanduser()
        except (RuntimeError, OSError) as e:
            raise PathValidationError(f"Cannot parse path: {path_str}") from e

        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate

        resolved = candidate.resolve(strict=False)

        if candidate.is_symlink():
            resolved = candidate.resolve(strict=True)

        resolved_str = str(resolved)
        basename = resolved.name.lower()

        if any(resolved_str == f or resolved_str.startswith(f + os.sep) for f in self._forbidden_files):
            raise PathValidationError(f"Access forbidden: {path_str}")

        if any(resolved_str == d or resolved_str.startswith(d + os.sep) for d in self._forbidden_dirs):
            raise PathValidationError(f"Access forbidden (protected directory): {path_str}")

        for pattern in self._forbidden_globs:
            if fnmatch.fnmatch(basename, pattern.lower()):
                raise PathValidationError(f"Access forbidden (matched '{pattern}'): {path_str}")

        if not any(
            resolved_str == d or resolved_str.startswith(d + os.sep)
            for d in self._allowed_dirs
        ):
            raise PathValidationError(
                f"Path not in allowed directories: {path_str}. "
                f"Allowed: {', '.join(self._allowed_dirs)}"
            )

        if not resolved.exists():
            raise PathValidationError(f"File not found: {path_str}")

        if not resolved.is_file():
            raise PathValidationError(f"Not a regular file: {path_str}")

        return resolved
