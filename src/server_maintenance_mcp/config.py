"""Configuration loading from YAML file with environment variable overrides."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


_DEFAULT_CONFIG_PATHS = [
    "config.yaml",
    "/etc/server-maintenance-mcp/config.yaml",
]


class ServerConfig(BaseModel):
    """Runtime configuration for the MCP server."""

    auth_token: str = Field(
        default="",
        description="Static bearer token for authenticating MCP clients. "
        "Must be set via config file or MAINT_AUTH_TOKEN env var.",
    )
    host: str = Field(
        default="127.0.0.1",
        description="Bind address for the HTTP/SSE transport.",
    )
    port: int = Field(
        default=8000,
        description="Port for the HTTP/SSE transport.",
    )
    allowed_log_dirs: list[str] = Field(
        default_factory=lambda: ["/var/log"],
        description="Directories from which log files may be read. "
        "Additional dirs can be added via config or MAINT_EXTRA_LOG_DIRS.",
    )
    max_log_lines: int = Field(
        default=1000,
        description="Maximum number of log lines returned by a single tool call.",
    )
    default_log_lines: int = Field(
        default=100,
        description="Default number of log lines returned when not specified.",
    )

    @field_validator("allowed_log_dirs")
    @classmethod
    def _normalize_dirs(cls, v: list[str]) -> list[str]:
        return [str(Path(d).resolve()) for d in v]

    @field_validator("max_log_lines", "default_log_lines")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("must be positive")
        return v


def load_config(config_path: str | None = None) -> ServerConfig:
    """Load configuration from a YAML file, then apply env var overrides.

    Resolution order (later wins):
      1. Defaults defined in ServerConfig
      2. YAML file (auto-discovered or explicit path)
      3. Environment variables (MAINT_*)
    """
    data: dict = {}

    path = _find_config_file(config_path)
    if path is not None:
        with open(path) as f:
            data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Config file {path} must contain a YAML mapping")

    env_overrides = _collect_env_overrides()
    data = {**data, **env_overrides}

    return ServerConfig(**data)


def _find_config_file(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {explicit}")
        return p

    env_path = os.environ.get("MAINT_CONFIG_FILE")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    for candidate in _DEFAULT_CONFIG_PATHS:
        p = Path(candidate)
        if p.is_file():
            return p

    return None


def _collect_env_overrides() -> dict:
    overrides: dict = {}

    if v := os.environ.get("MAINT_AUTH_TOKEN"):
        overrides["auth_token"] = v
    if v := os.environ.get("MAINT_HOST"):
        overrides["host"] = v
    if v := os.environ.get("MAINT_PORT"):
        overrides["port"] = int(v)
    if v := os.environ.get("MAINT_MAX_LOG_LINES"):
        overrides["max_log_lines"] = int(v)
    if v := os.environ.get("MAINT_DEFAULT_LOG_LINES"):
        overrides["default_log_lines"] = int(v)
    if v := os.environ.get("MAINT_EXTRA_LOG_DIRS"):
        extras = [d.strip() for d in v.split(",") if d.strip()]
        if extras:
            existing = os.environ.get("MAINT_REPLACE_LOG_DIRS")
            if existing:
                overrides["allowed_log_dirs"] = extras
            else:
                base = _DEFAULT_CONFIG_PATHS
                merged = set(["/var/log"])
                for d in extras:
                    merged.add(d)
                overrides["allowed_log_dirs"] = list(merged)

    return overrides
