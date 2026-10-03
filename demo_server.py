"""Small demo MCP server built on the official MCP Python SDK (v2 API).

Shows all three primitives in one file: tools, a resource, and a prompt.
Name, description, and argument schema are read from the functions
themselves (name, docstring, type hints) — no JSON Schema anywhere.

Configuration comes from a JSON file (demo_config.json):
    {
      "host": "0.0.0.0",          # bind address
      "port": 8899,               # bind port
      "bearer_token": "..."       # non-empty -> bearer auth required;
    }                             # "" -> auth switched off

Run it:
    python demo_server.py                     # streamable-http (default)
    python demo_server.py --config other.json # different config file
    python demo_server.py --stdio             # stdio (for hosts / mcp dev)
"""

from __future__ import annotations

import datetime as dt
import json
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict
from zoneinfo import ZoneInfo

from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError

DEFAULT_CONFIG_FILE = Path(__file__).resolve().parent / "demo_config.json"
_DEFAULTS = {"host": "0.0.0.0", "port": 8899, "bearer_token": ""}


@dataclass
class DemoConfig:
    """Values loaded from the JSON config file."""

    host: str
    port: int
    bearer_token: str  # "" disables bearer auth


def load_config(path: str | None = None) -> DemoConfig:
    """Load host/port/bearer_token from a JSON file.

    An explicit path must exist; the default path falls back to built-in
    defaults (auth off) if the file is missing. Empty `bearer_token`
    switches bearer auth off.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_FILE
    if not config_path.is_file():
        if path:
            raise FileNotFoundError(f"Config file not found: {config_path}")
        print(f"note: {config_path.name} not found, using defaults (bearer auth off)")
        return DemoConfig(**_DEFAULTS)

    data: dict[str, Any] = json.loads(config_path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Config file {config_path} must contain a JSON object")

    unknown = set(data) - set(_DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown config keys: {sorted(unknown)}; expected {sorted(_DEFAULTS)}")
    for key, default in _DEFAULTS.items():
        value = data.get(key, default)
        if type(value) is not type(default):  # bools are ints — exact type check avoids surprises
            raise ValueError(f"Config key {key!r} must be {type(default).__name__}, got {type(value).__name__}")

    if not (0 < data.get("port", _DEFAULTS["port"]) < 65536):
        raise ValueError("Config key 'port' must be between 1 and 65535")

    return DemoConfig(
        host=data.get("host", _DEFAULTS["host"]),
        port=data.get("port", _DEFAULTS["port"]),
        bearer_token=data.get("bearer_token", _DEFAULTS["bearer_token"]),
    )


class _StaticTokenVerifier(TokenVerifier):
    """Accepts exactly one configured token (demo-grade auth)."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if token == self._token:
            return AccessToken(token=token, client_id="demo-client", scopes=[])
        return None


class DiskUsage(TypedDict):
    """Disk usage figures in bytes for one filesystem."""

    path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int


def build_server(config: DemoConfig) -> MCPServer:
    """Create the MCPServer; wires bearer auth when a token is configured."""
    auth_kwargs: dict[str, Any] = {}
    if config.bearer_token:
        auth_kwargs = {
            "token_verifier": _StaticTokenVerifier(config.bearer_token),
            "auth": AuthSettings(
                issuer_url=f"http://127.0.0.1:{config.port}",
                resource_server_url=f"http://127.0.0.1:{config.port}/mcp",
                validate_token_resource=False,  # the static verifier checks the token itself
            ),
        }

    mcp = MCPServer(
        "demo-server",
        instructions="A tiny read-only demo server with a few system tools.",
        **auth_kwargs,
    )

    @mcp.tool()
    def ping() -> str:
        """Return 'pong' to prove the server is alive."""
        return "pong"

    @mcp.tool()
    def disk_free(path: str = "/") -> DiskUsage:
        """Report disk usage for the filesystem containing `path`."""
        usage = shutil.disk_usage(path)
        return {
            "path": path,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
        }

    @mcp.tool()
    def current_time(tz: str = "UTC") -> str:
        """Return the current time in the given IANA time zone (e.g. 'UTC', 'Europe/Berlin')."""
        try:
            zone = ZoneInfo(tz)
        except Exception:
            # ToolError -> an is_error result the model can read.
            raise ToolError(f"Unknown time zone: {tz!r}")
        return dt.datetime.now(zone).isoformat()

    @mcp.resource("system://info")
    def system_info() -> dict:
        """Basic info about the host running this server."""
        return {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        }

    @mcp.prompt()
    def incident_report(hostname: str, symptom: str) -> str:
        """Draft a concise incident report."""
        return (
            f"Write a concise incident report for host {hostname!r} "
            f"with the reported symptom {symptom!r}. "
            "Include impact, likely causes, and next diagnostic steps."
        )

    return mcp


# Module-level instance (importable for in-memory tests; uses demo_config.json).
mcp = build_server(load_config())


def main() -> None:
    config_path = None
    if "--config" in sys.argv:
        config_path = sys.argv[sys.argv.index("--config") + 1]
    config = load_config(config_path)
    server = build_server(config)

    if "--stdio" in sys.argv:
        server.run(transport="stdio")
    else:
        state = "ON" if config.bearer_token else "OFF (empty bearer_token)"
        print(f"Bearer auth: {state}")
        server.run(transport="streamable-http", host=config.host, port=config.port)


if __name__ == "__main__":
    main()