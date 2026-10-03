"""MCP server instance with auth and tool registration (official SDK, v2 API).

Same startup pattern as demo_server.py: load config -> build_server() ->
run streamable-http. Bearer auth is wired when the configured token is
non-empty; an empty token switches auth off entirely.
"""

from __future__ import annotations

import sys
from typing import Any

from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

from server_maintenance_mcp import __version__
from server_maintenance_mcp.config import ServerConfig, load_config
from server_maintenance_mcp.tools import logs as logs_tools
from server_maintenance_mcp.tools import system as system_tools
from server_maintenance_mcp.tools import systemd as systemd_tools


class StaticTokenVerifier(TokenVerifier):
    """Accepts exactly the one token configured for the server."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        if token == self._token:
            return AccessToken(
                token=token,
                client_id="maintenance-client",
                scopes=["maintenance"],
            )
        return None


def _base_url(config: ServerConfig) -> str:
    """A usable base URL for auth metadata (0.0.0.0 is not addressable)."""
    host = config.host if config.host not in ("", "0.0.0.0", "::") else "127.0.0.1"
    return f"http://{host}:{config.port}"


def build_server(config: ServerConfig | None = None) -> MCPServer:
    """Create and configure the MCPServer instance with all tools registered.

    Args:
        config: Optional ServerConfig. If None, loads from file/env.

    Returns:
        A configured MCPServer with all tools registered.
    """
    if config is None:
        config = load_config()

    auth_kwargs: dict[str, Any] = {}
    if config.auth_token:
        auth_kwargs = {
            "token_verifier": StaticTokenVerifier(config.auth_token),
            "auth": AuthSettings(
                issuer_url=_base_url(config),
                resource_server_url=f"{_base_url(config)}/mcp",
                required_scopes=["maintenance"],
                validate_token_resource=False,  # the static verifier checks the token itself
            ),
        }

    mcp = MCPServer(
        "server-maintenance-mcp",
        instructions=(
            "Read-only server maintenance tools. "
            "Provides systemd service status, log file reading, and system "
            "resource monitoring. All output is automatically redacted to "
            "remove passwords, API keys, private keys, and other secrets."
        ),
        version=__version__,
        **auth_kwargs,
    )

    systemd_tools.register(mcp)
    system_tools.register(mcp)
    logs_tools.register(mcp, config)

    @mcp.tool()
    def echo_test(message: str = "hello") -> str:
        """Connectivity test tool: echoes the message back with the server version.

        Touches no system state and runs no commands, so it is safe to call
        on any machine. Use it to verify reachability, authentication, and
        the tool plumbing without invoking the real maintenance tools.
        """
        return f"echo: {message} (server-maintenance-mcp v{__version__})"

    return mcp


if __name__ == "__main__":
    # This module only builds the server; it has no startup code.
    # Start the real server with:
    #   python -m server_maintenance_mcp   (add --config <file> / --stdio as needed)
    # or run the demo server with:  python demo_server.py
    sys.exit(
        "server.py is a library module and does nothing on its own.\n"
        "Start the server with:  python -m server_maintenance_mcp\n"
        "(run it with the project's venv python: .venv/bin/python)"
    )