"""FastMCP server instance with auth and tool registration."""

from __future__ import annotations

from fastmcp import FastMCP

from server_maintenance_mcp import __version__
from server_maintenance_mcp.config import ServerConfig, load_config
from server_maintenance_mcp.tools import logs as logs_tools
from server_maintenance_mcp.tools import system as system_tools
from server_maintenance_mcp.tools import systemd as systemd_tools


def create_server(config: ServerConfig | None = None) -> FastMCP:
    """Create and configure the FastMCP server instance.

    Args:
        config: Optional ServerConfig. If None, loads from file/env.

    Returns:
        A configured FastMCP instance with all tools registered.
    """
    if config is None:
        config = load_config()

    auth = None
    if config.auth_token:
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        auth = StaticTokenVerifier(
            tokens={
                config.auth_token: {
                    "client_id": "maintenance-client",
                    "scopes": ["maintenance"],
                }
            },
            required_scopes=["maintenance"],
        )

    mcp = FastMCP(
        name="server-maintenance-mcp",
        instructions=(
            "Read-only server maintenance tools. "
            "Provides systemd service status, log file reading, and system "
            "resource monitoring. All output is automatically redacted to "
            "remove passwords, API keys, private keys, and other secrets."
        ),
        version=__version__,
        auth=auth,
    )

    systemd_tools.register(mcp)
    system_tools.register(mcp)
    logs_tools.register(mcp, config)

    return mcp


def run() -> None:
    """Load config and start the server with HTTP transport."""
    config = load_config()
    mcp = create_server(config)
    mcp.run(
        transport="http",
        host=config.host,
        port=config.port,
    )
