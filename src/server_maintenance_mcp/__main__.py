"""Entry point: python -m server_maintenance_mcp (or the console script)."""

from __future__ import annotations

import sys

from server_maintenance_mcp.config import load_config
from server_maintenance_mcp.server import build_server


def main() -> None:
    """Parse args, load config, start the server (same startup as demo_server.py)."""
    config_path = None
    if "--config" in sys.argv:
        try:
            config_path = sys.argv[sys.argv.index("--config") + 1]
        except IndexError:
            sys.exit("--config requires a file path argument")
    config = load_config(config_path)
    server = build_server(config)

    if "--stdio" in sys.argv:
        server.run(transport="stdio")
    else:
        state = "ON" if config.auth_token else "OFF (empty auth_token)"
        print(f"Bearer auth: {state}")
        server.run(transport="streamable-http", host=config.host, port=config.port)


if __name__ == "__main__":
    main()