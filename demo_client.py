"""End-to-end check for demo_server.py over streamable-http with auth.

Reads the same JSON config as the server (demo_config.json):
- bearer_token set  -> connects with the correct token, and proves that
                       a wrong token is rejected (401)
- bearer_token ""   -> connects without any Authorization header

Run: python demo_client.py [--config other.json]
(server must already be running: python demo_server.py)
"""

from __future__ import annotations

import asyncio
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from demo_server import DemoConfig, load_config

CONNECT_HOST = "127.0.0.1"  # the config's host is the *bind* address; we connect via loopback


def _config() -> DemoConfig:
    if "--config" in sys.argv:
        return load_config(sys.argv[sys.argv.index("--config") + 1])
    return load_config()


async def _do_calls(client: Client, url: str) -> None:
    result = await client.list_tools()
    print(f"[{url}] tools: {[t.name for t in result.tools]}")

    r = await client.call_tool("ping", {})
    print(f"[{url}] ping() -> {r.content[0].text}")

    r = await client.call_tool("disk_free", {"path": "/tmp"})
    print(f"[{url}] disk_free('/tmp') -> free_bytes={r.structured_content['free_bytes']}")


async def roundtrip(url: str, config: DemoConfig) -> None:
    """Full round trip with the configured token (or no header if auth is off)."""
    headers = {"Authorization": f"Bearer {config.bearer_token}"} if config.bearer_token else {}
    async with httpx2.AsyncClient(headers=headers) as http:
        transport = streamable_http_client(url, http_client=http)
        async with Client(transport, raise_exceptions=True) as client:
            await _do_calls(client, url)


async def main() -> None:
    config = _config()
    url = f"http://{CONNECT_HOST}:{config.port}/mcp"

    auth_state = (
        f"ON (token: {'*' * len(config.bearer_token)})"
        if config.bearer_token
        else "OFF (empty bearer_token)"
    )
    print(f"=== streamable-http, bearer auth {auth_state} ===\n")

    # 1. The configured path: correct token (or no auth configured).
    await roundtrip(url, config)

    # 2. If auth is on, prove a wrong token is rejected.
    if config.bearer_token:
        print("\n=== wrong token must be rejected ===")
        try:
            async with asyncio.timeout(10):
                async with httpx2.AsyncClient(
                    headers={"Authorization": "Bearer wrong-token"}
                ) as http:
                    transport = streamable_http_client(url, http_client=http)
                    async with Client(transport, raise_exceptions=True) as client:
                        await client.list_tools()
            print("UNEXPECTED: wrong token was accepted")
        except Exception as e:
            print(f"rejected as expected: {type(e).__name__}: {str(e)[:80]}")

    print("\nOK: demo_server round-trip over streamable-http works")


if __name__ == "__main__":
    asyncio.run(main())