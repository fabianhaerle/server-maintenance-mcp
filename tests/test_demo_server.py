"""Tests for demo_server.py — in-memory client, no subprocess, no port.

Uses the official SDK's `Client(mcp)` in-memory connection, the same way
the SDK tests its own docs examples. The client is created inside each
test (not a yield fixture) because anyio cancel scopes must be exited in
the task that entered them.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

from mcp import Client

from demo_server import mcp


@asynccontextmanager
async def client():
    async with Client(mcp, raise_exceptions=True) as c:
        yield c


async def test_ping():
    async with client() as c:
        result = await c.call_tool("ping", {})
    assert result.content[0].text == "pong"


async def test_disk_free_structured_output():
    async with client() as c:
        result = await c.call_tool("disk_free", {"path": "/tmp"})
    structured = result.structured_content
    assert structured["path"] == "/tmp"
    assert structured["free_bytes"] > 0
    assert structured["total_bytes"] >= structured["used_bytes"]


async def test_current_time_utc():
    async with client() as c:
        result = await c.call_tool("current_time", {"tz": "UTC"})
    assert "T" in result.content[0].text  # ISO timestamp


async def test_current_time_bad_zone_is_tool_error():
    async with client() as c:
        result = await c.call_tool("current_time", {"tz": "Not/AZone"})
    assert result.is_error
    assert "Unknown time zone" in result.content[0].text


async def test_list_tools():
    async with client() as c:
        result = await c.list_tools()
    assert {t.name for t in result.tools} == {"ping", "disk_free", "current_time"}


async def test_read_resource():
    async with client() as c:
        result = await c.read_resource("system://info")
    data = json.loads(result.contents[0].text)
    assert "python" in data
    assert "platform" in data


async def test_get_prompt():
    async with client() as c:
        result = await c.get_prompt(
            "incident_report", {"hostname": "web-01", "symptom": "high load"}
        )
    text = result.messages[0].content.text
    assert "web-01" in text
    assert "high load" in text