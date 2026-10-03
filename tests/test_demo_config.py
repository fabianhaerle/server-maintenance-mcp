"""Tests for demo_server config loading and bearer-auth wiring."""

from __future__ import annotations

import json

import pytest

from demo_server import DemoConfig, _StaticTokenVerifier, build_server, load_config, mcp
from mcp import Client
from mcp.server.auth.provider import AccessToken


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


def _write_config(tmp_path, **overrides):
    data = {"host": "127.0.0.1", "port": 9000, "bearer_token": ""}
    data.update(overrides)
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data))
    return str(p)


class TestLoadConfig:
    def test_loads_all_fields(self, tmp_path):
        path = _write_config(tmp_path, host="0.0.0.0", port=9999, bearer_token="s3cret")
        cfg = load_config(path)
        assert cfg == DemoConfig(host="0.0.0.0", port=9999, bearer_token="s3cret")

    def test_partial_file_fills_defaults(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps({"port": 7000}))
        cfg = load_config(str(p))
        assert cfg == DemoConfig(host="0.0.0.0", port=7000, bearer_token="")

    def test_missing_explicit_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nope.json"))

    def test_empty_bearer_token_is_the_auth_off_switch(self, tmp_path):
        path = _write_config(tmp_path, bearer_token="")
        assert load_config(path).bearer_token == ""

    def test_rejects_unknown_keys(self, tmp_path):
        path = _write_config(tmp_path, bearer_tokenX="oops")
        with pytest.raises(ValueError, match="Unknown config keys"):
            load_config(path)

    def test_rejects_wrong_types(self, tmp_path):
        path = _write_config(tmp_path, port="8899")
        with pytest.raises(ValueError, match="must be int"):
            load_config(path)

    def test_rejects_port_out_of_range(self, tmp_path):
        path = _write_config(tmp_path, port=70000)
        with pytest.raises(ValueError, match="port"):
            load_config(path)

    def test_rejects_non_object_file(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps(["not", "an", "object"]))
        with pytest.raises(ValueError, match="JSON object"):
            load_config(str(p))


# ---------------------------------------------------------------------------
# build_server auth wiring
# ---------------------------------------------------------------------------


class TestBuildServerAuth:
    def test_empty_token_builds_server_without_auth(self, tmp_path):
        cfg = DemoConfig(host="0.0.0.0", port=8899, bearer_token="")
        server = build_server(cfg)
        assert server._token_verifier is None
        assert server.settings.auth is None

    def test_non_empty_token_wires_verifier_and_settings(self, tmp_path):
        cfg = DemoConfig(host="0.0.0.0", port=8899, bearer_token="s3cret")
        server = build_server(cfg)
        assert server._token_verifier is not None
        assert server.settings.auth is not None
        assert str(server.settings.auth.resource_server_url) == "http://127.0.0.1:8899/mcp"


class TestStaticTokenVerifier:
    async def test_correct_token_gets_access(self):
        verifier = _StaticTokenVerifier("s3cret")
        result = await verifier.verify_token("s3cret")
        assert isinstance(result, AccessToken)
        assert result.client_id == "demo-client"

    async def test_wrong_token_rejected(self):
        verifier = _StaticTokenVerifier("s3cret")
        assert await verifier.verify_token("wrong") is None
        assert await verifier.verify_token("") is None


# ---------------------------------------------------------------------------
# module-level mcp instance (built from demo_config.json) still serves tools
# in memory — HTTP-layer auth is not applied on in-process connections
# ---------------------------------------------------------------------------


async def test_in_memory_tools_work_regardless_of_auth():
    async with Client(mcp, raise_exceptions=True) as c:
        result = await c.call_tool("ping", {})
    assert result.content[0].text == "pong"