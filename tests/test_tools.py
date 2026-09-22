"""Tests for tool modules — mocked subprocess, no real system calls."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from server_maintenance_mcp.config import ServerConfig
from server_maintenance_mcp.tools._utils import validate_service_name


def _mock_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


async def _call_tool(mcp, name: str, **kwargs) -> str:
    """Helper: call a registered tool by name and return its text output."""
    tool = await mcp.get_tool(name)
    assert tool is not None, f"Tool '{name}' not found"
    result = await tool.run(kwargs)
    texts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            texts.append(text)
    return "\n".join(texts)


# ---------------------------------------------------------------------------
# _utils.validate_service_name
# ---------------------------------------------------------------------------


class TestValidateServiceName:
    def test_valid_names(self):
        assert validate_service_name("nginx.service") == "nginx.service"
        assert validate_service_name("sshd") == "sshd"
        assert validate_service_name("user@1000.service") == "user@1000.service"
        assert validate_service_name("my-app_v2.service") == "my-app_v2.service"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_service_name("")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            validate_service_name("nginx; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError):
            validate_service_name("nginx | cat")

    def test_rejects_shell_metacharacters(self):
        with pytest.raises(ValueError):
            validate_service_name("nginx && reboot")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError):
            validate_service_name("../etc/passwd")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            validate_service_name(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# systemd tools
# ---------------------------------------------------------------------------


class TestSystemdTools:
    @pytest.fixture
    def mcp(self):
        from fastmcp import FastMCP
        mcp = FastMCP("test-systemd")
        from server_maintenance_mcp.tools import systemd as systemd_mod
        systemd_mod.register(mcp)
        return mcp

    async def test_list_services(self, mcp):
        mock_output = (
            "nginx.service    loaded active running The nginx HTTP server\n"
            "ssh.service      loaded active running OpenSSH server\n"
            "docker.service   loaded inactive dead  Docker daemon\n"
        )
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout=mock_output),
        ):
            result = await _call_tool(mcp, "list_services", state=None)
            assert "nginx.service" in result
            assert "ssh.service" in result
            assert "docker.service" in result

    async def test_list_services_invalid_state(self, mcp):
        result = await _call_tool(mcp, "list_services", state="hacked")
        assert "invalid state filter" in result

    async def test_service_status_active(self, mcp):
        mock_output = (
            "\u25cf nginx.service - The nginx HTTP and reverse proxy server\n"
            "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
            "     Active: active (running) since Mon 2024-01-01 00:00:00 UTC\n"
            "   Main PID: 1234 (nginx)\n"
            "      Tasks: 5 (limit: 4915)\n"
            "     Memory: 5.2M\n"
        )
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout=mock_output),
        ):
            result = await _call_tool(mcp, "service_status", service="nginx.service")
            assert "nginx.service" in result
            assert "active" in result
            assert "enabled" in result
            assert "1234" in result

    async def test_service_status_invalid_name(self, mcp):
        result = await _call_tool(mcp, "service_status", service="nginx; rm -rf /")
        assert "Error" in result

    async def test_is_service_enabled(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout="enabled"),
        ):
            result = await _call_tool(mcp, "is_service_enabled", service="nginx.service")
            assert "enabled" in result

    async def test_is_service_disabled(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout="disabled", returncode=1),
        ):
            result = await _call_tool(mcp, "is_service_enabled", service="nginx.service")
            assert "disabled" in result

    async def test_service_logs(self, mcp):
        mock_output = (
            "Jan 01 00:00:01 host nginx[1234]: request handled\n"
            "Jan 01 00:00:02 host nginx[1234]: request handled\n"
        )
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout=mock_output),
        ):
            result = await _call_tool(mcp, "service_logs", service="nginx.service", lines=10)
            assert "request handled" in result

    async def test_service_logs_redacts_secrets(self, mcp):
        mock_output = (
            "Jan 01 00:00:01 host app[1234]: password=mysecret123\n"
            "Jan 01 00:00:02 host app[1234]: token=ghp_1234567890abcdef1234567890abcdef1234\n"
        )
        with patch(
            "server_maintenance_mcp.tools.systemd.run_command",
            return_value=_mock_completed(stdout=mock_output),
        ):
            result = await _call_tool(mcp, "service_logs", service="app.service", lines=10)
            assert "mysecret123" not in result
            assert "ghp_1234567890abcdef1234567890abcdef1234" not in result
            assert "[REDACTED]" in result

    async def test_service_logs_rejects_invalid_since(self, mcp):
        result = await _call_tool(
            mcp, "service_logs", service="nginx.service", lines=10, since="foo; rm -rf /"
        )
        assert "invalid" in result.lower()


# ---------------------------------------------------------------------------
# log tools
# ---------------------------------------------------------------------------


class TestLogTools:
    @pytest.fixture
    def mcp_with_config(self, tmp_path):
        from fastmcp import FastMCP
        config = ServerConfig(
            allowed_log_dirs=[str(tmp_path)],
            max_log_lines=1000,
            default_log_lines=100,
        )
        mcp = FastMCP("test-logs")
        from server_maintenance_mcp.tools import logs as logs_mod
        logs_mod.register(mcp, config)
        return mcp, tmp_path

    async def test_read_log(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("line1\nline2\nline3\n")
        result = await _call_tool(mcp, "read_log", path=str(log_file), lines=10)
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result

    async def test_read_log_path_blocked(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        env_file = tmp_path / "config.env"
        env_file.write_text("SECRET=xxx")
        result = await _call_tool(mcp, "read_log", path=str(env_file), lines=10)
        assert "Error" in result
        assert "forbidden" in result.lower()

    async def test_read_log_redacts_secrets(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text(
            "password=hunter2 status=ok\n"
            "token=ghp_1234567890abcdef1234567890abcdef1234\n"
        )
        result = await _call_tool(mcp, "read_log", path=str(log_file), lines=10)
        assert "hunter2" not in result
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in result
        assert "[REDACTED]" in result
        assert "status=ok" in result

    async def test_read_log_lines_cap(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("\n".join(f"line{i}" for i in range(2000)) + "\n")
        result = await _call_tool(mcp, "read_log", path=str(log_file), lines=10000)
        result_lines = [l for l in result.strip().splitlines() if l]
        assert len(result_lines) <= 1000

    async def test_search_logs(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("error: connection failed\ninfo: started ok\nerror: timeout\n")
        result = await _call_tool(mcp, "search_logs", path=str(log_file), pattern="error", lines=10)
        assert "connection failed" in result
        assert "timeout" in result
        assert "started ok" not in result

    async def test_search_logs_invalid_regex(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("line1\n")
        result = await _call_tool(mcp, "search_logs", path=str(log_file), pattern="[invalid(", lines=10)
        assert "invalid regex" in result.lower()

    async def test_search_logs_redacts(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("auth password=s3cr3t here\n")
        result = await _call_tool(mcp, "search_logs", path=str(log_file), pattern="auth", lines=10)
        assert "s3cr3t" not in result
        assert "[REDACTED]" in result

    async def test_read_log_level_filter(self, mcp_with_config):
        mcp, tmp_path = mcp_with_config
        log_file = tmp_path / "app.log"
        log_file.write_text("info: starting\nerr: failed\ndebug: x=1\nwarning: low mem\n")
        result = await _call_tool(mcp, "read_log", path=str(log_file), lines=10, level="err")
        assert "failed" in result
        assert "starting" not in result


# ---------------------------------------------------------------------------
# system tools
# ---------------------------------------------------------------------------


class TestSystemTools:
    @pytest.fixture
    def mcp(self):
        from fastmcp import FastMCP
        mcp = FastMCP("test-system")
        from server_maintenance_mcp.tools import system as system_mod
        system_mod.register(mcp)
        return mcp

    async def test_disk_usage(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.system.run_command",
            return_value=_mock_completed(
                stdout="Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   20G   30G  40% /\n"
            ),
        ):
            result = await _call_tool(mcp, "disk_usage")
            assert "/dev/sda1" in result
            assert "50G" in result

    async def test_memory_usage_free(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.system.run_command",
            return_value=_mock_completed(
                stdout="              total        used        free      shared  buff/cache   available\n"
                "Mem:           16Gi       8Gi       4Gi       1Gi       4Gi       7Gi\n"
            ),
        ):
            result = await _call_tool(mcp, "memory_usage")
            assert "Mem:" in result

    async def test_cpu_usage(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.system.run_command",
            return_value=_mock_completed(
                stdout=" 1234  5.2  1.0  nginx\n 5678  3.1  0.5  postgres\n"
            ),
        ):
            result = await _call_tool(mcp, "cpu_usage")
            assert "Load averages" in result
            assert "nginx" in result

    async def test_system_info(self, mcp):
        with patch(
            "server_maintenance_mcp.tools.system.run_command",
            return_value=_mock_completed(stdout="6.8.0"),
        ):
            result = await _call_tool(mcp, "system_info")
            assert "Hostname:" in result
            assert "Kernel:" in result
            assert "CPU cores:" in result


# ---------------------------------------------------------------------------
# server creation
# ---------------------------------------------------------------------------


class TestServerCreation:
    def test_create_server_no_auth(self):
        from server_maintenance_mcp.server import create_server

        config = ServerConfig(auth_token="")
        mcp = create_server(config)
        assert mcp is not None

    def test_create_server_with_auth(self):
        from server_maintenance_mcp.server import create_server

        config = ServerConfig(auth_token="test-token-12345")
        mcp = create_server(config)
        assert mcp is not None

    async def test_server_has_all_tools(self):
        import tempfile
        from server_maintenance_mcp.server import create_server

        with tempfile.TemporaryDirectory() as td:
            config = ServerConfig(
                auth_token="test-token",
                allowed_log_dirs=[td],
            )
            mcp = create_server(config)
            tools = await mcp.list_tools()
            tool_names = {t.name for t in tools}
            assert "list_services" in tool_names
            assert "service_status" in tool_names
            assert "is_service_enabled" in tool_names
            assert "service_logs" in tool_names
            assert "read_log" in tool_names
            assert "search_logs" in tool_names
            assert "disk_usage" in tool_names
            assert "memory_usage" in tool_names
            assert "cpu_usage" in tool_names
            assert "system_info" in tool_names
