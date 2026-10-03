"""Systemd service inspection tools (read-only)."""

from __future__ import annotations

from mcp.server import MCPServer

from server_maintenance_mcp.security.redaction import redact_output
from server_maintenance_mcp.tools._utils import run_command, validate_service_name


def register(mcp: MCPServer) -> None:
    """Register all systemd tools on the given MCPServer instance."""

    @mcp.tool()
    @redact_output
    async def list_services(state: str | None = None) -> str:
        """List systemd service units and their active/sub states.

        Args:
            state: Optional filter by active state: 'active', 'inactive',
                   'failed', 'running', 'dead'. None lists all.

        Returns:
            Tab-separated lines of: unit, load, active, sub, description.
        """
        valid_states = {None, "active", "inactive", "failed", "running", "dead"}
        if state not in valid_states:
            return f"Error: invalid state filter '{state}'. Use one of: {', '.join(sorted(s for s in valid_states if s))}"

        args = [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
        ]
        if state:
            if state in ("running", "dead"):
                args.append(f"--state={state}")
            else:
                args.append(f"--state={state}")

        result = run_command(args, timeout=15.0)

        if result.returncode != 0:
            return f"Error listing services (rc={result.returncode}): {result.stderr.strip()}"

        lines = result.stdout.strip().splitlines()
        if not lines:
            return "No services found."

        formatted = []
        for line in lines:
            parts = line.split(None, 4)
            if len(parts) >= 4:
                unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
                desc = parts[4] if len(parts) > 4 else ""
                formatted.append(f"{unit}\t{load}\t{active}\t{sub}\t{desc}")

        return f"{'Unit':<40} {'Load':<8} {'Active':<10} {'Sub':<10} Description\n" + "\n".join(formatted)

    @mcp.tool()
    @redact_output
    async def service_status(service: str) -> str:
        """Get the status of a systemd service.

        Args:
            service: The service unit name (e.g. 'nginx.service').

        Returns:
            Formatted status: active state, enabled/disabled, PID, memory, uptime.
        """
        try:
            service = validate_service_name(service)
        except ValueError as e:
            return f"Error: {e}"

        args = ["systemctl", "status", service, "--no-pager", "--plain"]
        result = run_command(args, timeout=10.0)

        if result.returncode != 0:
            return (
                f"Service '{service}' status (rc={result.returncode}):\n"
                f"{result.stdout.strip()}\n{result.stderr.strip()}".strip()
            )

        lines = result.stdout.strip().splitlines()

        active_state = "unknown"
        enabled = "unknown"
        pid = "unknown"
        memory = "unknown"
        description = ""

        for line in lines:
            ll = line.lower().strip()
            if ll.startswith("●"):
                description = line.strip("● ").strip()
            elif ll.startswith("active:"):
                active_state = line.split(":", 1)[1].strip()
            elif "loaded" in ll and ("enabled" in ll or "disabled" in ll or "masked" in ll):
                if "enabled" in ll:
                    enabled = "enabled"
                elif "disabled" in ll:
                    enabled = "disabled"
                elif "masked" in ll:
                    enabled = "masked"
            elif "main pid:" in ll:
                pid = ll.split("main pid:")[1].strip().split()[0] if "main pid:" in ll else "unknown"
            elif "memory:" in ll:
                memory = ll.split("memory:", 1)[1].strip() if "memory:" in ll else "unknown"

        summary = (
            f"Service: {service}\n"
            f"Description: {description}\n"
            f"Active: {active_state}\n"
            f"Enabled: {enabled}\n"
            f"Main PID: {pid}\n"
            f"Memory: {memory}\n"
        )
        return summary

    @mcp.tool()
    @redact_output
    async def is_service_enabled(service: str) -> str:
        """Check whether a systemd service is enabled at boot.

        Args:
            service: The service unit name.

        Returns:
            'enabled', 'disabled', 'masked', 'static', 'indirect', or error message.
        """
        try:
            service = validate_service_name(service)
        except ValueError as e:
            return f"Error: {e}"

        result = run_command(
            ["systemctl", "is-enabled", service],
            timeout=5.0,
        )

        state = result.stdout.strip()
        stderr = result.stderr.strip()
        rc = result.returncode

        if rc == 0:
            return f"{service}: enabled ({state})"
        if "disabled" in state:
            return f"{service}: disabled"
        if "masked" in state:
            return f"{service}: masked"
        if state:
            return f"{service}: {state}"
        if stderr:
            return f"{service}: error - {stderr}"
        return f"{service}: unknown (rc={rc})"

    @mcp.tool()
    @redact_output
    async def service_logs(
        service: str,
        lines: int = 50,
        since: str | None = None,
    ) -> str:
        """Read recent journalctl logs for a systemd service.

        Args:
            service: The service unit name.
            lines: Number of recent log lines to return (max 1000).
            since: Optional time filter passed to journalctl (e.g. '1 hour ago',
                   '2024-01-01', 'today'). Only simple time strings are allowed.

        Returns:
            Journal log lines, with secrets redacted.
        """
        try:
            service = validate_service_name(service)
        except ValueError as e:
            return f"Error: {e}"

        lines = max(1, min(lines, 1000))

        args = [
            "journalctl",
            "-u", service,
            "-n", str(lines),
            "--no-pager",
            "--plain",
        ]

        if since:
            if isinstance(since, str) and len(since) <= 100 and ";" not in since and "|" not in since:
                args.extend(["--since", since])
            else:
                return "Error: invalid 'since' value (max 100 chars, no special characters)"

        result = run_command(args, timeout=15.0)

        if result.returncode != 0:
            return f"Error reading logs for '{service}' (rc={result.returncode}): {result.stderr.strip()}"

        output = result.stdout.strip()
        if not output:
            return f"No log entries found for service '{service}'."

        return output
