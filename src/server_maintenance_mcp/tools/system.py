"""System resource monitoring tools (read-only)."""

from __future__ import annotations

import shutil
from pathlib import Path

from mcp.server import MCPServer

from server_maintenance_mcp.security.redaction import redact_output
from server_maintenance_mcp.tools._utils import run_command


def register(mcp: MCPServer) -> None:
    """Register system monitoring tools on the given MCPServer instance."""

    @mcp.tool()
    @redact_output
    async def disk_usage() -> str:
        """Show disk space usage for all mounted filesystems.

        Returns:
            Filesystem, size, used, available, use%, and mount point for each
            filesystem. Equivalent to 'df -h'.
        """
        result = run_command(["df", "-h"], timeout=10.0)
        if result.returncode != 0:
            return f"Error getting disk usage (rc={result.returncode}): {result.stderr.strip()}"
        return result.stdout.strip()

    @mcp.tool()
    @redact_output
    async def memory_usage() -> str:
        """Show system memory usage (RAM and swap).

        Returns:
            Total, used, and free memory for both RAM and swap. Reads from
            /proc/meminfo on Linux or uses the 'free -h' command.
        """
        result = run_command(["free", "-h"], timeout=10.0)
        if result.returncode == 0:
            return result.stdout.strip()

        meminfo_path = Path("/proc/meminfo")
        if meminfo_path.exists():
            try:
                content = meminfo_path.read_text()
            except OSError as e:
                return f"Error reading /proc/meminfo: {e}"
            lines = []
            for key in ("MemTotal", "MemFree", "MemAvailable", "Cached", "SwapTotal", "SwapFree"):
                for line in content.splitlines():
                    if line.startswith(key + ":"):
                        lines.append(line)
                        break
            if lines:
                return "\n".join(lines)

        return "Error: unable to determine memory usage (neither 'free' nor /proc/meminfo available)"

    @mcp.tool()
    @redact_output
    async def cpu_usage() -> str:
        """Show CPU load averages and top processes by CPU usage.

        Returns:
            Load averages (1/5/15 min) and the top 10 processes by CPU%.
        """
        loadavg = "unknown"
        loadavg_path = Path("/proc/loadavg")
        if loadavg_path.exists():
            try:
                loadavg = loadavg_path.read_text().strip()
            except OSError:
                pass
        else:
            try:
                import os
                loadavg = " ".join(str(x) for x in os.getloadavg())
            except (AttributeError, OSError):
                loadavg = "unavailable on this platform"

        result = run_command(
            ["ps", "-eo", "pid,pcpu,pmem,comm", "--sort=-pcpu", "--no-headers"],
            timeout=10.0,
        )

        if result.returncode != 0:
            return f"Load averages: {loadavg}\n\nError getting process list: {result.stderr.strip()}"

        top_lines = result.stdout.strip().splitlines()[:10]
        header = "  PID  %CPU %MEM  COMMAND\n"
        formatted = header + "\n".join(line.strip() for line in top_lines)

        return f"Load averages (1/5/15 min): {loadavg}\n\nTop processes by CPU:\n{formatted}"

    @mcp.tool()
    @redact_output
    async def system_info() -> str:
        """Show general system information.

        Returns:
            Hostname, kernel version, uptime, OS info, and CPU count.
        """
        lines = []

        import os
        lines.append(f"Hostname: {os.uname().nodename if hasattr(os, 'uname') else 'unknown'}")

        uname_result = run_command(["uname", "-r"], timeout=5.0)
        if uname_result.returncode == 0:
            lines.append(f"Kernel: {uname_result.stdout.strip()}")

        uptime = "unknown"
        uptime_path = Path("/proc/uptime")
        if uptime_path.exists():
            try:
                raw = uptime_path.read_text().split()
                secs = float(raw[0])
                days, rem = divmod(int(secs), 86400)
                hours, rem = divmod(rem, 3600)
                mins, _ = divmod(rem, 60)
                uptime = f"{days}d {hours}h {mins}m"
            except (OSError, ValueError, IndexError):
                pass
        lines.append(f"Uptime: {uptime}")

        if hasattr(os, "uname"):
            u = os.uname()
            lines.append(f"OS: {u.sysname} {u.machine}")

        cpu_count = os.cpu_count()
        lines.append(f"CPU cores: {cpu_count}")

        return "\n".join(lines)
