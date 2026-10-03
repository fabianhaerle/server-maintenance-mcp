# server-maintenance-mcp

A read-only MCP (Model Context Protocol) server for server maintenance, built with the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk). Provides tools for inspecting systemd services, reading log files, and monitoring system resources — with **defense-in-depth privacy protection** that prevents LLMs from accessing credentials, keys, and other secrets.

## Features

- **Systemd tools**: list services, check status, read service logs (journalctl)
- **Log tools**: read and search log files within allowed directories
- **System tools**: disk usage, memory, CPU load, system info
- **Privacy-first**: all output is automatically redacted — passwords, API keys, private keys, tokens, and connection strings are replaced with `[REDACTED]`
- **Path protection**: credential files (`.env`, `*.pem`, `id_rsa`, etc.) and sensitive directories (`~/.ssh`, `~/.aws`, etc.) are always blocked
- **Command injection safe**: all subprocesses use argument lists (no `shell=True`), service names are validated
- **Bearer token auth**: static token authentication for HTTP/SSE transport

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml — set auth_token to a random string (openssl rand -hex 32)

# Run
python -m server_maintenance_mcp
```

## Configuration

Settings are loaded from a YAML file (`config.yaml` or `/etc/server-maintenance-mcp/config.yaml`) with environment variable overrides (`MAINT_*`).

| Setting | Env var | Default | Description |
|---|---|---|---|
| `auth_token` | `MAINT_AUTH_TOKEN` | (empty) | Bearer token for client auth |
| `host` | `MAINT_HOST` | `127.0.0.1` | Bind address |
| `port` | `MAINT_PORT` | `8000` | Listen port |
| `allowed_log_dirs` | `MAINT_EXTRA_LOG_DIRS` | `["/var/log"]` | Directories for log reading |
| `max_log_lines` | `MAINT_MAX_LOG_LINES` | `1000` | Max lines per call |
| `default_log_lines` | `MAINT_DEFAULT_LOG_LINES` | `100` | Default lines returned |

## Tools

### Systemd

| Tool | Description |
|---|---|
| `list_services(state)` | List all services, optionally filtered by state (active/inactive/failed) |
| `service_status(service)` | Detailed status: active state, enabled, PID, memory |
| `is_service_enabled(service)` | Check if service starts at boot |
| `service_logs(service, lines, since)` | Read recent journalctl logs for a service |

### Logs

| Tool | Description |
|---|---|
| `read_log(path, lines, level)` | Read the tail of a log file (path must be in allowed dirs) |
| `search_logs(path, pattern, lines)` | Search log file with regex pattern |

### System

| Tool | Description |
|---|---|
| `disk_usage()` | Disk space for all filesystems (`df -h`) |
| `memory_usage()` | RAM and swap usage |
| `cpu_usage()` | Load averages + top processes by CPU |
| `system_info()` | Hostname, kernel, uptime, CPU count |

## Security Model

Four layers of protection ensure the LLM cannot access or exfiltrate secrets:

### Layer 1: Authentication
HTTP/SSE transport requires a valid bearer token. Requests without the correct token receive 401.

### Layer 2: Path Allowlisting
File-reading tools only access directories in `allowed_log_dirs` (default: `/var/log`). These paths are **always blocked**:
- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`
- `/etc/ssh`, `/etc/ssl/private`
- Files matching: `*.env`, `*.pem`, `*.key`, `*.p12`, `*credential*`, `*secret*`, `authorized_keys`, `id_rsa*`, `.netrc`, `.pgpass`, `.my.cnf`, and more

Symlinks are resolved before checking to prevent escape via symlinks.

### Layer 3: Output Redaction
Every tool's output passes through a redaction filter that replaces secrets with `[REDACTED]`:

| Pattern | Example |
|---|---|
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----...` |
| AWS access keys | `AKIA...` |
| GitHub tokens | `ghp_...`, `gho_...` |
| Slack tokens | `xoxb-...` |
| JWTs | `eyJ...eyJ...` |
| Bearer tokens | `Bearer eyJ...` |
| Password assignments | `password=hunter2` → `password=[REDACTED]` |
| Credentialed URLs | `postgres://user:pass@host` |
| Credit card numbers | `4111-1111-1111-1111` |

Usernames in log lines (e.g. `Accepted publickey for admin`) are **not** redacted — only credential values are scrubbed.

### Layer 4: Input Validation
- Service names validated with `^[a-zA-Z0-9_.@-]+$` — no shell metacharacters
- All subprocesses use `subprocess.run(args, shell=False)` — no shell injection possible
- Log line counts capped (default max: 1000)
- Search regex patterns limited to 200 characters

## Running as a systemd service

```ini
# /etc/systemd/system/server-maintenance-mcp.service
[Unit]
Description=Server Maintenance MCP
After=network.target

[Service]
Type=simple
ExecStart=/path/to/venv/bin/python -m server_maintenance_mcp
Environment=MAINT_AUTH_TOKEN=your-secret-token
Environment=MAINT_HOST=127.0.0.1
Environment=MAINT_PORT=8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run without auth (for local testing)
MAINT_AUTH_TOKEN="" python -m server_maintenance_mcp
```

## Project Structure

```
src/server_maintenance_mcp/
├── __init__.py
├── __main__.py          # Entry point
├── server.py            # FastMCP instance + auth + tool registration
├── config.py            # YAML + env config loading
├── security/
│   ├── paths.py         # PathGuard: allow/forbidden rules
│   └── redaction.py     # Redactor + @redact_output decorator
└── tools/
    ├── _utils.py        # Shared: validate_service_name, run_command
    ├── systemd.py       # Service status/logs tools
    ├── logs.py          # Log read/search tools
    └── system.py        # Disk/memory/CPU/info tools
```

## License

Apache-2.0
