> **This repository is archived and no longer maintained.**
>
> `server-management-lib` now lives in the [`elmuz/server-mcp`](https://github.com/elmuz/server-mcp)
> monorepo together with `remote-server-mcp` and `disk-health-mcp`. That repository is the single
> source of truth for code, releases, issues and pull requests; the full history of this
> repository was imported into it.
>
> New location:
> [packages/server-management-lib](https://github.com/elmuz/server-mcp/tree/main/packages/server-management-lib).
>
> This repository is read-only. Please use the monorepo instead.

# Server Management Library

Shared components for server management MCPs.

## Components

| Module | Purpose |
|--------|---------|
| `config` | YAML configuration loader with defaults |
| `security` | Input validation (commands, queries, paths, device/service names) |
| `ssh_manager` | Secure SSH connection management with whitelisted commands |
| `http_clients` | InfluxDB and Prometheus HTTP API clients |

## Usage

```python
from server_management_lib import (
    SSHManager,
    SecurityValidator,
    InfluxDBClient,
    PrometheusClient,
    load_config,
)

config = load_config(Path("config.yaml"))
security = SecurityValidator(config)
ssh = SSHManager(config, security)
influxdb = InfluxDBClient(
    host=config["influxdb"]["host"],
    token=config["influxdb"]["token"],
)
```

## Security Model

- **No generic command execution** - Commands must pass whitelist or dangerous-pattern blocking
- **Device name validation** - Regex pattern matching for block devices
- **Service name validation** - Alphanumeric with hyphens/underscores only
- **Path traversal prevention** - Including Unicode/URL-encoded bypass detection
- **Query validation** - Read-only enforcement for SQL/PromQL
- **Endpoint whitelisting** - InfluxDB admin/write endpoints blocked at HTTP level
