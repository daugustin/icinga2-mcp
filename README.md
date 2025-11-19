# Icinga2 MCP Server

A Model Context Protocol (MCP) server for interacting with Icinga2 monitoring systems. This server enables AI assistants to query monitoring status, manage downtimes, and acknowledge problems through a natural language interface.

## Features

- **Query Monitoring Status**: List and search hosts and services with flexible filtering
- **Manage Downtimes**: Schedule, list, and cancel maintenance windows for single or multiple hosts/services
- **Handle Alerts**: Acknowledge problems with customizable comments
- **Check Management**: Reschedule checks to run immediately, with support for bulk operations by state or pattern
- **Event Monitoring**: Query recent state changes and problem events with configurable time ranges
- **Passive Checks**: Submit external check results for hosts and services with performance data
- **Flexible Detail Levels**: Control response verbosity to optimize context usage
- **SSH Tunnel Support**: Access non-public Icinga2 APIs through SSH tunneling

## Installation

```bash
pip install -e .
```

## Configuration

Configure the server using environment variables:

**Required:**
- `ICINGA2_API_URL`: Icinga2 API endpoint (e.g., `https://icinga.example.com:5665`)
- `ICINGA2_API_USER`: API username
- `ICINGA2_API_PASSWORD`: API password

**Optional:**
- `ICINGA2_VERIFY_SSL`: Verify SSL certificates (default: `true`, set to `false` for self-signed certs)

**Optional (for SSH tunnel):**
- `ICINGA2_SSH_HOST`: SSH server hostname/IP
- `ICINGA2_SSH_PORT`: SSH server port (default: 22)
- `ICINGA2_SSH_USER`: SSH username
- `ICINGA2_SSH_KEY_PATH`: Path to SSH private key
- `ICINGA2_SSH_PASSWORD`: SSH password (if not using key)

Note: When using SSH tunnel, the remote Icinga2 host and port are automatically extracted from `ICINGA2_API_URL`.

See `.env.example` for a complete configuration template.

## Usage

### As MCP Server

**Direct API Access:**

```json
{
  "mcpServers": {
    "icinga2": {
      "command": "python",
      "args": ["-m", "icinga2_mcp"],
      "env": {
        "ICINGA2_API_URL": "https://icinga.example.com:5665",
        "ICINGA2_API_USER": "mcp-user",
        "ICINGA2_API_PASSWORD": "your-password"
      }
    }
  }
}
```

**With SSH Tunnel (for non-public APIs):**

```json
{
  "mcpServers": {
    "icinga2": {
      "command": "python",
      "args": ["-m", "icinga2_mcp"],
      "env": {
        "ICINGA2_API_URL": "https://icinga.internal:5665",
        "ICINGA2_API_USER": "mcp-user",
        "ICINGA2_API_PASSWORD": "your-password",
        "ICINGA2_SSH_HOST": "bastion.example.com",
        "ICINGA2_SSH_USER": "ssh-user",
        "ICINGA2_SSH_KEY_PATH": "/home/user/.ssh/id_rsa"
      }
    }
  }
}
```

The tunnel will automatically forward to `icinga.internal:5665` as specified in the `ICINGA2_API_URL`.

### Available Tools

#### Monitoring & Status

- `list_hosts`: Query hosts with filtering and detail levels
- `list_services`: Query services with filtering and detail levels
- `get_host_details`: Get comprehensive information about a specific host
- `get_service_details`: Get comprehensive information about a specific service
- `query_events`: Query recent events (state changes, problems) with configurable time ranges

#### Downtime Management

- `schedule_downtime`: Schedule maintenance downtime for single or multiple hosts/services
- `list_downtimes`: List all scheduled and active downtimes with filtering options
- `remove_downtime`: Cancel/remove downtimes by name, host, service, or bulk operations

#### Problem Management

- `acknowledge_problem`: Acknowledge a host or service problem with custom comments

#### Check Operations

- `reschedule_check`: Force immediate check execution for hosts/services
  - Supports filtering by name, state (critical, warning, etc.), or pattern matching
  - Useful for bulk check scheduling (e.g., all critical services)
- `submit_passive_check`: Submit external check results for passive checks
  - Supports both host checks (up/down) and service checks (ok/warning/critical/unknown)
  - Includes optional performance data and check source tracking

## Detail Levels

Most query tools support three detail levels:

- **summary**: Minimal information (name, state, basic status)
- **normal**: Standard information including check output and performance data
- **detailed**: Comprehensive information including all attributes and metadata

## Security

- Uses HTTPS with TLS 1.2+ (enforced by Icinga2)
- HTTP Basic Authentication
- Credentials stored in environment variables
- Certificate verification enabled by default (can be disabled for self-signed certificates via `ICINGA2_VERIFY_SSL=false`)
- SSH tunnel support for secure access to private networks

**⚠️ Security Warning**: Disabling SSL verification (`ICINGA2_VERIFY_SSL=false`) should only be used in development/testing environments with self-signed certificates. Never disable SSL verification in production.

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Format code:

```bash
black src/
ruff check src/
```
