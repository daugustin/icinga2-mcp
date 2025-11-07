# Icinga2 MCP Server

A Model Context Protocol (MCP) server for interacting with Icinga2 monitoring systems. This server enables AI assistants to query monitoring status, manage downtimes, and acknowledge problems through a natural language interface.

## Features

- **Query Monitoring Status**: List and search hosts and services with flexible filtering
- **Manage Downtimes**: Schedule maintenance windows for hosts and services
- **Handle Alerts**: Acknowledge problems with customizable comments
- **Flexible Detail Levels**: Control response verbosity to optimize context usage

## Installation

```bash
pip install -e .
```

## Configuration

Configure the server using environment variables:

- `ICINGA2_API_URL`: Icinga2 API endpoint (e.g., `https://icinga.example.com:5665`)
- `ICINGA2_API_USER`: API username
- `ICINGA2_API_PASSWORD`: API password

## Usage

### As MCP Server

Add to your MCP client configuration:

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

### Available Tools

#### Monitoring & Status

- `list_hosts`: Query hosts with filtering and detail levels
- `list_services`: Query services with filtering and detail levels
- `get_host_details`: Get comprehensive information about a specific host
- `get_service_details`: Get comprehensive information about a specific service

#### Operations

- `schedule_downtime`: Schedule maintenance downtime for hosts or services
- `acknowledge_problem`: Acknowledge a host or service problem

## Detail Levels

Most query tools support three detail levels:

- **summary**: Minimal information (name, state, basic status)
- **normal**: Standard information including check output and performance data
- **detailed**: Comprehensive information including all attributes and metadata

## Security

- Uses HTTPS with TLS 1.2+ (enforced by Icinga2)
- HTTP Basic Authentication
- Credentials stored in environment variables
- Certificate verification enabled by default

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

## License

MIT
