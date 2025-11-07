"""Icinga2 MCP Server - Main server implementation with tool definitions."""

import logging
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field, field_validator

from .client import Icinga2Client, Icinga2APIError
from .tunnel import SSHTunnel

logger = logging.getLogger(__name__)

# Initialize MCP server
app = Server("icinga2-mcp")


class DetailLevel(str, Enum):
    """Detail level for query responses."""
    SUMMARY = "summary"
    NORMAL = "normal"
    DETAILED = "detailed"


class StateFilter(str, Enum):
    """State filter options."""
    ALL = "all"
    UP = "up"
    DOWN = "down"
    PROBLEM = "problem"
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# ============================================================================
# Input Models (Pydantic v2 for validation)
# ============================================================================


class ListHostsInput(BaseModel):
    """Input for listing hosts."""

    filter_text: Optional[str] = Field(
        None,
        description="Optional text to filter hosts by name (case-insensitive partial match)",
        examples=["web", "database", "prod"],
    )
    state: StateFilter = Field(
        StateFilter.ALL,
        description="Filter by host state: all, up, down, or problem (down/unreachable)",
    )
    detail_level: DetailLevel = Field(
        DetailLevel.NORMAL,
        description="Level of detail: summary (minimal), normal (standard), or detailed (comprehensive)",
    )
    limit: int = Field(
        50,
        ge=1,
        le=500,
        description="Maximum number of hosts to return",
    )


class ListServicesInput(BaseModel):
    """Input for listing services."""

    host_filter: Optional[str] = Field(
        None,
        description="Optional text to filter by host name",
        examples=["web01", "database"],
    )
    service_filter: Optional[str] = Field(
        None,
        description="Optional text to filter by service name",
        examples=["http", "mysql", "disk"],
    )
    state: StateFilter = Field(
        StateFilter.ALL,
        description="Filter by service state: all, ok, warning, critical, unknown, or problem (non-OK)",
    )
    detail_level: DetailLevel = Field(
        DetailLevel.NORMAL,
        description="Level of detail: summary (minimal), normal (standard), or detailed (comprehensive)",
    )
    limit: int = Field(
        50,
        ge=1,
        le=500,
        description="Maximum number of services to return",
    )


class GetHostDetailsInput(BaseModel):
    """Input for getting host details."""

    host_name: str = Field(
        ...,
        description="Name of the host to query",
        examples=["web01.example.com", "db-master"],
        min_length=1,
    )


class GetServiceDetailsInput(BaseModel):
    """Input for getting service details."""

    host_name: str = Field(
        ...,
        description="Name of the host",
        examples=["web01.example.com"],
        min_length=1,
    )
    service_name: str = Field(
        ...,
        description="Name of the service",
        examples=["HTTP", "MySQL", "Disk /"],
        min_length=1,
    )


class ScheduleDowntimeInput(BaseModel):
    """Input for scheduling downtime."""

    object_type: Literal["host", "service"] = Field(
        ...,
        description="Type of object: host or service",
    )
    host_name: str = Field(
        ...,
        description="Name of the host",
        examples=["web01.example.com"],
        min_length=1,
    )
    service_name: Optional[str] = Field(
        None,
        description="Name of the service (required if object_type is 'service')",
        examples=["HTTP", "MySQL"],
    )
    author: str = Field(
        ...,
        description="Author of the downtime",
        examples=["admin", "ops-team"],
        min_length=1,
    )
    comment: str = Field(
        ...,
        description="Reason for the downtime",
        examples=["Scheduled maintenance", "Database migration"],
        min_length=1,
    )
    duration_minutes: int = Field(
        60,
        ge=1,
        le=43200,  # Max 30 days
        description="Duration of the downtime in minutes",
    )
    start_in_minutes: int = Field(
        0,
        ge=0,
        le=10080,  # Max 7 days
        description="Start downtime in X minutes from now (0 = now)",
    )
    fixed: bool = Field(
        True,
        description="If true, downtime starts/ends at exact times. If false, it's flexible.",
    )
    all_services: bool = Field(
        False,
        description="For hosts only: also schedule downtime for all services",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: Optional[str], info) -> Optional[str]:
        """Validate that service_name is provided when object_type is 'service'."""
        if info.data.get("object_type") == "service" and not v:
            raise ValueError("service_name is required when object_type is 'service'")
        return v


class AcknowledgeProblemInput(BaseModel):
    """Input for acknowledging a problem."""

    object_type: Literal["host", "service"] = Field(
        ...,
        description="Type of object: host or service",
    )
    host_name: str = Field(
        ...,
        description="Name of the host",
        examples=["web01.example.com"],
        min_length=1,
    )
    service_name: Optional[str] = Field(
        None,
        description="Name of the service (required if object_type is 'service')",
        examples=["HTTP", "MySQL"],
    )
    author: str = Field(
        ...,
        description="Author of the acknowledgment",
        examples=["admin", "ops-team"],
        min_length=1,
    )
    comment: str = Field(
        ...,
        description="Acknowledgment comment explaining the issue and action taken",
        examples=["Working on fix", "Known issue, will resolve by end of day"],
        min_length=1,
    )
    sticky: bool = Field(
        False,
        description="If true, acknowledgment persists through state changes",
    )
    notify: bool = Field(
        True,
        description="Send notifications about this acknowledgment",
    )
    persistent: bool = Field(
        False,
        description="If true, acknowledgment survives Icinga2 restarts",
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: Optional[str], info) -> Optional[str]:
        """Validate that service_name is provided when object_type is 'service'."""
        if info.data.get("object_type") == "service" and not v:
            raise ValueError("service_name is required when object_type is 'service'")
        return v


# ============================================================================
# Helper Functions
# ============================================================================


def get_icinga2_client() -> Icinga2Client:
    """
    Create an Icinga2 client from environment variables.

    Supports both direct API access and SSH tunneling.

    Environment variables:
    - Required:
      - ICINGA2_API_URL: API endpoint URL
      - ICINGA2_API_USER: API username
      - ICINGA2_API_PASSWORD: API password
    - Optional (for SSH tunnel):
      - ICINGA2_SSH_HOST: SSH server hostname/IP
      - ICINGA2_SSH_PORT: SSH server port (default: 22)
      - ICINGA2_SSH_USER: SSH username
      - ICINGA2_SSH_KEY_PATH: Path to SSH private key
      - ICINGA2_SSH_PASSWORD: SSH password (if not using key)
      - ICINGA2_REMOTE_HOST: Icinga2 host as seen from SSH server (default: localhost)
      - ICINGA2_REMOTE_PORT: Icinga2 API port (default: 5665)

    Returns:
        Configured Icinga2Client instance

    Raises:
        ValueError: If required environment variables are missing
    """
    api_url = os.getenv("ICINGA2_API_URL")
    api_user = os.getenv("ICINGA2_API_USER")
    api_password = os.getenv("ICINGA2_API_PASSWORD")

    if not all([api_url, api_user, api_password]):
        raise ValueError(
            "Missing required environment variables: "
            "ICINGA2_API_URL, ICINGA2_API_USER, ICINGA2_API_PASSWORD"
        )

    # Check if SSH tunnel is configured
    ssh_host = os.getenv("ICINGA2_SSH_HOST")
    ssh_tunnel = None

    if ssh_host:
        logger.info("SSH tunnel configuration detected")

        # Get SSH configuration
        ssh_port = int(os.getenv("ICINGA2_SSH_PORT", "22"))
        ssh_user = os.getenv("ICINGA2_SSH_USER")
        ssh_key_path = os.getenv("ICINGA2_SSH_KEY_PATH")
        ssh_password = os.getenv("ICINGA2_SSH_PASSWORD")
        remote_host = os.getenv("ICINGA2_REMOTE_HOST", "localhost")
        remote_port = int(os.getenv("ICINGA2_REMOTE_PORT", "5665"))

        if not ssh_user:
            raise ValueError(
                "ICINGA2_SSH_USER is required when ICINGA2_SSH_HOST is set"
            )

        if not ssh_key_path and not ssh_password:
            raise ValueError(
                "Either ICINGA2_SSH_KEY_PATH or ICINGA2_SSH_PASSWORD is required for SSH authentication"
            )

        # Create SSH tunnel
        ssh_tunnel = SSHTunnel(
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            remote_host=remote_host,
            remote_port=remote_port,
            ssh_key_path=ssh_key_path,
            ssh_password=ssh_password,
            known_hosts=None,  # Accept any host key (for simplicity)
        )

        logger.info(
            f"SSH tunnel configured: {ssh_user}@{ssh_host}:{ssh_port} -> "
            f"{remote_host}:{remote_port}"
        )

    return Icinga2Client(api_url, api_user, api_password, ssh_tunnel=ssh_tunnel)


def build_state_filter(object_type: str, state: StateFilter) -> Optional[str]:
    """
    Build Icinga2 filter expression for state filtering.

    Args:
        object_type: "Host" or "Service"
        state: State filter enum value

    Returns:
        Filter expression or None for "all"
    """
    if state == StateFilter.ALL:
        return None

    if object_type == "Host":
        state_map = {
            StateFilter.UP: "host.state == 0",
            StateFilter.DOWN: "host.state == 1",
            StateFilter.PROBLEM: "host.state != 0",
        }
    else:  # Service
        state_map = {
            StateFilter.OK: "service.state == 0",
            StateFilter.WARNING: "service.state == 1",
            StateFilter.CRITICAL: "service.state == 2",
            StateFilter.UNKNOWN: "service.state == 3",
            StateFilter.PROBLEM: "service.state != 0",
        }

    return state_map.get(state)


def format_host_summary(host: Dict[str, Any]) -> str:
    """Format host information in summary detail level."""
    attrs = host.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    state = attrs.get("state", 0)
    state_str = "UP" if state == 0 else "DOWN"

    return f"• {display_name} ({name}) - {state_str}"


def format_host_normal(host: Dict[str, Any]) -> str:
    """Format host information in normal detail level."""
    attrs = host.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    state = attrs.get("state", 0)
    state_str = "UP" if state == 0 else "DOWN"
    check_output = attrs.get("last_check_result", {}).get("output", "No output")
    address = attrs.get("address", "N/A")

    lines = [
        f"**{display_name}** ({name})",
        f"  State: {state_str}",
        f"  Address: {address}",
        f"  Output: {check_output}",
    ]

    # Add acknowledgment info if present
    if attrs.get("acknowledgement", 0) != 0:
        lines.append("  ⚠️ Acknowledged")

    # Add downtime info if present
    if attrs.get("downtime_depth", 0) > 0:
        lines.append("  🔧 In downtime")

    return "\n".join(lines)


def format_host_detailed(host: Dict[str, Any]) -> str:
    """Format host information in detailed level."""
    attrs = host.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    state = attrs.get("state", 0)
    state_str = "UP" if state == 0 else "DOWN"

    last_check_result = attrs.get("last_check_result", {})
    check_output = last_check_result.get("output", "No output")
    check_time = last_check_result.get("execution_end", 0)
    check_time_str = datetime.fromtimestamp(check_time).isoformat() if check_time else "Never"

    address = attrs.get("address", "N/A")
    address6 = attrs.get("address6", "N/A")

    lines = [
        f"**{display_name}** ({name})",
        f"  State: {state_str}",
        f"  IPv4: {address}",
        f"  IPv6: {address6}",
        f"  Last Check: {check_time_str}",
        f"  Output: {check_output}",
    ]

    # Add acknowledgment details
    if attrs.get("acknowledgement", 0) != 0:
        ack_comment = attrs.get("acknowledgement_last_change", "")
        lines.append(f"  ⚠️ Acknowledged: {ack_comment}")

    # Add downtime details
    if attrs.get("downtime_depth", 0) > 0:
        lines.append(f"  🔧 In downtime (depth: {attrs.get('downtime_depth')})")

    # Add groups
    groups = attrs.get("groups", [])
    if groups:
        lines.append(f"  Groups: {', '.join(groups)}")

    return "\n".join(lines)


def format_service_summary(service: Dict[str, Any]) -> str:
    """Format service information in summary detail level."""
    attrs = service.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    state = attrs.get("state", 0)
    state_map = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
    state_str = state_map.get(state, "UNKNOWN")

    return f"• {display_name} ({name}) - {state_str}"


def format_service_normal(service: Dict[str, Any]) -> str:
    """Format service information in normal detail level."""
    attrs = service.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    host_name = attrs.get("host_name", "Unknown")
    state = attrs.get("state", 0)
    state_map = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
    state_str = state_map.get(state, "UNKNOWN")
    check_output = attrs.get("last_check_result", {}).get("output", "No output")

    lines = [
        f"**{display_name}** on {host_name}",
        f"  Name: {name}",
        f"  State: {state_str}",
        f"  Output: {check_output}",
    ]

    # Add acknowledgment info if present
    if attrs.get("acknowledgement", 0) != 0:
        lines.append("  ⚠️ Acknowledged")

    # Add downtime info if present
    if attrs.get("downtime_depth", 0) > 0:
        lines.append("  🔧 In downtime")

    return "\n".join(lines)


def format_service_detailed(service: Dict[str, Any]) -> str:
    """Format service information in detailed level."""
    attrs = service.get("attrs", {})
    name = attrs.get("name", "Unknown")
    display_name = attrs.get("display_name", name)
    host_name = attrs.get("host_name", "Unknown")
    state = attrs.get("state", 0)
    state_map = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
    state_str = state_map.get(state, "UNKNOWN")

    last_check_result = attrs.get("last_check_result", {})
    check_output = last_check_result.get("output", "No output")
    check_time = last_check_result.get("execution_end", 0)
    check_time_str = datetime.fromtimestamp(check_time).isoformat() if check_time else "Never"
    perf_data = last_check_result.get("performance_data", [])

    lines = [
        f"**{display_name}** on {host_name}",
        f"  Name: {name}",
        f"  State: {state_str}",
        f"  Last Check: {check_time_str}",
        f"  Output: {check_output}",
    ]

    # Add performance data
    if perf_data:
        lines.append("  Performance Data:")
        for metric in perf_data[:5]:  # Limit to 5 metrics
            lines.append(f"    - {metric}")

    # Add acknowledgment details
    if attrs.get("acknowledgement", 0) != 0:
        lines.append("  ⚠️ Acknowledged")

    # Add downtime details
    if attrs.get("downtime_depth", 0) > 0:
        lines.append(f"  🔧 In downtime (depth: {attrs.get('downtime_depth')})")

    # Add groups
    groups = attrs.get("groups", [])
    if groups:
        lines.append(f"  Groups: {', '.join(groups)}")

    return "\n".join(lines)


# ============================================================================
# Tool Implementations
# ============================================================================


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="list_hosts",
            description=(
                "Query and list Icinga2 monitored hosts with flexible filtering options. "
                "Use this to get an overview of host status, find specific hosts, or identify problems. "
                "Supports filtering by name and state, with configurable detail levels."
            ),
            inputSchema=ListHostsInput.model_json_schema(),
        ),
        Tool(
            name="list_services",
            description=(
                "Query and list Icinga2 monitored services with flexible filtering options. "
                "Use this to check service status, find specific services, or identify issues. "
                "Supports filtering by host name, service name, and state with configurable detail levels."
            ),
            inputSchema=ListServicesInput.model_json_schema(),
        ),
        Tool(
            name="get_host_details",
            description=(
                "Get comprehensive information about a specific host including current state, "
                "check results, acknowledgments, downtime status, and metadata. "
                "Use this when you need detailed information about a particular host."
            ),
            inputSchema=GetHostDetailsInput.model_json_schema(),
        ),
        Tool(
            name="get_service_details",
            description=(
                "Get comprehensive information about a specific service including current state, "
                "check results, performance data, acknowledgments, and downtime status. "
                "Use this when you need detailed information about a particular service."
            ),
            inputSchema=GetServiceDetailsInput.model_json_schema(),
        ),
        Tool(
            name="schedule_downtime",
            description=(
                "Schedule maintenance downtime for a host or service to suppress alerts during "
                "planned maintenance windows. Supports both fixed and flexible downtimes. "
                "Can optionally schedule downtime for all services on a host."
            ),
            inputSchema=ScheduleDowntimeInput.model_json_schema(),
        ),
        Tool(
            name="acknowledge_problem",
            description=(
                "Acknowledge a host or service problem to indicate that the issue is known "
                "and being worked on. This suppresses repeated notifications. "
                "Supports sticky, persistent, and notification options."
            ),
            inputSchema=AcknowledgeProblemInput.model_json_schema(),
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "list_hosts":
            return await handle_list_hosts(ListHostsInput(**arguments))
        elif name == "list_services":
            return await handle_list_services(ListServicesInput(**arguments))
        elif name == "get_host_details":
            return await handle_get_host_details(GetHostDetailsInput(**arguments))
        elif name == "get_service_details":
            return await handle_get_service_details(GetServiceDetailsInput(**arguments))
        elif name == "schedule_downtime":
            return await handle_schedule_downtime(ScheduleDowntimeInput(**arguments))
        elif name == "acknowledge_problem":
            return await handle_acknowledge_problem(AcknowledgeProblemInput(**arguments))
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error in tool {name}: {e}", exc_info=True)
        return [
            TextContent(
                type="text",
                text=f"Error executing {name}: {str(e)}\n\n"
                "Please check your configuration and ensure Icinga2 API is accessible.",
            )
        ]


async def handle_list_hosts(params: ListHostsInput) -> list[TextContent]:
    """Handle list_hosts tool call."""
    client = get_icinga2_client()

    async with client:
        # Build filter expression
        filters = []

        # Add text filter
        if params.filter_text:
            filters.append(f'match("*{params.filter_text}*", host.name)')

        # Add state filter
        state_filter = build_state_filter("Host", params.state)
        if state_filter:
            filters.append(state_filter)

        filter_expr = " && ".join(filters) if filters else None

        # Determine attributes to fetch based on detail level
        if params.detail_level == DetailLevel.SUMMARY:
            attrs = ["name", "display_name", "state"]
        elif params.detail_level == DetailLevel.NORMAL:
            attrs = [
                "name", "display_name", "state", "address",
                "last_check_result", "acknowledgement", "downtime_depth"
            ]
        else:  # DETAILED
            attrs = None  # Fetch all attributes

        # Query hosts
        hosts = await client.query_objects("Host", filters=filter_expr, attrs=attrs)

        # Limit results
        hosts = hosts[:params.limit]

        # Format output
        if not hosts:
            return [TextContent(type="text", text="No hosts found matching the criteria.")]

        # Format based on detail level
        format_func = {
            DetailLevel.SUMMARY: format_host_summary,
            DetailLevel.NORMAL: format_host_normal,
            DetailLevel.DETAILED: format_host_detailed,
        }[params.detail_level]

        formatted_hosts = [format_func(host) for host in hosts]

        header = f"# Hosts ({len(hosts)} found)\n\n"
        if params.filter_text:
            header += f"Filter: name contains '{params.filter_text}'\n"
        if params.state != StateFilter.ALL:
            header += f"State: {params.state.value}\n"
        header += "\n"

        output = header + "\n\n".join(formatted_hosts)

        return [TextContent(type="text", text=output)]


async def handle_list_services(params: ListServicesInput) -> list[TextContent]:
    """Handle list_services tool call."""
    client = get_icinga2_client()

    async with client:
        # Build filter expression
        filters = []

        # Add host filter
        if params.host_filter:
            filters.append(f'match("*{params.host_filter}*", host.name)')

        # Add service filter
        if params.service_filter:
            filters.append(f'match("*{params.service_filter}*", service.name)')

        # Add state filter
        state_filter = build_state_filter("Service", params.state)
        if state_filter:
            filters.append(state_filter)

        filter_expr = " && ".join(filters) if filters else None

        # Determine attributes to fetch based on detail level
        if params.detail_level == DetailLevel.SUMMARY:
            attrs = ["name", "display_name", "host_name", "state"]
        elif params.detail_level == DetailLevel.NORMAL:
            attrs = [
                "name", "display_name", "host_name", "state",
                "last_check_result", "acknowledgement", "downtime_depth"
            ]
        else:  # DETAILED
            attrs = None  # Fetch all attributes

        # Query services
        services = await client.query_objects("Service", filters=filter_expr, attrs=attrs)

        # Limit results
        services = services[:params.limit]

        # Format output
        if not services:
            return [TextContent(type="text", text="No services found matching the criteria.")]

        # Format based on detail level
        format_func = {
            DetailLevel.SUMMARY: format_service_summary,
            DetailLevel.NORMAL: format_service_normal,
            DetailLevel.DETAILED: format_service_detailed,
        }[params.detail_level]

        formatted_services = [format_func(service) for service in services]

        header = f"# Services ({len(services)} found)\n\n"
        if params.host_filter:
            header += f"Host filter: '{params.host_filter}'\n"
        if params.service_filter:
            header += f"Service filter: '{params.service_filter}'\n"
        if params.state != StateFilter.ALL:
            header += f"State: {params.state.value}\n"
        header += "\n"

        output = header + "\n\n".join(formatted_services)

        return [TextContent(type="text", text=output)]


async def handle_get_host_details(params: GetHostDetailsInput) -> list[TextContent]:
    """Handle get_host_details tool call."""
    client = get_icinga2_client()

    async with client:
        # Query specific host
        filter_expr = f'host.name == "{params.host_name}"'
        hosts = await client.query_objects("Host", filters=filter_expr)

        if not hosts:
            return [TextContent(type="text", text=f"Host '{params.host_name}' not found.")]

        # Format detailed output
        output = format_host_detailed(hosts[0])

        return [TextContent(type="text", text=output)]


async def handle_get_service_details(params: GetServiceDetailsInput) -> list[TextContent]:
    """Handle get_service_details tool call."""
    client = get_icinga2_client()

    async with client:
        # Build service identifier
        service_id = f"{params.host_name}!{params.service_name}"

        # Query specific service
        filter_expr = f'service.name == "{service_id}"'
        services = await client.query_objects("Service", filters=filter_expr)

        if not services:
            return [
                TextContent(
                    type="text",
                    text=f"Service '{params.service_name}' on host '{params.host_name}' not found.",
                )
            ]

        # Format detailed output
        output = format_service_detailed(services[0])

        return [TextContent(type="text", text=output)]


async def handle_schedule_downtime(params: ScheduleDowntimeInput) -> list[TextContent]:
    """Handle schedule_downtime tool call."""
    client = get_icinga2_client()

    # Calculate start and end times
    start_time = datetime.now() + timedelta(minutes=params.start_in_minutes)
    end_time = start_time + timedelta(minutes=params.duration_minutes)

    # Determine object type and name
    object_type = "Host" if params.object_type == "host" else "Service"
    if params.object_type == "service":
        object_name = f"{params.host_name}!{params.service_name}"
    else:
        object_name = params.host_name

    async with client:
        try:
            result = await client.schedule_downtime(
                object_type=object_type,
                object_name=object_name,
                author=params.author,
                comment=params.comment,
                start_time=start_time,
                end_time=end_time,
                duration=params.duration_minutes * 60 if not params.fixed else None,
                fixed=params.fixed,
                all_services=params.all_services if params.object_type == "host" else False,
            )

            # Format success message
            target = f"{params.object_type} '{params.host_name}"
            if params.object_type == "service":
                target += f"!{params.service_name}"
            target += "'"

            output = [
                f"✅ Downtime scheduled successfully for {target}",
                f"",
                f"**Details:**",
                f"- Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- End: {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- Duration: {params.duration_minutes} minutes",
                f"- Type: {'Fixed' if params.fixed else 'Flexible'}",
                f"- Author: {params.author}",
                f"- Comment: {params.comment}",
            ]

            if params.all_services:
                output.append(f"- All services: Yes")

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to schedule downtime: {str(e)}\n\n"
                    "Please verify the host/service name and try again.",
                )
            ]


async def handle_acknowledge_problem(params: AcknowledgeProblemInput) -> list[TextContent]:
    """Handle acknowledge_problem tool call."""
    client = get_icinga2_client()

    # Determine object type and name
    object_type = "Host" if params.object_type == "host" else "Service"
    if params.object_type == "service":
        object_name = f"{params.host_name}!{params.service_name}"
    else:
        object_name = params.host_name

    async with client:
        try:
            result = await client.acknowledge_problem(
                object_type=object_type,
                object_name=object_name,
                author=params.author,
                comment=params.comment,
                sticky=params.sticky,
                notify=params.notify,
                persistent=params.persistent,
            )

            # Format success message
            target = f"{params.object_type} '{params.host_name}"
            if params.object_type == "service":
                target += f"!{params.service_name}"
            target += "'"

            output = [
                f"✅ Problem acknowledged successfully for {target}",
                f"",
                f"**Details:**",
                f"- Author: {params.author}",
                f"- Comment: {params.comment}",
                f"- Sticky: {params.sticky}",
                f"- Notify: {params.notify}",
                f"- Persistent: {params.persistent}",
            ]

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to acknowledge problem: {str(e)}\n\n"
                    "Please verify the host/service name and that there is an active problem.",
                )
            ]
