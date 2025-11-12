"""Icinga2 MCP Server - Main server implementation with tool definitions."""

import logging
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from urllib.parse import urlparse

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
    host_name: Union[str, List[str]] = Field(
        ...,
        description="Name of the host(s). Can be a single host name or a list of host names for bulk operations.",
        examples=["web01.example.com", ["web01.example.com", "web02.example.com", "web03.example.com"]],
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

    @field_validator("host_name")
    @classmethod
    def validate_host_name(cls, v: Union[str, List[str]]) -> Union[str, List[str]]:
        """Validate host_name and ensure list is not empty."""
        if isinstance(v, list):
            if len(v) == 0:
                raise ValueError("host_name list cannot be empty")
            if len(v) > 100:
                raise ValueError("Cannot schedule downtime for more than 100 hosts at once")
            for host in v:
                if not host or not host.strip():
                    raise ValueError("host_name list contains empty host name")
        elif isinstance(v, str):
            if not v or not v.strip():
                raise ValueError("host_name cannot be empty")
        return v

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: Optional[str], info) -> Optional[str]:
        """Validate that service_name is provided when object_type is 'service'."""
        if info.data.get("object_type") == "service" and not v:
            raise ValueError("service_name is required when object_type is 'service'")
        # For service type, only single host is supported
        if info.data.get("object_type") == "service":
            host_name = info.data.get("host_name")
            if isinstance(host_name, list):
                raise ValueError("Multiple hosts are not supported for service downtime. Use object_type='host' for bulk operations.")
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


class RescheduleCheckInput(BaseModel):
    """Input for rescheduling checks."""

    object_type: Literal["host", "service"] = Field(
        ...,
        description="Type of object: host or service",
    )
    filter_type: Literal["name", "state", "pattern"] = Field(
        ...,
        description="Type of filter to apply: name (specific host/service), state (by check state), or pattern (wildcard match)",
    )
    filter_value: str = Field(
        ...,
        description=(
            "Filter value based on filter_type:\n"
            "- For 'name': exact host name (e.g., 'web01.example.com') or service name (e.g., 'web01.example.com!HTTP')\n"
            "- For 'state': state name (up/down for hosts, ok/warning/critical/unknown for services, or 'problem' for any non-OK state)\n"
            "- For 'pattern': wildcard pattern (e.g., 'web*' for hosts starting with 'web', '*disk*' for services containing 'disk')"
        ),
        examples=["web01.example.com", "critical", "web*", "*disk*"],
        min_length=1,
    )
    force: bool = Field(
        True,
        description="Force check execution regardless of time period restrictions",
    )

    @field_validator("filter_value")
    @classmethod
    def validate_filter_value(cls, v: str, info) -> str:
        """Validate filter_value based on filter_type."""
        filter_type = info.data.get("filter_type")
        object_type = info.data.get("object_type")

        if filter_type == "state":
            if object_type == "host":
                valid_states = ["up", "down", "problem"]
                if v.lower() not in valid_states:
                    raise ValueError(f"For host state filter, value must be one of: {', '.join(valid_states)}")
            else:  # service
                valid_states = ["ok", "warning", "critical", "unknown", "problem"]
                if v.lower() not in valid_states:
                    raise ValueError(f"For service state filter, value must be one of: {', '.join(valid_states)}")

        return v


class QueryEventsInput(BaseModel):
    """Input for querying recent events."""

    object_type: Literal["host", "service", "both"] = Field(
        "both",
        description="Type of objects to query: host, service, or both",
    )
    event_type: Literal["state_change", "problem", "all"] = Field(
        "all",
        description=(
            "Type of events to query:\n"
            "- state_change: Objects that changed state recently\n"
            "- problem: Objects currently in problem state\n"
            "- all: All recent activity (state changes and problems)"
        ),
    )
    time_range_minutes: int = Field(
        60,
        ge=1,
        le=1440,  # Max 24 hours
        description="How many minutes back to look for events",
    )
    limit: int = Field(
        50,
        ge=1,
        le=500,
        description="Maximum number of events to return",
    )


class ListDowntimesInput(BaseModel):
    """Input for listing downtimes."""

    filter_type: Literal["all", "active", "host", "service"] = Field(
        "all",
        description=(
            "Type of downtimes to list:\n"
            "- all: All scheduled downtimes\n"
            "- active: Only currently active downtimes\n"
            "- host: Only host downtimes\n"
            "- service: Only service downtimes"
        ),
    )
    host_filter: Optional[str] = Field(
        None,
        description="Optional filter to match host names (e.g., 'web01' or 'web*')",
        examples=["web01", "web*"],
    )


class RemoveDowntimeInput(BaseModel):
    """Input for removing downtimes."""

    filter_type: Literal["name", "host", "service", "all_host", "all_service"] = Field(
        ...,
        description=(
            "How to select downtimes to remove:\n"
            "- name: Remove specific downtime by name\n"
            "- host: Remove all downtimes for a specific host\n"
            "- service: Remove all downtimes for a specific service\n"
            "- all_host: Remove all host downtimes\n"
            "- all_service: Remove all service downtimes"
        ),
    )
    filter_value: Optional[str] = Field(
        None,
        description=(
            "Value for the filter (required for 'name', 'host', 'service'):\n"
            "- For 'name': exact downtime name\n"
            "- For 'host': host name\n"
            "- For 'service': service name (format: hostname!servicename)"
        ),
        examples=["web01.example.com", "web01.example.com!HTTP"],
    )

    @field_validator("filter_value")
    @classmethod
    def validate_filter_value(cls, v: Optional[str], info) -> Optional[str]:
        """Validate that filter_value is provided when required."""
        filter_type = info.data.get("filter_type")
        if filter_type in ["name", "host", "service"] and not v:
            raise ValueError(f"filter_value is required when filter_type is '{filter_type}'")
        return v


class SubmitPassiveCheckInput(BaseModel):
    """Input for submitting passive check results."""

    check_type: Literal["host", "service"] = Field(
        ...,
        description="Type of check to submit: 'host' for host checks, 'service' for service checks",
    )
    target: str = Field(
        ...,
        description=(
            "Target object to submit check for:\n"
            "- For host checks: host name (e.g., 'web01.example.com')\n"
            "- For service checks: service name in format 'hostname!servicename' "
            "(e.g., 'web01.example.com!HTTP')"
        ),
        examples=["web01.example.com", "web01.example.com!HTTP"],
    )
    status: Literal["ok", "warning", "critical", "unknown", "up", "down"] = Field(
        ...,
        description=(
            "Check result status:\n"
            "- For service checks: ok, warning, critical, unknown\n"
            "- For host checks: up, down"
        ),
    )
    output: str = Field(
        ...,
        description="Check output message describing the status",
        min_length=1,
        examples=[
            "HTTP OK - Response time: 0.123s",
            "CRITICAL - Disk usage at 95%",
            "Host is responding to ICMP pings",
        ],
    )
    performance_data: Optional[List[str]] = Field(
        None,
        description=(
            "Optional performance metrics in Nagios plugin format.\n"
            "Format: 'label=value[UOM];[warn];[crit];[min];[max]'\n"
            "Examples: ['time=0.123s', 'size=1024KB;800;900;0;1000']"
        ),
        examples=[["time=0.123s", "size=1024KB;800;900"]],
    )
    check_source: Optional[str] = Field(
        None,
        description="Optional identifier for the source submitting the check (e.g., 'monitoring-script')",
        examples=["external-monitor", "backup-script"],
    )

    @field_validator("status")
    @classmethod
    def validate_status_for_type(cls, v: str, info) -> str:
        """Validate that status is appropriate for check type."""
        check_type = info.data.get("check_type")
        service_statuses = ["ok", "warning", "critical", "unknown"]
        host_statuses = ["up", "down"]

        if check_type == "service" and v not in service_statuses:
            raise ValueError(
                f"For service checks, status must be one of: {', '.join(service_statuses)}"
            )
        elif check_type == "host" and v not in host_statuses:
            raise ValueError(f"For host checks, status must be one of: {', '.join(host_statuses)}")

        return v

    @field_validator("target")
    @classmethod
    def validate_target_format(cls, v: str, info) -> str:
        """Validate target format matches check type."""
        check_type = info.data.get("check_type")

        if check_type == "service" and "!" not in v:
            raise ValueError(
                "For service checks, target must be in format 'hostname!servicename'"
            )
        elif check_type == "host" and "!" in v:
            raise ValueError("For host checks, target must be just the hostname (no '!' separator)")

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
    - Optional:
      - ICINGA2_VERIFY_SSL: Verify SSL certificates (default: true, set to "false" to disable)
    - Optional (for SSH tunnel):
      - ICINGA2_SSH_HOST: SSH server hostname/IP
      - ICINGA2_SSH_PORT: SSH server port (default: 22)
      - ICINGA2_SSH_USER: SSH username
      - ICINGA2_SSH_KEY_PATH: Path to SSH private key
      - ICINGA2_SSH_PASSWORD: SSH password (if not using key)

    Returns:
        Configured Icinga2Client instance

    Raises:
        ValueError: If required environment variables are missing

    Note:
        When using SSH tunnel, the remote host and port are extracted from ICINGA2_API_URL.
        For example, if ICINGA2_API_URL is "https://icinga.example.com:5665", the tunnel
        will forward to icinga.example.com:5665 as seen from the SSH server.
    """
    api_url = os.getenv("ICINGA2_API_URL")
    api_user = os.getenv("ICINGA2_API_USER")
    api_password = os.getenv("ICINGA2_API_PASSWORD")

    if not all([api_url, api_user, api_password]):
        raise ValueError(
            "Missing required environment variables: "
            "ICINGA2_API_URL, ICINGA2_API_USER, ICINGA2_API_PASSWORD"
        )

    # SSL verification (default: True for security)
    verify_ssl_str = os.getenv("ICINGA2_VERIFY_SSL", "true").lower()
    verify_ssl = verify_ssl_str not in ("false", "0", "no", "off")

    if not verify_ssl:
        logger.warning(
            "⚠️  SSL certificate verification is DISABLED. "
            "This is insecure and should only be used in development/testing environments."
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

        if not ssh_user:
            raise ValueError(
                "ICINGA2_SSH_USER is required when ICINGA2_SSH_HOST is set"
            )

        if not ssh_key_path and not ssh_password:
            raise ValueError(
                "Either ICINGA2_SSH_KEY_PATH or ICINGA2_SSH_PASSWORD is required for SSH authentication"
            )

        # Parse the API URL to extract the remote host and port
        parsed_url = urlparse(api_url)
        remote_host = parsed_url.hostname
        remote_port = parsed_url.port

        if not remote_host:
            raise ValueError(
                f"Could not parse hostname from ICINGA2_API_URL: {api_url}"
            )

        # Default to 5665 if no port specified (standard Icinga2 API port)
        if not remote_port:
            remote_port = 5665
            logger.info(f"No port specified in API URL, using default Icinga2 port: {remote_port}")

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

    return Icinga2Client(
        api_url, api_user, api_password, verify_ssl=verify_ssl, ssh_tunnel=ssh_tunnel
    )


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
                "Schedule maintenance downtime for one or multiple hosts/services to suppress alerts during "
                "planned maintenance windows. Supports both fixed and flexible downtimes. "
                "Can optionally schedule downtime for all services on a host. "
                "For bulk operations, provide a list of host names to schedule downtime for multiple hosts at once."
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
        Tool(
            name="reschedule_check",
            description=(
                "Reschedule check execution for hosts or services to run immediately (ASAP). "
                "Supports flexible filtering: by exact name, by state (e.g., all critical services), "
                "or by wildcard pattern (e.g., all hosts matching 'web*'). "
                "Useful for forcing immediate checks after fixing issues or for bulk check rescheduling."
            ),
            inputSchema=RescheduleCheckInput.model_json_schema(),
        ),
        Tool(
            name="query_events",
            description=(
                "Query recent monitoring events to see what has been happening in your infrastructure. "
                "Shows recent state changes, current problems, and other monitoring activity. "
                "Supports filtering by time range (up to 24 hours), object type (hosts, services, or both), "
                "and event type (state changes, problems, or all activity). "
                "Useful for getting an overview of recent issues and system activity."
            ),
            inputSchema=QueryEventsInput.model_json_schema(),
        ),
        Tool(
            name="list_downtimes",
            description=(
                "List all scheduled and active maintenance downtimes. "
                "Filter by type (all, active, host, service) and optionally by host name. "
                "Shows downtime details including start/end times, author, and comments. "
                "Useful for reviewing scheduled maintenance windows and checking what's currently in downtime."
            ),
            inputSchema=ListDowntimesInput.model_json_schema(),
        ),
        Tool(
            name="remove_downtime",
            description=(
                "Cancel/remove scheduled maintenance downtimes. "
                "Supports removing by downtime name, by host/service, or bulk removal. "
                "Use this to cancel maintenance windows that are no longer needed. "
                "Can remove specific downtimes or all downtimes for a host/service."
            ),
            inputSchema=RemoveDowntimeInput.model_json_schema(),
        ),
        Tool(
            name="submit_passive_check",
            description=(
                "Submit passive check results for hosts or services that don't perform active checks. "
                "Use this to report status from external monitoring systems, scripts, or manual checks. "
                "Supports both host checks (up/down) and service checks (ok/warning/critical/unknown). "
                "Can include performance data and custom check source. "
                "Useful for integrating external monitoring data into Icinga2."
            ),
            inputSchema=SubmitPassiveCheckInput.model_json_schema(),
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
        elif name == "reschedule_check":
            return await handle_reschedule_check(RescheduleCheckInput(**arguments))
        elif name == "query_events":
            return await handle_query_events(QueryEventsInput(**arguments))
        elif name == "list_downtimes":
            return await handle_list_downtimes(ListDowntimesInput(**arguments))
        elif name == "remove_downtime":
            return await handle_remove_downtime(RemoveDowntimeInput(**arguments))
        elif name == "submit_passive_check":
            return await handle_submit_passive_check(SubmitPassiveCheckInput(**arguments))
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

    # Normalize host_name to list for uniform processing
    host_names = params.host_name if isinstance(params.host_name, list) else [params.host_name]

    # Determine object type
    object_type = "Host" if params.object_type == "host" else "Service"

    # Track results
    successful_hosts = []
    failed_hosts = []

    async with client:
        # Schedule downtime for each host
        for host_name in host_names:
            if params.object_type == "service":
                object_name = f"{host_name}!{params.service_name}"
            else:
                object_name = host_name

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
                successful_hosts.append(host_name)
            except Icinga2APIError as e:
                failed_hosts.append((host_name, str(e)))

        # Format output based on results
        if len(host_names) == 1:
            # Single host - original format
            if successful_hosts:
                target = f"{params.object_type} '{host_names[0]}"
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
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"❌ Failed to schedule downtime for {host_names[0]}: {failed_hosts[0][1]}\n\n"
                        "Please verify the host/service name and try again.",
                    )
                ]
        else:
            # Multiple hosts - summary format
            output = [
                f"# Bulk Downtime Scheduling Results",
                f"",
                f"**Summary:**",
                f"- Total hosts: {len(host_names)}",
                f"- Successful: {len(successful_hosts)}",
                f"- Failed: {len(failed_hosts)}",
                f"",
                f"**Downtime Details:**",
                f"- Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- End: {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- Duration: {params.duration_minutes} minutes",
                f"- Type: {'Fixed' if params.fixed else 'Flexible'}",
                f"- Author: {params.author}",
                f"- Comment: {params.comment}",
            ]

            if params.all_services:
                output.append(f"- All services: Yes")

            if successful_hosts:
                output.append(f"")
                output.append(f"**✅ Successful ({len(successful_hosts)}):**")
                for host in successful_hosts:
                    output.append(f"  - {host}")

            if failed_hosts:
                output.append(f"")
                output.append(f"**❌ Failed ({len(failed_hosts)}):**")
                for host, error in failed_hosts:
                    output.append(f"  - {host}: {error}")

            return [TextContent(type="text", text="\n".join(output))]


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


async def handle_reschedule_check(params: RescheduleCheckInput) -> list[TextContent]:
    """Handle reschedule_check tool call."""
    client = get_icinga2_client()

    # Determine object type
    object_type = "Host" if params.object_type == "host" else "Service"

    # Build filter expression based on filter_type
    if params.filter_type == "name":
        # Exact name match
        if params.object_type == "host":
            filter_expr = f'host.name=="{params.filter_value}"'
        else:  # service
            filter_expr = f'service.name=="{params.filter_value}"'
    elif params.filter_type == "state":
        # State-based filter
        state_value = params.filter_value.lower()
        if params.object_type == "host":
            state_map = {
                "up": "host.state == 0",
                "down": "host.state == 1",
                "problem": "host.state != 0",
            }
            filter_expr = state_map[state_value]
        else:  # service
            state_map = {
                "ok": "service.state == 0",
                "warning": "service.state == 1",
                "critical": "service.state == 2",
                "unknown": "service.state == 3",
                "problem": "service.state != 0",
            }
            filter_expr = state_map[state_value]
    else:  # pattern
        # Wildcard pattern match
        if params.object_type == "host":
            filter_expr = f'match("{params.filter_value}", host.name)'
        else:  # service
            filter_expr = f'match("{params.filter_value}", service.name)'

    async with client:
        try:
            result = await client.reschedule_check(
                object_type=object_type,
                filter_expr=filter_expr,
                next_check=None,  # Always schedule ASAP
                force=params.force,
            )

            # Parse result to count affected objects
            status = result.get("results", [])
            affected_count = len([s for s in status if s.get("code") == 200])

            # Format success message
            filter_desc = {
                "name": f"name '{params.filter_value}'",
                "state": f"state '{params.filter_value}'",
                "pattern": f"pattern '{params.filter_value}'",
            }[params.filter_type]

            output = [
                f"✅ Check(s) rescheduled successfully",
                f"",
                f"**Details:**",
                f"- Object type: {params.object_type}",
                f"- Filter: {filter_desc}",
                f"- Affected objects: {affected_count}",
                f"- Schedule: Immediately (ASAP)",
                f"- Force: {params.force}",
            ]

            if affected_count == 0:
                output.append("")
                output.append("⚠️ Note: No objects matched the filter criteria.")

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to reschedule check(s): {str(e)}\n\n"
                    "Please verify the filter criteria and try again.",
                )
            ]


async def handle_query_events(params: QueryEventsInput) -> list[TextContent]:
    """Handle query_events tool call."""
    client = get_icinga2_client()

    # Determine which object types to query
    if params.object_type == "both":
        object_types = ["Host", "Service"]
    elif params.object_type == "host":
        object_types = ["Host"]
    else:
        object_types = ["Service"]

    # Determine event types to query
    event_types = [params.event_type]

    async with client:
        try:
            events = await client.query_recent_events(
                object_types=object_types,
                event_types=event_types,
                minutes_ago=params.time_range_minutes,
                limit=params.limit,
            )

            if not events:
                return [
                    TextContent(
                        type="text",
                        text=f"No events found in the last {params.time_range_minutes} minutes.",
                    )
                ]

            # Format output
            output = [
                f"# Recent Events ({len(events)} found)",
                f"",
                f"**Time range:** Last {params.time_range_minutes} minutes",
                f"**Event type:** {params.event_type}",
                f"**Object type:** {params.object_type}",
                f"",
            ]

            # Group events by type
            host_events = [e for e in events if e["type"] == "host"]
            service_events = [e for e in events if e["type"] == "service"]

            if host_events:
                output.append("## Host Events")
                output.append("")
                for event in host_events:
                    timestamp_str = datetime.fromtimestamp(event["timestamp"]).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    flags = []
                    if event["acknowledged"]:
                        flags.append("ACK")
                    if event["in_downtime"]:
                        flags.append("DT")

                    flag_str = f" [{', '.join(flags)}]" if flags else ""

                    icon = "🔴" if event["is_problem"] else "🟢"
                    output.append(
                        f"{icon} **{event['display_name']}** - {event['state']}{flag_str}"
                    )
                    output.append(f"   Time: {timestamp_str}")
                    if event["output"]:
                        # Truncate long output
                        output_text = event["output"][:150]
                        if len(event["output"]) > 150:
                            output_text += "..."
                        output.append(f"   Output: {output_text}")
                    output.append("")

            if service_events:
                output.append("## Service Events")
                output.append("")
                for event in service_events:
                    timestamp_str = datetime.fromtimestamp(event["timestamp"]).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    flags = []
                    if event["acknowledged"]:
                        flags.append("ACK")
                    if event["in_downtime"]:
                        flags.append("DT")

                    flag_str = f" [{', '.join(flags)}]" if flags else ""

                    # Icon based on state
                    state_icons = {
                        "OK": "🟢",
                        "WARNING": "🟡",
                        "CRITICAL": "🔴",
                        "UNKNOWN": "⚪",
                    }
                    icon = state_icons.get(event["state"], "⚪")

                    output.append(
                        f"{icon} **{event['display_name']}** - {event['state']}{flag_str}"
                    )
                    output.append(f"   Name: {event['name']}")
                    output.append(f"   Time: {timestamp_str}")
                    if event["output"]:
                        # Truncate long output
                        output_text = event["output"][:150]
                        if len(event["output"]) > 150:
                            output_text += "..."
                        output.append(f"   Output: {output_text}")
                    output.append("")

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to query events: {str(e)}\n\n"
                    "Please check your configuration and try again.",
                )
            ]


async def handle_list_downtimes(params: ListDowntimesInput) -> list[TextContent]:
    """Handle list_downtimes tool call."""
    client = get_icinga2_client()

    async with client:
        try:
            # Build filter expression
            filters = []

            if params.filter_type == "active":
                # Active downtimes (start_time <= now < end_time)
                now = int(datetime.now().timestamp())
                filters.append(f"downtime.start_time <= {now} && downtime.end_time > {now}")
            elif params.filter_type == "host":
                filters.append("downtime.service_name == \"\"")
            elif params.filter_type == "service":
                filters.append("downtime.service_name != \"\"")

            # Add host name filter if provided
            if params.host_filter:
                if "*" in params.host_filter:
                    filters.append(f'match("{params.host_filter}", downtime.host_name)')
                else:
                    filters.append(f'downtime.host_name == "{params.host_filter}"')

            filter_expr = " && ".join(filters) if filters else None

            # Query downtimes
            downtimes = await client.query_objects("Downtime", filters=filter_expr)

            if not downtimes:
                return [
                    TextContent(
                        type="text",
                        text="No downtimes found matching the criteria.",
                    )
                ]

            # Format output
            output = [
                f"# Scheduled Downtimes ({len(downtimes)} found)",
                f"",
                f"**Filter:** {params.filter_type}",
            ]

            if params.host_filter:
                output.append(f"**Host filter:** {params.host_filter}")

            output.append("")

            # Group by host and service
            host_downtimes = []
            service_downtimes = []

            for dt in downtimes:
                attrs = dt.get("attrs", {})
                if not attrs.get("service_name"):
                    host_downtimes.append(attrs)
                else:
                    service_downtimes.append(attrs)

            if host_downtimes:
                output.append("## Host Downtimes")
                output.append("")
                for dt in host_downtimes:
                    name = dt.get("name", "Unknown")
                    host = dt.get("host_name", "Unknown")
                    author = dt.get("author", "Unknown")
                    comment = dt.get("comment", "")
                    start_time = datetime.fromtimestamp(dt.get("start_time", 0)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    end_time = datetime.fromtimestamp(dt.get("end_time", 0)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    # Check if active
                    now = datetime.now().timestamp()
                    is_active = dt.get("start_time", 0) <= now < dt.get("end_time", 0)
                    status = "🟢 ACTIVE" if is_active else "⏰ SCHEDULED"

                    output.append(f"**{host}** - {status}")
                    output.append(f"  Name: {name}")
                    output.append(f"  Start: {start_time}")
                    output.append(f"  End: {end_time}")
                    output.append(f"  Author: {author}")
                    if comment:
                        output.append(f"  Comment: {comment}")
                    output.append("")

            if service_downtimes:
                output.append("## Service Downtimes")
                output.append("")
                for dt in service_downtimes:
                    name = dt.get("name", "Unknown")
                    host = dt.get("host_name", "Unknown")
                    service = dt.get("service_name", "Unknown")
                    author = dt.get("author", "Unknown")
                    comment = dt.get("comment", "")
                    start_time = datetime.fromtimestamp(dt.get("start_time", 0)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    end_time = datetime.fromtimestamp(dt.get("end_time", 0)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    # Check if active
                    now = datetime.now().timestamp()
                    is_active = dt.get("start_time", 0) <= now < dt.get("end_time", 0)
                    status = "🟢 ACTIVE" if is_active else "⏰ SCHEDULED"

                    output.append(f"**{host}!{service}** - {status}")
                    output.append(f"  Name: {name}")
                    output.append(f"  Start: {start_time}")
                    output.append(f"  End: {end_time}")
                    output.append(f"  Author: {author}")
                    if comment:
                        output.append(f"  Comment: {comment}")
                    output.append("")

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to list downtimes: {str(e)}\n\n"
                    "Please check your configuration and try again.",
                )
            ]


async def handle_remove_downtime(params: RemoveDowntimeInput) -> list[TextContent]:
    """Handle remove_downtime tool call."""
    client = get_icinga2_client()

    # Build filter expression based on filter_type
    if params.filter_type == "name":
        filter_expr = f'downtime.name=="{params.filter_value}"'
        target_desc = f"downtime '{params.filter_value}'"
    elif params.filter_type == "host":
        filter_expr = f'downtime.host_name=="{params.filter_value}" && downtime.service_name==""'
        target_desc = f"all host downtimes for '{params.filter_value}'"
    elif params.filter_type == "service":
        # Service format: hostname!servicename
        if "!" in params.filter_value:
            host, service = params.filter_value.split("!", 1)
            filter_expr = (
                f'downtime.host_name=="{host}" && downtime.service_name=="{service}"'
            )
        else:
            filter_expr = f'downtime.service_name=="{params.filter_value}"'
        target_desc = f"all service downtimes for '{params.filter_value}'"
    elif params.filter_type == "all_host":
        filter_expr = 'downtime.service_name==""'
        target_desc = "all host downtimes"
    else:  # all_service
        filter_expr = 'downtime.service_name!=""'
        target_desc = "all service downtimes"

    async with client:
        try:
            result = await client.remove_downtime(filter_expr=filter_expr)

            # Count affected downtimes
            status = result.get("results", [])
            affected_count = len([s for s in status if s.get("code") == 200])

            output = [
                f"✅ Downtime(s) removed successfully",
                f"",
                f"**Target:** {target_desc}",
                f"**Removed:** {affected_count} downtime(s)",
            ]

            if affected_count == 0:
                output.append("")
                output.append("⚠️ Note: No downtimes matched the criteria.")

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to remove downtime(s): {str(e)}\n\n"
                    "Please verify the filter criteria and try again.",
                )
            ]


async def handle_submit_passive_check(
    params: SubmitPassiveCheckInput,
) -> list[TextContent]:
    """Handle submit_passive_check tool call."""
    client = get_icinga2_client()

    # Map user-friendly status to Icinga2 exit codes
    status_map = {
        # Service statuses
        "ok": 0,
        "warning": 1,
        "critical": 2,
        "unknown": 3,
        # Host statuses
        "up": 0,
        "down": 1,
    }

    exit_status = status_map[params.status]

    # Determine object type and build filter
    if params.check_type == "host":
        object_type = "Host"
        filter_expr = f'host.name=="{params.target}"'
        target_display = params.target
    else:  # service
        # Parse hostname!servicename
        host, service = params.target.split("!", 1)
        object_type = "Service"
        filter_expr = f'host.name=="{host}" && service.name=="{service}"'
        target_display = params.target

    async with client:
        try:
            result = await client.submit_passive_check(
                object_type=object_type,
                filter_expr=filter_expr,
                exit_status=exit_status,
                plugin_output=params.output,
                performance_data=params.performance_data,
                check_source=params.check_source,
            )

            # Check submission status
            status_results = result.get("results", [])
            success_count = len([s for s in status_results if s.get("code") == 200])

            if success_count == 0:
                return [
                    TextContent(
                        type="text",
                        text=f"❌ Failed to submit passive check result\n\n"
                        f"**Target:** {target_display}\n"
                        f"**Type:** {params.check_type}\n\n"
                        "The target object may not exist or may not accept passive checks.\n"
                        "Please verify the target exists and is configured for passive checks.",
                    )
                ]

            # Map exit status back to readable status for display
            status_display = params.status.upper()
            status_emoji = {
                "ok": "✅",
                "up": "✅",
                "warning": "⚠️",
                "critical": "🔴",
                "unknown": "❓",
                "down": "🔴",
            }.get(params.status, "ℹ️")

            output = [
                f"{status_emoji} Passive check result submitted successfully",
                f"",
                f"**Target:** {target_display}",
                f"**Type:** {params.check_type.title()}",
                f"**Status:** {status_display}",
                f"**Output:** {params.output}",
            ]

            if params.performance_data:
                output.append(f"**Performance data:** {', '.join(params.performance_data)}")

            if params.check_source:
                output.append(f"**Check source:** {params.check_source}")

            output.extend(
                [
                    "",
                    "The check result has been processed and will appear in Icinga2.",
                ]
            )

            return [TextContent(type="text", text="\n".join(output))]

        except Icinga2APIError as e:
            return [
                TextContent(
                    type="text",
                    text=f"❌ Failed to submit passive check result: {str(e)}\n\n"
                    "Please verify the target exists and is configured for passive checks.",
                )
            ]
