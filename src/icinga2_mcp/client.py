"""Icinga2 API client wrapper with error handling and type safety."""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import httpx

from .tunnel import SSHTunnel

logger = logging.getLogger(__name__)


class Icinga2APIError(Exception):
    """Base exception for Icinga2 API errors."""
    pass


class Icinga2Client:
    """
    Asynchronous client for Icinga2 REST API.

    Handles authentication, request/response formatting, and error handling.
    Supports SSH tunneling for accessing non-public Icinga2 APIs.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        ssh_tunnel: Optional[SSHTunnel] = None,
    ):
        """
        Initialize Icinga2 API client.

        Args:
            base_url: Icinga2 API base URL (e.g., https://icinga.example.com:5665)
            username: API username
            password: API password
            verify_ssl: Whether to verify SSL certificates
            ssh_tunnel: Optional SSH tunnel instance for accessing non-public APIs
        """
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_ssl = verify_ssl
        self.ssh_tunnel = ssh_tunnel
        self.client: Optional[httpx.AsyncClient] = None
        self._tunnel_managed = False

    async def __aenter__(self):
        """Async context manager entry."""
        # If SSH tunnel is configured, establish it first
        if self.ssh_tunnel and not self.ssh_tunnel.is_connected:
            logger.info("Establishing SSH tunnel...")
            await self.ssh_tunnel.connect()
            self._tunnel_managed = True

            # Use tunnel URL instead of original base_url
            self.base_url = self.ssh_tunnel.get_tunnel_url(use_https=True)
            logger.info(f"Using tunneled connection: {self.base_url}")

        self.client = httpx.AsyncClient(
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=30.0,
            headers={"Accept": "application/json"},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

        # Close SSH tunnel if we established it
        if self._tunnel_managed and self.ssh_tunnel:
            logger.info("Closing SSH tunnel...")
            await self.ssh_tunnel.close()
            self._tunnel_managed = False

    async def _request(
        self, method: str, endpoint: str, json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make an authenticated request to the Icinga2 API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            json_data: Optional JSON payload

        Returns:
            API response as dictionary

        Raises:
            Icinga2APIError: On API errors or connection issues
        """
        if not self.client:
            raise Icinga2APIError("Client not initialized. Use async context manager.")

        url = f"{self.base_url}/v1{endpoint}"

        try:
            response = await self.client.request(method, url, json=json_data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            error_detail = ""
            try:
                error_data = e.response.json()
                if "error" in error_data:
                    error_detail = f": {error_data['error']}"
            except Exception:
                error_detail = f": {e.response.text}"

            raise Icinga2APIError(
                f"API request failed with status {e.response.status_code}{error_detail}"
            ) from e
        except httpx.RequestError as e:
            raise Icinga2APIError(f"Connection error: {str(e)}") from e

    async def query_objects(
        self,
        object_type: str,
        filters: Optional[str] = None,
        attrs: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Icinga2 objects with optional filtering.

        Args:
            object_type: Type of object (Host, Service, etc.)
            filters: Optional filter expression
            attrs: Optional list of attributes to return

        Returns:
            List of matching objects
        """
        payload: Dict[str, Any] = {}
        if filters:
            payload["filter"] = filters
        if attrs:
            payload["attrs"] = attrs

        result = await self._request("GET", f"/objects/{object_type.lower()}s", payload)
        return result.get("results", [])

    async def perform_action(
        self,
        action: str,
        object_type: str,
        filters: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Perform an action on Icinga2 objects.

        Args:
            action: Action name (acknowledge-problem, schedule-downtime, etc.)
            object_type: Type of object (Host, Service)
            filters: Filter expression to select objects
            params: Action-specific parameters

        Returns:
            Action result
        """
        payload = {
            "type": object_type,
            "filter": filters,
            **params,
        }

        return await self._request("POST", f"/actions/{action}", payload)

    async def acknowledge_problem(
        self,
        object_type: str,
        object_name: str,
        author: str,
        comment: str,
        sticky: bool = False,
        notify: bool = True,
        persistent: bool = False,
    ) -> Dict[str, Any]:
        """
        Acknowledge a host or service problem.

        Args:
            object_type: "Host" or "Service"
            object_name: Name of the object (for services: "hostname!servicename")
            author: Author of the acknowledgment
            comment: Acknowledgment comment
            sticky: Whether acknowledgment survives state changes
            notify: Whether to send notifications
            persistent: Whether acknowledgment persists across restarts

        Returns:
            Acknowledgment result
        """
        filter_expr = f'"{object_name}"' if object_type == "Host" else f'service.name=="{object_name}"'

        params = {
            "author": author,
            "comment": comment,
            "sticky": sticky,
            "notify": notify,
            "persistent": persistent,
        }

        return await self.perform_action(
            "acknowledge-problem", object_type, filter_expr, params
        )

    async def schedule_downtime(
        self,
        object_type: str,
        object_name: str,
        author: str,
        comment: str,
        start_time: datetime,
        end_time: datetime,
        duration: Optional[int] = None,
        fixed: bool = True,
        all_services: bool = False,
    ) -> Dict[str, Any]:
        """
        Schedule downtime for a host or service.

        Args:
            object_type: "Host" or "Service"
            object_name: Name of the object (for services: "hostname!servicename")
            author: Author of the downtime
            comment: Downtime comment
            start_time: Start time of downtime
            end_time: End time of downtime
            duration: Flexible downtime duration in seconds (if not fixed)
            fixed: Whether downtime is fixed (true) or flexible (false)
            all_services: Whether to schedule downtime for all services (host only)

        Returns:
            Downtime scheduling result
        """
        filter_expr = f'host.name=="{object_name}"' if object_type == "Host" else f'service.name=="{object_name}"'

        params = {
            "author": author,
            "comment": comment,
            "start_time": int(start_time.timestamp()),
            "end_time": int(end_time.timestamp()),
            "fixed": fixed,
        }

        if duration is not None:
            params["duration"] = duration

        if object_type == "Host" and all_services:
            params["all_services"] = all_services

        return await self.perform_action(
            "schedule-downtime", object_type, filter_expr, params
        )

    async def reschedule_check(
        self,
        object_type: str,
        filter_expr: str,
        next_check: Optional[datetime] = None,
        force: bool = True,
    ) -> Dict[str, Any]:
        """
        Reschedule check(s) for hosts or services matching a filter.

        Args:
            object_type: "Host" or "Service"
            filter_expr: Filter expression to select objects
            next_check: When to schedule the next check (None = now)
            force: Force check execution regardless of time period restrictions

        Returns:
            Reschedule result
        """
        # Use current time if not specified (schedule ASAP)
        check_time = next_check if next_check else datetime.now()

        params = {
            "next_check": int(check_time.timestamp()),
            "force": force,
        }

        return await self.perform_action(
            "reschedule-check", object_type, filter_expr, params
        )

    async def query_recent_events(
        self,
        object_types: List[str],
        event_types: List[str],
        minutes_ago: int = 60,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query recent events by looking at object state changes and check results.

        Args:
            object_types: List of object types to query ("Host", "Service")
            event_types: List of event types ("state_change", "problem", "recovery", "all")
            minutes_ago: How many minutes back to look
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries with normalized format
        """
        events = []
        cutoff_time = datetime.now() - timedelta(minutes=minutes_ago)
        cutoff_timestamp = int(cutoff_time.timestamp())

        for obj_type in object_types:
            # Build filter based on event types
            filters = []

            if "state_change" in event_types or "all" in event_types:
                # Objects that had recent state changes
                filters.append(f"{obj_type.lower()}.last_state_change > {cutoff_timestamp}")

            if "problem" in event_types or "all" in event_types:
                # Objects currently in problem state
                if obj_type == "Host":
                    filters.append(f"{obj_type.lower()}.state != 0")
                else:
                    filters.append(f"{obj_type.lower()}.state != 0")

            # Combine filters with OR
            if filters:
                filter_expr = " || ".join([f"({f})" for f in filters])
            else:
                filter_expr = None

            # Query objects
            attrs = [
                "name", "display_name", "state", "last_state_change",
                "last_check_result", "acknowledgement", "downtime_depth",
                "last_state_type", "last_hard_state_change"
            ]

            results = await self.query_objects(obj_type, filters=filter_expr, attrs=attrs)

            # Convert to event format
            for result in results[:limit]:
                attrs_data = result.get("attrs", {})

                # Determine event type
                state = attrs_data.get("state", 0)
                last_state_change = attrs_data.get("last_state_change", 0)

                if obj_type == "Host":
                    state_str = "UP" if state == 0 else "DOWN"
                    is_problem = state != 0
                else:
                    state_map = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
                    state_str = state_map.get(state, "UNKNOWN")
                    is_problem = state != 0

                event = {
                    "type": obj_type.lower(),
                    "name": attrs_data.get("name"),
                    "display_name": attrs_data.get("display_name"),
                    "state": state_str,
                    "is_problem": is_problem,
                    "timestamp": last_state_change,
                    "last_check": attrs_data.get("last_check_result", {}).get("execution_end", 0),
                    "output": attrs_data.get("last_check_result", {}).get("output", ""),
                    "acknowledged": attrs_data.get("acknowledgement", 0) != 0,
                    "in_downtime": attrs_data.get("downtime_depth", 0) > 0,
                }

                events.append(event)

        # Sort by timestamp (most recent first)
        events.sort(key=lambda x: x["timestamp"], reverse=True)

        return events[:limit]

    async def remove_downtime(
        self,
        downtime_name: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Remove/cancel scheduled downtime(s).

        Args:
            downtime_name: Specific downtime name to remove
            filter_expr: Filter expression to select multiple downtimes

        Returns:
            Removal result

        Note:
            Either downtime_name or filter_expr must be provided
        """
        if downtime_name:
            filter_expr = f'downtime.name=="{downtime_name}"'
        elif not filter_expr:
            raise ValueError("Either downtime_name or filter_expr must be provided")

        payload = {
            "type": "Downtime",
            "filter": filter_expr,
        }

        return await self._request("POST", "/actions/remove-downtime", payload)

    async def submit_passive_check(
        self,
        object_type: str,
        filter_expr: str,
        exit_status: int,
        plugin_output: str,
        performance_data: Optional[List[str]] = None,
        check_source: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Submit a passive check result for hosts or services.

        Args:
            object_type: "Host" or "Service"
            filter_expr: Filter to select the target object(s)
            exit_status: Check result status code:
                - For services: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
                - For hosts: 0=UP, 1=DOWN
            plugin_output: Check output text (status message)
            performance_data: Optional performance data metrics
            check_source: Optional check source identifier
            ttl: Optional time-to-live in seconds

        Returns:
            Submission result
        """
        payload = {
            "type": object_type,
            "filter": filter_expr,
            "exit_status": exit_status,
            "plugin_output": plugin_output,
        }

        if performance_data:
            payload["performance_data"] = performance_data

        if check_source:
            payload["check_source"] = check_source

        if ttl is not None:
            payload["ttl"] = ttl

        return await self._request("POST", "/actions/process-check-result", payload)
