"""SSH tunnel management for accessing Icinga2 API through SSH."""

import asyncio
import logging
from typing import Optional
from pathlib import Path

import asyncssh

logger = logging.getLogger(__name__)


class SSHTunnelError(Exception):
    """Base exception for SSH tunnel errors."""
    pass


class SSHTunnel:
    """
    Manages SSH tunnel for forwarding local port to remote Icinga2 API.

    This allows accessing Icinga2 API that is not publicly reachable
    by creating an SSH tunnel through a bastion/jump host.
    """

    def __init__(
        self,
        ssh_host: str,
        ssh_port: int,
        ssh_user: str,
        remote_host: str,
        remote_port: int,
        local_port: int = 0,  # 0 = auto-assign
        ssh_key_path: Optional[str] = None,
        ssh_password: Optional[str] = None,
        known_hosts: Optional[str] = None,
    ):
        """
        Initialize SSH tunnel configuration.

        Args:
            ssh_host: SSH server hostname/IP
            ssh_port: SSH server port (typically 22)
            ssh_user: SSH username
            remote_host: Icinga2 API host (as seen from SSH server, e.g., 'localhost' or '10.0.1.5')
            remote_port: Icinga2 API port (typically 5665)
            local_port: Local port to bind (0 for auto-assign)
            ssh_key_path: Path to SSH private key (optional if using password)
            ssh_password: SSH password (optional if using key)
            known_hosts: Path to known_hosts file (None to disable checking)
        """
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_port = local_port
        self.ssh_key_path = ssh_key_path
        self.ssh_password = ssh_password
        self.known_hosts = known_hosts

        self.connection: Optional[asyncssh.SSHClientConnection] = None
        self.listener: Optional[asyncssh.SSHListener] = None
        self.assigned_port: Optional[int] = None

    async def __aenter__(self):
        """Async context manager entry - establish tunnel."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - close tunnel."""
        await self.close()

    async def connect(self) -> int:
        """
        Establish SSH connection and create tunnel.

        Returns:
            Local port number that was bound

        Raises:
            SSHTunnelError: If connection or tunnel creation fails
        """
        try:
            # Prepare connection options
            connect_options = {
                "host": self.ssh_host,
                "port": self.ssh_port,
                "username": self.ssh_user,
                "known_hosts": self.known_hosts,
            }

            # Add authentication
            if self.ssh_key_path:
                connect_options["client_keys"] = [self.ssh_key_path]
            if self.ssh_password:
                connect_options["password"] = self.ssh_password

            logger.info(f"Connecting to SSH server {self.ssh_user}@{self.ssh_host}:{self.ssh_port}")

            # Establish SSH connection
            self.connection = await asyncssh.connect(**connect_options)

            logger.info(
                f"Creating tunnel: localhost:{self.local_port} -> "
                f"{self.remote_host}:{self.remote_port}"
            )

            # Create port forwarding tunnel
            self.listener = await self.connection.forward_local_port(
                "",  # Listen on all interfaces
                self.local_port,
                self.remote_host,
                self.remote_port,
            )

            # Get the actual port that was bound (if we used 0 for auto-assign)
            self.assigned_port = self.listener.get_port()

            logger.info(f"SSH tunnel established on local port {self.assigned_port}")

            return self.assigned_port

        except asyncssh.Error as e:
            raise SSHTunnelError(f"Failed to establish SSH tunnel: {str(e)}") from e
        except Exception as e:
            raise SSHTunnelError(f"Unexpected error creating SSH tunnel: {str(e)}") from e

    async def close(self):
        """Close SSH tunnel and connection."""
        if self.listener:
            logger.info("Closing SSH tunnel...")
            self.listener.close()
            await self.listener.wait_closed()
            self.listener = None

        if self.connection:
            logger.info("Closing SSH connection...")
            self.connection.close()
            await self.connection.wait_closed()
            self.connection = None

        self.assigned_port = None

    def get_tunnel_url(self, use_https: bool = True) -> str:
        """
        Get the URL to use for accessing the tunneled service.

        Args:
            use_https: Whether to use https:// or http:// prefix

        Returns:
            URL string (e.g., "https://localhost:12345")

        Raises:
            SSHTunnelError: If tunnel is not established
        """
        if not self.assigned_port:
            raise SSHTunnelError("Tunnel not established. Call connect() first.")

        protocol = "https" if use_https else "http"
        return f"{protocol}://localhost:{self.assigned_port}"

    @property
    def is_connected(self) -> bool:
        """Check if tunnel is currently connected."""
        return self.connection is not None and self.assigned_port is not None
