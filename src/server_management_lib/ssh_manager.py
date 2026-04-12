"""
SSH Connection Manager for Remote Server Operations

Handles SSH connections with strict security:
- NO generic command execution
- Only pre-defined safe commands allowed
- All commands validated before execution
"""

import logging

import asyncssh

from .security import SecurityValidator

logger = logging.getLogger(__name__)


def _patch_asyncssh_for_mlkem():
    """
    Patch asyncssh to handle ML-KEM algorithm errors gracefully.

    asyncssh 2.22.0 doesn't support mlkem768x25519-sha256 (post-quantum key exchange).
    When the SSH server advertises this algorithm, asyncssh tries to parse it and fails
    with "p must be exactly 1024, 2048, 3072, or 4096 bits long".

    This patch catches the error during key exchange and allows fallback to
    supported algorithms.
    """
    try:
        from asyncssh import kex

        original_kex_algorithms = getattr(kex, "client_kex_algorithms", None)

        if original_kex_algorithms:
            safe_kex = [
                alg
                for alg in original_kex_algorithms
                if not alg.startswith(b"mlkem") and not alg.startswith(b"x25519")
            ]

            if safe_kex:
                kex.client_kex_algorithms = safe_kex  # type: ignore[attr-defined]
                logger.info(
                    "Patched asyncssh: removed ML-KEM from key exchange algorithms"
                )
    except Exception as e:
        logger.warning(f"Could not patch asyncssh for ML-KEM: {e}")


# Apply patch on module load
_patch_asyncssh_for_mlkem()


class SSHManager:
    """Manages SSH connections with strict security controls."""

    def __init__(self, config: dict, security: SecurityValidator):
        """
        Initialize SSH manager.

        Args:
            config: Configuration dictionary with SSH settings
            security: Security validator instance
        """
        self.config = config
        self.security = security
        self.ssh_config = config.get("ssh", {})
        self.connection: asyncssh.SSHClientConnection | None = None
        self._connected = False

    async def connect(self) -> None:
        """Establish SSH connection to the remote server."""
        host = self.ssh_config.get("host", "localhost")
        port = self.ssh_config.get("port", 22)
        username = self.ssh_config.get("username", "root")
        password = self.ssh_config.get("password")
        key_path = self.ssh_config.get("key_path")

        connect_kwargs = {
            "host": host,
            "port": port,
            "username": username,
            "known_hosts": None,
        }

        if key_path:
            import os

            expanded_path = os.path.expanduser(key_path)
            connect_kwargs["client_keys"] = [expanded_path]
            logger.info(f"Using SSH key: {expanded_path}")
        elif password:
            connect_kwargs["password"] = password

        try:
            self.connection = await asyncssh.connect(**connect_kwargs)
            self._connected = True
            logger.info(f"Connected to {host}:{port} as {username}")
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            raise

    async def disconnect(self) -> None:
        """Close SSH connection."""
        if self.connection:
            self.connection.close()
            self._connected = False
            logger.info("SSH connection closed")

    async def execute_safe_command(self, command: str, timeout: int = 30) -> str:
        """
        Execute a pre-validated safe command.

        Args:
            command: Pre-validated command (constructed by application code)
            timeout: Timeout in seconds (default: 30)

        Returns:
            Command output
        """
        if not self.security.is_command_safe(command):
            logger.error(f"Attempted to execute unsafe command: {command}")
            return "❌ Security violation: Command blocked by security policy"

        if not self._connected or not self.connection:
            await self.connect()

        if self.connection is None:
            return "❌ Connection failed"

        try:
            result = await self.connection.run(
                command,
                check=False,
                timeout=timeout,
            )

            output: str = ""
            if result.stdout:
                output += str(result.stdout)
            if result.stderr:
                if output:
                    output += "\n--- STDERR ---\n"
                output += str(result.stderr)

            if result.exit_status != 0:
                output += f"\n\n⚠️ Exit code: {result.exit_status}"

            return output
        except asyncssh.Error as e:
            return f"❌ SSH error: {e}"
        except TimeoutError:
            return f"❌ Command timed out after {timeout}s"
        except Exception as e:
            return f"❌ Error executing command: {e}"

    async def check_service_exists(self, service: str) -> bool:
        """
        Check if a service directory exists in /srv/.

        Args:
            service: Service name (should be validated already)

        Returns:
            True if service exists
        """
        try:
            cmd = f"test -d /srv/{service} && echo 'exists' || echo 'not_exists'"
            result = await self.execute_safe_command(cmd)
            return "exists" in result and "not_exists" not in result
        except Exception:
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
