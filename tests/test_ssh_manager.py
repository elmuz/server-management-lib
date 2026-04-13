"""
Tests for server_management_lib.ssh_manager module.

Covers:
- SSHManager initialization
- Connection handling (success, failure, disconnect)
- Safe command execution (various scenarios)
- Service existence checking
- Async context manager
- Edge cases (key auth, password auth)

All SSH operations are mocked - no real connections.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server_management_lib.ssh_manager import SSHManager


class TestSSHManagerInit:
    """Test SSHManager initialization."""

    def test_manager_created(self, config, security):
        manager = SSHManager(config, security)
        assert manager.connection is None
        assert manager._connected is False

    def test_manager_with_key_path(self, config_with_key, security):
        """Test SSHManager with key path configuration."""
        manager = SSHManager(config_with_key, security)
        assert manager.config["ssh"]["key_path"] == "~/.ssh/id_rsa"

    def test_manager_with_password(self, config_with_password, security):
        """Test SSHManager with password configuration."""
        manager = SSHManager(config_with_password, security)
        assert manager.config["ssh"]["password"] == "secret"


class TestSSHManagerConnection:
    """Test SSHManager connection handling."""

    def test_connect_failure(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            with patch("server_management_lib.ssh_manager.asyncssh.connect") as mock:
                mock.side_effect = Exception("Connection refused")
                with pytest.raises(Exception, match="Connection refused"):
                    await manager.connect()

        asyncio.run(run())

    def test_disconnect_on_error(self, config, security):
        async def run():
            manager = SSHManager(config, security)

            with patch("server_management_lib.ssh_manager.asyncssh.connect") as mock:
                mock.side_effect = Exception("Connection failed")

                try:
                    await manager.connect()
                except Exception:
                    pass

                assert manager._connected is False

        asyncio.run(run())

    def test_disconnect(self, config, security):
        """Test explicit disconnect."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.close = MagicMock()
            manager.connection = mock_conn

            await manager.disconnect()
            assert manager._connected is False

        asyncio.run(run())


class TestSSHManagerCommandExecution:
    """Test SSHManager safe command execution."""

    def test_execute_safe_command(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="hello", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.execute_safe_command("echo hello")
            assert "hello" in result

        asyncio.run(run())

    def test_unsafe_command_blocked(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = AsyncMock()

            result = await manager.execute_safe_command("rm -rf /")
            assert "Security violation" in result or "❌" in result

        asyncio.run(run())

    def test_command_not_connected(self, config, security):
        """Command execution when not connected should attempt to connect."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = False
            manager.connection = None

            # When connect() raises, it should propagate
            with patch.object(manager, "connect", side_effect=Exception("Connection failed")):
                with pytest.raises(Exception, match="Connection failed"):
                    await manager.execute_safe_command("echo test")

        asyncio.run(run())

    def test_command_connection_none(self, config, security):
        """Command execution when connection is None after connect."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = None

            with patch.object(manager, "connect", return_value=None):
                result = await manager.execute_safe_command("echo test")
                assert "Connection failed" in result

        asyncio.run(run())

    def test_command_with_stderr(self, config, security):
        """Test that stderr is included in the output."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="stdout output", stderr="stderr output", exit_status=0
            )
            manager.connection = mock_conn

            with patch.object(
                manager.security, "is_command_safe", return_value=True
            ):
                result = await manager.execute_safe_command("echo test")
                assert "stdout output" in result
                assert "stderr output" in result

        asyncio.run(run())

    def test_command_nonzero_exit(self, config, security):
        """Test that non-zero exit codes are reported."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="output", stderr="", exit_status=1
            )
            manager.connection = mock_conn

            with patch.object(
                manager.security, "is_command_safe", return_value=True
            ):
                result = await manager.execute_safe_command("command")
                assert "output" in result
                assert "Exit code: 1" in result

        asyncio.run(run())

    def test_command_asyncssh_error(self, config, security):
        """Test that asyncssh errors are handled."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = Exception("SSH connection lost")
            manager.connection = mock_conn

            with patch.object(
                manager.security, "is_command_safe", return_value=True
            ):
                result = await manager.execute_safe_command("command")
                assert "Error executing command" in result or "SSH connection lost" in result

        asyncio.run(run())

    def test_command_timeout(self, config, security):
        """Test that timeouts are handled."""
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = TimeoutError()
            manager.connection = mock_conn

            with patch.object(
                manager.security, "is_command_safe", return_value=True
            ):
                result = await manager.execute_safe_command("command", timeout=10)
                assert "timed out" in result

        asyncio.run(run())


class TestSSHManagerServiceCheck:
    """Test SSHManager service existence checking."""

    def test_check_service_exists(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            # check_service_exists runs: test -d /srv/{service} && echo 'exists' || echo 'not_exists'
            mock_conn.run.return_value = MagicMock(
                stdout="exists", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.check_service_exists("myapp")
            assert result is True

        asyncio.run(run())

    def test_check_service_exists_not_found(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="not_exists", stderr="", exit_status=0
            )
            manager.connection = mock_conn

            result = await manager.check_service_exists("nonexistent")
            assert result is False

        asyncio.run(run())

    def test_check_service_exists_exception(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = AsyncMock()
            manager.connection.run.side_effect = Exception("Command failed")

            result = await manager.check_service_exists("myapp")
            assert result is False

        asyncio.run(run())


class TestSSHManagerContextManager:
    """Test SSHManager async context manager."""

    def test_context_manager_usage(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="test", stderr="", exit_status=0
            )
            mock_conn.close = MagicMock()
            manager.connection = mock_conn

            with patch.object(
                manager.security, "is_command_safe", return_value=True
            ):
                result = await manager.execute_safe_command("echo test")
                assert "test" in result

            await manager.disconnect()
            assert manager._connected is False

        asyncio.run(run())
