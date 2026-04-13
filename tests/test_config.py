"""
Tests for server_management_lib.config module.

Covers:
- Default configuration structure
- YAML config loading
- Edge cases (non-existent files, invalid YAML, valid overrides)
"""

from pathlib import Path

import pytest

from server_management_lib.config import DEFAULT_CONFIG, load_config


class TestDefaultConfiguration:
    """Test default configuration structure."""

    def test_has_all_sections(self):
        """Default config must have all expected sections."""
        assert "ssh" in DEFAULT_CONFIG
        assert "security" in DEFAULT_CONFIG
        assert "host" in DEFAULT_CONFIG
        assert "influxdb" in DEFAULT_CONFIG
        assert "prometheus" in DEFAULT_CONFIG

    def test_security_settings(self):
        """Generic command execution must be disabled by default."""
        assert DEFAULT_CONFIG["security"]["allow_generic_commands"] is False

    def test_load_example_config(self):
        """Example config file should load without error."""
        example_path = Path(__file__).parent.parent / "config.example.yaml"
        if example_path.exists():
            config = load_config(example_path)
            assert "ssh" in config
            assert "security" in config


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
