"""
Configuration loader for Server Management Library

Loads YAML configuration with sensible defaults for SSH, security,
InfluxDB, Prometheus, and host data source settings.
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict = {
    "ssh": {
        "host": "localhost",
        "port": 22,
        "username": "root",
        "password": None,
        "key_path": None,
    },
    "security": {
        # Service directory base path (for remote-server-mcp)
        "services_path": "/srv",
        # NEVER allow generic command execution
        "allow_generic_commands": False,
    },
    "host": {
        "enabled": False,
    },
    "influxdb": {
        "enabled": False,
        "host": "localhost",
        "port": 8181,
        "use_https": False,
        "database": None,
        "token": None,
        "query_limit": 1000,
    },
    "prometheus": {
        "enabled": False,
        "host": "localhost",
        "port": 9090,
        "use_https": False,
        "token": None,
        "query_timeout": "30s",
    },
}


def load_config(config_path: Path | None = None) -> dict:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to config file (optional, uses default if not found)

    Returns:
        Configuration dictionary
    """
    if config_path and config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            logger.warning("Using default configuration")

    logger.warning("No configuration file found, using defaults")
    return DEFAULT_CONFIG.copy()
