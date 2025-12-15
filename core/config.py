"""
Configuration Management
Handles loading, saving, and accessing application configuration
"""

import json
import os
import logging
from pathlib import Path
from typing import Any, Optional, Dict

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Manages application configuration with support for:
    - JSON config file loading/saving
    - Nested key access (e.g., 'azure.tenant_id')
    - Default values
    - Config validation
    """

    DEFAULT_CONFIG = {
        "abnormal": {
            "base_url": "https://api.abnormalplatform.com",
            "api_key": "",
            "api_version": "v1"
        },
        "azure": {
            "tenant_id": "YOUR_TENANT_ID",
            "client_id": "",
            "client_secret": "",
            "subscription_id": "YOUR_SUBSCRIPTION_ID"
        },
        "claude": {
            "endpoint": "https://YOUR_APIM_ENDPOINT.azure-api.net/foundry",
            "api_key": "",
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "api_version": "2024-10-21"
        },
        "settings": {
            "refresh_interval_minutes": 5,
            "threat_lookback_hours": 24,
            "case_lookback_days": 7,
            "cache_ttl_minutes": 15,
            "auto_analyze": False,
            "auto_diagnose": True
        },
        "diagnostics": {
            "enabled_rules": [
                "auth_spf_permerror",
                "auth_dkim_missing",
                "auth_dmarc_fail",
                "flow_connector_loop",
                "flow_queue_delay",
                "threat_post_delivery_gap",
                "threat_html_smuggling",
                "threat_qr_code_phishing",
                "threat_inbox_rule_persistence",
                "threat_oauth_consent_phishing",
                "integration_token_expiry",
                "integration_rate_limit"
            ]
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ConfigManager

        Args:
            config_path: Path to config.json. If None, looks in current directory
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Look for config in current directory or user's home
            cwd_config = Path("config.json")
            home_config = Path.home() / ".config" / "email-security-analyzer" / "config.json"

            if cwd_config.exists():
                self.config_path = cwd_config
            elif home_config.exists():
                self.config_path = home_config
            else:
                self.config_path = cwd_config

        self._config: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in config file: {e}")
                self._config = self.DEFAULT_CONFIG.copy()
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                self._config = self.DEFAULT_CONFIG.copy()
        else:
            logger.info("No config file found, using defaults")
            self._config = self.DEFAULT_CONFIG.copy()

    def reload(self) -> None:
        """Reload configuration from file"""
        self._load()

    def save(self) -> None:
        """Save current configuration to file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
            logger.info(f"Saved configuration to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            key: Dot-separated key path (e.g., 'azure.tenant_id')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            # Try to get from defaults
            default_value = self.DEFAULT_CONFIG
            try:
                for k in keys:
                    default_value = default_value[k]
                return default_value
            except (KeyError, TypeError):
                return default

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation

        Args:
            key: Dot-separated key path (e.g., 'azure.tenant_id')
            value: Value to set
        """
        keys = key.split('.')
        config = self._config

        # Navigate to parent
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        # Set value
        config[keys[-1]] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section

        Args:
            section: Section name (e.g., 'azure', 'abnormal')

        Returns:
            Section dictionary or empty dict
        """
        return self._config.get(section, self.DEFAULT_CONFIG.get(section, {}))

    def validate(self) -> Dict[str, str]:
        """
        Validate configuration for required values

        Returns:
            Dictionary of validation errors {field: error_message}
        """
        errors = {}

        # Check Abnormal config
        if not self.get('abnormal.api_key'):
            errors['abnormal.api_key'] = "Abnormal Security API key is required"

        # Check Azure config
        if not self.get('azure.tenant_id'):
            errors['azure.tenant_id'] = "Azure tenant ID is required"
        if not self.get('azure.client_id'):
            errors['azure.client_id'] = "Azure client ID is required"
        if not self.get('azure.client_secret'):
            errors['azure.client_secret'] = "Azure client secret is required"

        # Check Claude config
        if not self.get('claude.api_key'):
            errors['claude.api_key'] = "Claude API key (APIM subscription key) is required"

        return errors

    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return len(self.validate()) == 0

    @property
    def config(self) -> Dict[str, Any]:
        """Get raw configuration dictionary"""
        return self._config.copy()

    def __repr__(self) -> str:
        return f"ConfigManager(path={self.config_path}, valid={self.is_valid()})"
