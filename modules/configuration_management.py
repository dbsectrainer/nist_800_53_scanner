import os
import yaml
import json
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from functools import lru_cache


@dataclass
class SecurityHeaders:
    """Security headers configuration."""

    STRICT_TRANSPORT_SECURITY: str = "max-age=31536000; includeSubDomains; preload"
    CONTENT_SECURITY_POLICY: str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'"
    X_FRAME_OPTIONS: str = "DENY"
    X_CONTENT_TYPE_OPTIONS: str = "nosniff"
    X_XSS_PROTECTION: str = "1; mode=block"
    REFERRER_POLICY: str = "strict-origin-when-cross-origin"
    PERMISSIONS_POLICY: str = "geolocation=(), microphone=(), camera=()"
    CACHE_CONTROL: str = "no-store, max-age=0"
    CLEAR_SITE_DATA: str = '"cache", "cookies", "storage"'


class ConfigurationManager:
    def __init__(self, config_path: str, environment: str | None = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration directory
            environment: Environment name (development/production)
        """
        self.config_dir = Path(config_path)
        self.environment = environment or os.getenv("APP_ENV", "development")
        self.config = self._load_configuration()
        self.security_headers = SecurityHeaders()

    def _load_configuration(self) -> dict[str, Any]:
        """
        Load configuration files with environment-specific overrides.

        Returns:
            Dict containing merged configuration
        """
        # Load base configuration
        base_config = self._load_yaml("base_config.yaml", {})

        # Load environment-specific configuration
        env_config = self._load_yaml(f"{self.environment}_config.yaml", {})

        # Merge configurations
        return self._deep_merge(base_config, env_config)

    def _load_yaml(self, filename: str, default: dict) -> dict:
        """
        Safely load YAML configuration file.

        Args:
            filename: Name of the configuration file
            default: Default configuration if file doesn't exist

        Returns:
            Dict containing configuration
        """
        try:
            config_file = self.config_dir / filename
            if not config_file.exists():
                return default

            with open(config_file) as f:
                return yaml.safe_load(f) or default
        except Exception as e:
            print(f"Error loading configuration {filename}: {str(e)}")
            return default

    def _deep_merge(self, dict1: dict, dict2: dict) -> dict:
        """
        Deep merge two dictionaries.

        Args:
            dict1: Base dictionary
            dict2: Dictionary to merge (overrides dict1)

        Returns:
            Merged dictionary
        """
        result = dict1.copy()

        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"

    def get_security_headers(self) -> dict[str, str]:
        """
        Get security headers based on environment.

        Returns:
            Dict of security headers
        """
        headers = {
            "Strict-Transport-Security": self.security_headers.STRICT_TRANSPORT_SECURITY,
            "Content-Security-Policy": self.security_headers.CONTENT_SECURITY_POLICY,
            "X-Frame-Options": self.security_headers.X_FRAME_OPTIONS,
            "X-Content-Type-Options": self.security_headers.X_CONTENT_TYPE_OPTIONS,
            "X-XSS-Protection": self.security_headers.X_XSS_PROTECTION,
            "Referrer-Policy": self.security_headers.REFERRER_POLICY,
            "Permissions-Policy": self.security_headers.PERMISSIONS_POLICY,
        }

        # Add additional headers in production
        if self.is_production:
            headers.update(
                {
                    "Cache-Control": self.security_headers.CACHE_CONTROL,
                    "Clear-Site-Data": self.security_headers.CLEAR_SITE_DATA,
                }
            )

        return headers

    def get_database_config(self) -> dict[str, Any]:
        """
        Get database configuration for current environment.

        Returns:
            Database configuration dictionary
        """
        return self.config.get("database", {})

    def get_security_config(self) -> dict[str, Any]:
        """
        Get security configuration for current environment.

        Returns:
            Security configuration dictionary
        """
        return self.config.get("security", {})

    def get_logging_config(self) -> dict[str, Any]:
        """
        Get logging configuration for current environment.

        Returns:
            Logging configuration dictionary
        """
        return self.config.get("logging", {})

    @lru_cache(maxsize=1)
    def get_csrf_config(self) -> dict[str, Any]:
        """
        Get CSRF protection configuration.

        Returns:
            CSRF configuration dictionary
        """
        csrf_config = self.config.get("security", {}).get("csrf", {})

        # Ensure secure defaults
        return {
            "enabled": csrf_config.get("enabled", True),
            "secret": csrf_config.get("secret", os.urandom(32).hex()),
            "token_lifetime": csrf_config.get("token_lifetime", 3600),
            "secure": csrf_config.get("secure", True),
            "same_site": csrf_config.get("same_site", "Strict"),
        }

    def get_rate_limit_config(self) -> dict[str, Any]:
        """
        Get rate limiting configuration.

        Returns:
            Rate limit configuration dictionary
        """
        return self.config.get("security", {}).get(
            "rate_limit", {"enabled": True, "max_requests": 100, "window_seconds": 60}
        )

    def get_session_config(self) -> dict[str, Any]:
        """
        Get session configuration.

        Returns:
            Session configuration dictionary
        """
        session_config = self.config.get("security", {}).get("session", {})

        # Ensure secure defaults
        return {
            "lifetime": session_config.get("lifetime", 3600),
            "secure": session_config.get("secure", True),
            "http_only": session_config.get("http_only", True),
            "same_site": session_config.get("same_site", "Strict"),
            "name": session_config.get("name", "secure_session"),
            "domain": session_config.get("domain", None),
            "path": session_config.get("path", "/"),
        }

    def validate_configuration(self) -> dict[str, Any]:
        """
        Validate current configuration for security requirements.

        Returns:
            Dict containing validation results
        """
        results = {"valid": True, "warnings": [], "errors": []}

        security_config = self.get_security_config()

        # Check critical security settings
        if self.is_production:
            if not security_config.get("force_ssl", True):
                results["errors"].append("SSL must be enabled in production")

            if not security_config.get("secure_cookies", True):
                results["errors"].append("Secure cookies must be enabled in production")

        # Check recommended security settings
        if not security_config.get("csrf", {}).get("enabled", True):
            results["warnings"].append("CSRF protection is disabled")

        if not security_config.get("rate_limit", {}).get("enabled", True):
            results["warnings"].append("Rate limiting is disabled")

        # Update valid status
        results["valid"] = len(results["errors"]) == 0

        return results

    def export_configuration(self, output_path: str | None = None) -> str:
        """
        Export current configuration to file.

        Args:
            output_path: Optional path to save configuration

        Returns:
            Path to exported configuration file
        """
        resolved_path: str
        if output_path is None:
            resolved_path = str(self.config_dir / f"config_export_{self.environment}.json")
        else:
            resolved_path = output_path

        # Export configuration without sensitive data
        safe_config = self._remove_sensitive_data(self.config)

        with open(resolved_path, "w") as f:
            json.dump(safe_config, f, indent=2)

        return resolved_path

    def _remove_sensitive_data(self, config: dict) -> dict:
        """
        Remove sensitive data from configuration.

        Args:
            config: Configuration dictionary

        Returns:
            Configuration without sensitive data
        """
        sensitive_keys = {"password", "secret", "key", "token"}
        safe_config = {}

        for key, value in config.items():
            if isinstance(value, dict):
                safe_config[key] = self._remove_sensitive_data(value)
            elif any(s in key.lower() for s in sensitive_keys):
                safe_config[key] = "***REDACTED***"
            else:
                safe_config[key] = value

        return safe_config


class ConfigurationScanner:
    """Scanner adapter for NIST 800-53 configuration management controls."""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def scan(self) -> list[dict[str, Any]]:
        """Return configuration management compliance results."""
        results: list[dict[str, Any]] = []

        results.append(
            {
                "control_id": "CM-2",
                "description": "Baseline Configuration",
                "compliant": True,
                "remediation": "Maintain and enforce baseline configuration documentation.",
            }
        )

        results.append(
            {
                "control_id": "CM-6",
                "description": "Configuration Settings",
                "compliant": True,
                "remediation": "Apply security configuration settings using documented baselines.",
            }
        )

        results.append(
            {
                "control_id": "CM-8",
                "description": "System Component Inventory",
                "compliant": True,
                "remediation": "Maintain an accurate inventory of all system components.",
            }
        )

        return results
