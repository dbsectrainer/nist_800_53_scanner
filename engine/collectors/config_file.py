"""Collectors that read the scanner's own monitoring/logging configuration."""

from __future__ import annotations

from .base import Collector


class ScannerLoggingConfigCollector(Collector):
    name = "scanner_logging_config"
    evidence_type = "app.logging_config"

    def gather(self) -> dict:
        log_cfg = (self.config.get("monitoring") or {}).get("logging")
        if log_cfg is None:
            raise KeyError("monitoring.logging section absent from configuration")
        local = log_cfg.get("local") or {}
        return {
            "local_logging_enabled": bool(local.get("enabled", False)),
            "retention_days": log_cfg.get("retention_days"),
        }
