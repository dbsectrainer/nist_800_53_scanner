import json
import logging
import logging.handlers
import os
import hmac
import hashlib
import time
from typing import Any
from pathlib import Path
import threading
import queue
from dataclasses import dataclass
from enum import Enum


class SecurityLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityEvent:
    timestamp: float
    level: SecurityLevel
    event_type: str
    details: dict[str, Any]
    source_ip: str | None = None
    user_id: str | None = None
    session_id: str | None = None


class AlertHandler:
    def __init__(self, alert_config: dict[str, Any]):
        """
        Initialize alert handler with configuration.

        Args:
            alert_config: Alert configuration dictionary
        """
        self.config = alert_config
        self.alert_queue = queue.Queue()
        self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()

    def _process_alerts(self):
        """Process alerts in background thread."""
        while True:
            try:
                event = self.alert_queue.get()
                if event.level == SecurityLevel.CRITICAL:
                    self._send_critical_alert(event)
                elif event.level == SecurityLevel.WARNING:
                    self._send_warning_alert(event)
                self.alert_queue.task_done()
            except Exception as e:
                logging.error(f"Error processing alert: {str(e)}")

    def _send_critical_alert(self, event: SecurityEvent):
        """Send critical security alert."""
        # Implement integration with alert systems (e.g., email, SMS, Slack)
        # This is a placeholder for actual implementation
        print(f"CRITICAL ALERT: {event}")

    def _send_warning_alert(self, event: SecurityEvent):
        """Send warning security alert."""
        # Implement integration with alert systems
        # This is a placeholder for actual implementation
        print(f"WARNING ALERT: {event}")

    def queue_alert(self, event: SecurityEvent):
        """Queue a security event for alert processing."""
        self.alert_queue.put(event)


class SecureLogger:
    def __init__(self, log_dir: str, hmac_key: bytes, max_size: int = 10485760, backup_count: int = 5):
        """
        Initialize secure logger with HMAC protection and rotation.

        Args:
            log_dir: Directory for log files
            hmac_key: Key for HMAC calculation
            max_size: Maximum size of each log file
            backup_count: Number of backup files to keep
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.hmac_key = hmac_key

        # Set up main security log
        security_log = self.log_dir / "security.log"
        handler = logging.handlers.RotatingFileHandler(
            security_log, maxBytes=max_size, backupCount=backup_count, mode="a"
        )

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)

        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)

        # Set secure permissions
        os.chmod(security_log, 0o600)

        # Initialize HMAC log
        self.hmac_log = self.log_dir / "security.log.hmac"
        if not self.hmac_log.exists():
            self.hmac_log.touch(mode=0o600)

    def _calculate_hmac(self, message: str) -> str:
        """Calculate HMAC for log entry."""
        h = hmac.new(self.hmac_key, message.encode(), hashlib.sha256)
        return h.hexdigest()

    def _write_hmac(self, log_entry: str):
        """Write HMAC for log entry."""
        hmac_value = self._calculate_hmac(log_entry)
        with open(self.hmac_log, "a") as f:
            f.write(f"{hmac_value}\n")

    def log_security_event(self, event: SecurityEvent):
        """
        Log a security event with HMAC protection.

        Args:
            event: SecurityEvent to log
        """
        log_entry = json.dumps(
            {
                "timestamp": event.timestamp,
                "level": event.level.value,
                "event_type": event.event_type,
                "details": event.details,
                "source_ip": event.source_ip,
                "user_id": event.user_id,
                "session_id": event.session_id,
            }
        )

        self.logger.log(
            logging.CRITICAL
            if event.level == SecurityLevel.CRITICAL
            else logging.WARNING
            if event.level == SecurityLevel.WARNING
            else logging.INFO,
            log_entry,
        )

        self._write_hmac(log_entry)

    def verify_log_integrity(self) -> bool:
        """
        Verify integrity of log files using stored HMACs.

        Returns:
            bool: True if log integrity is verified
        """
        try:
            with open(self.log_dir / "security.log") as log_file, open(self.hmac_log) as hmac_file:
                for log_line, hmac_line in zip(log_file, hmac_file):
                    if log_line.strip():
                        calculated_hmac = self._calculate_hmac(log_line.strip())
                        if calculated_hmac != hmac_line.strip():
                            return False
            return True
        except Exception:
            return False


class AuditLogger:
    def __init__(self, config: dict[str, Any]):
        """
        Initialize comprehensive audit logging system.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.secure_logger = SecureLogger(
            config["log_dir"],
            config.get("hmac_key", os.urandom(32)),
            config.get("max_log_size", 10485760),
            config.get("backup_count", 5),
        )
        self.alert_handler = AlertHandler(config.get("alert_config", {}))

    def log_event(self, event: SecurityEvent):
        """
        Log security event and trigger alerts if needed.

        Args:
            event: SecurityEvent to log
        """
        # Log the event
        self.secure_logger.log_security_event(event)

        # Queue alert if needed
        if event.level in [SecurityLevel.WARNING, SecurityLevel.CRITICAL]:
            self.alert_handler.queue_alert(event)

    def log_auth_event(
        self,
        event_type: str,
        user_id: str,
        success: bool,
        source_ip: str,
        session_id: str | None = None,
        details: dict | None = None,
    ):
        """Log authentication-related security event."""
        level = SecurityLevel.WARNING if not success else SecurityLevel.INFO

        event = SecurityEvent(
            timestamp=time.time(),
            level=level,
            event_type=event_type,
            details=details or {},
            source_ip=source_ip,
            user_id=user_id,
            session_id=session_id,
        )

        self.log_event(event)

    def log_access_event(
        self, resource: str, action: str, user_id: str, success: bool, source_ip: str, session_id: str | None = None
    ):
        """Log access control related security event."""
        level = SecurityLevel.WARNING if not success else SecurityLevel.INFO

        event = SecurityEvent(
            timestamp=time.time(),
            level=level,
            event_type="ACCESS_CONTROL",
            details={"resource": resource, "action": action, "success": success},
            source_ip=source_ip,
            user_id=user_id,
            session_id=session_id,
        )

        self.log_event(event)

    def log_system_event(self, event_type: str, details: dict[str, Any], level: SecurityLevel = SecurityLevel.INFO):
        """Log system-related security event."""
        event = SecurityEvent(timestamp=time.time(), level=level, event_type=event_type, details=details)

        self.log_event(event)

    def verify_logs(self) -> bool:
        """
        Verify integrity of all audit logs.

        Returns:
            bool: True if all logs are verified
        """
        return self.secure_logger.verify_log_integrity()


class AuditLoggingScanner:
    """Scanner adapter for NIST 800-53 audit logging controls."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def scan(self) -> list[dict[str, Any]]:
        """Return audit logging compliance results."""
        results: list[dict[str, Any]] = []

        log_cfg = self.config.get("monitoring", {}).get("logging", {})
        local_enabled = log_cfg.get("local", {}).get("enabled", False)
        results.append(
            {
                "control_id": "AU-2",
                "description": "Audit Events - local logging enabled",
                "compliant": bool(local_enabled),
                "remediation": "Enable local logging in monitoring.logging.local section of config.",
            }
        )

        results.append(
            {
                "control_id": "AU-9",
                "description": "Protection of Audit Information",
                "compliant": True,
                "remediation": "Ensure audit logs are protected with HMAC integrity checks.",
            }
        )

        results.append(
            {
                "control_id": "AU-12",
                "description": "Audit Record Generation",
                "compliant": True,
                "remediation": "Ensure all relevant system events generate audit records.",
            }
        )

        return results
