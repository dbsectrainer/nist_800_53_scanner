import time
import logging
import threading
import psutil
from typing import Any
import json
import os
import socket


class SystemMonitor:
    def __init__(
        self, log_dir: str = "logs", monitoring_interval: int = 60, alert_thresholds: dict[str, float] | None = None
    ):
        """
        Initialize system monitoring.

        Args:
            log_dir: Directory to store monitoring logs
            monitoring_interval: Interval between monitoring checks (in seconds)
            alert_thresholds: Custom thresholds for system resources
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # Default alert thresholds
        self.alert_thresholds = alert_thresholds or {
            "cpu_percent": 80.0,  # 80% CPU usage
            "memory_percent": 90.0,  # 90% memory usage
            "disk_percent": 90.0,  # 90% disk usage
        }

        self.monitoring_interval = monitoring_interval
        self.is_monitoring = False
        self.monitoring_thread = None

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            handlers=[logging.FileHandler(os.path.join(log_dir, "system_monitor.log")), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

    def _get_system_metrics(self) -> dict[str, Any]:
        """
        Collect current system metrics.

        Returns:
            Dictionary of system resource usage
        """
        return {
            "timestamp": time.time(),
            "hostname": socket.gethostname(),
            "cpu_percent": psutil.cpu_percent(),
            "memory_usage": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent,
            },
            "disk_usage": {
                "total": psutil.disk_usage("/").total,
                "free": psutil.disk_usage("/").free,
                "percent": psutil.disk_usage("/").percent,
            },
            "network_io": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
            },
            "processes": sum(1 for _ in psutil.process_iter()),
        }

    def _check_thresholds(self, metrics: dict[str, Any]) -> None:
        """
        Check if system metrics exceed defined thresholds.

        Args:
            metrics: System metrics to check
        """
        # Check CPU usage
        if metrics["cpu_percent"] > self.alert_thresholds["cpu_percent"]:
            self.logger.warning(f"High CPU usage: {metrics['cpu_percent']}%")

        # Check memory usage
        if metrics["memory_usage"]["percent"] > self.alert_thresholds["memory_percent"]:
            self.logger.warning(f"High memory usage: {metrics['memory_usage']['percent']}%")

        # Check disk usage
        if metrics["disk_usage"]["percent"] > self.alert_thresholds["disk_percent"]:
            self.logger.warning(f"High disk usage: {metrics['disk_usage']['percent']}%")

    def _log_metrics(self, metrics: dict[str, Any]) -> None:
        """
        Log system metrics to a JSON file.

        Args:
            metrics: System metrics to log
        """
        log_file = os.path.join(self.log_dir, f"metrics_{int(time.time())}.json")
        with open(log_file, "w") as f:
            json.dump(metrics, f, indent=2)

    def _monitoring_loop(self) -> None:
        """
        Continuous monitoring loop.
        """
        while self.is_monitoring:
            try:
                # Collect metrics
                metrics = self._get_system_metrics()

                # Check thresholds
                self._check_thresholds(metrics)

                # Log metrics
                self._log_metrics(metrics)

                # Wait for next interval
                time.sleep(self.monitoring_interval)

            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                # Wait before retrying to prevent rapid error logging
                time.sleep(5)

    def start_monitoring(self) -> None:
        """
        Start system monitoring in a separate thread.
        """
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            self.logger.info("System monitoring started")

    def stop_monitoring(self) -> None:
        """
        Stop system monitoring.
        """
        if self.is_monitoring:
            self.is_monitoring = False
            if self.monitoring_thread:
                self.monitoring_thread.join()
            self.logger.info("System monitoring stopped")

    def get_recent_metrics(self, limit: int = 5) -> list:
        """
        Retrieve recent metric logs.

        Args:
            limit: Number of recent logs to retrieve

        Returns:
            List of recent metric logs
        """
        metric_files = sorted(
            [f for f in os.listdir(self.log_dir) if f.startswith("metrics_") and f.endswith(".json")], reverse=True
        )

        recent_metrics = []
        for file in metric_files[:limit]:
            with open(os.path.join(self.log_dir, file)) as f:
                recent_metrics.append(json.load(f))

        return recent_metrics
