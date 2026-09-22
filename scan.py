#!/usr/bin/env python3
import argparse
import logging
import os
import yaml
from datetime import datetime
from typing import Dict, List, Optional

# Cloud and Authentication Imports
import boto3
from azure.identity import DefaultAzureCredential

# Compliance and Security Modules
from modules.access_control import AccessControlScanner
from modules.audit_logging import AuditLoggingScanner
from modules.network_security import NetworkSecurityScanner
from modules.configuration_management import ConfigurationScanner
from modules.incident_response import IncidentResponseScanner

# New Security Modules
from modules.authentication import AuthenticationManager
from modules.encryption import SecureDataHandler, SecureKeyStorage
from modules.input_validator import InputValidator
from modules.rate_limiter import RateLimiter, RateLimit
from modules.monitoring import SystemMonitor
from modules.report_versioning import ReportVersionManager

# Observability and Monitoring
import prometheus_client
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# FastAPI (for API key exception type only)
from fastapi import HTTPException


class MultiTenantNISTComplianceScanner:
    def __init__(self, config_path: str, tenant_id: Optional[str] = None):
        """
        Initialize Multi-Tenant NIST 800-53 Compliance Scanner with enhanced security

        :param config_path: Path to configuration file
        :param tenant_id: Optional tenant identifier for multi-tenant mode
        """
        with open(config_path, "r") as config_file:
            self.config = yaml.safe_load(config_file)

        self.tenant_id = tenant_id

        # Initialize security modules
        key_storage_path = self.config.get("security", {}).get("master_key_path", ".keys/master.key")
        key_storage = SecureKeyStorage(key_storage_path)
        self.encryption_handler = SecureDataHandler(key_storage)

        self.auth_manager = AuthenticationManager()

        # Build RateLimiter with new API (dict of named limits)
        rate_cfg = self.config.get("security", {}).get("rate_limiting", {})
        max_req = rate_cfg.get("max_requests", 100)
        time_win = rate_cfg.get("time_window", 3600)
        self.rate_limiter = RateLimiter(
            limits={
                "default": RateLimit(
                    max_requests=max_req,
                    window_seconds=time_win,
                )
            }
        )

        self.monitoring_handler = SystemMonitor()
        self.report_manager = ReportVersionManager()

        self._setup_logging()
        self._setup_observability()

        # Tenant-specific configuration
        self.tenant_config = self._get_tenant_config() if tenant_id else self.config

    def _setup_logging(self) -> None:
        """Configure structured logging."""
        log_cfg = self.config.get("monitoring", {}).get("logging", {}).get("local", {})
        log_dir = log_cfg.get("path", "./logs")
        os.makedirs(log_dir, exist_ok=True)

        log_level = getattr(logging, self.config.get("global", {}).get("log_level", "INFO"), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(os.path.join(log_dir, "scanner.log")),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Logging initialised")

    def _setup_observability(self) -> None:
        """Set up OpenTelemetry tracing and Prometheus metrics."""
        monitoring_cfg = self.config.get("monitoring", {})

        # --- Prometheus metrics ---
        if monitoring_cfg.get("metrics", {}).get("prometheus", {}).get("enabled", False):
            prometheus_port = monitoring_cfg.get("metrics", {}).get("prometheus", {}).get("port", 9092)
            try:
                prometheus_client.start_http_server(prometheus_port)
                self.logger.info(f"Prometheus metrics server started on port {prometheus_port}")
            except OSError:
                self.logger.warning(f"Prometheus port {prometheus_port} already in use; skipping.")

        # Compliance scan counter metric
        self.compliance_scan_counter = prometheus_client.Counter(
            "nist_compliance_scans_total",
            "Total number of compliance scans",
            ["tenant_id", "cloud_provider"],
        )

        # --- OpenTelemetry tracing ---
        provider = TracerProvider()
        tracing_cfg = monitoring_cfg.get("metrics", {}).get("tracing", {}).get("jaeger", {})
        if tracing_cfg.get("enabled", False):
            # Use OTLP exporter (Jaeger supports OTLP natively since Jaeger 1.35+)
            otlp_endpoint = os.environ.get(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                f"http://{tracing_cfg.get('agent_host', 'localhost')}:4318",
            )
            try:
                exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
                provider.add_span_processor(BatchSpanProcessor(exporter))
                self.logger.info(f"OTLP trace exporter configured at {otlp_endpoint}")
            except Exception as exc:
                self.logger.warning(f"Could not configure OTLP exporter: {exc}")

        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer(__name__)

    def _get_tenant_config(self) -> Dict:
        """
        Return tenant-specific configuration, falling back to global config.

        :return: Tenant configuration dict
        """
        tenants = self.config.get("tenants", {})
        if self.tenant_id and self.tenant_id in tenants:
            # Merge tenant overrides onto a copy of the global config
            import copy

            merged = copy.deepcopy(self.config)
            merged.update(tenants[self.tenant_id])
            return merged
        return self.config

    def _validate_scan_parameters(self, scan_params: Dict) -> bool:
        """
        Validate scan parameters using new input validation module

        :param scan_params: Scan configuration parameters
        :return: Boolean indicating parameter validity
        """
        result = InputValidator.validate_scan_parameters(scan_params)
        return result.get("valid", False)

    def run_scans(self, api_key: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Run comprehensive security control scans with multi-tenant support and authentication

        :param api_key: Optional API key for authentication
        :return: Dictionary of scan results by control category
        """
        # Authenticate API key if provided
        if api_key:
            user = self.auth_manager.validate_api_key(api_key)
            if not user:
                raise HTTPException(status_code=401, detail="Invalid API key")

        # Rate limit scan execution
        is_limited, _ = self.rate_limiter.is_rate_limited("default", self.tenant_id or "default")
        if is_limited:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        scan_results: Dict[str, List[Dict]] = {
            "access_control": [],
            "audit_logging": [],
            "network_security": [],
            "configuration_management": [],
            "incident_response": [],
        }

        # Initialize scanners with tenant-specific configuration
        scanners = [
            AccessControlScanner(self.tenant_config),
            AuditLoggingScanner(self.tenant_config),
            NetworkSecurityScanner(self.tenant_config),
            ConfigurationScanner(self.tenant_config),
            IncidentResponseScanner(self.tenant_config),
        ]

        # Parallel scanning support
        if self.tenant_config.get("scan_options", {}).get("parallel_scanning", False):
            from concurrent.futures import ThreadPoolExecutor, as_completed

            max_workers = self.tenant_config["scan_options"].get("max_concurrent_scans", 5)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scanner.scan): scanner for scanner in scanners}
                for future in as_completed(futures):
                    scanner = futures[future]
                    category = scanner.__class__.__name__.lower().replace("scanner", "")
                    try:
                        scan_results[category] = future.result()
                        self.compliance_scan_counter.labels(
                            tenant_id=self.tenant_id or "default",
                            cloud_provider=category,
                        ).inc()
                    except Exception as e:
                        self.logger.error(f"Error in {scanner.__class__.__name__}: {e}")
        else:
            # Sequential scanning
            for scanner in scanners:
                category = scanner.__class__.__name__.lower().replace("scanner", "")
                try:
                    scan_results[category] = scanner.scan()
                    self.compliance_scan_counter.labels(
                        tenant_id=self.tenant_id or "default",
                        cloud_provider=category,
                    ).inc()
                except Exception as e:
                    self.logger.error(f"Error in {scanner.__class__.__name__}: {e}")

        # Encrypt sensitive scan results
        encrypted_results = self.encryption_handler.encrypt_data(scan_results)

        # Create versioned report
        self.report_manager.create_report_version(
            {
                "results": encrypted_results,
                "tenant_id": self.tenant_id,
            }
        )

        return scan_results

    def generate_report(self, scan_results: Dict[str, List[Dict]]) -> str:
        """
        Generate a comprehensive compliance report with tenant context

        :param scan_results: Dictionary of scan results
        :return: Path to the generated report file
        """
        report_filename = (
            f"nist_800_53_report_{self.tenant_id or 'default'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )

        with open(report_filename, "w") as report_file:
            report_file.write("# NIST 800-53 Compliance Report\n")
            report_file.write(f"## Tenant: {self.tenant_id or 'Default'}\n")
            report_file.write(f"## Scan Date: {datetime.now()}\n\n")

            total_controls = 0
            compliant_controls = 0

            for category, results in scan_results.items():
                report_file.write(f"## {category.replace('_', ' ').title()} Controls\n")

                for result in results:
                    total_controls += 1
                    status = "Compliant" if result["compliant"] else "Non-Compliant"
                    report_file.write(f"- **{result['control_id']}**: {status}\n")
                    report_file.write(f"  - Description: {result['description']}\n")

                    if not result["compliant"]:
                        report_file.write(
                            f"  - Remediation: {result.get('remediation', 'No specific remediation provided')}\n"
                        )

                    compliant_controls += 1 if result["compliant"] else 0

            compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
            report_file.write(f"\n## Overall Compliance: {compliance_percentage:.2f}%")

        self.logger.info(f"Compliance report generated: {report_filename}")
        return report_filename


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Tenant NIST 800-53 Security Compliance Scanner")
    parser.add_argument("--config", required=True, help="Path to configuration file")
    parser.add_argument("--tenant", help="Tenant identifier for multi-tenant scanning")
    parser.add_argument(
        "--environment",
        choices=["cloud", "onprem"],
        default="cloud",
        help="Environment type",
    )
    parser.add_argument("--api-key", help="API key for authenticated scanning")

    args = parser.parse_args()

    scanner = MultiTenantNISTComplianceScanner(args.config, args.tenant)
    scan_results = scanner.run_scans(api_key=args.api_key)
    scanner.generate_report(scan_results)


if __name__ == "__main__":
    main()
