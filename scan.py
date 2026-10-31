#!/usr/bin/env python3
import argparse
import json
import logging
import os
import yaml
from datetime import datetime
from typing import Dict, List, Optional

# Assessment engine (collect -> evaluate -> prove)
from engine.coverage import summarize
from engine.models import AssessmentRun, Status
from engine.oscal import to_assessment_results, to_poam
from engine.runner import run_assessment

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



class ScanAuthError(PermissionError):
    """Invalid API key."""


class ScanRateLimitError(RuntimeError):
    """Scan rate limit exceeded."""


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

    def run_scans(
        self,
        api_key: Optional[str] = None,
        catalog_path: Optional[str] = None,
        rules_dir: Optional[str] = None,
        policy_path: Optional[str] = None,
    ) -> AssessmentRun:
        """
        Collect evidence and evaluate it against policy-as-code rules.

        Collector failures, missing or stale evidence produce ``not_assessed``
        results; they are never reported as compliant.

        :param api_key: Optional API key for authentication
        :return: The completed assessment run
        """
        if api_key:
            user = self.auth_manager.validate_api_key(api_key)
            if not user:
                raise ScanAuthError("Invalid API key")

        is_limited, _ = self.rate_limiter.is_rate_limited("default", self.tenant_id or "default")
        if is_limited:
            raise ScanRateLimitError("Rate limit exceeded")

        parallel = self.tenant_config.get("scan_options", {}).get("parallel_scanning", False)
        run = run_assessment(
            self.tenant_config,
            system_id=self.tenant_id or "default",
            rules_dir=rules_dir,
            policy_path=policy_path,
            catalog_path=catalog_path,
            parallel=parallel,
        )
        self.compliance_scan_counter.labels(
            tenant_id=self.tenant_id or "default", cloud_provider="engine"
        ).inc()

        # Encrypt and version the full run (evidence + assessments)
        self.report_manager.create_report_version(
            {"results": self.encryption_handler.encrypt_data(run.to_dict()), "tenant_id": self.tenant_id}
        )
        return run

    def generate_report(self, run: AssessmentRun, fmt: str = "markdown", output_dir: str = ".") -> str:
        """
        Write the assessment report.

        :param run: Completed assessment run
        :param fmt: markdown | json | oscal
        :return: Path to the generated report file
        """
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(output_dir, f"nist_800_53_report_{self.tenant_id or 'default'}_{stamp}")

        if fmt == "oscal":
            path = base + ".oscal.json"
            with open(path, "w") as fh:
                json.dump(to_assessment_results(run), fh, indent=2)
            poam = to_poam(run)
            # OSCAL forbids an empty poam-items list, so only write when findings are open.
            if poam["plan-of-action-and-milestones"]["poam-items"]:
                with open(base + ".poam.oscal.json", "w") as fh:
                    json.dump(poam, fh, indent=2)
        elif fmt == "json":
            path = base + ".json"
            with open(path, "w") as fh:
                json.dump({**run.to_dict(), "summary": summarize(run)}, fh, indent=2)
        elif fmt == "markdown":
            path = base + ".md"
            with open(path, "w") as fh:
                fh.write(self._render_markdown(run))
        else:
            raise ValueError(f"Unsupported report format: {fmt}")

        self.logger.info(f"Assessment report generated: {path}")
        return path

    def _render_markdown(self, run: AssessmentRun) -> str:
        summary = summarize(run)
        labels = {
            Status.SATISFIED: "Satisfied",
            Status.OTHER_THAN_SATISFIED: "Other than satisfied",
            Status.NOT_ASSESSED: "Not assessed",
            Status.NOT_APPLICABLE: "Not applicable",
        }
        lines = [
            "# NIST 800-53 Assessment Report",
            f"## System: {run.system_id}",
            f"## Run: {run.run_id} ({run.started_at.isoformat()})",
            "",
            "> Scanner output is evidence and recommendations only; it is not an authorization decision.",
            "",
            "## Summary",
            f"- Control coverage: {summary['controls_assessed']}/{summary['controls_total']} "
            f"controls assessed ({summary['control_coverage_pct']}%)",
        ]
        for status in Status:
            lines.append(f"- {labels[status]} objectives: {summary['objective_counts'].get(status.value, 0)}")
        lines += [
            f"- Evidence items: {summary['evidence_items']} (stale: {summary['evidence_stale']})",
            f"- Collection errors (coverage gaps): {summary['collection_errors']}",
            "",
        ]
        if run.errors:
            lines.append("## Collection errors")
            lines += [f"- **{e.collector}** ({e.evidence_type}): {e.message}" for e in run.errors]
            lines.append("")
        lines.append("## Assessments")
        for a in sorted(run.assessments, key=lambda x: (x.control_id, x.rule_id)):
            lines.append(f"- **{a.control_id}** {a.title} [{a.rule_id}]: {labels[a.status]}"
                         + (f" (asset {a.asset_id})" if a.asset_id else ""))
            if a.observed:
                lines.append(f"  - Observed: {a.observed}")
            if a.reason:
                lines.append(f"  - Reason: {a.reason}")
            if a.exception:
                lines.append(f"  - Exception: {a.exception}")
            if a.status == Status.OTHER_THAN_SATISFIED and a.recommended_action:
                lines.append(f"  - Recommended action: {a.recommended_action}")
            for ref in a.evidence_refs:
                lines.append(f"  - Evidence: {ref}")
        return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Tenant NIST 800-53 Security Compliance Scanner")
    parser.add_argument("--config", required=True, help="Path to configuration file")
    parser.add_argument("--tenant", help="Tenant identifier for multi-tenant scanning")
    parser.add_argument("--api-key", help="API key for authenticated scanning")
    parser.add_argument("--format", choices=["markdown", "json", "oscal"], default="markdown",
                        help="Report format (oscal writes assessment-results and POA&M)")
    parser.add_argument("--catalog", help="OSCAL catalog JSON (e.g. NIST SP 800-53 rev5) for coverage accounting")
    parser.add_argument("--rules-dir", help="Directory of policy-as-code rule files")
    parser.add_argument("--parameters", help="Organizational parameters/exceptions YAML")

    args = parser.parse_args()

    scanner = MultiTenantNISTComplianceScanner(args.config, args.tenant)
    run = scanner.run_scans(api_key=args.api_key, catalog_path=args.catalog,
                            rules_dir=args.rules_dir, policy_path=args.parameters)
    print(scanner.generate_report(run, fmt=args.format))


if __name__ == "__main__":
    main()
