#!/usr/bin/env python3
import argparse
import yaml
import logging
from typing import Dict, List, Optional
from datetime import datetime
from functools import wraps

# Cloud and Authentication Imports
import boto3
from azure.identity import DefaultAzureCredential
from google.cloud import core
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

# Compliance and Security Modules
from modules.access_control import AccessControlScanner
from modules.audit_logging import AuditLoggingScanner
from modules.network_security import NetworkSecurityScanner
from modules.configuration_management import ConfigurationScanner
from modules.incident_response import IncidentResponseScanner

# New Security Modules
from modules.authentication import AuthenticationManager
from modules.encryption import SecureDataHandler
from modules.input_validator import InputValidator
from modules.rate_limiter import RateLimiter
from modules.monitoring import SystemMonitor
from modules.report_versioning import ReportVersionManager

# Observability and Monitoring
import prometheus_client
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter

class MultiTenantNISTComplianceScanner:
    def __init__(self, config_path: str, tenant_id: Optional[str] = None):
        """
        Initialize Multi-Tenant NIST 800-53 Compliance Scanner with enhanced security
        
        :param config_path: Path to configuration file
        :param tenant_id: Optional tenant identifier for multi-tenant mode
        """
        with open(config_path, 'r') as config_file:
            self.config = yaml.safe_load(config_file)
        
        self.tenant_id = tenant_id
        
        # Initialize new security modules
        self.auth_manager = AuthenticationManager()
        self.encryption_handler = SecureDataHandler()
        self.rate_limiter = RateLimiter(max_requests=100, time_window=3600)
        self.monitoring_handler = SystemMonitor()
        self.report_manager = ReportVersionManager()
        
        self._setup_logging()
        self._setup_observability()
        
        # Tenant-specific configuration
        self.tenant_config = self._get_tenant_config() if tenant_id else self.config

    def _validate_scan_parameters(self, scan_params: Dict) -> bool:
        """
        Validate scan parameters using new input validation module
        
        :param scan_params: Scan configuration parameters
        :return: Boolean indicating parameter validity
        """
        return InputValidator.validate_scan_parameters(scan_params)

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
        if not self.rate_limiter.is_allowed(self.tenant_id or 'default'):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        scan_results = {
            'access_control': [],
            'audit_logging': [],
            'network_security': [],
            'configuration_management': [],
            'incident_response': []
        }

        # Initialize scanners with tenant-specific configuration
        scanners = [
            AccessControlScanner(self.tenant_config),
            AuditLoggingScanner(self.tenant_config),
            NetworkSecurityScanner(self.tenant_config),
            ConfigurationScanner(self.tenant_config),
            IncidentResponseScanner(self.tenant_config)
        ]

        # Parallel scanning support
        if self.tenant_config.get('scan_options', {}).get('parallel_scanning', False):
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=self.tenant_config['scan_options'].get('max_concurrent_scans', 5)) as executor:
                futures = {executor.submit(scanner.scan): scanner for scanner in scanners}
                for future in as_completed(futures):
                    scanner = futures[future]
                    category = scanner.__class__.__name__.lower().replace('scanner', '')
                    try:
                        scan_results[category] = future.result()
                        # Record metrics
                        self.compliance_scan_counter.labels(
                            tenant_id=self.tenant_id or 'default', 
                            cloud_provider=category
                        ).inc()
                    except Exception as e:
                        self.logger.error(f"Error in {scanner.__class__.__name__}: {str(e)}")
        else:
            # Sequential scanning
            for scanner in scanners:
                category = scanner.__class__.__name__.lower().replace('scanner', '')
                try:
                    scan_results[category] = scanner.scan()
                    # Record metrics
                    self.compliance_scan_counter.labels(
                        tenant_id=self.tenant_id or 'default', 
                        cloud_provider=category
                    ).inc()
                except Exception as e:
                    self.logger.error(f"Error in {scanner.__class__.__name__}: {str(e)}")

        # Encrypt sensitive scan results
        encrypted_results = self.encryption_handler.encrypt_data(scan_results)
        
        # Create versioned report
        self.report_manager.create_report_version({
            'results': encrypted_results,
            'tenant_id': self.tenant_id
        })

        return scan_results

    def generate_report(self, scan_results: Dict[str, List[Dict]]):
        """
        Generate a comprehensive compliance report with tenant context
        
        :param scan_results: Dictionary of scan results
        """
        report_filename = f'nist_800_53_report_{self.tenant_id or "default"}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        
        with open(report_filename, 'w') as report_file:
            report_file.write(f"# NIST 800-53 Compliance Report\n")
            report_file.write(f"## Tenant: {self.tenant_id or 'Default'}\n")
            report_file.write(f"## Scan Date: {datetime.now()}\n\n")

            total_controls = 0
            compliant_controls = 0

            for category, results in scan_results.items():
                report_file.write(f"## {category.replace('_', ' ').title()} Controls\n")
                
                for result in results:
                    total_controls += 1
                    status = "✅ Compliant" if result['compliant'] else "❌ Non-Compliant"
                    report_file.write(f"- **{result['control_id']}**: {status}\n")
                    report_file.write(f"  - Description: {result['description']}\n")
                    
                    if not result['compliant']:
                        report_file.write(f"  - Remediation: {result.get('remediation', 'No specific remediation provided')}\n")
                    
                    compliant_controls += 1 if result['compliant'] else 0

            # Overall compliance summary
            compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
            report_file.write(f"\n## Overall Compliance: {compliance_percentage:.2f}%")

        self.logger.info(f"Compliance report generated: {report_filename}")
        return report_filename

def main():
    parser = argparse.ArgumentParser(description='Multi-Tenant NIST 800-53 Security Compliance Scanner')
    parser.add_argument('--config', required=True, help='Path to configuration file')
    parser.add_argument('--tenant', help='Tenant identifier for multi-tenant scanning')
    parser.add_argument('--environment', choices=['cloud', 'onprem'], default='cloud', help='Environment type')
    parser.add_argument('--api-key', help='API key for authenticated scanning')
    
    args = parser.parse_args()

    scanner = MultiTenantNISTComplianceScanner(args.config, args.tenant)
    scan_results = scanner.run_scans(api_key=args.api_key)
    scanner.generate_report(scan_results)

if __name__ == '__main__':
    main()
