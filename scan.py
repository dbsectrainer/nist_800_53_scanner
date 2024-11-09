#!/usr/bin/env python3
import argparse
import yaml
import logging
from typing import Dict, List
from datetime import datetime

# Import security control modules
from modules.access_control import AccessControlScanner
from modules.audit_logging import AuditLoggingScanner
from modules.network_security import NetworkSecurityScanner
from modules.configuration_management import ConfigurationScanner
from modules.incident_response import IncidentResponseScanner

class NISTComplianceScanner:
    def __init__(self, config_path: str):
        """
        Initialize the NIST 800-53 compliance scanner
        
        :param config_path: Path to configuration file
        """
        with open(config_path, 'r') as config_file:
            self.config = yaml.safe_load(config_file)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='nist_compliance_scan.log'
        )
        self.logger = logging.getLogger(__name__)

    def run_scans(self) -> Dict[str, List[Dict]]:
        """
        Run comprehensive security control scans
        
        :return: Dictionary of scan results by control category
        """
        scan_results = {
            'access_control': [],
            'audit_logging': [],
            'network_security': [],
            'configuration_management': [],
            'incident_response': []
        }

        # Initialize scanners
        scanners = [
            AccessControlScanner(self.config),
            AuditLoggingScanner(self.config),
            NetworkSecurityScanner(self.config),
            ConfigurationScanner(self.config),
            IncidentResponseScanner(self.config)
        ]

        # Run each scanner and collect results
        for scanner in scanners:
            try:
                category = scanner.__class__.__name__.lower().replace('scanner', '')
                scan_results[category] = scanner.scan()
            except Exception as e:
                self.logger.error(f"Error in {scanner.__class__.__name__}: {str(e)}")

        return scan_results

    def generate_report(self, scan_results: Dict[str, List[Dict]]):
        """
        Generate a comprehensive compliance report
        
        :param scan_results: Dictionary of scan results
        """
        report_filename = f'nist_800_53_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
        
        with open(report_filename, 'w') as report_file:
            report_file.write("# NIST 800-53 Compliance Scan Report\n")
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
        print(f"Compliance report generated: {report_filename}")

def main():
    parser = argparse.ArgumentParser(description='NIST 800-53 Security Compliance Scanner')
    parser.add_argument('--config', required=True, help='Path to configuration file')
    parser.add_argument('--environment', choices=['cloud', 'onprem'], default='cloud', help='Environment type')
    
    args = parser.parse_args()

    scanner = NISTComplianceScanner(args.config)
    scan_results = scanner.run_scans()
    scanner.generate_report(scan_results)

if __name__ == '__main__':
    main()
