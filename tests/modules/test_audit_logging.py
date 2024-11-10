import unittest
import sys
import os
import tempfile
import json
import logging

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.audit_logging import AuditLoggingScanner

class TestAuditLoggingScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for audit logging scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'logging': {
                'linux': {'enabled': True},
                'windows': {'enabled': False}
            }
        }
        self.scanner = AuditLoggingScanner(self.config)

    def test_check_log_retention(self):
        """
        Test log retention policy checks
        """
        retention_results = self.scanner._check_log_retention()
        
        self.assertIsInstance(retention_results, list, "Should return a list of log retention findings")
        
        # Validate control IDs for log retention
        control_ids = [result.get('control_id') for result in retention_results]
        expected_controls = ['AU-11', 'AU-7']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_check_log_integrity(self):
        """
        Test log file integrity checks
        """
        # Create a temporary log file for testing
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_log:
            temp_log.write("Test log entry\n")
            temp_log_path = temp_log.name

        try:
            integrity_results = self.scanner._check_log_integrity([temp_log_path])
            
            self.assertIsInstance(integrity_results, list, "Should return a list of log integrity findings")
            
            # Check for specific control IDs related to log integrity
            control_ids = [result.get('control_id') for result in integrity_results]
            self.assertIn('AU-9', control_ids, "Should check log integrity control")

        finally:
            # Clean up temporary file
            os.unlink(temp_log_path)

    def test_check_logging_configuration(self):
        """
        Test logging system configuration checks
        """
        config_results = self.scanner._check_logging_configuration()
        
        self.assertIsInstance(config_results, list, "Should return a list of logging configuration findings")
        
        # Validate key logging configuration controls
        expected_controls = ['AU-2', 'AU-3', 'AU-12']
        control_ids = [result.get('control_id') for result in config_results]
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_scan_method_configuration(self):
        """
        Test scan method with different configuration scenarios
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'logging': {
                'linux': {'enabled': False},
                'windows': {'enabled': False}
            }
        }
        disabled_scanner = AuditLoggingScanner(disabled_config)
        results = disabled_scanner.scan()
        
        # Should return an empty or minimal results list
        self.assertIsInstance(results, list, "Scan should always return a list")

    def test_log_event_correlation(self):
        """
        Test log event correlation and analysis
        """
        # Simulate log events
        log_events = [
            {'timestamp': '2023-06-15T10:00:00', 'source': 'auth', 'event_type': 'login'},
            {'timestamp': '2023-06-15T10:05:00', 'source': 'network', 'event_type': 'connection'}
        ]
        
        correlation_results = self.scanner._correlate_log_events(log_events)
        
        self.assertIsInstance(correlation_results, list, "Should return a list of correlated findings")
        
        # Check for specific correlation control
        control_ids = [result.get('control_id') for result in correlation_results]
        self.assertIn('AU-6', control_ids, "Should include log analysis control")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
