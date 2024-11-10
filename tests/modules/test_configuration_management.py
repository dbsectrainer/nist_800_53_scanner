import unittest
import sys
import os
import tempfile
import json

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.configuration_management import ConfigurationManagementScanner

class TestConfigurationManagementScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for configuration management scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'configuration': {
                'linux': {'enabled': True},
                'windows': {'enabled': False}
            }
        }
        self.scanner = ConfigurationManagementScanner(self.config)

    def test_baseline_configuration_check(self):
        """
        Test baseline configuration compliance checks
        """
        baseline_results = self.scanner._check_baseline_configurations()
        
        self.assertIsInstance(baseline_results, list, "Should return a list of baseline configuration findings")
        
        # Validate control IDs for baseline configurations
        control_ids = [result.get('control_id') for result in baseline_results]
        expected_controls = ['CM-2', 'CM-6']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_configuration_change_tracking(self):
        """
        Test configuration change tracking and monitoring
        """
        # Create a temporary configuration file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_config:
            json.dump({
                'network': {'firewall': 'enabled'},
                'security': {'encryption': 'AES-256'}
            }, temp_config)
            temp_config_path = temp_config.name

        try:
            # Simulate configuration change tracking
            change_results = self.scanner._track_configuration_changes([temp_config_path])
            
            self.assertIsInstance(change_results, list, "Should return a list of configuration change findings")
            
            # Check for configuration change control IDs
            control_ids = [result.get('control_id') for result in change_results]
            self.assertIn('CM-3', control_ids, "Should include configuration change control")

        finally:
            # Clean up temporary file
            os.unlink(temp_config_path)

    def test_software_inventory_check(self):
        """
        Test software and hardware inventory management
        """
        inventory_results = self.scanner._check_software_hardware_inventory()
        
        self.assertIsInstance(inventory_results, list, "Should return a list of inventory findings")
        
        # Validate inventory-related control IDs
        control_ids = [result.get('control_id') for result in inventory_results]
        expected_controls = ['CM-8', 'CM-7']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_configuration_scan_method(self):
        """
        Test scan method with different configuration scenarios
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'configuration': {
                'linux': {'enabled': False},
                'windows': {'enabled': False}
            }
        }
        disabled_scanner = ConfigurationManagementScanner(disabled_config)
        results = disabled_scanner.scan()
        
        # Should return an empty or minimal results list
        self.assertIsInstance(results, list, "Scan should always return a list")

    def test_security_parameter_configuration(self):
        """
        Test security parameter configuration checks
        """
        security_param_results = self.scanner._check_security_parameters()
        
        self.assertIsInstance(security_param_results, list, "Should return a list of security parameter findings")
        
        # Validate security parameter control IDs
        control_ids = [result.get('control_id') for result in security_param_results]
        expected_controls = ['CM-5', 'CM-6']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
