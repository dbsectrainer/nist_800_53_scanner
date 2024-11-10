import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.cloud_access_scanner import CloudAccessScanner

class TestCloudAccessScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for cloud access scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'aws': {'enabled': True},
            'azure': {'enabled': False},
            'gcp': {'enabled': False}
        }
        self.scanner = CloudAccessScanner(self.config)

    def test_aws_access_controls(self):
        """
        Test AWS access control scanning
        """
        results = self.scanner._scan_aws_access_controls()
        
        self.assertIsInstance(results, list, "Should return a list of findings")
        
        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-2(1)', 'AC-3(7)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_azure_access_controls(self):
        """
        Test Azure access control scanning
        """
        results = self.scanner._scan_azure_access_controls()
        
        self.assertIsInstance(results, list, "Should return a list of findings")
        
        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-2(3)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_gcp_access_controls(self):
        """
        Test Google Cloud Platform access control scanning
        """
        results = self.scanner._scan_gcp_access_controls()
        
        self.assertIsInstance(results, list, "Should return a list of findings")
        
        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-3(5)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_cloud_access_controls_scanning(self):
        """
        Test comprehensive cloud access controls scanning
        """
        results = self.scanner.scan_cloud_access_controls()
        
        self.assertIsInstance(results, list, "Should return a list of findings")
        
        # Verify result structure
        for result in results:
            self.assertIn('control_id', result, "Each result should have a control ID")
            self.assertIn('description', result, "Each result should have a description")
            self.assertIn('compliant', result, "Each result should have a compliance status")
            self.assertIn('details', result, "Each result should have details")
            self.assertIn('remediation', result, "Each result should have remediation guidance")

    def test_cloud_provider_configuration(self):
        """
        Test scanning with different cloud provider configurations
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'aws': {'enabled': False},
            'azure': {'enabled': False},
            'gcp': {'enabled': False}
        }
        disabled_scanner = CloudAccessScanner(disabled_config)
        results = disabled_scanner.scan_cloud_access_controls()
        
        # Should return an empty list
        self.assertEqual(len(results), 0, "Should return an empty list when no providers are enabled")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
