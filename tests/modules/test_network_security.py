import unittest
import sys
import os
import tempfile
import json
import ipaddress

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.network_security import NetworkSecurityScanner

class TestNetworkSecurityScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for network security scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'network_security': {
                'linux': {'enabled': True},
                'windows': {'enabled': False}
            }
        }
        self.scanner = NetworkSecurityScanner(self.config)

    def test_firewall_configuration_check(self):
        """
        Test firewall configuration and rule analysis
        """
        # Create a temporary firewall configuration file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_firewall_config:
            json.dump({
                'rules': [
                    {
                        'source': '0.0.0.0/0',
                        'destination': '192.168.1.0/24',
                        'port': 22,
                        'action': 'allow'
                    }
                ]
            }, temp_firewall_config)
            temp_config_path = temp_firewall_config.name

        try:
            firewall_results = self.scanner._check_firewall_configurations([temp_config_path])
            
            self.assertIsInstance(firewall_results, list, "Should return a list of firewall configuration findings")
            
            # Validate firewall-related control IDs
            control_ids = [result.get('control_id') for result in firewall_results]
            expected_controls = ['SC-7', 'SC-7(3)', 'SC-7(4)']
            
            for control in expected_controls:
                self.assertIn(control, control_ids, f"Missing expected control {control}")

        finally:
            # Clean up temporary file
            os.unlink(temp_config_path)

    def test_network_segmentation_check(self):
        """
        Test network segmentation and isolation mechanisms
        """
        # Simulate network topology
        network_topology = {
            'subnets': [
                {'name': 'DMZ', 'cidr': '192.168.10.0/24'},
                {'name': 'Internal', 'cidr': '192.168.20.0/24'},
                {'name': 'Management', 'cidr': '192.168.30.0/24'}
            ]
        }
        
        segmentation_results = self.scanner._check_network_segmentation(network_topology)
        
        self.assertIsInstance(segmentation_results, list, "Should return a list of network segmentation findings")
        
        # Validate network segmentation control IDs
        control_ids = [result.get('control_id') for result in segmentation_results]
        expected_controls = ['SC-32', 'SC-7(2)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_remote_access_security(self):
        """
        Test remote access security configurations
        """
        # Simulate remote access configuration
        remote_access_config = {
            'vpn': {
                'enabled': True,
                'authentication_method': 'multi-factor'
            },
            'ssh': {
                'port': 22,
                'protocol_version': '2'
            }
        }
        
        remote_access_results = self.scanner._check_remote_access_security(remote_access_config)
        
        self.assertIsInstance(remote_access_results, list, "Should return a list of remote access security findings")
        
        # Validate remote access control IDs
        control_ids = [result.get('control_id') for result in remote_access_results]
        expected_controls = ['AC-17', 'AC-17(1)', 'AC-17(2)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_intrusion_detection_check(self):
        """
        Test intrusion detection and prevention system configurations
        """
        # Create a temporary IDS/IPS log file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_ids_log:
            json.dump({
                'alerts': [
                    {
                        'timestamp': '2023-06-15T10:00:00',
                        'source_ip': '203.0.113.45',
                        'type': 'potential_scan',
                        'severity': 'medium'
                    }
                ]
            }, temp_ids_log)
            temp_log_path = temp_ids_log.name

        try:
            ids_results = self.scanner._check_intrusion_detection_systems([temp_log_path])
            
            self.assertIsInstance(ids_results, list, "Should return a list of IDS/IPS findings")
            
            # Check for IDS/IPS related control IDs
            control_ids = [result.get('control_id') for result in ids_results]
            self.assertIn('SI-4', control_ids, "Should include intrusion monitoring control")

        finally:
            # Clean up temporary file
            os.unlink(temp_log_path)

    def test_scan_method_configuration(self):
        """
        Test scan method with different configuration scenarios
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'network_security': {
                'linux': {'enabled': False},
                'windows': {'enabled': False}
            }
        }
        disabled_scanner = NetworkSecurityScanner(disabled_config)
        results = disabled_scanner.scan()
        
        # Should return an empty or minimal results list
        self.assertIsInstance(results, list, "Scan should always return a list")

    def test_dns_security_check(self):
        """
        Test DNS security configurations and monitoring
        """
        # Simulate DNS configuration
        dns_config = {
            'resolvers': ['8.8.8.8', '1.1.1.1'],
            'dnssec': {'enabled': True},
            'cache_poisoning_mitigation': True
        }
        
        dns_results = self.scanner._check_dns_security(dns_config)
        
        self.assertIsInstance(dns_results, list, "Should return a list of DNS security findings")
        
        # Validate DNS security control IDs
        control_ids = [result.get('control_id') for result in dns_results]
        expected_controls = ['SC-20', 'SC-21']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
