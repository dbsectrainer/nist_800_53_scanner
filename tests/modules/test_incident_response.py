import unittest
import sys
import os
import tempfile
import json
import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.incident_response import IncidentResponseScanner

class TestIncidentResponseScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for incident response scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'incident_response': {
                'linux': {'enabled': True},
                'windows': {'enabled': False}
            }
        }
        self.scanner = IncidentResponseScanner(self.config)

    def test_incident_response_plan_check(self):
        """
        Test incident response plan evaluation
        """
        plan_results = self.scanner._evaluate_incident_response_plan()
        
        self.assertIsInstance(plan_results, list, "Should return a list of incident response plan findings")
        
        # Validate control IDs for incident response planning
        control_ids = [result.get('control_id') for result in plan_results]
        expected_controls = ['IR-2', 'IR-4', 'IR-8']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_incident_detection_capabilities(self):
        """
        Test incident detection and monitoring mechanisms
        """
        # Simulate sample incident detection events
        sample_events = [
            {
                'timestamp': datetime.datetime.now().isoformat(),
                'type': 'unauthorized_access',
                'severity': 'high'
            },
            {
                'timestamp': (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
                'type': 'potential_malware',
                'severity': 'medium'
            }
        ]
        
        detection_results = self.scanner._check_incident_detection_capabilities(sample_events)
        
        self.assertIsInstance(detection_results, list, "Should return a list of incident detection findings")
        
        # Validate incident detection control IDs
        control_ids = [result.get('control_id') for result in detection_results]
        self.assertIn('IR-5', control_ids, "Should include incident tracking control")

    def test_incident_response_training_check(self):
        """
        Test incident response training and awareness evaluation
        """
        training_results = self.scanner._evaluate_incident_response_training()
        
        self.assertIsInstance(training_results, list, "Should return a list of incident response training findings")
        
        # Validate training-related control IDs
        control_ids = [result.get('control_id') for result in training_results]
        expected_controls = ['IR-2(1)', 'IR-2(2)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_incident_communication_protocols(self):
        """
        Test incident communication and reporting mechanisms
        """
        # Create a temporary communication log file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_log:
            json.dump({
                'incidents': [
                    {
                        'id': '001',
                        'reported_at': datetime.datetime.now().isoformat(),
                        'status': 'in_progress'
                    }
                ]
            }, temp_log)
            temp_log_path = temp_log.name

        try:
            communication_results = self.scanner._check_incident_communication_protocols([temp_log_path])
            
            self.assertIsInstance(communication_results, list, "Should return a list of communication protocol findings")
            
            # Check for communication-related control IDs
            control_ids = [result.get('control_id') for result in communication_results]
            self.assertIn('IR-6', control_ids, "Should include incident reporting control")

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
            'incident_response': {
                'linux': {'enabled': False},
                'windows': {'enabled': False}
            }
        }
        disabled_scanner = IncidentResponseScanner(disabled_config)
        results = disabled_scanner.scan()
        
        # Should return an empty or minimal results list
        self.assertIsInstance(results, list, "Scan should always return a list")

    def test_incident_containment_strategies(self):
        """
        Test incident containment and mitigation strategies
        """
        # Simulate an incident scenario
        incident_scenario = {
            'type': 'data_breach',
            'initial_detection_time': datetime.datetime.now().isoformat(),
            'affected_systems': ['web_server', 'database']
        }
        
        containment_results = self.scanner._evaluate_incident_containment(incident_scenario)
        
        self.assertIsInstance(containment_results, list, "Should return a list of containment strategy findings")
        
        # Validate containment-related control IDs
        control_ids = [result.get('control_id') for result in containment_results]
        expected_controls = ['IR-4', 'IR-7']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
