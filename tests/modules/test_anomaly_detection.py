import unittest
import sys
import os
import numpy as np

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.anomaly_detection import AnomalyDetector

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for anomaly detector
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'anomaly_detection': {
                'enabled': True,
                'sensitivity': 0.1
            }
        }
        self.detector = AnomalyDetector(self.config)

    def test_severity_mapping(self):
        """
        Test severity mapping for different descriptions
        """
        test_cases = [
            ('Critical Security Vulnerability', 3),
            ('High Risk Configuration', 2),
            ('Medium Impact Finding', 1),
            ('Low Priority Issue', 0),
            ('Normal Configuration', 0)
        ]
        
        for description, expected_severity in test_cases:
            severity = self.detector._map_severity(description)
            self.assertEqual(severity, expected_severity, f"Failed for description: {description}")

    def test_detect_security_anomalies(self):
        """
        Test security anomaly detection
        """
        # Simulate scan results with some anomalies
        scan_results = [
            {
                'control_id': 'TEST-001',
                'description': 'Critical Security Configuration',
                'compliant': False,
                'details': {'risk_factor': 0.9}
            },
            {
                'control_id': 'TEST-002',
                'description': 'Normal Security Configuration',
                'compliant': True,
                'details': {'risk_factor': 0.1}
            },
            {
                'control_id': 'TEST-003',
                'description': 'High Risk Finding',
                'compliant': False,
                'details': {'risk_factor': 0.8}
            }
        ]
        
        anomalies = self.detector.detect_security_anomalies(scan_results)
        
        # Verify anomaly detection results
        self.assertIsInstance(anomalies, list, "Should return a list of anomalies")
        
        # Check anomaly result structure
        for anomaly in anomalies:
            self.assertIn('control_id', anomaly, "Anomaly should have a control ID")
            self.assertIn('description', anomaly, "Anomaly should have a description")
            self.assertIn('compliant', anomaly, "Anomaly should have a compliance status")
            self.assertIn('details', anomaly, "Anomaly should have details")
            self.assertIn('remediation', anomaly, "Anomaly should have remediation guidance")
            
            # Verify anomaly detection specifics
            self.assertFalse(anomaly['compliant'], "Anomalies should be marked as non-compliant")
            self.assertIn('anomaly_score', anomaly['details'], "Anomaly should have an anomaly score")

    def test_empty_scan_results(self):
        """
        Test anomaly detection with empty scan results
        """
        anomalies = self.detector.detect_security_anomalies([])
        
        # Should return an empty list or error handling result
        self.assertIsInstance(anomalies, list, "Should handle empty scan results")

    def test_single_scan_result(self):
        """
        Test anomaly detection with a single scan result
        """
        single_result = [
            {
                'control_id': 'TEST-SINGLE',
                'description': 'Single Configuration Check',
                'compliant': True,
                'details': {'check_type': 'basic'}
            }
        ]
        
        anomalies = self.detector.detect_security_anomalies(single_result)
        
        # Should return an empty list for insufficient data
        self.assertEqual(len(anomalies), 0, "Should not detect anomalies with insufficient data")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
