#!/usr/bin/env python3
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
from typing import Any

class AnomalyDetector:
    def __init__(self, config: dict):
        """
        Initialize Anomaly Detection module
        
        :param config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Anomaly detection configuration
        self.detection_thresholds = {
            'contamination': 0.1,  # 10% of data points considered potential anomalies
            'max_features': 10,
            'random_state': 42
        }

    def _prepare_security_data(self, scan_results: list[dict[str, Any]]) -> pd.DataFrame:
        """
        Prepare security scan data for anomaly detection
        
        :param scan_results: List of security scan results
        :return: Prepared DataFrame for anomaly detection
        """
        # Extract relevant features for anomaly detection
        features = []
        for result in scan_results:
            feature_vector = {
                'compliant': int(result.get('compliant', False)),
                'severity': self._map_severity(result.get('description', '')),
                'control_complexity': len(result.get('details', {}))
            }
            features.append(feature_vector)
        
        return pd.DataFrame(features)

    def _map_severity(self, description: str) -> int:
        """
        Map description to severity level
        
        :param description: Result description
        :return: Severity level (0-3)
        """
        severity_map = {
            'critical': 3,
            'high': 2,
            'medium': 1,
            'low': 0
        }
        
        description_lower = description.lower()
        for key, value in severity_map.items():
            if key in description_lower:
                return value
        
        return 0

    def detect_security_anomalies(self, scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect anomalies in security scan results using Isolation Forest
        
        :param scan_results: List of security scan results
        :return: List of detected anomalies
        """
        anomalies = []
        
        try:
            # Prepare data
            data = self._prepare_security_data(scan_results)
            
            # Check if we have enough data
            if len(data) < 2:
                return anomalies
            
            # Scale features
            scaler = StandardScaler()
            scaled_data = scaler.fit_transform(data)
            
            # Isolation Forest for anomaly detection
            clf = IsolationForest(
                contamination=self.detection_thresholds['contamination'],
                random_state=self.detection_thresholds['random_state']
            )
            
            # Predict anomalies
            predictions = clf.fit_predict(scaled_data)
            
            # Process anomalies
            for idx, prediction in enumerate(predictions):
                if prediction == -1:  # Anomaly detected
                    anomaly = {
                        'control_id': 'ANOMALY-ML-001',
                        'description': 'Machine Learning Detected Security Anomaly',
                        'compliant': False,
                        'details': {
                            'original_result': scan_results[idx],
                            'anomaly_score': clf.decision_function([scaled_data[idx]])[0]
                        },
                        'remediation': 'Investigate the flagged security configuration for potential risks'
                    }
                    anomalies.append(anomaly)
            
            self.logger.info(f"Detected {len(anomalies)} security anomalies")
        
        except Exception as e:
            self.logger.error(f"Anomaly Detection Error: {e}")
            anomalies.append({
                'control_id': 'ANOMALY-ERROR-001',
                'description': 'Anomaly Detection Failure',
                'compliant': False,
                'details': {'error': str(e)},
                'remediation': 'Review and fix anomaly detection module'
            })
        
        return anomalies
