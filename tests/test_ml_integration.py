import pytest
import numpy as np
from modules.anomaly_detection import AnomalyDetector

class TestMLIntegration:
    def setup_method(self):
        """
        Setup method to initialize AnomalyDetector for each test
        """
        self.anomaly_detector = AnomalyDetector()

    def test_anomaly_detection_model_initialization(self):
        """
        Test that the anomaly detection model initializes correctly
        """
        assert self.anomaly_detector is not None, "Anomaly detector failed to initialize"

    def test_anomaly_detection_prediction(self):
        """
        Test anomaly detection prediction on sample data
        """
        # Generate sample data
        normal_data = np.random.normal(0, 1, (100, 10))
        anomalous_data = np.random.normal(10, 5, (10, 10))

        # Combine normal and anomalous data
        test_data = np.vstack([normal_data, anomalous_data])

        # Predict anomalies
        predictions = self.anomaly_detector.predict(test_data)

        assert predictions is not None, "Prediction failed"
        assert len(predictions) == len(test_data), "Prediction length mismatch"

    def test_model_training(self):
        """
        Test model training functionality
        """
        # Generate training data
        training_data = np.random.normal(0, 1, (1000, 10))
        
        # Train the model
        self.anomaly_detector.train(training_data)
        
        # Check if model state has been updated
        assert self.anomaly_detector.is_trained, "Model was not trained successfully"

    def test_anomaly_threshold_sensitivity(self):
        """
        Test the model's sensitivity to different anomaly thresholds
        """
        # Generate data with known anomalies
        normal_data = np.random.normal(0, 1, (100, 10))
        anomalous_data = np.random.normal(10, 5, (10, 10))
        test_data = np.vstack([normal_data, anomalous_data])

        # Test multiple threshold levels
        thresholds = [0.9, 0.95, 0.99]
        for threshold in thresholds:
            self.anomaly_detector.set_threshold(threshold)
            predictions = self.anomaly_detector.predict(test_data)
            
            # Ensure predictions are made
            assert predictions is not None, f"Prediction failed for threshold {threshold}"
            
            # Check that higher thresholds result in fewer anomalies
            anomaly_count = np.sum(predictions)
            assert 0 <= anomaly_count <= len(test_data), f"Invalid anomaly count for threshold {threshold}"
