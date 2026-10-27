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
        rng = np.random.default_rng(0)
        self.anomaly_detector.train(rng.normal(0, 1, (1000, 10)))

        normal_data = rng.normal(0, 1, (100, 10))
        anomalous_data = rng.normal(10, 5, (10, 10))
        test_data = np.vstack([normal_data, anomalous_data])

        predictions = self.anomaly_detector.predict(test_data)

        assert len(predictions) == len(test_data), "Prediction length mismatch"
        assert set(np.unique(predictions)) <= {0, 1}, "Predictions must be 0 (normal) or 1 (anomaly)"
        assert predictions[100:].mean() > 0.8, "Far-out points should be flagged as anomalies"
        assert predictions[:100].mean() < 0.3, "In-distribution points should mostly pass"

    def test_predict_requires_training(self):
        with pytest.raises(RuntimeError, match="trained"):
            self.anomaly_detector.predict(np.zeros((3, 10)))

    def test_train_rejects_unusable_data(self):
        with pytest.raises(ValueError):
            self.anomaly_detector.train(np.zeros(10))  # 1-D
        with pytest.raises(ValueError):
            self.anomaly_detector.train(np.zeros((1, 10)))  # single sample

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
        Higher contamination (the detector's sensitivity setting) flags at least as many points
        """
        rng = np.random.default_rng(1)
        training_data = rng.normal(0, 1, (1000, 10))
        test_data = np.vstack([rng.normal(0, 1, (100, 10)), rng.normal(10, 5, (10, 10))])

        anomaly_counts = []
        for contamination in [0.02, 0.1, 0.3]:
            detector = AnomalyDetector(config={'contamination': contamination})
            detector.train(training_data)
            anomaly_counts.append(int(np.sum(detector.predict(test_data))))

        assert anomaly_counts == sorted(anomaly_counts), f"Sensitivity should be monotonic: {anomaly_counts}"
        assert anomaly_counts[-1] > anomaly_counts[0], "Highest sensitivity should flag more points than lowest"
