import logging
from typing import Any

import numpy as np

from .anomaly_detection import AnomalyDetector
from .model_versioning import ModelVersionManager


class ModelPerformanceMonitor:
    """
    Tracks anomaly detection model quality and detects data drift
    """

    def __init__(self, model_version_manager: ModelVersionManager, log_path: str = 'model_performance.log'):
        """
        :param model_version_manager: Manager for the versions being monitored
        :param log_path: File that metric and drift records are appended to
        """
        self.model_version_manager = model_version_manager
        self.log_path = log_path
        self.logger = logging.getLogger(f"{__name__}.{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self._handler = logging.FileHandler(log_path)
        self._handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.logger.addHandler(self._handler)

    def close(self) -> None:
        self.logger.removeHandler(self._handler)
        self._handler.close()

    def log_model_metrics(self, model: AnomalyDetector, test_data: np.ndarray,
                          version_id: str) -> dict[str, Any]:
        """
        Score the model on test data and log the result

        Rows whose feature mean is negative are treated as the expected-normal
        class (matching ModelRetrainingPipeline), the rest as expected-anomalous.

        :return: Metrics dictionary
        """
        predictions = model.predict(test_data)
        expected_normal = test_data.mean(axis=1) < 0

        normal_preds = predictions[expected_normal]
        anomalous_preds = predictions[~expected_normal]
        metrics = {
            'version_id': version_id,
            'total_samples': int(len(test_data)),
            'false_positive_rate': float(np.mean(normal_preds)) if len(normal_preds) else 0.0,
            'false_negative_rate': float(1 - np.mean(anomalous_preds)) if len(anomalous_preds) else 0.0,
            'anomaly_detection_rate': float(np.mean(predictions)) if len(predictions) else 0.0,
        }
        self.logger.info("model_metrics %s", metrics)
        return metrics

    def monitor_model_drift(self, model: AnomalyDetector, new_data: np.ndarray,
                            threshold: float = 0.1) -> bool:
        """
        Detect drift as the anomaly rate on new data exceeding the training
        contamination rate by more than the threshold

        :return: True if drift is detected
        """
        expected_rate = model.detection_thresholds['contamination']
        observed_rate = float(np.mean(model.predict(new_data)))
        drifted = bool(observed_rate - expected_rate > threshold)
        level = logging.WARNING if drifted else logging.INFO
        self.logger.log(level, "drift_check observed=%.3f expected=%.3f threshold=%.3f drifted=%s",
                        observed_rate, expected_rate, threshold, drifted)
        return drifted
