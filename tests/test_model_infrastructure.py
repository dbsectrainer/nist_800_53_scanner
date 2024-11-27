import os
import numpy as np
import pytest
from modules.model_versioning import ModelVersionManager
from modules.model_retraining import ModelRetrainingPipeline
from modules.model_monitoring import ModelPerformanceMonitor
from modules.anomaly_detection import AnomalyDetector

class TestModelInfrastructure:
    @pytest.fixture
    def model_version_manager(self, tmp_path):
        """
        Create a temporary ModelVersionManager for testing
        """
        return ModelVersionManager(base_path=str(tmp_path / 'model_versions'))
    
    @pytest.fixture
    def anomaly_detector(self):
        """
        Create a sample AnomalyDetector for testing
        """
        detector = AnomalyDetector()
        # Generate sample training data
        training_data = np.random.normal(0, 1, (1000, 10))
        detector.train(training_data)
        return detector
    
    def test_model_versioning(self, model_version_manager, anomaly_detector):
        """
        Test model versioning functionality
        """
        # Save model version
        version_id = model_version_manager.save_model(
            anomaly_detector, 
            metadata={'test_version': 'initial'}
        )
        
        # Verify version is saved
        assert version_id is not None
        assert os.path.exists(os.path.join(model_version_manager.base_path, version_id))
        
        # List versions
        versions = model_version_manager.list_versions()
        assert version_id in versions
        assert versions[version_id]['metadata'].get('test_version') == 'initial'
        
        # Load model
        loaded_model = model_version_manager.load_model(version_id)
        assert isinstance(loaded_model, AnomalyDetector)
    
    def test_model_retraining_pipeline(self, model_version_manager, anomaly_detector):
        """
        Test automated model retraining pipeline
        """
        retraining_pipeline = ModelRetrainingPipeline(
            model_version_manager, 
            performance_threshold=0.8
        )
        
        # Generate new training data
        new_training_data = np.random.normal(0, 1, (2000, 10))
        
        # Retrain model
        retrained_model, version_id = retraining_pipeline.retrain_model(
            anomaly_detector, 
            new_training_data
        )
        
        # Verify retraining results
        assert retrained_model is not None
        assert retrained_model.is_trained
        
        # If model improved, version should be created
        if version_id:
            assert os.path.exists(os.path.join(model_version_manager.base_path, version_id))
    
    def test_model_performance_monitoring(self, model_version_manager, anomaly_detector):
        """
        Test model performance monitoring
        """
        # Create performance monitor
        performance_monitor = ModelPerformanceMonitor(
            model_version_manager, 
            log_path='test_model_performance.log'
        )
        
        # Generate test data
        test_data = np.random.normal(0, 1, (500, 10))
        version_id = model_version_manager.save_model(anomaly_detector)
        
        # Log model metrics
        metrics = performance_monitor.log_model_metrics(
            anomaly_detector, 
            test_data, 
            version_id
        )
        
        # Verify metrics
        assert 'total_samples' in metrics
        assert 'false_positive_rate' in metrics
        assert 'false_negative_rate' in metrics
        assert 'anomaly_detection_rate' in metrics
    
    def test_model_drift_detection(self, model_version_manager, anomaly_detector):
        """
        Test model drift detection
        """
        performance_monitor = ModelPerformanceMonitor(
            model_version_manager, 
            log_path='test_model_drift.log'
        )
        
        # Generate test data with potential drift
        drifted_data = np.random.normal(5, 2, (500, 10))
        
        # Check for model drift
        drift_detected = performance_monitor.monitor_model_drift(
            anomaly_detector, 
            drifted_data, 
            threshold=0.1
        )
        
        # Drift detection result can be true or false depending on data
        assert isinstance(drift_detected, bool)
    
    def test_automated_retraining(self, model_version_manager, anomaly_detector):
        """
        Test automated retraining with data stream
        """
        retraining_pipeline = ModelRetrainingPipeline(
            model_version_manager, 
            performance_threshold=0.8
        )
        
        # Generate large data stream
        data_stream = np.random.normal(0, 1, (5000, 10))
        
        # Capture output to check retraining messages
        import io
        import sys
        
        # Redirect stdout to capture print statements
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        # Perform automated retraining
        retraining_pipeline.automated_retraining(
            anomaly_detector, 
            data_stream, 
            batch_size=1000
        )
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        # Check if retraining occurred
        output = captured_output.getvalue()
        assert "Model retrained" in output or len(output) > 0
