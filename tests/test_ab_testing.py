import numpy as np
import pytest
from modules.ab_testing import MLModelABTester
from modules.model_versioning import ModelVersionManager
from modules.anomaly_detection import AnomalyDetector

class TestMLABTesting:
    @pytest.fixture
    def model_version_manager(self, tmp_path):
        """
        Create a temporary ModelVersionManager for testing
        """
        return ModelVersionManager(base_path=str(tmp_path / 'model_versions'))
    
    @pytest.fixture
    def sample_anomaly_detectors(self):
        """
        Create sample anomaly detection models with different configurations
        """
        models = []
        for threshold in [0.5, 0.7, 0.9]:
            model = AnomalyDetector(threshold=threshold)
            training_data = np.random.normal(0, 1, (1000, 10))
            model.train(training_data)
            models.append(model)
        return models
    
    def test_ab_testing_model_comparison(self, model_version_manager, sample_anomaly_detectors):
        """
        Test model comparison in A/B testing
        """
        ab_tester = MLModelABTester(model_version_manager)
        
        # Generate test data
        test_data = np.random.normal(0, 1, (500, 10))
        ground_truth = np.random.randint(0, 2, 500)
        
        # Save models and get version IDs
        version_ids = [
            model_version_manager.save_model(model) 
            for model in sample_anomaly_detectors
        ]
        
        # Compare models
        performances = ab_tester.compare_models(version_ids, test_data, ground_truth)
        
        # Verify results
        assert len(performances) == len(version_ids)
        for performance in performances.values():
            assert 0 <= performance <= 1
    
    def test_ab_testing_experiment(self, model_version_manager, sample_anomaly_detectors):
        """
        Test full A/B testing experiment
        """
        ab_tester = MLModelABTester(model_version_manager)
        
        # Generate test data
        test_data = np.random.normal(0, 1, (500, 10))
        ground_truth = np.random.randint(0, 2, 500)
        
        # Run experiment
        experiment_results = ab_tester.run_experiment(
            sample_anomaly_detectors, 
            test_data, 
            ground_truth
        )
        
        # Verify experiment results
        assert 'model_performances' in experiment_results
        assert 'best_model_version' in experiment_results
        assert 'performance_std' in experiment_results
        assert 'statistically_significant' in experiment_results
    
    def test_model_configuration_experiment(self, model_version_manager):
        """
        Test generating model variants with different configurations
        """
        ab_tester = MLModelABTester(model_version_manager)
        
        # Base model
        base_model = AnomalyDetector()
        
        # Parameter grid for experiment
        parameter_grid = {
            'threshold': [0.5, 0.7, 0.9],
        }
        
        # Generate model variants
        model_variants = ab_tester.configure_experiment(base_model, parameter_grid)
        
        # Verify variants
        assert len(model_variants) == 3
        thresholds = [model.threshold for model in model_variants]
        assert set(thresholds) == {0.5, 0.7, 0.9}
    
    def test_custom_evaluation_metric(self, model_version_manager, sample_anomaly_detectors):
        """
        Test A/B testing with a custom evaluation metric
        """
        # Custom evaluation metric (e.g., precision)
        def precision_metric(predictions, ground_truth):
            true_positives = np.sum((predictions == 1) & (ground_truth == 1))
            predicted_positives = np.sum(predictions == 1)
            return true_positives / predicted_positives if predicted_positives > 0 else 0
        
        ab_tester = MLModelABTester(
            model_version_manager, 
            evaluation_metric=precision_metric
        )
        
        # Generate test data
        test_data = np.random.normal(0, 1, (500, 10))
        ground_truth = np.random.randint(0, 2, 500)
        
        # Save models and get version IDs
        version_ids = [
            model_version_manager.save_model(model) 
            for model in sample_anomaly_detectors
        ]
        
        # Compare models with custom metric
        performances = ab_tester.compare_models(version_ids, test_data, ground_truth)
        
        # Verify results
        assert len(performances) == len(version_ids)
        for performance in performances.values():
            assert 0 <= performance <= 1
