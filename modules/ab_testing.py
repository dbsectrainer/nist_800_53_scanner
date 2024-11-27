import numpy as np
from typing import List, Dict, Any, Callable
from .model_versioning import ModelVersionManager
from .anomaly_detection import AnomalyDetector

class MLModelABTester:
    """
    A/B Testing framework for machine learning models
    Supports comparing multiple model versions and configurations
    """
    def __init__(self, 
                 model_version_manager: ModelVersionManager,
                 evaluation_metric: Callable[[np.ndarray, np.ndarray], float] = None):
        """
        Initialize A/B Testing framework
        
        :param model_version_manager: Manager for model versions
        :param evaluation_metric: Custom metric for model comparison
        """
        self.model_version_manager = model_version_manager
        self.evaluation_metric = evaluation_metric or self._default_evaluation_metric
    
    def _default_evaluation_metric(self, 
                                   predictions: np.ndarray, 
                                   ground_truth: np.ndarray) -> float:
        """
        Default evaluation metric (F1 Score)
        
        :param predictions: Model predictions
        :param ground_truth: Actual labels
        :return: Performance score
        """
        # Compute precision
        true_positives = np.sum((predictions == 1) & (ground_truth == 1))
        predicted_positives = np.sum(predictions == 1)
        precision = true_positives / predicted_positives if predicted_positives > 0 else 0
        
        # Compute recall
        actual_positives = np.sum(ground_truth == 1)
        recall = true_positives / actual_positives if actual_positives > 0 else 0
        
        # Compute F1 Score
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return f1_score
    
    def compare_models(self, 
                       version_ids: List[str], 
                       test_data: np.ndarray, 
                       ground_truth: np.ndarray) -> Dict[str, float]:
        """
        Compare multiple model versions
        
        :param version_ids: List of model version identifiers
        :param test_data: Test dataset
        :param ground_truth: Ground truth labels
        :return: Performance scores for each model
        """
        model_performances = {}
        
        for version_id in version_ids:
            try:
                # Load model
                model = self.model_version_manager.load_model(version_id)
                
                # Make predictions
                predictions = model.predict(test_data)
                
                # Evaluate model
                performance = self.evaluation_metric(predictions, ground_truth)
                
                model_performances[version_id] = performance
            
            except Exception as e:
                print(f"Error evaluating model {version_id}: {e}")
        
        return model_performances
    
    def run_experiment(self, 
                       models: List[AnomalyDetector], 
                       test_data: np.ndarray, 
                       ground_truth: np.ndarray, 
                       significance_level: float = 0.05) -> Dict[str, Any]:
        """
        Run a full A/B testing experiment
        
        :param models: List of models to test
        :param test_data: Test dataset
        :param ground_truth: Ground truth labels
        :param significance_level: Statistical significance threshold
        :return: Experiment results
        """
        # Save models and get version IDs
        version_ids = [
            self.model_version_manager.save_model(
                model, 
                metadata={'experiment': 'ab_test'}
            ) for model in models
        ]
        
        # Compare models
        performances = self.compare_models(version_ids, test_data, ground_truth)
        
        # Determine best performing model
        best_model_version = max(performances, key=performances.get)
        
        # Statistical significance (simplified approach)
        performance_values = list(performances.values())
        performance_std = np.std(performance_values)
        
        # Prepare results
        results = {
            'model_performances': performances,
            'best_model_version': best_model_version,
            'performance_std': performance_std,
            'statistically_significant': performance_std < significance_level
        }
        
        return results
    
    def configure_experiment(self, 
                             base_model: AnomalyDetector, 
                             parameter_grid: Dict[str, List[Any]]) -> List[AnomalyDetector]:
        """
        Generate model variants with different configurations
        
        :param base_model: Base model to create variants from
        :param parameter_grid: Dictionary of parameters to vary
        :return: List of model variants
        """
        from itertools import product
        
        model_variants = []
        
        # Generate all parameter combinations
        param_names = list(parameter_grid.keys())
        param_values = list(parameter_grid.values())
        
        for combination in product(*param_values):
            # Create a copy of the base model
            variant = base_model.__class__()
            
            # Apply parameter configuration
            for name, value in zip(param_names, combination):
                setattr(variant, name, value)
            
            model_variants.append(variant)
        
        return model_variants
