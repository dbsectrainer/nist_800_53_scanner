import hashlib
import json
import os
import time

import numpy as np
import pytest

# Import key modules for end-to-end testing
from modules.scan_api import ScanAPI
from modules.distributed_scanner import DistributedScanner
from modules.anomaly_detection import AnomalyDetector
from modules.model_versioning import ModelVersionManager
from modules.model_retraining import ModelRetrainingPipeline
from modules.ab_testing import MLModelABTester

FEATURE_COUNT = 10


def fake_scan(target):
    """
    Deterministic stand-in for a network scan: derives a feature vector from the
    target name, so the pipeline runs offline and reproducibly.
    """
    if not target or ':' in target:
        raise ValueError(f"Unscannable target: {target!r}")
    seed = int.from_bytes(hashlib.sha256(target.encode()).digest()[:4], 'big')
    features = np.random.default_rng(seed).normal(0, 1, FEATURE_COUNT)
    return {'target': target, 'features': features.tolist()}


class TestEndToEndSecurityScanning:
    @pytest.fixture
    def setup_environment(self, tmp_path):
        """
        Set up a comprehensive testing environment
        """
        # Create temporary directories
        model_versions_dir = tmp_path / 'model_versions'
        scan_results_dir = tmp_path / 'scan_results'
        os.makedirs(model_versions_dir, exist_ok=True)
        os.makedirs(scan_results_dir, exist_ok=True)
        
        # Initialize key components
        model_version_manager = ModelVersionManager(base_path=str(model_versions_dir))
        
        return {
            'model_version_manager': model_version_manager,
            'scan_results_dir': scan_results_dir
        }
    
    def test_full_security_scanning_workflow(self, setup_environment):
        """
        End-to-end test of the security scanning workflow
        Covers multiple components and their interactions
        """
        model_version_manager = setup_environment['model_version_manager']
        scan_results_dir = setup_environment['scan_results_dir']

        # 1. Prepare anomaly detection model
        anomaly_detector = AnomalyDetector(config={'contamination': 0.1})
        anomaly_detector.train(np.random.default_rng(0).normal(0, 1, (1000, FEATURE_COUNT)))

        # 2. Model versioning
        model_version_id = model_version_manager.save_model(
            anomaly_detector,
            metadata={'workflow_test': 'end_to_end'}
        )
        assert model_version_manager.load_model(model_version_id).is_trained

        # 3. Scanning
        scan_targets = ['localhost', '127.0.0.1', 'example.com']
        scanner = DistributedScanner(max_workers=2, distributed_mode=False)
        scan_results = scanner.distributed_scan(scan_targets, fake_scan)
        assert len(scan_results) == len(scan_targets), "Every target should be scanned"

        # 4. Anomaly detection on scan results
        features = np.array([result['features'] for result in scan_results])
        anomaly_predictions = anomaly_detector.predict(features)
        assert len(anomaly_predictions) == len(scan_results)

        # 5. Save scan results
        results_file = os.path.join(scan_results_dir, f'{model_version_id}_scan_results.json')
        with open(results_file, 'w') as f:
            json.dump({
                'model_version': model_version_id,
                'scan_targets': scan_targets,
                'results': scan_results,
                'anomalies': anomaly_predictions.tolist()
            }, f, indent=2)
        with open(results_file) as f:
            assert json.load(f)['model_version'] == model_version_id

        # 6. Retraining pipeline
        retraining_pipeline = ModelRetrainingPipeline(model_version_manager)
        retrained_model, _ = retraining_pipeline.retrain_model(
            anomaly_detector,
            np.random.default_rng(1).normal(0, 1, (2000, FEATURE_COUNT))
        )
        assert retrained_model.is_trained

        # 7. A/B testing
        ab_tester = MLModelABTester(model_version_manager)
        rng = np.random.default_rng(2)
        experiment_results = ab_tester.run_experiment(
            [anomaly_detector, retrained_model],
            rng.normal(0, 1, (500, FEATURE_COUNT)),
            rng.integers(0, 2, 500)
        )

        assert 'best_model_version' in experiment_results
        assert 'model_performances' in experiment_results

    def test_error_handling_and_resilience(self, setup_environment):
        """
        Unscannable targets are skipped without taking the scan down
        """
        scanner = DistributedScanner(max_workers=2, distributed_mode=False)

        scan_results = scanner.distributed_scan(
            ['non_existent_host', 'invalid_ip:999999', '', 'example.com'],
            fake_scan
        )

        assert sorted(result['target'] for result in scan_results) == ['example.com', 'non_existent_host']

    def test_performance_under_load(self, setup_environment):
        """
        Test system performance with a large number of scan targets
        """
        scanner = DistributedScanner(distributed_mode=False)
        large_target_set = [f'target_{i}.example.com' for i in range(100)]

        start_time = time.time()
        scan_results = scanner.distributed_scan(large_target_set, fake_scan)
        elapsed = time.time() - start_time

        assert len(scan_results) == len(large_target_set), "Large-scale scanning lost targets"
        assert elapsed < 60, "Scanning took too long"
