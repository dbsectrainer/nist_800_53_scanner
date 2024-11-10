import os
import time
import threading
import multiprocessing
import pytest
from modules.distributed_scanner import DistributedScanner

class TestDistributedScanner:
    def setup_method(self):
        """Create a fresh distributed scanner for each test"""
        self.scanner = DistributedScanner(
            max_workers=multiprocessing.cpu_count(),
            distributed_mode=False  # Default to local parallel mode
        )

    def test_local_parallel_scan(self):
        """Test local parallel scanning functionality"""
        # Sample scan targets
        scan_targets = list(range(100))
        
        def mock_scan_function(target):
            """Simulate a scanning operation"""
            time.sleep(0.01)  # Simulate some processing time
            return {
                'target': target,
                'status': 'scanned',
                'timestamp': time.time()
            }
        
        # Perform parallel scan
        results = self.scanner._local_parallel_scan(scan_targets, mock_scan_function)
        
        # Verify results
        assert len(results) == len(scan_targets), "Should process all targets"
        assert all('target' in result for result in results), "Each result should have a target"
        assert all('status' in result for result in results), "Each result should have a status"

    def test_parallel_scan_performance(self):
        """Test performance of parallel scanning"""
        # Large number of targets to demonstrate parallel processing
        scan_targets = list(range(1000))
        
        def mock_scan_function(target):
            """Simulate a scanning operation with variable processing time"""
            time.sleep(0.01)  # Simulate processing time
            return {'target': target, 'processed': True}
        
        # Measure sequential scan time
        start_sequential = time.time()
        sequential_results = [mock_scan_function(target) for target in scan_targets]
        sequential_time = time.time() - start_sequential
        
        # Measure parallel scan time
        start_parallel = time.time()
        parallel_results = self.scanner._local_parallel_scan(scan_targets, mock_scan_function)
        parallel_time = time.time() - start_parallel
        
        # Verify results
        assert len(parallel_results) == len(scan_targets), "Parallel scan should process all targets"
        assert parallel_time < sequential_time, "Parallel scan should be faster than sequential"

    def test_error_handling_in_parallel_scan(self):
        """Test error handling during parallel scanning"""
        scan_targets = list(range(100))
        
        def mock_scan_function_with_errors(target):
            """Simulate scanning with occasional errors"""
            if target % 10 == 0:
                raise ValueError(f"Simulated error for target {target}")
            
            time.sleep(0.01)
            return {
                'target': target,
                'status': 'scanned'
            }
        
        # Perform parallel scan
        results = self.scanner._local_parallel_scan(scan_targets, mock_scan_function_with_errors)
        
        # Verify results
        assert len(results) < len(scan_targets), "Some targets should be skipped due to errors"
        assert all('target' in result for result in results), "Successful results should have target"

    def test_distributed_scan_configuration(self):
        """Test distributed scanning configuration"""
        # Enable distributed mode
        distributed_scanner = DistributedScanner(
            max_workers=4,
            distributed_mode=True,
            broker_address='localhost',
            broker_port=5555
        )
        
        # Verify configuration
        assert distributed_scanner.distributed_mode == True, "Distributed mode should be enabled"
        assert distributed_scanner.max_workers == 4, "Max workers should be set correctly"
        assert distributed_scanner.broker_address == 'localhost', "Broker address should be set"
        assert distributed_scanner.broker_port == 5555, "Broker port should be set"

    def test_worker_process_initialization(self):
        """Test worker process initialization"""
        def mock_scan_function(target):
            """Simulate a scanning operation"""
            return {
                'target': target,
                'status': 'scanned',
                'timestamp': time.time()
            }
        
        # Create a distributed scanner in distributed mode
        distributed_scanner = DistributedScanner(
            distributed_mode=True,
            broker_address='localhost',
            broker_port=5556
        )
        
        # Simulate worker process initialization
        try:
            distributed_scanner.worker_process(mock_scan_function)
        except Exception as e:
            pytest.fail(f"Worker process initialization failed: {e}")

    def test_concurrent_distributed_scan(self):
        """Test concurrent distributed scanning simulation"""
        def mock_scan_function(target):
            """Simulate a scanning operation"""
            time.sleep(0.01)  # Simulate processing time
            return {
                'target': target,
                'status': 'scanned',
                'timestamp': time.time()
            }
        
        # Large number of targets
        scan_targets = list(range(500))
        
        # Create distributed scanner
        distributed_scanner = DistributedScanner(
            max_workers=4,
            distributed_mode=True
        )
        
        # Perform distributed scan
        results = distributed_scanner.distributed_scan(scan_targets, mock_scan_function)
        
        # Verify results
        assert len(results) > 0, "Distributed scan should return results"
        assert len(results) <= len(scan_targets), "Results should not exceed target count"
        assert all('target' in result for result in results), "Each result should have a target"

    def test_scalability_with_large_dataset(self):
        """Test scanner scalability with very large dataset"""
        # Extremely large number of targets
        scan_targets = list(range(10000))
        
        def mock_scan_function(target):
            """Simulate a scanning operation with minimal overhead"""
            return {
                'target': target,
                'status': 'scanned'
            }
        
        # Create distributed scanner with high worker count
        distributed_scanner = DistributedScanner(
            max_workers=os.cpu_count() * 2,
            distributed_mode=True
        )
        
        # Perform distributed scan
        start_time = time.time()
        results = distributed_scanner.distributed_scan(scan_targets, mock_scan_function)
        total_time = time.time() - start_time
        
        # Verify scalability
        assert len(results) == len(scan_targets), "Should process all targets"
        assert total_time < (len(scan_targets) * 0.001), "Scan should complete efficiently"

    def test_error_recovery_in_distributed_scan(self):
        """Test error recovery during distributed scanning"""
        scan_targets = list(range(100))
        
        def mock_scan_function_with_errors(target):
            """Simulate scanning with occasional errors"""
            if target % 10 == 0:
                raise ValueError(f"Simulated error for target {target}")
            
            return {
                'target': target,
                'status': 'scanned'
            }
        
        # Create distributed scanner
        distributed_scanner = DistributedScanner(
            max_workers=4,
            distributed_mode=True
        )
        
        # Perform distributed scan
        results = distributed_scanner.distributed_scan(scan_targets, mock_scan_function_with_errors)
        
        # Verify error handling
        assert len(results) > 0, "Should return some results despite errors"
        assert len(results) < len(scan_targets), "Some targets should be skipped due to errors"
