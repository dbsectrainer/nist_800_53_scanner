import pytest
import time
import memory_profiler
from modules.scan_api import ScanAPI
from modules.distributed_scanner import DistributedScanner

class TestPerformanceBenchmarks:
    def test_scan_api_response_time(self):
        """
        Performance test for scan API response time.
        Goal: Ensure API responds within acceptable time limits.
        """
        scan_api = ScanAPI()
        start_time = time.time()
        result = scan_api.perform_scan()
        end_time = time.time()
        
        # Benchmark: API response should be under 5 seconds
        assert (end_time - start_time) < 5.0, f"Scan API response time too slow: {end_time - start_time} seconds"

    def test_distributed_scanner_memory_usage(self):
        """
        Memory usage test for distributed scanner.
        Goal: Ensure memory consumption is within acceptable limits.
        """
        scanner = DistributedScanner()
        
        @memory_profiler.profile
        def run_scan():
            scanner.distributed_scan()
        
        # Run memory profiling
        memory_usage = memory_profiler.memory_usage(run_scan, max_iterations=1)
        
        # Benchmark: Memory usage should be under 500 MB
        assert max(memory_usage) < 500, f"Excessive memory usage: {max(memory_usage)} MB"

    def test_scanning_scalability(self):
        """
        Scalability test to ensure performance remains consistent with increasing load.
        """
        scanner = DistributedScanner()
        
        # Test with increasing number of scan targets
        scan_targets = [
            ['target1'],
            ['target1', 'target2'],
            ['target1', 'target2', 'target3', 'target4', 'target5']
        ]
        
        for targets in scan_targets:
            start_time = time.time()
            results = scanner.distributed_scan(targets)
            end_time = time.time()
            
            # Ensure scan time scales somewhat linearly
            assert (end_time - start_time) < (len(targets) * 2), \
                f"Scan time disproportionate to number of targets: {end_time - start_time} seconds"

    def test_concurrent_scan_performance(self):
        """
        Test concurrent scanning capabilities.
        """
        scanner = DistributedScanner()
        
        start_time = time.time()
        concurrent_results = scanner.concurrent_scan()
        end_time = time.time()
        
        # Ensure concurrent scan is faster than sequential
        assert len(concurrent_results) > 0, "No results from concurrent scan"
        assert (end_time - start_time) < 10, f"Concurrent scan took too long: {end_time - start_time} seconds"
