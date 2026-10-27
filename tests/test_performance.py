import time

import memory_profiler
import pytest

from modules.authentication import AuthenticationManager
from modules.distributed_scanner import DistributedScanner
from modules.encryption import SecureDataHandler, SecureKeyStorage
from modules.monitoring import SystemMonitor
from modules.report_versioning import ReportVersionManager
from modules.scan_api import ScanAPI

SCAN_DELAY = 0.01


def io_bound_scan(target):
    """Stand-in for a network scan: time is spent waiting, not computing"""
    time.sleep(SCAN_DELAY)
    return {'target': target, 'status': 'scanned'}


class TestPerformanceBenchmarks:
    def test_scan_api_response_time(self, tmp_path):
        """
        Performance test for scan API response time.
        Goal: Ensure a complete authenticated scan request (validate, scan, encrypt, store) is fast.
        """
        auth = AuthenticationManager(credentials_file=str(tmp_path / 'credentials.json'))
        auth.create_user('perf_user', 'Perf0rmance!Test#9', role='admin')
        api_key = auth.authenticate('perf_user', 'Perf0rmance!Test#9')

        scan_api = ScanAPI(
            auth_manager=auth,
            encryption_handler=SecureDataHandler(
                SecureKeyStorage(str(tmp_path / 'master.key')),
                keys_file=str(tmp_path / 'keys.json')
            ),
            monitoring_handler=SystemMonitor(log_dir=str(tmp_path / 'logs')),
            report_manager=ReportVersionManager(base_path=str(tmp_path / 'reports')),
        )
        client = scan_api.app.test_client()

        start_time = time.perf_counter()
        response = client.post(
            '/api/scan',
            json={'target': '192.168.1.1', 'scan_type': 'network'},
            headers={'X-API-Key': api_key},
        )
        elapsed = time.perf_counter() - start_time

        assert response.status_code == 200
        assert elapsed < 5.0, f"Scan API response time too slow: {elapsed} seconds"

    def test_distributed_scanner_memory_usage(self):
        """
        Memory growth while scanning a large target list.
        """
        scanner = DistributedScanner(max_workers=8)
        scan_targets = list(range(5000))

        def run_scan():
            return scanner.distributed_scan(scan_targets, lambda target: {'target': target})

        baseline = memory_profiler.memory_usage(-1, interval=0.05, timeout=0.2)[0]
        samples, results = memory_profiler.memory_usage((run_scan, (), {}), interval=0.05, retval=True)

        assert len(results) == len(scan_targets)
        growth = max(samples) - baseline
        assert growth < 200, f"Excessive memory growth: {growth:.1f} MB"

    def test_scanning_scalability(self):
        """
        Scan time must stay far below sequential time as load grows.
        """
        scanner = DistributedScanner(max_workers=8)

        # Work is split into chunks of 10 targets, so a single chunk (10 targets)
        # is inherently sequential; only larger loads can show a speedup.
        for count in (100, 400):
            targets = list(range(count))

            start_time = time.perf_counter()
            results = scanner.distributed_scan(targets, io_bound_scan)
            elapsed = time.perf_counter() - start_time

            assert len(results) == count
            sequential_time = count * SCAN_DELAY
            assert elapsed < sequential_time, \
                f"{count} targets took {elapsed:.2f}s, no better than sequential {sequential_time:.2f}s"

    def test_concurrent_scan_performance(self):
        """
        Parallel scanning must clearly beat sequential scanning.
        """
        scanner = DistributedScanner(max_workers=8)
        targets = list(range(200))
        sequential_time = len(targets) * SCAN_DELAY

        start_time = time.perf_counter()
        concurrent_results = scanner.distributed_scan(targets, io_bound_scan)
        elapsed = time.perf_counter() - start_time

        assert len(concurrent_results) == len(targets), "No results lost"
        assert elapsed < sequential_time / 2, \
            f"Concurrent scan ({elapsed:.2f}s) should be at least 2x faster than sequential ({sequential_time:.2f}s)"
