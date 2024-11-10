import os
import time
import json
import tempfile
import threading
import pytest
import psutil
from modules.monitoring import SystemMonitor

class TestSystemMonitor:
    def setup_method(self):
        """Create a fresh system monitor for each test"""
        # Use a temporary directory for log files
        self.temp_dir = tempfile.mkdtemp(prefix='nist_scanner_monitoring_')
        self.monitor = SystemMonitor(
            log_dir=self.temp_dir, 
            monitoring_interval=0.5  # Short interval for testing
        )

    def teardown_method(self):
        """Clean up temporary log directory and stop monitoring"""
        self.monitor.stop_monitoring()
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_metrics_collection(self):
        """Test system metrics collection"""
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Wait for a few monitoring cycles
        time.sleep(1.5)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        # Check log files
        log_files = [f for f in os.listdir(self.temp_dir) if f.startswith('metrics_')]
        assert len(log_files) > 0, "Metrics log files should be created"
        
        # Verify log file contents
        for log_file in log_files:
            with open(os.path.join(self.temp_dir, log_file), 'r') as f:
                metrics = json.load(f)
            
            # Check key metrics
            assert 'timestamp' in metrics, "Metrics should include timestamp"
            assert 'cpu_percent' in metrics, "Metrics should include CPU usage"
            assert 'memory_usage' in metrics, "Metrics should include memory usage"
            assert 'disk_usage' in metrics, "Metrics should include disk usage"

    def test_threshold_checking(self):
        """Test system metrics threshold checking"""
        # Custom low thresholds to trigger warnings
        custom_thresholds = {
            'cpu_percent': 10.0,   # Very low threshold
            'memory_percent': 10.0,
            'disk_percent': 10.0
        }
        
        # Create monitor with custom thresholds
        threshold_monitor = SystemMonitor(
            log_dir=self.temp_dir, 
            monitoring_interval=0.5,
            alert_thresholds=custom_thresholds
        )
        
        # Capture log messages
        import logging
        log_capture = []
        
        # Custom log handler to capture warnings
        class CaptureHandler(logging.Handler):
            def emit(self, record):
                log_capture.append(record.getMessage())
        
        # Add capture handler
        capture_handler = CaptureHandler()
        threshold_monitor.logger.addHandler(capture_handler)
        
        # Start monitoring
        threshold_monitor.start_monitoring()
        
        # Wait for monitoring cycles
        time.sleep(1.5)
        
        # Stop monitoring
        threshold_monitor.stop_monitoring()
        
        # Check for warning logs
        warning_logs = [log for log in log_capture if 'WARNING' in log]
        assert len(warning_logs) > 0, "Should generate warning logs for high resource usage"

    def test_recent_metrics_retrieval(self):
        """Test retrieving recent metrics"""
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Wait for multiple monitoring cycles
        time.sleep(1.5)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        # Retrieve recent metrics
        recent_metrics = self.monitor.get_recent_metrics(limit=3)
        
        assert len(recent_metrics) > 0, "Should retrieve recent metrics"
        assert len(recent_metrics) <= 3, "Should limit metrics to specified count"
        
        # Verify metrics structure
        for metrics in recent_metrics:
            assert 'timestamp' in metrics, "Each metrics set should have a timestamp"
            assert 'cpu_percent' in metrics, "Metrics should include CPU usage"

    def test_concurrent_monitoring(self):
        """Test monitoring under concurrent access"""
        # Flag to track monitoring status
        monitoring_successful = [False]
        
        def run_monitoring():
            try:
                # Start and stop monitoring multiple times
                for _ in range(5):
                    self.monitor.start_monitoring()
                    time.sleep(0.2)
                    self.monitor.stop_monitoring()
                monitoring_successful[0] = True
            except Exception:
                monitoring_successful[0] = False
        
        # Create multiple threads
        threads = [threading.Thread(target=run_monitoring) for _ in range(3)]
        
        # Start threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Verify all monitoring attempts were successful
        assert monitoring_successful[0], "Monitoring should be thread-safe"

    def test_error_handling(self):
        """Test error handling in monitoring"""
        # Mock psutil to simulate errors
        original_cpu_percent = psutil.cpu_percent
        
        def error_raising_cpu_percent(*args, **kwargs):
            raise Exception("Simulated system metrics collection error")
        
        try:
            # Replace CPU percent with error-raising function
            psutil.cpu_percent = error_raising_cpu_percent
            
            # Capture log messages
            import logging
            log_capture = []
            
            class CaptureHandler(logging.Handler):
                def emit(self, record):
                    log_capture.append(record.getMessage())
            
            # Add capture handler
            capture_handler = CaptureHandler()
            self.monitor.logger.addHandler(capture_handler)
            
            # Start monitoring
            self.monitor.start_monitoring()
            
            # Wait for monitoring cycle
            time.sleep(1)
            
            # Stop monitoring
            self.monitor.stop_monitoring()
            
            # Check for error logs
            error_logs = [log for log in log_capture if 'ERROR' in log]
            assert len(error_logs) > 0, "Should log errors during metrics collection"
        
        finally:
            # Restore original CPU percent function
            psutil.cpu_percent = original_cpu_percent

    def test_long_running_monitoring(self):
        """Test monitoring over an extended period"""
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Monitor for a longer duration
        time.sleep(3)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        # Check log files
        log_files = [f for f in os.listdir(self.temp_dir) if f.startswith('metrics_')]
        
        # Should have multiple log files
        assert len(log_files) > 3, "Should generate multiple metrics log files"
