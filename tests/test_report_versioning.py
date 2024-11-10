import os
import time
import json
import tempfile
import pytest
from modules.report_versioning import ReportVersionManager

class TestReportVersionManager:
    def setup_method(self):
        """Create a fresh report version manager for each test"""
        # Use a temporary directory for test reports
        self.temp_dir = tempfile.mkdtemp(prefix='nist_scanner_test_reports_')
        self.report_manager = ReportVersionManager(base_path=self.temp_dir)

    def teardown_method(self):
        """Clean up temporary report directory"""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_report_creation(self):
        """Test basic report creation"""
        scan_results = {
            'target': '192.168.1.1',
            'findings': [
                {'control_id': 'AC-1', 'status': 'compliant'},
                {'control_id': 'AC-2', 'status': 'non-compliant'}
            ]
        }
        
        # Create report
        report_path = self.report_manager.create_report_version(scan_results)
        
        # Verify report file was created
        assert os.path.exists(report_path), "Report file should be created"
        
        # Verify report contents
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'report_id' in report_data, "Report should have a unique ID"
        assert 'timestamp' in report_data, "Report should have a timestamp"
        assert report_data['results'] == scan_results, "Report contents should match input"

    def test_report_versioning(self):
        """Test multiple report versions"""
        scan_results_1 = {'target': '192.168.1.1', 'findings': [{'status': 'compliant'}]}
        scan_results_2 = {'target': '192.168.1.2', 'findings': [{'status': 'non-compliant'}]}
        
        # Create multiple reports
        report_path_1 = self.report_manager.create_report_version(scan_results_1)
        time.sleep(0.1)  # Ensure different timestamps
        report_path_2 = self.report_manager.create_report_version(scan_results_2)
        
        # Verify different report IDs
        with open(report_path_1, 'r') as f1, open(report_path_2, 'r') as f2:
            report_1 = json.load(f1)
            report_2 = json.load(f2)
        
        assert report_1['report_id'] != report_2['report_id'], "Reports should have unique IDs"
        assert report_1['timestamp'] != report_2['timestamp'], "Reports should have different timestamps"

    def test_report_retrieval(self):
        """Test retrieving report versions"""
        # Create multiple reports
        reports_data = [
            {'target': '192.168.1.1', 'findings': [{'status': 'compliant'}]},
            {'target': '192.168.1.2', 'findings': [{'status': 'non-compliant'}]},
            {'target': '192.168.1.3', 'findings': [{'status': 'partially-compliant'}]}
        ]
        
        report_paths = []
        for data in reports_data:
            report_paths.append(self.report_manager.create_report_version(data))
        
        # Retrieve report versions
        report_versions = self.report_manager.get_report_versions()
        
        # Verify retrieval
        assert len(report_versions) == len(reports_data), "Should retrieve all reports"
        
        # Verify sorting (most recent first)
        assert all(
            report_versions[i]['timestamp'] >= report_versions[i+1]['timestamp'] 
            for i in range(len(report_versions)-1)
        ), "Reports should be sorted by timestamp in descending order"

    def test_report_retrieval_by_id(self):
        """Test retrieving a specific report by ID"""
        scan_results = {'target': '192.168.1.1', 'findings': [{'status': 'compliant'}]}
        
        # Create report
        report_path = self.report_manager.create_report_version(scan_results)
        
        # Read report to get its ID
        with open(report_path, 'r') as f:
            original_report = json.load(f)
        
        # Retrieve by ID
        retrieved_report = self.report_manager.get_report_by_id(original_report['report_id'])
        
        assert retrieved_report is not None, "Should retrieve report by ID"
        assert retrieved_report['report_id'] == original_report['report_id'], "Retrieved report ID should match"
        assert retrieved_report['results'] == scan_results, "Retrieved report contents should match"

    def test_report_metadata(self):
        """Test adding custom metadata to reports"""
        scan_results = {'target': '192.168.1.1', 'findings': [{'status': 'compliant'}]}
        metadata = {
            'scan_type': 'network',
            'environment': 'production',
            'scanner_version': '1.0.0'
        }
        
        # Create report with metadata
        report_path = self.report_manager.create_report_version(
            scan_results, 
            metadata=metadata
        )
        
        # Verify metadata
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'metadata' in report_data, "Report should include metadata"
        assert report_data['metadata'] == metadata, "Metadata should match input"

    def test_nonexistent_report_retrieval(self):
        """Test retrieving a non-existent report"""
        non_existent_id = 'non-existent-report-id'
        retrieved_report = self.report_manager.get_report_by_id(non_existent_id)
        
        assert retrieved_report is None, "Should return None for non-existent report"

    def test_report_storage_limit(self):
        """Test report storage limit functionality"""
        # Override report manager with a small max_reports limit
        limited_report_manager = ReportVersionManager(
            base_path=self.temp_dir, 
            max_reports=3
        )
        
        # Create more reports than the limit
        for i in range(5):
            scan_results = {'target': f'192.168.1.{i}', 'findings': [{'status': 'compliant'}]}
            limited_report_manager.create_report_version(scan_results)
        
        # Retrieve report versions
        report_versions = limited_report_manager.get_report_versions()
        
        # Should only keep the most recent 3 reports
        assert len(report_versions) == 3, "Should maintain only the most recent reports"
        
        # Verify oldest reports are removed
        assert all(
            report_versions[i]['timestamp'] >= report_versions[i+1]['timestamp'] 
            for i in range(len(report_versions)-1)
        ), "Remaining reports should be the most recent"

    def test_concurrent_report_creation(self):
        """Test thread-safe report creation"""
        import threading
        
        def create_report():
            scan_results = {'target': '192.168.1.1', 'findings': [{'status': 'compliant'}]}
            self.report_manager.create_report_version(scan_results)
        
        # Create multiple threads to simulate concurrent report generation
        threads = [threading.Thread(target=create_report) for _ in range(10)]
        
        # Start threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify unique report versions were created
        report_versions = self.report_manager.get_report_versions()
        report_ids = [report['report_id'] for report in report_versions]
        
        assert len(set(report_ids)) == len(report_ids), "All reports should have unique IDs"
