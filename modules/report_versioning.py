import uuid
from datetime import datetime
import json
import os

class ReportVersionManager:
    def __init__(self, base_path='reports'):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

    def generate_report_id(self):
        """Generate a unique report identifier."""
        return str(uuid.uuid4())

    def create_report_version(self, scan_results, metadata=None):
        """
        Create a versioned report with unique ID and timestamp.
        
        Args:
            scan_results (dict): Scan results to be stored
            metadata (dict, optional): Additional metadata for the report
        
        Returns:
            str: Path to the saved report
        """
        report_id = self.generate_report_id()
        timestamp = datetime.utcnow().isoformat()
        
        report_data = {
            'report_id': report_id,
            'timestamp': timestamp,
            'metadata': metadata or {},
            'results': scan_results
        }
        
        report_filename = f"{report_id}.json"
        report_path = os.path.join(self.base_path, report_filename)
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return report_path

    def get_report_versions(self):
        """
        Retrieve all report versions.
        
        Returns:
            list: List of report metadata
        """
        reports = []
        for filename in os.listdir(self.base_path):
            if filename.endswith('.json'):
                with open(os.path.join(self.base_path, filename)) as f:
                    report = json.load(f)
                    reports.append({
                        'report_id': report['report_id'],
                        'timestamp': report['timestamp']
                    })
        return sorted(reports, key=lambda x: x['timestamp'], reverse=True)

    def get_report_by_id(self, report_id):
        """
        Retrieve a specific report by its ID.
        
        Args:
            report_id (str): Unique report identifier
        
        Returns:
            dict: Report data or None if not found
        """
        report_path = os.path.join(self.base_path, f"{report_id}.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                return json.load(f)
        return None
