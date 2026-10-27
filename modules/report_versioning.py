import uuid
from datetime import UTC, datetime
import json
import os
import re

_REPORT_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")

class ReportVersionManager:
    def __init__(self, base_path: str = "reports", max_reports: int | None = None) -> None:
        """
        Args:
            base_path: Directory reports are stored in
            max_reports: If set, keep only this many of the most recent reports
        """
        self.base_path = base_path
        self.max_reports = max_reports
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
        timestamp = datetime.now(UTC).isoformat()
        
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

        self._enforce_retention()

        return report_path

    def _enforce_retention(self) -> None:
        """Delete the oldest reports beyond max_reports."""
        if self.max_reports is None:
            return
        stale = self.get_report_versions()[self.max_reports:]
        for report in stale:
            os.remove(os.path.join(self.base_path, f"{report['report_id']}.json"))

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
        # IDs come from URLs; reject anything that could escape base_path
        if not isinstance(report_id, str) or not _REPORT_ID_PATTERN.match(report_id):
            return None

        report_path = os.path.join(self.base_path, f"{report_id}.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                return json.load(f)
        return None
