#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import yaml
import os
import json
from datetime import datetime
import csv
import io

app = Flask(__name__)
CORS(app)

class ComplianceDashboard:
    def __init__(self, reports_dir='scan_reports'):
        """
        Initialize the Compliance Dashboard
        
        :param reports_dir: Directory containing scan reports
        """
        self.reports_dir = reports_dir
        
    def get_latest_reports(self):
        """
        Retrieve the latest scan reports
        
        :return: List of latest scan reports
        """
        reports = []
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        for filename in os.listdir(self.reports_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.reports_dir, filename)
                with open(filepath, 'r') as f:
                    report = json.load(f)
                    reports.append(report)
        
        # Sort reports by date, most recent first
        return sorted(reports, key=lambda x: x.get('scan_date', ''), reverse=True)

    def calculate_overall_compliance(self, reports):
        """
        Calculate overall compliance percentage
        
        :param reports: List of scan reports
        :return: Compliance statistics
        """
        if not reports:
            return {
                'total_controls': 0,
                'compliant_controls': 0,
                'compliance_percentage': 0
            }
        
        latest_report = reports[0]
        total_controls = 0
        compliant_controls = 0
        
        control_categories = [
            'access_control', 
            'audit_logging', 
            'network_security', 
            'configuration_management', 
            'incident_response'
        ]
        
        for category in control_categories:
            for control in latest_report.get(category, []):
                total_controls += 1
                if control.get('compliant', False):
                    compliant_controls += 1
        
        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            'total_controls': total_controls,
            'compliant_controls': compliant_controls,
            'compliance_percentage': round(compliance_percentage, 2)
        }

    def filter_reports(self, reports, filters=None):
        """
        Filter reports based on given criteria
        
        :param reports: List of reports to filter
        :param filters: Dictionary of filter criteria
        :return: Filtered list of reports
        """
        if not filters:
            return reports

        filtered_reports = reports

        # Filter by environment
        if filters.get('environment'):
            filtered_reports = [
                report for report in filtered_reports 
                if report.get('environment', '').lower() == filters['environment'].lower()
            ]

        # Filter by compliance status
        if filters.get('compliance_status'):
            filtered_reports = [
                report for report in filtered_reports 
                if self._check_compliance_status(report, filters['compliance_status'])
            ]

        # Filter by date range
        if filters.get('start_date') and filters.get('end_date'):
            filtered_reports = [
                report for report in filtered_reports
                if filters['start_date'] <= report.get('scan_date', '') <= filters['end_date']
            ]

        return filtered_reports

    def _check_compliance_status(self, report, status):
        """
        Check the compliance status of a report
        
        :param report: Report to check
        :param status: Compliance status to check
        :return: Boolean indicating compliance status
        """
        total_controls = 0
        compliant_controls = 0
        
        control_categories = [
            'access_control', 
            'audit_logging', 
            'network_security', 
            'configuration_management', 
            'incident_response'
        ]
        
        for category in control_categories:
            for control in report.get(category, []):
                total_controls += 1
                if control.get('compliant', False):
                    compliant_controls += 1
        
        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        if status == 'fully_compliant':
            return compliance_percentage == 100
        elif status == 'mostly_compliant':
            return 75 <= compliance_percentage < 100
        elif status == 'partially_compliant':
            return 50 <= compliance_percentage < 75
        elif status == 'non_compliant':
            return compliance_percentage < 50
        
        return True

dashboard = ComplianceDashboard()

@app.route('/')
def index():
    """
    Render the main dashboard page
    """
    reports = dashboard.get_latest_reports()
    compliance_stats = dashboard.calculate_overall_compliance(reports)
    
    return render_template('index.html', 
                           reports=reports, 
                           compliance_stats=compliance_stats)

@app.route('/api/compliance-stats')
def compliance_stats():
    """
    API endpoint for compliance statistics
    """
    reports = dashboard.get_latest_reports()
    compliance_stats = dashboard.calculate_overall_compliance(reports)
    return jsonify(compliance_stats)

@app.route('/api/reports')
def get_reports():
    """
    API endpoint for scan reports with filtering
    """
    reports = dashboard.get_latest_reports()
    
    # Get filter parameters
    filters = {
        'environment': request.args.get('environment'),
        'compliance_status': request.args.get('compliance_status'),
        'start_date': request.args.get('start_date'),
        'end_date': request.args.get('end_date')
    }
    
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}
    
    filtered_reports = dashboard.filter_reports(reports, filters)
    
    return jsonify(filtered_reports)

@app.route('/api/reports/export')
def export_reports():
    """
    Export reports to CSV
    """
    reports = dashboard.get_latest_reports()
    
    # Create a CSV file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    headers = [
        'Scan Date', 'Environment', 'Total Controls', 
        'Compliant Controls', 'Compliance Percentage'
    ]
    writer.writerow(headers)
    
    # Write report data
    for report in reports:
        total_controls = 0
        compliant_controls = 0
        
        control_categories = [
            'access_control', 
            'audit_logging', 
            'network_security', 
            'configuration_management', 
            'incident_response'
        ]
        
        for category in control_categories:
            for control in report.get(category, []):
                total_controls += 1
                if control.get('compliant', False):
                    compliant_controls += 1
        
        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        writer.writerow([
            report.get('scan_date', 'N/A'),
            report.get('environment', 'N/A'),
            total_controls,
            compliant_controls,
            f"{compliance_percentage:.2f}%"
        ])
    
    # Create a response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='nist_compliance_reports.csv'
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
