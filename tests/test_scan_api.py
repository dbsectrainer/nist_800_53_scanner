import os
import time
import json
import pytest
from flask import Flask
from flask.testing import FlaskClient
from modules.scan_api import ScanAPI
from modules.authentication import AuthenticationManager
from modules.rate_limiter import RateLimiter
from modules.input_validator import InputValidator
from modules.encryption import SecureDataHandler
from modules.monitoring import SystemMonitor
from modules.report_versioning import ReportVersionManager

class TestScanAPI:
    @pytest.fixture
    def auth_manager(self):
        """Create an authentication manager for testing"""
        auth_manager = AuthenticationManager()
        # Create a test admin user
        auth_manager.create_user('testadmin', 'StrongP@ss123!', role='admin')
        auth_manager.create_user('testuser', 'UserP@ss456!', role='user')
        return auth_manager

    @pytest.fixture
    def scan_api(self, auth_manager):
        """Create a ScanAPI instance for testing"""
        return ScanAPI(
            auth_manager=auth_manager,
            rate_limiter=RateLimiter(max_requests=10, time_window=3600),
            encryption_handler=SecureDataHandler(),
            monitoring_handler=SystemMonitor(),
            report_manager=ReportVersionManager()
        )

    def test_api_authentication(self, scan_api, auth_manager):
        """Test API authentication mechanism"""
        # Get API key for admin user
        admin_api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        
        # Simulate scan request with valid API key
        scan_params = {
            'target': '192.168.1.1',
            'scan_type': 'network'
        }
        
        # Create test client
        test_client = scan_api.app.test_client()
        
        # Send request with valid API key
        response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': admin_api_key}
        )
        
        assert response.status_code == 200, "Request with valid API key should succeed"
        
        # Test with invalid API key
        response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': 'invalid_key'}
        )
        
        assert response.status_code == 401, "Request with invalid API key should be unauthorized"

    def test_role_based_access(self, scan_api, auth_manager):
        """Test role-based access control"""
        # Get API keys
        admin_api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        user_api_key = auth_manager.authenticate('testuser', 'UserP@ss456!')
        
        scan_params = {
            'target': '192.168.1.1',
            'scan_type': 'network'
        }
        
        test_client = scan_api.app.test_client()
        
        # Admin should have full access
        admin_response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': admin_api_key}
        )
        assert admin_response.status_code == 200, "Admin should have full scan access"
        
        # User with limited permissions
        user_response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': user_api_key}
        )
        assert user_response.status_code == 200, "User should have scan access"

    def test_rate_limiting(self, scan_api, auth_manager):
        """Test API rate limiting"""
        # Get API key for testing
        api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        
        scan_params = {
            'target': '192.168.1.1',
            'scan_type': 'network'
        }
        
        test_client = scan_api.app.test_client()
        
        # Send multiple requests to trigger rate limit
        responses = []
        for _ in range(15):  # Exceed rate limit
            response = test_client.post('/api/scan', 
                json=scan_params,
                headers={'X-API-Key': api_key}
            )
            responses.append(response)
        
        # Count 429 (Too Many Requests) responses
        rate_limit_responses = [r for r in responses if r.status_code == 429]
        assert len(rate_limit_responses) > 0, "Rate limiting should be enforced"

    def test_input_validation(self, scan_api, auth_manager):
        """Test input validation for scan parameters"""
        # Get API key for testing
        api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        
        test_client = scan_api.app.test_client()
        
        # Test valid input
        valid_params = {
            'target': '192.168.1.1',
            'scan_type': 'network',
            'depth': 3,
            'timeout': 300
        }
        
        valid_response = test_client.post('/api/scan', 
            json=valid_params,
            headers={'X-API-Key': api_key}
        )
        assert valid_response.status_code == 200, "Valid input should be accepted"
        
        # Test invalid inputs
        invalid_params_list = [
            {},  # Empty parameters
            {'target': 123},  # Invalid target type
            {'target': 'invalid-target', 'scan_type': 123},  # Invalid scan type
            {'target': 'example.com', 'depth': 'deep'}  # Invalid depth type
        ]
        
        for invalid_params in invalid_params_list:
            invalid_response = test_client.post('/api/scan', 
                json=invalid_params,
                headers={'X-API-Key': api_key}
            )
            assert invalid_response.status_code == 400, f"Invalid input {invalid_params} should be rejected"

    def test_report_generation(self, scan_api, auth_manager):
        """Test report generation through API"""
        # Get API key for testing
        api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        
        test_client = scan_api.app.test_client()
        
        # Perform scan
        scan_params = {
            'target': '192.168.1.1',
            'scan_type': 'network'
        }
        
        scan_response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': api_key}
        )
        
        # Verify scan response
        assert scan_response.status_code == 200, "Scan should be successful"
        
        # Check response contains report ID
        response_data = json.loads(scan_response.data)
        assert 'report_id' in response_data, "Response should include report ID"
        
        # Retrieve reports
        reports_response = test_client.get('/api/reports', 
            headers={'X-API-Key': api_key}
        )
        
        assert reports_response.status_code == 200, "Reports retrieval should succeed"
        reports_data = json.loads(reports_response.data)
        assert isinstance(reports_data, list), "Reports should be returned as a list"

    def test_encryption_of_scan_results(self, scan_api, auth_manager):
        """Test encryption of sensitive scan results"""
        # Get API key for testing
        api_key = auth_manager.authenticate('testadmin', 'StrongP@ss123!')
        
        test_client = scan_api.app.test_client()
        
        # Perform scan
        scan_params = {
            'target': '192.168.1.1',
            'scan_type': 'network'
        }
        
        scan_response = test_client.post('/api/scan', 
            json=scan_params,
            headers={'X-API-Key': api_key}
        )
        
        # Verify scan response
        assert scan_response.status_code == 200, "Scan should be successful"
        
        # Check response contains encrypted results
        response_data = json.loads(scan_response.data)
        assert 'report_id' in response_data, "Response should include report ID"
        
        # Retrieve specific report
        report_response = test_client.get(f'/api/report/{response_data["report_id"]}', 
            headers={'X-API-Key': api_key}
        )
        
        assert report_response.status_code == 200, "Report retrieval should succeed"
        report_data = json.loads(report_response.data)
        
        # Verify encryption (basic check)
        assert 'results' in report_data, "Report should contain results"
        # Note: More detailed encryption verification would require decryption testing
