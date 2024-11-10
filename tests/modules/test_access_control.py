import unittest
import sys
import os
import pwd
import tempfile
import shutil
import subprocess

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.access_control import AccessControlScanner

class TestAccessControlScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for access control scanner
        """
        # Create a mock configuration
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'on_premise': {
                'linux': {'enabled': True},
                'windows': {'enabled': False}
            }
        }
        self.scanner = AccessControlScanner(self.config)

    def test_find_inactive_users(self):
        """
        Test finding inactive users method
        """
        # This is a mock test as actual implementation depends on system state
        inactive_users = self.scanner._find_inactive_users(max_days=90)
        self.assertIsInstance(inactive_users, list, "Should return a list of inactive users")

    def test_check_sudo_access(self):
        """
        Test sudo access checking method
        """
        sudo_users = self.scanner._check_sudo_access()
        self.assertIsInstance(sudo_users, list, "Should return a list of sudo users")
        
        # Validate that sudo users count is within security threshold
        self.assertLessEqual(
            len(sudo_users), 
            self.scanner.security_thresholds['max_sudo_users'], 
            "Number of sudo users should not exceed security threshold"
        )

    def test_linux_user_accounts_check(self):
        """
        Test Linux user accounts security check
        """
        results = self.scanner._check_linux_user_accounts()
        
        # Validate results structure
        self.assertIsInstance(results, list, "Should return a list of findings")
        
        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-2(1)', 'AC-2(3)', 'AC-3(7)']
        
        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    def test_linux_ssh_key_security(self):
        """
        Test SSH key security checks
        """
        # Create a temporary directory to simulate user home
        with tempfile.TemporaryDirectory() as temp_home:
            # Simulate a user
            test_user = pwd.getpwuid(os.getuid()).pw_name
            ssh_dir = os.path.join(temp_home, '.ssh')
            os.makedirs(ssh_dir, exist_ok=True)
            
            # Create test SSH key with insecure permissions
            insecure_key_path = os.path.join(ssh_dir, 'id_rsa')
            with open(insecure_key_path, 'w') as f:
                f.write("test key content")
            
            # Set insecure permissions (world-readable)
            os.chmod(insecure_key_path, 0o644)
            
            # Temporarily modify pwd to include our test directory
            original_getpwall = pwd.getpwall
            try:
                def mock_getpwall():
                    original_users = original_getpwall()
                    mock_user = pwd.struct_passwd((
                        test_user, 'x', os.getuid(), os.getgid(), 
                        'Test User', temp_home, '/bin/bash'
                    ))
                    return original_users + [mock_user]
                
                pwd.getpwall = mock_getpwall
                
                # Run SSH key security check
                results = self.scanner._check_linux_ssh_key_security()
                
                # Validate results
                self.assertIsInstance(results, list, "Should return a list of findings")
                
                # Check for SSH key security finding
                ssh_findings = [
                    finding for finding in results 
                    if finding['control_id'] == 'AC-3(5)'
                ]
                
                self.assertTrue(len(ssh_findings) > 0, "Should have SSH key security findings")
                
                # Verify insecure keys are detected
                if ssh_findings:
                    finding = ssh_findings[0]
                    self.assertFalse(finding['compliant'], "Should flag insecure SSH keys")
                    self.assertTrue(
                        len(finding['details']['insecure_keys']) > 0, 
                        "Should detect insecure SSH keys"
                    )
            
            finally:
                # Restore original getpwall
                pwd.getpwall = original_getpwall

    def test_scan_method_configuration(self):
        """
        Test scan method with different configuration scenarios
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'on_premise': {
                'linux': {'enabled': False},
                'windows': {'enabled': False}
            }
        }
        disabled_scanner = AccessControlScanner(disabled_config)
        results = disabled_scanner.scan()
        
        # Should return an empty or minimal results list
        self.assertIsInstance(results, list, "Scan should always return a list")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
