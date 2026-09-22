import unittest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from modules.cloud_access_scanner import CloudAccessScanner

class TestCloudAccessScanner(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment for cloud access scanner
        """
        self.config = {
            'performance': {'max_concurrent_scans': 3},
            'aws': {'enabled': True},
            'azure': {'enabled': False, 'tenant_id': 'test-tenant-id'},
            'gcp': {
                'enabled': False,
                'projects': ['test-project'],
                'credentials': {
                    'method': 'service_account',
                    'credentials_path': '/path/to/credentials.json',
                },
            },
        }
        self.scanner = CloudAccessScanner(self.config)

    @patch('modules.cloud_access_scanner.boto3')
    def test_aws_access_controls(self, mock_boto3):
        """
        Test AWS access control scanning
        """
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam
        mock_iam.get_account_summary.return_value = {
            'SummaryMap': {'AccountMFAEnabled': 1}
        }
        mock_iam.list_users.return_value = {'Users': []}

        results = self.scanner._scan_aws_access_controls()

        self.assertIsInstance(results, list, "Should return a list of findings")

        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-2(1)', 'AC-3(7)']

        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

    @patch('modules.cloud_access_scanner.GraphServiceClient')
    @patch('modules.cloud_access_scanner.DefaultAzureCredential')
    @patch.object(CloudAccessScanner, '_fetch_azure_guest_users', new_callable=AsyncMock)
    @patch.object(CloudAccessScanner, '_fetch_azure_global_admins', new_callable=AsyncMock)
    def test_azure_access_controls(
        self, mock_global_admins, mock_guest_users, mock_credential, mock_graph_client
    ):
        """
        Test Azure access control scanning
        """
        mock_global_admins.return_value = ['admin@example.com']
        mock_guest_users.return_value = []

        results = self.scanner._scan_azure_access_controls()

        self.assertIsInstance(results, list, "Should return a list of findings")

        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-2(3)']

        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

        self.assertEqual(results[0]['details']['global_admins'], ['admin@example.com'])
        self.assertEqual(results[0]['details']['external_users'], [])

    @patch('modules.cloud_access_scanner.GraphServiceClient')
    @patch('modules.cloud_access_scanner.DefaultAzureCredential')
    @patch('modules.cloud_access_scanner.ClientSecretCredential')
    @patch.object(CloudAccessScanner, '_fetch_azure_guest_users', new_callable=AsyncMock)
    @patch.object(CloudAccessScanner, '_fetch_azure_global_admins', new_callable=AsyncMock)
    def test_azure_service_principal_credential(
        self,
        mock_global_admins,
        mock_guest_users,
        mock_client_secret_credential,
        mock_default_credential,
        mock_graph_client,
    ):
        """
        Test Azure access control scanning with explicit service-principal credentials
        """
        config = {
            'performance': {'max_concurrent_scans': 3},
            'aws': {'enabled': False},
            'azure': {
                'enabled': True,
                'tenant_id': 'tenant-id',
                'client_id': 'client-id',
                'client_secret': 'client-secret',
            },
            'gcp': {'enabled': False},
        }
        scanner = CloudAccessScanner(config)
        mock_global_admins.return_value = []
        mock_guest_users.return_value = []

        scanner._scan_azure_access_controls()

        mock_client_secret_credential.assert_called_once_with(
            'tenant-id', 'client-id', 'client-secret'
        )
        mock_default_credential.assert_not_called()

    @patch('modules.cloud_access_scanner.service_account.Credentials.from_service_account_file')
    @patch('modules.cloud_access_scanner.resourcemanager_v3')
    @patch('modules.cloud_access_scanner.iam_admin_v1')
    def test_gcp_access_controls(self, mock_iam_admin, mock_resourcemanager, mock_credentials):
        """
        Test Google Cloud Platform access control scanning
        """
        mock_credentials.return_value = MagicMock(name='gcp-credentials')
        mock_iam_client = MagicMock()
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        mock_service_account = MagicMock()
        mock_service_account.email = 'svc@test-project.iam.gserviceaccount.com'
        mock_iam_client.list_service_accounts.return_value = [mock_service_account]

        mock_rm_client = MagicMock()
        mock_resourcemanager.ProjectsClient.return_value = mock_rm_client
        mock_binding = MagicMock()
        mock_binding.members = ['user:someone@example.com']
        mock_policy = MagicMock()
        mock_policy.bindings = [mock_binding]
        mock_rm_client.get_iam_policy.return_value = mock_policy

        results = self.scanner._scan_gcp_access_controls()

        self.assertIsInstance(results, list, "Should return a list of findings")

        # Check for specific control IDs
        control_ids = [result.get('control_id') for result in results]
        expected_controls = ['AC-3(5)']

        for control in expected_controls:
            self.assertIn(control, control_ids, f"Missing expected control {control}")

        mock_credentials.assert_called_once_with(
            '/path/to/credentials.json',
            scopes=['https://www.googleapis.com/auth/cloud-platform'],
        )
        mock_rm_client.get_iam_policy.assert_called_once_with(
            request={'resource': 'projects/test-project'}
        )
        self.assertEqual(results[0]['details']['project_id'], 'test-project')
        self.assertEqual(
            results[0]['details']['service_accounts'],
            ['svc@test-project.iam.gserviceaccount.com'],
        )
        self.assertEqual(results[0]['details']['external_collaborators'], [])
        self.assertTrue(results[0]['compliant'])

    @patch('modules.cloud_access_scanner.service_account.Credentials.from_service_account_file')
    @patch('modules.cloud_access_scanner.resourcemanager_v3')
    @patch('modules.cloud_access_scanner.iam_admin_v1')
    def test_gcp_public_iam_binding_fails_compliance(
        self, mock_iam_admin, mock_resourcemanager, mock_credentials
    ):
        """
        Test that public IAM bindings fail the external collaborator control
        """
        mock_credentials.return_value = MagicMock(name='gcp-credentials')
        mock_iam_client = MagicMock()
        mock_iam_admin.IAMClient.return_value = mock_iam_client
        mock_iam_client.list_service_accounts.return_value = []

        mock_rm_client = MagicMock()
        mock_resourcemanager.ProjectsClient.return_value = mock_rm_client
        mock_binding = MagicMock()
        mock_binding.members = ['allUsers']
        mock_policy = MagicMock()
        mock_policy.bindings = [mock_binding]
        mock_rm_client.get_iam_policy.return_value = mock_policy

        results = self.scanner._scan_gcp_access_controls()

        self.assertFalse(results[0]['compliant'])
        self.assertEqual(results[0]['details']['external_collaborators'], ['allUsers'])

    def test_cloud_access_controls_scanning(self):
        """
        Test comprehensive cloud access controls scanning
        """
        with patch('modules.cloud_access_scanner.boto3') as mock_boto3:
            mock_iam = MagicMock()
            mock_boto3.client.return_value = mock_iam
            mock_iam.get_account_summary.return_value = {'SummaryMap': {'AccountMFAEnabled': 1}}
            mock_iam.list_users.return_value = {'Users': []}

            results = self.scanner.scan_cloud_access_controls()

        self.assertIsInstance(results, list, "Should return a list of findings")

        # Verify result structure
        for result in results:
            self.assertIn('control_id', result, "Each result should have a control ID")
            self.assertIn('description', result, "Each result should have a description")
            self.assertIn('compliant', result, "Each result should have a compliance status")
            self.assertIn('details', result, "Each result should have details")
            self.assertIn('remediation', result, "Each result should have remediation guidance")

    def test_cloud_provider_configuration(self):
        """
        Test scanning with different cloud provider configurations
        """
        # Test with all providers disabled
        disabled_config = {
            'performance': {'max_concurrent_scans': 1},
            'aws': {'enabled': False},
            'azure': {'enabled': False},
            'gcp': {'enabled': False}
        }
        disabled_scanner = CloudAccessScanner(disabled_config)
        results = disabled_scanner.scan_cloud_access_controls()

        # Should return an empty list
        self.assertEqual(len(results), 0, "Should return an empty list when no providers are enabled")

def main():
    unittest.main()

if __name__ == '__main__':
    main()
