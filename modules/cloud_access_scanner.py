#!/usr/bin/env python3
import asyncio
import logging
from typing import Any

import boto3
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from google.cloud import iam_admin_v1, resourcemanager_v3
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder


class CloudAccessScanner:
    def __init__(self, config: dict):
        """
        Initialize Cloud Access Scanner with advanced security checks

        :param config: Configuration dictionary, keyed by provider:
            ``{'aws': {'enabled': bool},
               'azure': {'enabled': bool, 'tenant_id': str,
                         'client_id': str, 'client_secret': str},
               'gcp': {'enabled': bool, 'project_id': str}}``
            Azure ``client_id``/``client_secret`` are optional; when omitted,
            authentication falls back to the standard DefaultAzureCredential
            chain (environment variables, managed identity, CLI, etc.).
            GCP authentication uses Application Default Credentials.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Security thresholds for cloud environments
        self.security_thresholds = {
            'max_privileged_users': 5,
            'max_service_accounts': 10,
            'max_external_collaborators': 3
        }

    def _scan_aws_access_controls(self) -> list[dict[str, Any]]:
        """
        Comprehensive AWS IAM access control scanning

        :return: List of AWS IAM security findings
        """
        results = []
        try:
            # Initialize AWS IAM client
            iam_client = boto3.client('iam')

            # Check root account usage
            root_usage = iam_client.get_account_summary()
            results.append({
                'control_id': 'AC-2(1)',
                'description': 'AWS Root Account Usage',
                'compliant': root_usage['SummaryMap'].get('AccountMFAEnabled', 0) > 0,
                'details': {
                    'root_mfa_enabled': root_usage['SummaryMap'].get('AccountMFAEnabled', 0) > 0
                },
                'remediation': 'Enable MFA for root account and avoid direct root usage'
            })

            # Check IAM users
            users = iam_client.list_users()
            privileged_users = [
                user for user in users['Users']
                if any(policy.startswith('arn:aws:iam::aws:policy/AdministratorAccess')
                       for policy in iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies'])
            ]

            results.append({
                'control_id': 'AC-3(7)',
                'description': 'AWS Privileged User Accounts',
                'compliant': len(privileged_users) <= self.security_thresholds['max_privileged_users'],
                'details': {
                    'privileged_users': [user['UserName'] for user in privileged_users]
                },
                'remediation': f'Limit privileged users to {self.security_thresholds["max_privileged_users"]} or fewer'
            })

        except Exception as e:
            self.logger.error(f"AWS Access Control Scan Error: {e}")
            results.append({
                'control_id': 'AC-AWS-001',
                'description': 'AWS Access Control Scan',
                'compliant': False,
                'remediation': f'Error scanning AWS access controls: {str(e)}'
            })

        return results

    def _build_azure_credential(self) -> ClientSecretCredential | DefaultAzureCredential:
        """
        Build an Azure credential, preferring an explicit service principal
        (config `azure.tenant_id`/`client_id`/`client_secret`) over the
        standard DefaultAzureCredential chain when all three are configured.

        :return: An azure-identity credential usable by GraphServiceClient
        """
        azure_config = self.config.get('azure', {})
        tenant_id = azure_config.get('tenant_id')
        client_id = azure_config.get('client_id')
        client_secret = azure_config.get('client_secret')
        if tenant_id and client_id and client_secret:
            return ClientSecretCredential(tenant_id, client_id, client_secret)
        return DefaultAzureCredential()

    async def _fetch_azure_global_admins(self, graph_client: GraphServiceClient) -> list[str]:
        """
        Query Azure AD for members of the Global Administrator directory role

        :param graph_client: Authenticated Microsoft Graph client
        :return: List of user principal names (or object IDs) holding Global Administrator
        """
        admins: list[str] = []
        roles = await graph_client.directory_roles.get()
        for role in roles.value or []:
            if role.display_name != 'Global Administrator':
                continue
            members = await graph_client.directory_roles.by_directory_role_id(role.id).members.get()
            for member in members.value or []:
                principal_name = (member.additional_data or {}).get('userPrincipalName')
                admins.append(principal_name or member.id)
            break
        return admins

    async def _fetch_azure_guest_users(self, graph_client: GraphServiceClient) -> list[str]:
        """
        Query Azure AD for guest (external) user accounts

        :param graph_client: Authenticated Microsoft Graph client
        :return: List of guest user principal names (or object IDs)
        """
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            filter="userType eq 'Guest'",
        )
        request_configuration = RequestConfiguration(query_parameters=query_params)
        users = await graph_client.users.get(request_configuration=request_configuration)
        return [user.user_principal_name or user.id for user in (users.value or [])]

    def _scan_azure_access_controls(self) -> list[dict[str, Any]]:
        """
        Comprehensive Azure Active Directory access control scanning

        :return: List of Azure AD security findings
        """
        results = []
        try:
            credential = self._build_azure_credential()
            graph_client = GraphServiceClient(
                credentials=credential,
                scopes=['https://graph.microsoft.com/.default'],
            )

            global_admins = asyncio.run(self._fetch_azure_global_admins(graph_client))
            external_users = asyncio.run(self._fetch_azure_guest_users(graph_client))

            admins_compliant = len(global_admins) <= self.security_thresholds['max_privileged_users']
            guests_compliant = len(external_users) <= self.security_thresholds['max_external_collaborators']

            results.append({
                'control_id': 'AC-2(3)',
                'description': 'Azure AD User Account Management',
                'compliant': admins_compliant and guests_compliant,
                'details': {
                    'global_admins': global_admins,
                    'external_users': external_users
                },
                'remediation': (
                    f'Limit Global Administrators to {self.security_thresholds["max_privileged_users"]} or fewer '
                    f'and guest/external users to {self.security_thresholds["max_external_collaborators"]} or fewer'
                )
            })

        except Exception as e:
            self.logger.error(f"Azure Access Control Scan Error: {e}")
            results.append({
                'control_id': 'AC-AZURE-001',
                'description': 'Azure Access Control Scan',
                'compliant': False,
                'remediation': f'Error scanning Azure access controls: {str(e)}'
            })

        return results

    def _scan_gcp_access_controls(self) -> list[dict[str, Any]]:
        """
        Comprehensive Google Cloud Platform IAM access control scanning

        :return: List of GCP IAM security findings
        """
        results = []
        try:
            project_id = self.config.get('gcp', {}).get('project_id')
            project_path = f'projects/{project_id}'

            # List service accounts via the IAM Admin API
            iam_client = iam_admin_v1.IAMClient()
            service_accounts = list(
                iam_client.list_service_accounts(request={'name': project_path})
            )

            # Inspect the project's IAM policy for publicly-exposed bindings
            # (allUsers / allAuthenticatedUsers), the standard GCP definition
            # of an "external collaborator" on a resource's access policy.
            rm_client = resourcemanager_v3.ProjectsClient()
            policy = rm_client.get_iam_policy(resource=project_path)
            external_collaborators = sorted({
                member
                for binding in policy.bindings
                for member in binding.members
                if member in ('allUsers', 'allAuthenticatedUsers')
            })

            accounts_compliant = len(service_accounts) <= self.security_thresholds['max_service_accounts']
            external_compliant = len(external_collaborators) <= self.security_thresholds['max_external_collaborators']

            results.append({
                'control_id': 'AC-3(5)',
                'description': 'GCP Service Account Management',
                'compliant': accounts_compliant and external_compliant,
                'details': {
                    'service_accounts': [account.email for account in service_accounts],
                    'external_collaborators': external_collaborators
                },
                'remediation': 'Review GCP service account permissions and public/external IAM policy bindings'
            })

        except Exception as e:
            self.logger.error(f"GCP Access Control Scan Error: {e}")
            results.append({
                'control_id': 'AC-GCP-001',
                'description': 'GCP Access Control Scan',
                'compliant': False,
                'remediation': f'Error scanning GCP access controls: {str(e)}'
            })

        return results

    def scan_cloud_access_controls(self) -> list[dict[str, Any]]:
        """
        Perform comprehensive cloud access control scans

        :return: List of cloud access control findings
        """
        results = []

        # Cloud provider scanning configuration
        cloud_providers = {
            'aws': self._scan_aws_access_controls,
            'azure': self._scan_azure_access_controls,
            'gcp': self._scan_gcp_access_controls
        }

        # Scan enabled cloud providers
        for provider, scan_method in cloud_providers.items():
            if self.config.get(provider, {}).get('enabled', False):
                try:
                    results.extend(scan_method())
                except Exception as e:
                    self.logger.error(f"{provider.upper()} Cloud Access Scan Error: {e}")
                    results.append({
                        'control_id': f'AC-{provider.upper()}-ERROR',
                        'description': f'{provider.upper()} Cloud Access Scan Failure',
                        'compliant': False,
                        'remediation': f'Error scanning {provider.upper()} access controls: {str(e)}'
                    })

        return results
