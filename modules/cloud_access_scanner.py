#!/usr/bin/env python3
import asyncio
import logging
from typing import Any

import boto3
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from google.cloud import iam_admin_v1, resourcemanager_v3
from google.oauth2 import service_account
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
               'gcp': {'enabled': bool, 'projects': list[str],
                       'credentials': {'method': str,
                                       'credentials_path': str}}}``
            Azure ``client_id``/``client_secret`` are optional; when omitted,
            authentication falls back to the standard DefaultAzureCredential
            chain (environment variables, managed identity, CLI, etc.).
            GCP reads ``gcp.projects`` and optional ``gcp.credentials``; when
            credentials are omitted, authentication uses Application Default
            Credentials. ``gcp.project_id`` is accepted as a legacy fallback.
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
        global_admin_role = None
        roles_page = await graph_client.directory_roles.get()
        while roles_page:
            for role in roles_page.value or []:
                if role.display_name == 'Global Administrator':
                    global_admin_role = role
                    break
            if global_admin_role or not roles_page.odata_next_link:
                break
            roles_page = await graph_client.directory_roles.with_url(
                roles_page.odata_next_link
            ).get()

        if not global_admin_role:
            return admins

        members_builder = graph_client.directory_roles.by_directory_role_id(
            global_admin_role.id
        ).members
        members_page = await members_builder.get()
        while members_page:
            for member in members_page.value or []:
                principal_name = (member.additional_data or {}).get('userPrincipalName')
                admins.append(principal_name or member.id)
            if not members_page.odata_next_link:
                break
            members_page = await members_builder.with_url(
                members_page.odata_next_link
            ).get()
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
        users_page = await graph_client.users.get(request_configuration=request_configuration)
        guests: list[str] = []
        while users_page:
            guests.extend(
                user.user_principal_name or user.id
                for user in (users_page.value or [])
            )
            if not users_page.odata_next_link:
                break
            users_page = await graph_client.users.with_url(
                users_page.odata_next_link
            ).get()
        return guests

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

    def _get_gcp_project_ids(self) -> list[str]:
        """
        Resolve configured GCP project IDs from the nested config schema.

        :return: Project IDs to scan, preferring ``gcp.projects`` over legacy
            ``gcp.project_id``
        """
        gcp_config = self.config.get('gcp', {})
        projects = gcp_config.get('projects')
        if projects:
            return list(projects)
        project_id = gcp_config.get('project_id')
        return [project_id] if project_id else []

    def _build_gcp_credentials(self) -> service_account.Credentials | None:
        """
        Build GCP credentials from configured service-account settings.

        :return: Service-account credentials when configured, otherwise ``None``
            to use Application Default Credentials
        """
        gcp_config = self.config.get('gcp', {})
        credentials_config = gcp_config.get('credentials', {})
        if credentials_config.get('method') != 'service_account':
            return None

        credentials_path = credentials_config.get('credentials_path')
        if not credentials_path:
            return None

        return service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=['https://www.googleapis.com/auth/cloud-platform'],
        )

    def _scan_gcp_access_controls(self) -> list[dict[str, Any]]:
        """
        Comprehensive Google Cloud Platform IAM access control scanning

        :return: List of GCP IAM security findings
        """
        results = []
        project_ids = self._get_gcp_project_ids()
        if not project_ids:
            return [{
                'control_id': 'AC-GCP-001',
                'description': 'GCP Access Control Scan',
                'compliant': False,
                'remediation': (
                    'Configure gcp.projects (or legacy gcp.project_id) in the scanner config'
                ),
            }]

        credentials = self._build_gcp_credentials()
        client_kwargs = {'credentials': credentials} if credentials else {}

        try:
            iam_client = iam_admin_v1.IAMClient(**client_kwargs)
            rm_client = resourcemanager_v3.ProjectsClient(**client_kwargs)

            for project_id in project_ids:
                project_path = f'projects/{project_id}'

                service_accounts = list(
                    iam_client.list_service_accounts(request={'name': project_path})
                )

                # Inspect the project's IAM policy for publicly-exposed bindings
                # (allUsers / allAuthenticatedUsers). Any public binding fails
                # this control regardless of the external-collaborator threshold.
                policy = rm_client.get_iam_policy(request={'resource': project_path})
                external_collaborators = sorted({
                    member
                    for binding in policy.bindings
                    for member in binding.members
                    if member in ('allUsers', 'allAuthenticatedUsers')
                })

                accounts_compliant = (
                    len(service_accounts) <= self.security_thresholds['max_service_accounts']
                )
                external_compliant = len(external_collaborators) == 0

                results.append({
                    'control_id': 'AC-3(5)',
                    'description': 'GCP Service Account Management',
                    'compliant': accounts_compliant and external_compliant,
                    'details': {
                        'project_id': project_id,
                        'service_accounts': [account.email for account in service_accounts],
                        'external_collaborators': external_collaborators,
                    },
                    'remediation': (
                        'Review GCP service account permissions and remove public '
                        'IAM policy bindings (allUsers / allAuthenticatedUsers)'
                    ),
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
