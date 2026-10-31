"""Cloud identity collectors (read-only).

Provider SDKs are imported lazily and clients/fetchers are injectable, so the
engine and its tests need no cloud credentials. Any failure (missing SDK,
expired credentials, API error) is a collection error -> ``not_assessed``.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from .base import Collector


def _provider_cfg(config: dict, name: str) -> dict:
    return ((config.get("cloud_providers") or {}).get(name)) or {}


def _expand(value: Any) -> Optional[str]:
    """Expand ${ENV} references; unresolved placeholders count as unset."""
    if not isinstance(value, str):
        return value
    expanded = os.path.expandvars(value)
    return None if "${" in expanded else expanded


class AwsIamCollector(Collector):
    name = "aws_iam"
    evidence_type = "aws.iam"

    def __init__(self, config: dict | None = None, client_factory: Callable[[], Any] | None = None):
        super().__init__(config)
        self._client_factory = client_factory

    @property
    def asset_id(self) -> str:
        return self.config.get("aws_account_id") or "aws-account"

    def _client(self) -> Any:
        if self._client_factory:
            return self._client_factory()
        import boto3  # lazy: optional dependency

        return boto3.client("iam")

    def gather(self) -> dict:
        if not _provider_cfg(self.config, "aws").get("enabled", False):
            raise RuntimeError("aws provider not enabled in cloud_providers.aws")
        iam = self._client()
        summary = iam.get_account_summary()["SummaryMap"]
        users, admins, no_mfa = [], [], []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page["Users"])
        for user in users:
            name = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            if any(p.get("PolicyArn", "").endswith("policy/AdministratorAccess") for p in attached):
                admins.append(name)
            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except Exception as exc:  # NoSuchEntity means no console password
                if exc.__class__.__name__ != "NoSuchEntityException":
                    raise
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                no_mfa.append(name)
        return {
            "root_mfa_enabled": summary.get("AccountMFAEnabled", 0) > 0,
            "user_count": len(users),
            "admin_users": sorted(admins),
            "console_users_without_mfa": sorted(no_mfa),
        }


class AzureDirectoryCollector(Collector):
    name = "azure_directory"
    evidence_type = "azure.directory"

    def __init__(self, config: dict | None = None, fetcher: Callable[[], dict] | None = None):
        super().__init__(config)
        self._fetcher = fetcher

    @property
    def asset_id(self) -> str:
        return self.config.get("azure_tenant_id") or "azure-tenant"

    def _default_fetch(self) -> dict:
        import asyncio

        from msgraph import GraphServiceClient  # lazy: optional dependency

        from modules.cloud_access_scanner import CloudAccessScanner

        az = _provider_cfg(self.config, "azure").get("credentials") or {}
        scanner = CloudAccessScanner({"azure": {
            "tenant_id": _expand(az.get("tenant_id")),
            "client_id": _expand(az.get("client_id")),
            "client_secret": _expand(az.get("client_secret")),
        }})
        client = GraphServiceClient(credentials=scanner._build_azure_credential(),
                                    scopes=["https://graph.microsoft.com/.default"])
        return {
            "global_admins": asyncio.run(scanner._fetch_azure_global_admins(client)),
            "guest_users": asyncio.run(scanner._fetch_azure_guest_users(client)),
        }

    def gather(self) -> dict:
        if not _provider_cfg(self.config, "azure").get("enabled", False):
            raise RuntimeError("azure provider not enabled in cloud_providers.azure")
        data = (self._fetcher or self._default_fetch)()
        return {"global_admins": sorted(data["global_admins"]), "guest_users": sorted(data["guest_users"])}


class GcpIamCollector(Collector):
    """One evidence item per configured project; a failing project is a per-asset error."""

    name = "gcp_iam"
    evidence_type = "gcp.iam"

    def __init__(self, config: dict | None = None, fetcher: Callable[[str], dict] | None = None):
        super().__init__(config)
        self._fetcher = fetcher

    def _default_fetch(self, project_id: str) -> dict:
        from google.cloud import iam_admin_v1, resourcemanager_v3  # lazy: optional dependency

        from modules.cloud_access_scanner import CloudAccessScanner

        gcp = _provider_cfg(self.config, "gcp")
        scanner = CloudAccessScanner({"gcp": gcp})
        creds = scanner._build_gcp_credentials()
        kwargs = {"credentials": creds} if creds else {}
        path = f"projects/{project_id}"
        accounts = list(iam_admin_v1.IAMClient(**kwargs).list_service_accounts(request={"name": path}))
        policy = resourcemanager_v3.ProjectsClient(**kwargs).get_iam_policy(request={"resource": path})
        public = sorted({m for b in policy.bindings for m in b.members if m in ("allUsers", "allAuthenticatedUsers")})
        return {"service_account_count": len(accounts), "public_members": public}

    def gather_assets(self) -> list[tuple[str, dict]]:
        from engine.models import CollectionError

        gcp = _provider_cfg(self.config, "gcp")
        if not gcp.get("enabled", False):
            raise RuntimeError("gcp provider not enabled in cloud_providers.gcp")
        projects = gcp.get("projects") or []
        if not projects:
            raise KeyError("cloud_providers.gcp.projects not configured")
        fetch = self._fetcher or self._default_fetch
        items = []
        for project in projects:
            try:
                items.append((f"gcp:{project}", fetch(project)))
            except Exception as exc:
                self.partial_errors.append(CollectionError(self.name, self.evidence_type, str(exc), f"gcp:{project}"))
        if not items and self.partial_errors:
            raise RuntimeError("; ".join(e.message for e in self.partial_errors))
        return items
