"""Collector registry.

``DEFAULT_COLLECTORS`` run everywhere (a collector that cannot gather its
evidence reports a coverage gap). ``OPTIONAL_COLLECTORS`` run only when their
config section is present.
"""

from .base import Collector
from .cloud import AwsIamCollector, AzureDirectoryCollector, GcpIamCollector
from .config_file import ScannerLoggingConfigCollector
from .linux import (
    AuditdCollector,
    CryptoPolicyCollector,
    LinuxAccountsCollector,
    ListeningServicesCollector,
    PackageUpdatesCollector,
    SshdConfigCollector,
    SshKeyPermissionsCollector,
    SysctlCollector,
)
from .network import FirewallRulesCollector
from .vulnerability import VulnerabilityScanReportCollector
from .windows import WindowsAccountsCollector

DEFAULT_COLLECTORS = [
    LinuxAccountsCollector,
    SshKeyPermissionsCollector,
    SshdConfigCollector,
    AuditdCollector,
    ListeningServicesCollector,
    SysctlCollector,
    CryptoPolicyCollector,
    PackageUpdatesCollector,
    ScannerLoggingConfigCollector,
]

# collector class -> predicate on the config deciding whether it is in scope
OPTIONAL_COLLECTORS = {
    FirewallRulesCollector: lambda c: bool((c.get("firewall") or {}).get("config_paths")),
    VulnerabilityScanReportCollector: lambda c: bool((c.get("vulnerability_scan") or {}).get("report_path")),
    AwsIamCollector: lambda c: bool(((c.get("cloud_providers") or {}).get("aws") or {}).get("enabled")),
    AzureDirectoryCollector: lambda c: bool(((c.get("cloud_providers") or {}).get("azure") or {}).get("enabled")),
    GcpIamCollector: lambda c: bool(((c.get("cloud_providers") or {}).get("gcp") or {}).get("enabled")),
    WindowsAccountsCollector: lambda c: bool((c.get("windows") or {}).get("enabled")),
}


def build_collectors(config: dict) -> list[Collector]:
    selected = [cls(config) for cls in DEFAULT_COLLECTORS]
    selected += [cls(config) for cls, wanted in OPTIONAL_COLLECTORS.items() if wanted(config)]
    return selected


__all__ = ["Collector", "DEFAULT_COLLECTORS", "OPTIONAL_COLLECTORS", "build_collectors"]
