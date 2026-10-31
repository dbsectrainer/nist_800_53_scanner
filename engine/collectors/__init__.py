from .base import Collector
from .config_file import ScannerLoggingConfigCollector
from .linux import AuditdCollector, LinuxAccountsCollector, SshdConfigCollector, SshKeyPermissionsCollector

DEFAULT_COLLECTORS = [
    LinuxAccountsCollector,
    SshKeyPermissionsCollector,
    SshdConfigCollector,
    AuditdCollector,
    ScannerLoggingConfigCollector,
]

__all__ = ["Collector", "DEFAULT_COLLECTORS", *[c.__name__ for c in DEFAULT_COLLECTORS]]
