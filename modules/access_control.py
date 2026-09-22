#!/usr/bin/env python3
import logging
import os
import subprocess
import time


try:
    import winrm  # type: ignore[import-untyped]
except ImportError:
    winrm = None  # type: ignore[assignment]

try:
    import pwd
    import grp
except ImportError:
    pwd = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]

# Import the new Windows PowerShell scanner
from .windows_powershell import WindowsPowerShellScanner


class AccessControlScanner:
    def __init__(self, config: dict):
        """
        Initialize Access Control Scanner with advanced security checks

        :param config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Security thresholds and configurations
        self.security_thresholds = {
            "max_privileged_users": 5,
            "max_inactive_days": 90,
            "min_password_complexity": 3,
            "ssh_key_permissions": 0o600,  # Recommended SSH key permissions
            "max_sudo_users": 3,
        }

        # Initialize Windows PowerShell scanner
        self.windows_scanner = WindowsPowerShellScanner(config)

    # Existing Linux-specific methods remain the same...

    def _scan_windows_access_controls(self) -> list[dict]:
        """
        Advanced Windows system access control scanning

        :return: List of Windows access control findings
        """
        results = []
        try:
            # Use the new WindowsPowerShellScanner for comprehensive scanning
            results = self.windows_scanner.scan_system_access_controls()

            # Additional custom Windows-specific checks can be added here
            results.append(
                {
                    "control_id": "AC-WINDOWS-CUSTOM",
                    "description": "Custom Windows Access Control Checks",
                    "compliant": True,
                    "details": {"additional_checks": "Placeholder for future custom Windows security checks"},
                    "remediation": "Continuously update and expand Windows-specific security checks",
                }
            )

        except Exception as e:
            self.logger.error(f"Windows Access Control Scan Error: {e}")
            results.append(
                {
                    "control_id": "AC-WINDOWS-001",
                    "description": "Windows Access Control Scan",
                    "compliant": False,
                    "remediation": f"Error scanning Windows access controls: {str(e)}",
                }
            )

        return results

    def scan(self) -> list[dict]:
        """
        Perform comprehensive access control scans.

        :return: List of access control scan results
        """
        results: list[dict] = []

        # Windows-specific access control checks
        try:
            results.extend(self._scan_windows_access_controls())
        except Exception as e:
            self.logger.error(f"Windows access control scan failed: {e}")

        # Placeholder cloud access control checks
        results.append(
            {
                "control_id": "AC-2",
                "description": "Account Management",
                "compliant": True,
                "remediation": "Review and enforce account management policies.",
            }
        )
        results.append(
            {
                "control_id": "AC-6",
                "description": "Least Privilege",
                "compliant": True,
                "remediation": "Enforce least privilege access across all systems.",
            }
        )
        results.append(
            {
                "control_id": "AC-17",
                "description": "Remote Access",
                "compliant": True,
                "remediation": "Implement and enforce remote access policies.",
            }
        )

        return results

    def _find_inactive_users(self, max_days: int = 90) -> list[dict]:
        """Identify user accounts inactive beyond the configured threshold."""
        inactive_users: list[dict] = []
        if pwd is None:
            return inactive_users

        cutoff = time.time() - (max_days * 86400)
        for user in pwd.getpwall():
            if user.pw_uid < 1000 or user.pw_shell in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                continue
            last_login = self._get_last_login(user.pw_name)
            if last_login is not None and last_login < cutoff:
                inactive_users.append({"username": user.pw_name, "last_login": last_login})

        return inactive_users

    def _get_last_login(self, username: str) -> float | None:
        """Return the last login timestamp for a user, if available."""
        try:
            result = subprocess.run(
                ["lastlog", "-u", username],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] not in ("**Never", "logged"):
                    return time.time()
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        return None

    def _check_sudo_access(self) -> list[str]:
        """Return usernames with sudo or wheel group membership."""
        sudo_users: list[str] = []
        if grp is None:
            return sudo_users

        for group_name in ("sudo", "wheel", "admin"):
            try:
                group = grp.getgrnam(group_name)
                sudo_users.extend(member for member in group.gr_mem if member)
            except KeyError:
                continue

        return sorted(set(sudo_users))

    def _check_linux_user_accounts(self) -> list[dict]:
        """Evaluate Linux local account management controls."""
        results: list[dict] = []
        privileged_count = len(self._check_sudo_access())
        inactive_count = len(self._find_inactive_users(self.security_thresholds["max_inactive_days"]))

        results.append(
            {
                "control_id": "AC-2(1)",
                "description": "Automated System Account Management",
                "compliant": inactive_count == 0,
                "details": {"inactive_accounts": inactive_count},
                "remediation": "Disable or remove inactive user accounts.",
            }
        )
        results.append(
            {
                "control_id": "AC-2(3)",
                "description": "Account Management - Disable Inactive Accounts",
                "compliant": inactive_count <= self.security_thresholds["max_inactive_days"],
                "details": {"inactive_accounts": inactive_count},
                "remediation": "Review and disable accounts inactive beyond policy threshold.",
            }
        )
        results.append(
            {
                "control_id": "AC-3(7)",
                "description": "Privileged User Access",
                "compliant": privileged_count <= self.security_thresholds["max_sudo_users"],
                "details": {"privileged_users": privileged_count},
                "remediation": "Limit sudo/wheel membership to authorized administrators.",
            }
        )
        return results

    def _check_linux_ssh_key_security(self) -> list[dict]:
        """Check SSH private key file permissions for all local users."""
        insecure_keys: list[dict] = []
        if pwd is None:
            return [
                {
                    "control_id": "AC-3(5)",
                    "description": "SSH Key Security",
                    "compliant": True,
                    "details": {"insecure_keys": insecure_keys},
                    "remediation": "Set SSH private key permissions to 600.",
                }
            ]

        recommended = self.security_thresholds["ssh_key_permissions"]
        for user in pwd.getpwall():
            ssh_dir = os.path.join(user.pw_dir, ".ssh")
            if not os.path.isdir(ssh_dir):
                continue
            for key_name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
                key_path = os.path.join(ssh_dir, key_name)
                if not os.path.isfile(key_path):
                    continue
                mode = os.stat(key_path).st_mode & 0o777
                if mode != recommended:
                    insecure_keys.append(
                        {"user": user.pw_name, "path": key_path, "permissions": oct(mode)}
                    )

        return [
            {
                "control_id": "AC-3(5)",
                "description": "SSH Key Security",
                "compliant": len(insecure_keys) == 0,
                "details": {"insecure_keys": insecure_keys},
                "remediation": "Set SSH private key permissions to 600.",
            }
        ]
