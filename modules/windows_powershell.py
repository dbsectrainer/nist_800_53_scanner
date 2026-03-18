#!/usr/bin/env python3
import subprocess
import json
import logging
from typing import Dict, Any, List


class WindowsPowerShellScanner:
    def __init__(self, config: Dict):
        """
        Initialize Windows PowerShell Scanner

        :param config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Security thresholds for Windows systems
        self.security_thresholds = {
            "max_admin_users": 3,
            "max_disabled_accounts": 5,
            "password_complexity": {"min_length": 12, "require_complexity": True},
        }

    def execute_powershell_script(self, script: str) -> Dict[str, Any]:
        """
        Execute a PowerShell script and return parsed results

        :param script: PowerShell script to execute
        :return: Parsed JSON results
        """
        try:
            # Encode script to handle special characters
            encoded_script = script.encode("utf-16le")

            # Execute PowerShell script
            result = subprocess.run(
                ["powershell.exe", "-EncodedCommand", subprocess.list2cmdline([encoded_script.decode("utf-16le")])],
                capture_output=True,
                text=True,
                shell=True,
            )

            # Check for errors
            if result.returncode != 0:
                self.logger.error(f"PowerShell Script Error: {result.stderr}")
                return {}

            # Parse JSON output
            return json.loads(result.stdout) if result.stdout else {}

        except Exception as e:
            self.logger.error(f"PowerShell Execution Error: {e}")
            return {}

    def scan_user_accounts(self) -> List[Dict[str, Any]]:
        """
        Comprehensive Windows user account security scan

        :return: List of user account security findings
        """
        ps_script = r"""
        # Advanced Windows User Account Security Scan
        $results = @{
            admin_users = @(),
            disabled_accounts = @(),
            password_policy = $null,
            local_groups = @()
        }

        # Get administrative users
        $results.admin_users = (Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name)

        # Find disabled accounts
        $results.disabled_accounts = (Get-LocalUser | Where-Object {$_.Enabled -eq $false} | Select-Object -ExpandProperty Name)

        # Retrieve password policy
        $results.password_policy = @{
            MinPasswordLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PasswdCAPs\Parameters" -Name "MinPasswordLength").MinPasswordLength
            ComplexityEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PasswdCAPs\Parameters" -Name "ComplexityEnabled").ComplexityEnabled
        }

        # Get local group memberships
        $results.local_groups = (Get-LocalGroup | ForEach-Object {
            @{
                Name = $_.Name
                Members = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name)
            }
        })

        # Convert to JSON
        $results | ConvertTo-Json -Depth 5
        """

        results = []
        try:
            scan_data = self.execute_powershell_script(ps_script)

            # Administrative Users Check
            results.append(
                {
                    "control_id": "AC-2(1)",
                    "description": "Administrative User Accounts",
                    "compliant": len(scan_data.get("admin_users", [])) <= self.security_thresholds["max_admin_users"],
                    "details": {"admin_users": scan_data.get("admin_users", [])},
                    "remediation": f"Limit administrative users to {self.security_thresholds['max_admin_users']} or fewer",
                }
            )

            # Disabled Accounts Check
            results.append(
                {
                    "control_id": "AC-2(3)",
                    "description": "Disabled User Accounts",
                    "compliant": len(scan_data.get("disabled_accounts", []))
                    <= self.security_thresholds["max_disabled_accounts"],
                    "details": {"disabled_accounts": scan_data.get("disabled_accounts", [])},
                    "remediation": "Review and remove unnecessary disabled accounts",
                }
            )

            # Password Policy Check
            password_policy = scan_data.get("password_policy", {})
            results.append(
                {
                    "control_id": "AC-3(4)",
                    "description": "Password Complexity",
                    "compliant": (
                        password_policy.get("MinPasswordLength", 0)
                        >= self.security_thresholds["password_complexity"]["min_length"]
                        and password_policy.get("ComplexityEnabled", False)
                        == self.security_thresholds["password_complexity"]["require_complexity"]
                    ),
                    "details": {
                        "min_password_length": password_policy.get("MinPasswordLength", 0),
                        "complexity_enabled": password_policy.get("ComplexityEnabled", False),
                    },
                    "remediation": "Enforce strong password policy with minimum 12 characters and complexity requirements",
                }
            )

        except Exception as e:
            self.logger.error(f"Windows User Account Scan Error: {e}")
            results.append(
                {
                    "control_id": "AC-WINDOWS-001",
                    "description": "Windows User Account Security Scan",
                    "compliant": False,
                    "remediation": f"Error scanning Windows user accounts: {str(e)}",
                }
            )

        return results

    def scan_system_access_controls(self) -> List[Dict[str, Any]]:
        """
        Comprehensive Windows system access control scanning

        :return: List of access control findings
        """
        results = []

        # Combine various access control scans
        results.extend(self.scan_user_accounts())

        return results
