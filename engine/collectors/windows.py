"""Windows local account collector (local PowerShell, read-only)."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from typing import Callable

from .base import Collector

SCRIPT = r"""
$ErrorActionPreference = 'Stop'

# Well-known SID avoids depending on the localized name of the Administrators group.
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'

# secedit exports effective local policy without parsing localized `net accounts` text.
$inf = Join-Path $env:TEMP ("nist-secpol-" + [guid]::NewGuid().ToString() + ".inf")
secedit /export /cfg $inf /areas SECURITYPOLICY | Out-Null
if ($LASTEXITCODE -ne 0) { throw "secedit failed with exit code $LASTEXITCODE" }
$policyText = Get-Content -Path $inf -Raw
Remove-Item -Path $inf -Force
$match = [regex]::Match($policyText, 'MinimumPasswordLength\s*=\s*(\d+)')
if (-not $match.Success) { throw 'MinimumPasswordLength not found in exported security policy' }

$domainJoined = [bool](Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain

[pscustomobject]@{
  admin_users = @(Get-LocalGroupMember -Group $adminGroup | Select-Object -ExpandProperty Name)
  disabled_accounts = @(Get-LocalUser | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
  min_password_length = [int]$match.Groups[1].Value
  domain_joined = $domainJoined
} | ConvertTo-Json -Compress
"""


def run_powershell(script: str) -> dict:
    """Run a script via -EncodedCommand (base64 UTF-16LE, no shell) and parse JSON stdout."""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    exe = "powershell.exe" if sys.platform == "win32" else "pwsh"
    res = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"PowerShell failed: {res.stderr.strip() or res.returncode}")
    if not res.stdout.strip():
        raise RuntimeError("PowerShell returned no output")
    return json.loads(res.stdout)


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]  # ConvertTo-Json can collapse a one-element array
    raise ValueError(f"expected a list, got {type(value).__name__}")


class WindowsAccountsCollector(Collector):
    name = "windows_accounts"
    evidence_type = "windows.accounts"

    def __init__(self, config: dict | None = None, runner: Callable[[str], dict] | None = None):
        super().__init__(config)
        self._runner = runner or run_powershell

    def gather(self) -> dict:
        data = self._runner(SCRIPT)
        missing = [
            k for k in ("admin_users", "disabled_accounts", "min_password_length", "domain_joined") if k not in data
        ]
        if missing:
            raise ValueError(f"PowerShell output missing fields: {', '.join(missing)}")
        return {
            "admin_users": sorted(_as_list(data["admin_users"])),
            "disabled_accounts": sorted(_as_list(data["disabled_accounts"])),
            "min_password_length": int(data["min_password_length"]),
            "domain_joined": bool(data["domain_joined"]),
        }
