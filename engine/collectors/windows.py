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
$min = (net accounts | Select-String 'Minimum password length').ToString().Split(':')[1].Trim()
[pscustomobject]@{
  admin_users = @(Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name)
  disabled_accounts = @(Get-LocalUser | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
  min_password_length = [int]$min
} | ConvertTo-Json -Compress
"""


def run_powershell(script: str) -> dict:
    """Run a script via -EncodedCommand (base64 UTF-16LE, no shell) and parse JSON stdout."""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    exe = "powershell.exe" if sys.platform == "win32" else "pwsh"
    res = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                         capture_output=True, text=True, timeout=60, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"PowerShell failed: {res.stderr.strip() or res.returncode}")
    if not res.stdout.strip():
        raise RuntimeError("PowerShell returned no output")
    return json.loads(res.stdout)


class WindowsAccountsCollector(Collector):
    name = "windows_accounts"
    evidence_type = "windows.accounts"

    def __init__(self, config: dict | None = None, runner: Callable[[str], dict] | None = None):
        super().__init__(config)
        self._runner = runner or run_powershell

    def gather(self) -> dict:
        data = self._runner(SCRIPT)
        missing = [k for k in ("admin_users", "disabled_accounts", "min_password_length") if k not in data]
        if missing:
            raise ValueError(f"PowerShell output missing fields: {', '.join(missing)}")
        return {"admin_users": sorted(data["admin_users"]), "disabled_accounts": sorted(data["disabled_accounts"]),
                "min_password_length": int(data["min_password_length"])}
