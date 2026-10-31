#!/usr/bin/env python3
"""Generate synthetic dashboard reports for local demos and screenshots.

The reports are written as plaintext engine reports into ``reports/`` (which is
gitignored). The collectors are stubs: this script never touches the host,
cloud APIs, or the network, so it is safe to run anywhere.

Usage:
    python scripts/generate_demo_reports.py [--output-dir reports]

Then start the dashboard and log in with the development credentials:
    python dashboard/app.py
    # http://127.0.0.1:5001/login  (admin / password)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.collectors.base import Collector  # noqa: E402
from engine.coverage import summarize  # noqa: E402
from engine.runner import run_assessment  # noqa: E402


class StubCollector(Collector):
    """Collector that returns a fixed payload (or raises a given error)."""

    def __init__(self, name: str, evidence_type: str, payload: dict[str, Any] | Exception):
        super().__init__({"asset_id": "demo-host"})
        self.name = name
        self.evidence_type = evidence_type
        self._payload = payload

    def gather(self) -> dict[str, Any]:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _collectors(day: datetime, *, healthy: bool, partial: bool = False, vuln_report: bool = True) -> list[Collector]:
    """Build one synthetic fleet of collectors for a given report day."""
    reference = datetime.now(timezone.utc)
    recent = _iso(day - timedelta(days=2))
    index = _iso(reference - timedelta(hours=1))
    stale_index = _iso(reference - timedelta(days=5))

    accounts = [
        {
            "username": "alice",
            "uid": 1000,
            "last_login_epoch": (day - timedelta(days=4)).timestamp(),
            "never_logged_in": False,
            "login_data_known": True,
        },
        {
            "username": "bob",
            "uid": 1001,
            "last_login_epoch": (day - timedelta(days=12)).timestamp(),
            "never_logged_in": False,
            "login_data_known": True,
        },
    ]
    if not healthy and not partial:
        accounts.append(
            {
                "username": "carol",
                "uid": 1002,
                "last_login_epoch": (day - timedelta(days=180)).timestamp(),
                "never_logged_in": False,
                "login_data_known": True,
            }
        )

    sshd = {
        "permitrootlogin": "no" if (healthy or partial) else "yes",
        "passwordauthentication": "no",
        "permitemptypasswords": "no",
        "maxauthtries": "4",
        "ciphers": "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
    }
    keys = [
        {"user": "alice", "path": "/home/alice/.ssh/id_ed25519", "mode": 0o600},
        {"user": "bob", "path": "/home/bob/.ssh/id_rsa", "mode": 0o600 if healthy else 0o644},
    ]
    listeners = [
        {"proto": "tcp", "address": "0.0.0.0", "port": 22, "loopback": False},
        {"proto": "tcp", "address": "127.0.0.1", "port": 631, "loopback": True},
    ]
    if not healthy and not partial:
        listeners.append({"proto": "tcp", "address": "0.0.0.0", "port": 8080, "loopback": False})

    collectors: list[Collector] = [
        StubCollector(
            "demo_accounts",
            "linux.accounts",
            {
                "accounts": accounts,
                "sudo_users": ["alice", "bob"],
                "sudoers_users": ["deploy"],
                "login_data_complete": True,
                "never_logged_in_accounts": [],
            },
        ),
        StubCollector("demo_sshd", "linux.sshd_config", {"settings": sshd, "complete": True}),
        StubCollector("demo_ssh_keys", "linux.ssh_keys", {"private_keys": keys, "unreadable": [], "complete": True}),
        StubCollector(
            "demo_auditd",
            "linux.audit",
            {
                "audit_rule_count": 14 if (healthy or partial) else 0,
                "auditd_settings": {"enabled": "1"},
                "auditd_running": True,
            },
        ),
        StubCollector("demo_sysctl", "linux.sysctl", {"values": {"kernel.randomize_va_space": "2"}}),
        StubCollector("demo_listeners", "linux.listening_services", {"listeners": listeners}),
        StubCollector("demo_crypto", "linux.crypto", {"fips_enabled": 1}),
        StubCollector(
            "demo_patches",
            "linux.patches",
            {
                "manager": "apt",
                "pending_updates": 0 if healthy else 3,
                "pending_security_updates": 0 if healthy else 2,
                "index_updated_at": index if (healthy or partial) else stale_index,
            },
        ),
        StubCollector(
            "demo_logging",
            "app.logging_config",
            {
                "local_logging_enabled": True,
                "retention_days": 400 if (healthy or partial) else 30,
            },
        ),
        StubCollector(
            "demo_firewall",
            "network.firewall_rules",
            {
                "configs": [{"path": "demo-firewall.json", "rule_count": 2, "sha256": "0" * 64}],
                "rules": [
                    {
                        "path": "demo-firewall.json",
                        "source": "10.0.0.0/8",
                        "action": "allow",
                        "source_raw": "10.0.0.0/8",
                        "action_raw": "allow",
                    },
                    {
                        "path": "demo-firewall.json",
                        "source": "any",
                        "action": "deny",
                        "source_raw": "0.0.0.0/0",
                        "action_raw": "deny",
                    },
                ],
                "unreadable": [],
            },
        ),
        StubCollector(
            "demo_vuln",
            "vuln.scan_report",
            {
                "completed_at": recent,
                "finding_count": 0 if (healthy or partial) else 4,
                "critical_count": 0 if (healthy or partial) else 1,
                "high_count": 0 if (healthy or partial) else 2,
                "report_path": "demo-vulnerability-report.json",
                "report_sha256": "0" * 64,
            },
        ),
        StubCollector(
            "demo_aws",
            "aws.iam",
            {
                "root_mfa_enabled": True,
                "user_count": 8,
                "admin_users": ["svc-admin", "breakglass"],
                "console_users_without_mfa": [] if (healthy or partial) else ["contractor"],
            },
        ),
        StubCollector(
            "demo_azure",
            "azure.directory",
            {
                "global_admins": ["admin@example.com"],
                "guest_users": [],
            },
        ),
        StubCollector(
            "demo_gcp",
            "gcp.iam",
            {
                "service_account_count": 4,
                "public_members": [] if (healthy or partial) else ["allUsers"],
                "policy_scope": "project",
            },
        ),
        StubCollector(
            "demo_windows",
            "windows.accounts",
            {
                "admin_users": ["Administrator", "svc-admin"],
                "disabled_accounts": [],
                "min_password_length": 14,
                "domain_joined": False,
            },
        ),
    ]
    if not vuln_report:
        collectors = [c for c in collectors if c.evidence_type != "vuln.scan_report"]
        collectors.append(
            StubCollector("demo_vuln", "vuln.scan_report", FileNotFoundError("demo vulnerability report missing"))
        )
    return collectors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=str(ROOT / "reports"),
        help="Directory for the generated JSON reports (default: reports/)",
    )
    parser.add_argument("--days", type=int, default=6, help="Number of historical reports (default: 6)")
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob("demo-*.json"):
        stale.unlink()

    today = datetime.now(timezone.utc).replace(microsecond=0)
    for offset in range(args.days, 0, -1):
        day = today - timedelta(days=offset)
        healthy = offset in (2, 3)  # clean reports in the middle of the trend
        partial = offset == 1  # newest report: two findings, for POA&M/Controls views
        run = run_assessment(
            {},
            system_id="demo-system",
            baseline="rules",
            collectors=_collectors(day, healthy=healthy, partial=partial, vuln_report=offset != args.days),
        )
        run.started_at = day
        run.run_id = f"demo-{day.strftime('%Y%m%d')}"
        for evidence in run.evidence:
            evidence.collected_at = day
        path = out / f"demo-{day.strftime('%Y%m%d')}.json"
        path.write_text(json.dumps({**run.to_dict(), "summary": summarize(run)}, indent=2))
        summary = summarize(run)
        print(
            f"{path.name}: {summary['controls_total']} controls, "
            f"{summary['objective_counts'].get('satisfied', 0)} satisfied, "
            f"{summary['objective_counts'].get('other_than_satisfied', 0)} findings, "
            f"{summary['collection_errors']} collection error(s)"
        )
    print(f"\nWrote {args.days} synthetic reports to {out}")
    print("Start the dashboard with: python dashboard/app.py")
    print("Then open http://127.0.0.1:5001/login (admin / password in dev config).")


if __name__ == "__main__":
    main()
