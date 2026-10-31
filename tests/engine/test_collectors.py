import json
import os
import subprocess

import pytest

from engine.collectors.base import Collector
from engine.collectors.cloud import AwsIamCollector, AzureDirectoryCollector, GcpIamCollector
from engine.collectors.linux import (
    CryptoPolicyCollector,
    ListeningServicesCollector,
    SshdConfigCollector,
    SysctlCollector,
    _parse_lastlog_line,
)
from engine.collectors.network import FirewallRulesCollector
from engine.collectors.vulnerability import VulnerabilityScanReportCollector
from engine.collectors.windows import WindowsAccountsCollector
from engine.collectors import build_collectors


def test_base_collect_error_becomes_coverage_gap():
    class Boom(Collector):
        name, evidence_type = "b", "x"

        def gather(self):
            raise RuntimeError("nope")

    ev, errs = Boom({"asset_id": "h"}).collect()
    assert ev == [] and errs[0].message == "nope" and errs[0].asset_id == "h"


def test_lastlog_parsing():
    assert _parse_lastlog_line("alice  pts/0  1.2.3.4  Mon Oct 27 10:00:00 +0000 2025")[0] is True
    assert _parse_lastlog_line("bob **Never logged in**") == (True, None)
    assert _parse_lastlog_line("garbled") == (False, None)


def test_parse_ss_marks_loopback():
    out = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 5 127.0.0.1:631 0.0.0.0:*\ntcp LISTEN 0 5 [::]:8080 [::]:*\n"
    got = ListeningServicesCollector.parse_ss(out)
    assert [(l["port"], l["loopback"]) for l in got] == [(22, False), (631, True), (8080, False)]


def test_sshd_config_first_value_wins_and_match_ignored(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("PermitRootLogin no\nPermitRootLogin yes\n# c\nMatch User bob\n  PasswordAuthentication yes\n")
    s = SshdConfigCollector({"sshd_config_path": str(f)}).gather()["settings"]
    assert s["permitrootlogin"] == "no" and "passwordauthentication" not in s


def test_sshd_missing_file_is_error(tmp_path):
    _, errs = SshdConfigCollector({"sshd_config_path": str(tmp_path / "none")}).collect()
    assert errs


def test_sysctl_and_fips(tmp_path):
    (tmp_path / "kernel").mkdir()
    (tmp_path / "kernel" / "randomize_va_space").write_text("2\n")
    assert SysctlCollector({"proc_sys_root": str(tmp_path)}).gather() == {"values": {"kernel.randomize_va_space": "2"}}
    assert SysctlCollector({"proc_sys_root": str(tmp_path / "x")}).collect()[1]
    fips = tmp_path / "fips"
    fips.write_text("1\n")
    assert CryptoPolicyCollector({"fips_flag_path": str(fips)}).gather() == {"fips_enabled": 1}
    assert CryptoPolicyCollector({"fips_flag_path": str(tmp_path / "no")}).collect()[1]


def test_firewall_unreadable_is_recorded_not_permissive(tmp_path):
    good = tmp_path / "fw.json"
    good.write_text(json.dumps({"rules": [{"source": "10.0.0.0/8", "action": "allow", "extra": 1}]}))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    payload = FirewallRulesCollector({"firewall": {"config_paths": [str(good), str(bad)]}}).gather()
    assert len(payload["configs"]) == 1 and len(payload["unreadable"]) == 1
    assert payload["rules"] == [{"path": str(good), "source": "10.0.0.0/8", "action": "allow"}]
    assert FirewallRulesCollector({}).collect()[1]  # unconfigured -> gap


def test_vulnerability_report(tmp_path):
    f = tmp_path / "scan.json"
    f.write_text(json.dumps({"completed_at": "2026-10-20T00:00:00Z",
                             "findings": [{"severity": "Critical"}, {"severity": "high"}, {"severity": "low"}]}))
    p = VulnerabilityScanReportCollector({"vulnerability_scan": {"report_path": str(f)}}).gather()
    assert (p["critical_count"], p["high_count"], p["finding_count"]) == (1, 1, 3)
    f.write_text("{}")
    assert VulnerabilityScanReportCollector({"vulnerability_scan": {"report_path": str(f)}}).collect()[1]


# --- cloud / windows with injected fakes (no SDKs or credentials) ---------
class FakeIam:
    class exceptions:
        pass

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1}}

    def get_paginator(self, name):
        assert name == "list_users"
        return type("P", (), {"paginate": lambda s: [{"Users": [{"UserName": "a"}, {"UserName": "b"}]}]})()

    def list_attached_user_policies(self, UserName):
        arn = "arn:aws:iam::aws:policy/AdministratorAccess" if UserName == "a" else "arn:aws:iam::aws:policy/ReadOnly"
        return {"AttachedPolicies": [{"PolicyArn": arn}]}

    def get_login_profile(self, UserName):
        if UserName == "b":
            raise type("NoSuchEntityException", (Exception,), {})()
        return {}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}


def test_aws_collector_with_fake_client():
    cfg = {"cloud_providers": {"aws": {"enabled": True}}}
    ev, errs = AwsIamCollector(cfg, client_factory=FakeIam).collect()
    assert not errs
    assert ev[0].payload == {"root_mfa_enabled": True, "user_count": 2, "admin_users": ["a"],
                             "console_users_without_mfa": ["a"]}


def test_cloud_disabled_or_failing_is_gap():
    assert AwsIamCollector({}, client_factory=FakeIam).collect()[1]  # not enabled
    boom = lambda: (_ for _ in ()).throw(PermissionError("expired token"))
    _, errs = AwsIamCollector({"cloud_providers": {"aws": {"enabled": True}}}, client_factory=boom).collect()
    assert "expired token" in errs[0].message


def test_azure_collector_with_fake_fetcher():
    cfg = {"cloud_providers": {"azure": {"enabled": True}}}
    ev, errs = AzureDirectoryCollector(cfg, fetcher=lambda: {"global_admins": ["z", "y"], "guest_users": []}).collect()
    assert not errs and ev[0].payload["global_admins"] == ["y", "z"]


def test_gcp_partial_failure_is_per_asset():
    cfg = {"cloud_providers": {"gcp": {"enabled": True, "projects": ["p1", "p2"]}}}

    def fetch(project):
        if project == "p2":
            raise PermissionError("denied")
        return {"service_account_count": 1, "public_members": []}

    ev, errs = GcpIamCollector(cfg, fetcher=fetch).collect()
    assert [e.asset_id for e in ev] == ["gcp:p1"] and errs[0].asset_id == "gcp:p2"
    ev, errs = GcpIamCollector(cfg, fetcher=lambda p: (_ for _ in ()).throw(RuntimeError("x"))).collect()
    assert not ev and errs


def test_windows_collector_validates_runner_output():
    ok = {"admin_users": ["b", "a"], "disabled_accounts": [], "min_password_length": "14"}
    ev, errs = WindowsAccountsCollector({}, runner=lambda s: ok).collect()
    assert ev[0].payload["admin_users"] == ["a", "b"] and ev[0].payload["min_password_length"] == 14
    assert WindowsAccountsCollector({}, runner=lambda s: {}).collect()[1]


def test_build_collectors_respects_config():
    names = {type(c).__name__ for c in build_collectors({})}
    assert "AwsIamCollector" not in names and "LinuxAccountsCollector" in names
    cfg = {"cloud_providers": {"aws": {"enabled": True}}, "windows": {"enabled": True},
           "firewall": {"config_paths": ["x"]}}
    names = {type(c).__name__ for c in build_collectors(cfg)}
    assert {"AwsIamCollector", "WindowsAccountsCollector", "FirewallRulesCollector"} <= names
