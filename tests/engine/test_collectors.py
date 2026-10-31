import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from engine.collectors.base import Collector
from engine.collectors.cloud import AwsIamCollector, AzureDirectoryCollector, GcpIamCollector
from engine.collectors.linux import (
    AuditdCollector,
    CryptoPolicyCollector,
    LinuxAccountsCollector,
    ListeningServicesCollector,
    PackageUpdatesCollector,
    SshdConfigCollector,
    SshKeyPermissionsCollector,
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
    # The printed offset is applied rather than discarded.
    assert (
        _parse_lastlog_line("alice  pts/0  1.2.3.4  Mon Oct 27 10:00:00 +0200 2025")[1]
        == datetime(2025, 10, 27, 8, 0, tzinfo=timezone.utc).timestamp()
    )


def test_parse_ss_marks_loopback():
    out = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 5 127.0.0.1:631 0.0.0.0:*\ntcp LISTEN 0 5 [::]:8080 [::]:*\n"
    got = ListeningServicesCollector.parse_ss(out)
    assert [(l["port"], l["loopback"]) for l in got] == [(22, False), (631, True), (8080, False)]


def test_sshd_config_first_value_wins_and_match_ignored(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("PermitRootLogin no\nPermitRootLogin yes\n# c\nMatch User bob\n  PasswordAuthentication yes\n")
    payload = SshdConfigCollector({"sshd_config_path": str(f)}).gather()
    assert payload["settings"]["permitrootlogin"] == "no" and "passwordauthentication" not in payload["settings"]
    assert payload["complete"] is True


def test_sshd_config_follows_include_first_value_wins(tmp_path):
    dropins = tmp_path / "sshd_config.d"
    dropins.mkdir()
    (dropins / "10-auth.conf").write_text("PasswordAuthentication no\n")
    (dropins / "20-root.conf").write_text("PermitRootLogin no\n")
    main = tmp_path / "sshd_config"
    main.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication yes\n")
    payload = SshdConfigCollector({"sshd_config_path": str(main)}).gather()
    assert payload["settings"]["passwordauthentication"] == "no"
    assert payload["settings"]["permitrootlogin"] == "no"
    assert {os.path.basename(p) for p in payload["included_files"]} == {"10-auth.conf", "20-root.conf"}
    assert payload["complete"] is True


def test_sshd_config_unreadable_include_is_incomplete(tmp_path):
    (tmp_path / "inc.conf").mkdir()  # a directory matches the glob but cannot be read as a file
    main = tmp_path / "sshd_config"
    main.write_text("Include inc.conf\nPasswordAuthentication no\n")
    payload = SshdConfigCollector({"sshd_config_path": str(main)}).gather()
    assert payload["complete"] is False


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
    assert len(payload["configs"][0]["sha256"]) == 64
    assert payload["rules"] == [
        {
            "path": str(good),
            "source": "10.0.0.0/8",
            "action": "allow",
            "source_raw": "10.0.0.0/8",
            "action_raw": "allow",
        }
    ]
    assert FirewallRulesCollector({}).collect()[1]  # unconfigured -> gap


def test_firewall_normalises_any_source_and_action(tmp_path):
    fw = tmp_path / "fw.json"
    fw.write_text(json.dumps({"rules": [{"source": "::/0", "action": "Accept"}]}))
    payload = FirewallRulesCollector({"firewall": {"config_paths": [str(fw)]}}).gather()
    assert payload["rules"][0]["source"] == "any"
    assert payload["rules"][0]["action"] == "allow"


def test_vulnerability_report(tmp_path):
    f = tmp_path / "scan.json"
    f.write_text(
        json.dumps(
            {
                "completed_at": "2026-10-20T00:00:00Z",
                "findings": [{"severity": "Critical"}, {"severity": "high"}, {"severity": "low"}],
            }
        )
    )
    p = VulnerabilityScanReportCollector({"vulnerability_scan": {"report_path": str(f)}}).gather()
    assert (p["critical_count"], p["high_count"], p["finding_count"]) == (1, 1, 3)
    assert len(p["report_sha256"]) == 64
    f.write_text("{}")
    assert VulnerabilityScanReportCollector({"vulnerability_scan": {"report_path": str(f)}}).collect()[1]


def test_ssh_keys_scans_all_id_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "id_rsa").write_text("x")
    (ssh / "id_rsa.pub").write_text("x")
    (ssh / "id_ed25519_sk").write_text("x")
    os.chmod(ssh / "id_rsa", 0o600)
    users = [SimpleNamespace(pw_name="u", pw_uid=1000, pw_dir=str(home), pw_shell="/bin/bash")]
    monkeypatch.setattr("engine.collectors.linux.pwd", SimpleNamespace(getpwall=lambda: users))
    payload = SshKeyPermissionsCollector({}).gather()
    assert {os.path.basename(k["path"]) for k in payload["private_keys"]} == {"id_rsa", "id_ed25519_sk"}
    assert payload["unreadable"] == [] and payload["complete"] is True


def test_ssh_keys_unreadable_home_is_a_gap(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    users = [SimpleNamespace(pw_name="u", pw_uid=1000, pw_dir=str(home), pw_shell="/bin/bash")]
    monkeypatch.setattr("engine.collectors.linux.pwd", SimpleNamespace(getpwall=lambda: users))
    monkeypatch.setattr("engine.collectors.linux.os.access", lambda path, mode: False)
    payload = SshKeyPermissionsCollector({}).gather()
    assert payload["complete"] is False and payload["unreadable"]


def test_linux_accounts_include_primary_group_and_sudoers(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    users = [
        SimpleNamespace(pw_name="u1", pw_uid=1000, pw_gid=27, pw_dir=str(home), pw_shell="/bin/bash"),
        SimpleNamespace(pw_name="root", pw_uid=0, pw_gid=0, pw_dir=str(home), pw_shell="/bin/bash"),
    ]

    class SudoGroup:
        gr_gid = 27
        gr_mem: list[str] = []

    class FakeGrp:
        @staticmethod
        def getgrnam(name):
            if name == "sudo":
                return SudoGroup()
            raise KeyError(name)

    sudoers = tmp_path / "sudoers"
    sudoers.write_text("root ALL=(ALL:ALL) ALL\nDefaults env_reset\n%wheel ALL=(ALL) ALL\n")
    monkeypatch.setattr("engine.collectors.linux.pwd", SimpleNamespace(getpwall=lambda: users))
    monkeypatch.setattr("engine.collectors.linux.grp", FakeGrp)
    monkeypatch.setattr(LinuxAccountsCollector, "_last_login", lambda self, user: (True, None))

    payload = LinuxAccountsCollector(
        {
            "sudoers_path": str(sudoers),
            "sudoers_dir": str(tmp_path / "sudoers.d"),
        }
    ).gather()
    assert "u1" in payload["sudo_users"]  # membership through primary group
    assert payload["sudoers_users"] == ["root"]


def test_auditd_reports_running_state(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules.d"
    rules_dir.mkdir()
    (rules_dir / "audit.rules").write_text("-w /etc/passwd -p wa -k identity\n# comment\n")
    conf = tmp_path / "auditd.conf"
    conf.write_text("enabled = 1\n")
    collector = AuditdCollector(
        {
            "audit_rules_dir": str(rules_dir),
            "auditd_conf": str(conf),
            "audit_rules_file": str(tmp_path / "missing.rules"),
        }
    )
    monkeypatch.setattr(AuditdCollector, "_auditd_running", lambda self: True)
    payload = collector.gather()
    assert payload["audit_rule_count"] == 1
    assert payload["auditd_running"] is True


def test_package_index_timestamp(tmp_path):
    lists = tmp_path / "lists"
    lists.mkdir()
    stamp = PackageUpdatesCollector({})._index_updated_at(str(lists))
    assert stamp and stamp.endswith("+00:00")
    assert PackageUpdatesCollector({})._index_updated_at(str(tmp_path / "missing")) is None


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

    def list_groups_for_user(self, UserName):
        return {"Groups": []}

    def list_attached_group_policies(self, GroupName):
        return {"AttachedPolicies": []}

    def list_group_policies(self, GroupName):
        return {"PolicyNames": []}

    def get_group_policy(self, GroupName, PolicyName):
        return {"PolicyDocument": {}}

    def list_user_policies(self, UserName):
        return {"PolicyNames": []}

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": {}}

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
    assert ev[0].payload == {
        "root_mfa_enabled": True,
        "user_count": 2,
        "admin_users": ["a"],
        "console_users_without_mfa": ["a"],
    }


def test_aws_group_and_inline_admins_are_detected():
    class GroupIam(FakeIam):
        def list_groups_for_user(self, UserName):
            return {"Groups": [{"GroupName": "Admins"}] if UserName == "b" else []}

        def list_attached_group_policies(self, GroupName):
            return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}

        def list_attached_user_policies(self, UserName):
            return {"AttachedPolicies": []}

    class InlineIam(FakeIam):
        def list_attached_user_policies(self, UserName):
            return {"AttachedPolicies": []}

        def list_user_policies(self, UserName):
            return {"PolicyNames": ["admin"] if UserName == "b" else []}

        def get_user_policy(self, UserName, PolicyName):
            return {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}

    cfg = {"cloud_providers": {"aws": {"enabled": True}}}
    ev, _ = AwsIamCollector(cfg, client_factory=GroupIam).collect()
    assert ev[0].payload["admin_users"] == ["b"]
    ev, _ = AwsIamCollector(cfg, client_factory=InlineIam).collect()
    assert ev[0].payload["admin_users"] == ["b"]


def test_cloud_disabled_or_failing_is_gap():
    assert AwsIamCollector({}, client_factory=FakeIam).collect()[1]  # not enabled
    boom = lambda: (_ for _ in ()).throw(PermissionError("expired token"))
    _, errs = AwsIamCollector({"cloud_providers": {"aws": {"enabled": True}}}, client_factory=boom).collect()
    assert "expired token" in errs[0].message


def test_aws_client_honours_configured_credentials(monkeypatch):
    calls = []

    class FakeSts:
        def assume_role(self, **kwargs):
            return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "SECRET", "SessionToken": "TOKEN"}}

    class FakeBoto3:
        def client(self, name, **kwargs):
            calls.append((name, kwargs))
            return FakeSts() if name == "sts" else object()

    monkeypatch.setitem(sys.modules, "boto3", FakeBoto3())

    assumed = {
        "cloud_providers": {
            "aws": {"enabled": True, "credentials": {"method": "assume_role", "role_arn": "arn:aws:iam::123:role/x"}}
        }
    }
    AwsIamCollector(assumed)._client()
    assert calls[0][0] == "sts"
    assert calls[1][1]["aws_access_key_id"] == "AKIA"
    assert calls[1][1]["aws_session_token"] == "TOKEN"

    static = {
        "cloud_providers": {
            "aws": {"enabled": True, "credentials": {"method": "static", "access_key": "AK", "secret_key": "SK"}}
        }
    }
    AwsIamCollector(static)._client()
    assert calls[-1][1]["aws_access_key_id"] == "AK"

    missing = {"cloud_providers": {"aws": {"enabled": True, "credentials": {"method": "static"}}}}
    with pytest.raises(RuntimeError, match="access_key"):
        AwsIamCollector(missing)._client()


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
    assert ev[0].payload["policy_scope"] == "project"
    ev, errs = GcpIamCollector(cfg, fetcher=lambda p: (_ for _ in ()).throw(RuntimeError("x"))).collect()
    assert not ev and errs


def test_windows_collector_validates_runner_output():
    ok = {"admin_users": ["b", "a"], "disabled_accounts": [], "min_password_length": "14", "domain_joined": False}
    ev, errs = WindowsAccountsCollector({}, runner=lambda s: ok).collect()
    assert ev[0].payload["admin_users"] == ["a", "b"]
    assert ev[0].payload["min_password_length"] == 14
    assert ev[0].payload["domain_joined"] is False
    assert WindowsAccountsCollector({}, runner=lambda s: {}).collect()[1]


def test_windows_collector_normalises_single_element_arrays():
    payload = {"admin_users": "only-admin", "disabled_accounts": [], "min_password_length": 14, "domain_joined": True}
    ev, errs = WindowsAccountsCollector({}, runner=lambda s: payload).collect()
    assert not errs
    assert ev[0].payload["admin_users"] == ["only-admin"]
    assert ev[0].payload["domain_joined"] is True


def test_build_collectors_respects_config():
    names = {type(c).__name__ for c in build_collectors({})}
    assert "AwsIamCollector" not in names and "LinuxAccountsCollector" in names
    cfg = {
        "cloud_providers": {"aws": {"enabled": True}},
        "windows": {"enabled": True},
        "firewall": {"config_paths": ["x"]},
    }
    names = {type(c).__name__ for c in build_collectors(cfg)}
    assert {"AwsIamCollector", "WindowsAccountsCollector", "FirewallRulesCollector"} <= names
