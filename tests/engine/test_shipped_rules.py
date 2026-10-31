"""Golden tests: every shipped automated rule against satisfying / failing / unassessable evidence."""

from datetime import datetime, timedelta, timezone

import pytest

from engine.evaluate import evaluate_rule
from engine.models import Evidence, Status
from engine.rules import Policy, load_rules
from engine.runner import ROOT

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
RULES = {r.rule_id: r for r in load_rules(f"{ROOT}/rules")}
ts = lambda days: (NOW - timedelta(days=days)).isoformat()
S, F, N = Status.SATISFIED, Status.OTHER_THAN_SATISFIED, Status.NOT_ASSESSED

CASES = [
    ("AC-2-INACTIVE-001", {"accounts": [{"last_login_epoch": (NOW - timedelta(days=5)).timestamp()}], "login_data_complete": True}, S),
    ("AC-2-INACTIVE-001", {"accounts": [{"last_login_epoch": (NOW - timedelta(days=200)).timestamp()}], "login_data_complete": True}, F),
    ("AC-2-INACTIVE-001", {"accounts": [], "login_data_complete": False}, N),
    ("AC-6-PRIV-001", {"sudo_users": ["a"]}, S),
    ("AC-6-PRIV-001", {"sudo_users": list("abcdef")}, F),
    ("AC-6-ROOTLOGIN-001", {"settings": {"permitrootlogin": "no"}}, S),
    ("AC-6-ROOTLOGIN-001", {"settings": {"permitrootlogin": "yes"}}, F),
    ("AC-6-ROOTLOGIN-001", {"settings": {}}, F),
    ("IA-2-SSHPASSWORD-001", {"settings": {"passwordauthentication": "no"}}, S),
    ("IA-2-SSHPASSWORD-001", {"settings": {}}, F),
    ("IA-5-SSHKEY-001", {"private_keys": [{"mode": 0o600}]}, S),
    ("IA-5-SSHKEY-001", {"private_keys": [{"mode": 0o644}]}, F),
    ("AU-2-LOCAL-001", {"local_logging_enabled": True}, S),
    ("AU-2-LOCAL-001", {"local_logging_enabled": False}, F),
    ("AU-11-RETENTION-001", {"retention_days": 400}, S),
    ("AU-11-RETENTION-001", {"retention_days": 30}, F),
    ("AU-11-RETENTION-001", {"retention_days": None}, N),
    ("AU-12-AUDITD-001", {"audit_rule_count": 3}, S),
    ("AU-12-AUDITD-001", {"audit_rule_count": 0}, F),
    ("CM-6-SSHD-EMPTYPW-001", {"settings": {}}, S),
    ("CM-6-SSHD-EMPTYPW-001", {"settings": {"permitemptypasswords": "yes"}}, F),
    ("CM-6-SSHD-MAXAUTH-001", {"settings": {"maxauthtries": "3"}}, S),
    ("CM-6-SSHD-MAXAUTH-001", {"settings": {"maxauthtries": "10"}}, F),
    ("CM-6-SSHD-MAXAUTH-001", {"settings": {"maxauthtries": "abc"}}, N),
    ("CM-6-SSHD-MAXAUTH-001", {"settings": {}}, N),
    ("CM-6-SYSCTL-ASLR-001", {"values": {"kernel.randomize_va_space": "2"}}, S),
    ("CM-6-SYSCTL-ASLR-001", {"values": {"kernel.randomize_va_space": "0"}}, F),
    ("CM-6-SYSCTL-ASLR-001", {"values": {"net.ipv4.ip_forward": "0"}}, N),
    ("CM-7-LISTENERS-001", {"listeners": [{"port": 22, "loopback": False}, {"port": 631, "loopback": True}]}, S),
    ("CM-7-LISTENERS-001", {"listeners": [{"port": 8080, "loopback": False}]}, F),
    ("SC-8-SSH-CIPHERS-001", {"settings": {"ciphers": "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"}}, S),
    ("SC-8-SSH-CIPHERS-001", {"settings": {"ciphers": "aes256-ctr,3DES-CBC"}}, F),
    ("SC-8-SSH-CIPHERS-001", {"settings": {"ciphers": "+aes128-cbc"}}, N),
    ("SC-8-SSH-CIPHERS-001", {"settings": {}}, N),
    ("SC-13-FIPS-001", {"fips_enabled": 1}, S),
    ("SC-13-FIPS-001", {"fips_enabled": 0}, F),
    ("SC-7-FIREWALL-001", {"rules": [{"source": "10.0.0.0/8", "action": "allow"}], "unreadable": []}, S),
    ("SC-7-FIREWALL-001", {"rules": [{"source": "0.0.0.0/0", "action": "allow"}], "unreadable": []}, F),
    ("SC-7-FIREWALL-001", {"rules": [], "unreadable": [{"path": "p"}]}, N),
    ("SI-2-PATCH-001", {"pending_security_updates": 0}, S),
    ("SI-2-PATCH-001", {"pending_security_updates": 4}, F),
    ("RA-5-SCAN-001", {"completed_at": ts(5)}, S),
    ("RA-5-SCAN-001", {"completed_at": ts(90)}, F),
    ("RA-5-CRITICAL-001", {"critical_count": 0}, S),
    ("RA-5-CRITICAL-001", {"critical_count": 2}, F),
    ("AC-6-AWS-ADMINS-001", {"admin_users": ["a"]}, S),
    ("AC-6-AWS-ADMINS-001", {"admin_users": list("abcdefg")}, F),
    ("IA-2-AWS-ROOTMFA-001", {"root_mfa_enabled": True}, S),
    ("IA-2-AWS-ROOTMFA-001", {"root_mfa_enabled": False}, F),
    ("IA-2-AWS-USERMFA-001", {"console_users_without_mfa": []}, S),
    ("IA-2-AWS-USERMFA-001", {"console_users_without_mfa": ["a"]}, F),
    ("AC-6-AZURE-GLOBALADMINS-001", {"global_admins": ["a"]}, S),
    ("AC-6-AZURE-GLOBALADMINS-001", {"global_admins": list("abcdefg")}, F),
    ("AC-2-AZURE-GUESTS-001", {"guest_users": []}, S),
    ("AC-2-AZURE-GUESTS-001", {"guest_users": list("abcd")}, F),
    ("AC-3-GCP-PUBLIC-001", {"public_members": []}, S),
    ("AC-3-GCP-PUBLIC-001", {"public_members": ["allUsers"]}, F),
    ("AC-2-GCP-SERVICEACCOUNTS-001", {"service_account_count": 3}, S),
    ("AC-2-GCP-SERVICEACCOUNTS-001", {"service_account_count": 30}, F),
    ("AC-6-WINADMINS-001", {"admin_users": ["a"]}, S),
    ("AC-6-WINADMINS-001", {"admin_users": list("abcde")}, F),
    ("IA-5-WINPASSWORD-001", {"min_password_length": 14}, S),
    ("IA-5-WINPASSWORD-001", {"min_password_length": 8}, F),
]


@pytest.mark.parametrize("rule_id,payload,expected", CASES)
def test_rule(rule_id, payload, expected):
    rule = RULES[rule_id]
    ev = Evidence(type=rule.evidence_type, asset_id="a", collector="t", payload=payload, collected_at=NOW)
    out = evaluate_rule(rule, [ev], [], Policy(), "sys", now=NOW)
    assert [a.status for a in out] == [expected], out[0].reason


def test_every_automated_rule_has_golden_cases():
    covered = {c[0] for c in CASES}
    for rid, rule in RULES.items():
        if rule.automated:
            assert rid in covered, f"{rid} has no golden test"
            statuses = {c[2] for c in CASES if c[0] == rid}
            assert S in statuses and F in statuses, f"{rid} needs both satisfied and failing cases"


def test_manual_rules_never_pass():
    for rule in RULES.values():
        if not rule.automated:
            out = evaluate_rule(rule, [], [], Policy(), "sys", now=NOW)
            assert [a.status for a in out] == [N]
