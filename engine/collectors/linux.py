"""Linux host collectors (read-only)."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone

from .base import Collector

try:
    import grp
    import pwd
except ImportError:  # non-POSIX
    pwd = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]

NOLOGIN = ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/usr/bin/nologin")
_LASTLOG_DATE = re.compile(r"([A-Z][a-z]{2}) ([A-Z][a-z]{2}) +(\d+) (\d\d:\d\d:\d\d) ([+-]\d{4} )?(\d{4})")


def _parse_lastlog_line(line: str) -> tuple[bool, float | None]:
    """Return (parsed_ok, epoch). 'Never logged in' parses OK with epoch None."""
    if "Never logged in" in line:
        return True, None
    m = _LASTLOG_DATE.search(line)
    if not m:
        return False, None
    _, mon, day, hms, _tz, year = m.groups()
    try:
        dt = datetime.strptime(f"{mon} {day} {hms} {year}", "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return False, None
    return True, dt.timestamp()


class LinuxAccountsCollector(Collector):
    name = "linux_accounts"
    evidence_type = "linux.accounts"

    def _last_login(self, user: str) -> tuple[bool, float | None]:
        result = subprocess.run(["lastlog", "-u", user], capture_output=True, text=True, timeout=10, check=False)
        lines = result.stdout.splitlines()
        if result.returncode != 0 or len(lines) < 2:
            return False, None
        return _parse_lastlog_line(lines[1])

    def gather(self) -> dict:
        if pwd is None or grp is None:
            raise RuntimeError("pwd/grp unavailable on this platform")
        accounts = []
        complete = True
        for u in pwd.getpwall():
            if u.pw_uid < 1000 or u.pw_shell in NOLOGIN:
                continue
            try:
                ok, epoch = self._last_login(u.pw_name)
            except (FileNotFoundError, subprocess.SubprocessError):
                ok, epoch = False, None
            complete = complete and ok
            accounts.append({"username": u.pw_name, "uid": u.pw_uid,
                             "last_login_epoch": epoch, "never_logged_in": ok and epoch is None,
                             "login_data_known": ok})
        sudoers: set[str] = set()
        for g in ("sudo", "wheel", "admin"):
            try:
                sudoers.update(m for m in grp.getgrnam(g).gr_mem if m)
            except KeyError:
                continue
        return {"accounts": accounts, "sudo_users": sorted(sudoers), "login_data_complete": complete}


class SshKeyPermissionsCollector(Collector):
    name = "linux_ssh_keys"
    evidence_type = "linux.ssh_keys"

    def gather(self) -> dict:
        if pwd is None:
            raise RuntimeError("pwd unavailable on this platform")
        keys = []
        for u in pwd.getpwall():
            ssh_dir = os.path.join(u.pw_dir, ".ssh")
            if not os.path.isdir(ssh_dir):
                continue
            for name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
                path = os.path.join(ssh_dir, name)
                if os.path.isfile(path):
                    keys.append({"user": u.pw_name, "path": path,
                                 "mode": os.stat(path).st_mode & 0o777})
        return {"private_keys": keys}


class SshdConfigCollector(Collector):
    name = "linux_sshd_config"
    evidence_type = "linux.sshd_config"

    def gather(self) -> dict:
        path = self.config.get("sshd_config_path", "/etc/ssh/sshd_config")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{path} not found")
        settings: dict[str, str] = {}
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    settings.setdefault(parts[0].lower(), parts[1].strip())  # first value wins
        return {"settings": settings}


class AuditdCollector(Collector):
    name = "linux_auditd"
    evidence_type = "linux.audit"

    def gather(self) -> dict:
        rules_dir = self.config.get("audit_rules_dir", "/etc/audit/rules.d")
        conf = self.config.get("auditd_conf", "/etc/audit/auditd.conf")
        if not os.path.isfile(conf) and not os.path.isdir(rules_dir):
            raise FileNotFoundError("auditd configuration not present")
        rule_count = 0
        if os.path.isdir(rules_dir):
            for f in os.listdir(rules_dir):
                if f.endswith(".rules"):
                    with open(os.path.join(rules_dir, f), encoding="utf-8") as fh:
                        rule_count += sum(1 for l in fh if l.strip() and not l.lstrip().startswith("#"))
        settings: dict[str, str] = {}
        if os.path.isfile(conf):
            with open(conf, encoding="utf-8") as fh:
                for line in fh:
                    if "=" in line and not line.lstrip().startswith("#"):
                        k, v = line.split("=", 1)
                        settings[k.strip()] = v.strip()
        return {"audit_rule_count": rule_count, "auditd_settings": settings}
