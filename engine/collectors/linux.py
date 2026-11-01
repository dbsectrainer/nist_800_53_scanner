"""Linux host collectors (read-only)."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
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
    _, mon, day, hms, tz, year = m.groups()
    # lastlog prints local time plus an offset; treat a missing offset as UTC
    # rather than silently discarding the one that is present.
    offset = tz.strip() if tz else "+0000"
    try:
        dt = datetime.strptime(f"{mon} {day} {hms} {offset} {year}", "%b %d %H:%M:%S %z %Y")
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
        sudoers: set[str] = set()
        privileged_gids: set[int] = set()
        for g in ("sudo", "wheel", "admin"):
            try:
                group = grp.getgrnam(g)
            except KeyError:
                continue
            privileged_gids.add(group.gr_gid)
            sudoers.update(member for member in group.gr_mem if member)
        accounts = []
        complete = True
        for u in pwd.getpwall():
            # Users whose primary group is privileged are just as privileged as
            # direct group members, but are absent from gr_mem.
            if u.pw_gid in privileged_gids:
                sudoers.add(u.pw_name)
            if u.pw_uid < 1000 or u.pw_shell in NOLOGIN:
                continue
            try:
                ok, epoch = self._last_login(u.pw_name)
            except (FileNotFoundError, subprocess.SubprocessError):
                ok, epoch = False, None
            complete = complete and ok
            accounts.append(
                {
                    "username": u.pw_name,
                    "uid": u.pw_uid,
                    "last_login_epoch": epoch,
                    "never_logged_in": ok and epoch is None,
                    "login_data_known": ok,
                }
            )
        return {
            "accounts": accounts,
            "sudo_users": sorted(sudoers),
            "sudoers_users": sorted(self._sudoers_users()),
            "login_data_complete": complete,
            # Never-logged-in accounts have no usable inactivity timestamp, so
            # the rule must not silently exclude them as if they were fresh.
            "never_logged_in_accounts": sorted(
                account["username"] for account in accounts if account["never_logged_in"]
            ),
        }

    def _sudoers_users(self) -> set[str]:
        """Users with explicit sudoers grants (best-effort; aliases/comma lists excluded)."""
        paths = [self.config.get("sudoers_path") or "/etc/sudoers"]
        sudoers_dir = self.config.get("sudoers_dir") or "/etc/sudoers.d"
        if os.path.isdir(sudoers_dir):
            paths.extend(os.path.join(sudoers_dir, name) for name in sorted(os.listdir(sudoers_dir)))
        users: set[str] = set()
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        line = raw.split("#", 1)[0].strip()
                        if not line or line[0] in "%@":
                            continue
                        if re.match(r"(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\b", line):
                            continue
                        match = re.match(r"([A-Za-z0-9_.-]+)\s+.*?ALL\s*=", line)
                        if match:
                            users.add(match.group(1))
            except OSError:
                continue
        return users


class SshKeyPermissionsCollector(Collector):
    name = "linux_ssh_keys"
    evidence_type = "linux.ssh_keys"

    def gather(self) -> dict:
        if pwd is None:
            raise RuntimeError("pwd unavailable on this platform")
        keys, unreadable = [], []
        for u in pwd.getpwall():
            home = u.pw_dir
            ssh_dir = os.path.join(home, ".ssh")
            if not os.path.isdir(home):
                continue
            if not os.access(home, os.R_OK | os.X_OK):
                unreadable.append({"user": u.pw_name, "path": home, "error": "home directory not readable"})
                continue
            if not os.path.isdir(ssh_dir):
                continue
            if not os.access(ssh_dir, os.R_OK | os.X_OK):
                unreadable.append({"user": u.pw_name, "path": ssh_dir, "error": "directory not readable"})
                continue
            try:
                names = sorted(os.listdir(ssh_dir))
            except OSError as exc:
                unreadable.append({"user": u.pw_name, "path": ssh_dir, "error": str(exc)})
                continue
            for name in names:
                # Scan every id_* private key, not just the four legacy defaults.
                if not name.startswith("id_") or name.endswith((".pub", ".cert")):
                    continue
                path = os.path.join(ssh_dir, name)
                if not os.path.isfile(path):
                    continue
                try:
                    mode = os.stat(path).st_mode & 0o777
                except OSError as exc:
                    unreadable.append({"user": u.pw_name, "path": path, "error": str(exc)})
                    continue
                keys.append({"user": u.pw_name, "path": path, "mode": mode})
        return {"private_keys": keys, "unreadable": unreadable, "complete": not unreadable}


class SshdConfigCollector(Collector):
    name = "linux_sshd_config"
    evidence_type = "linux.sshd_config"

    def gather(self) -> dict:
        path = self.config.get("sshd_config_path") or "/etc/ssh/sshd_config"
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{path} not found")
        settings: dict[str, str] = {}
        included: list[str] = []
        complete = True
        visited: set[str] = set()

        def parse(current: str, depth: int) -> None:
            nonlocal complete
            if depth > 10:
                complete = False  # include cycle / pathological nesting
                return
            if current in visited:
                return
            visited.add(current)
            try:
                fh = open(current, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
            except OSError:
                complete = False
                return
            with fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    key = parts[0].lower()
                    if key == "match":
                        # Match scopes are not evaluated here, so host-wide rules
                        # must not claim satisfaction from the global block.
                        complete = False
                        break
                    if key == "include" and len(parts) == 2:
                        pattern = parts[1].strip().strip('"')
                        base = os.path.dirname(current)
                        target = pattern if os.path.isabs(pattern) else os.path.join(base, pattern)
                        matches = sorted(glob.glob(target))
                        included.extend(matches)
                        for match in matches:
                            parse(match, depth + 1)
                        continue
                    if len(parts) == 2:
                        settings.setdefault(key, parts[1].strip())  # first value wins

        parse(path, 0)
        return {"settings": settings, "included_files": sorted(set(included)), "complete": complete}


class AuditdCollector(Collector):
    name = "linux_auditd"
    evidence_type = "linux.audit"

    @staticmethod
    def _count_rules(lines: Iterable[str]) -> int:
        """Count audit rules, not control directives such as -D, -b or -e."""
        return sum(1 for line in lines if line.lstrip().startswith(("-w ", "-a ", "-A ")))

    def _auditd_running(self) -> bool | None:
        """True/False when observable; None when neither pgrep nor systemctl is available."""
        if shutil.which("pgrep"):
            result = subprocess.run(["pgrep", "-x", "auditd"], capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0:
                return True
            if result.returncode == 1:
                return False
            return None
        if shutil.which("systemctl"):
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "auditd"], capture_output=True, text=True, timeout=10, check=False
            )
            if result.returncode == 0:
                return True
            if result.returncode in (1, 3, 4):
                return False
            return None
        return None

    def gather(self) -> dict:
        rules_dir = self.config.get("audit_rules_dir") or "/etc/audit/rules.d"
        conf = self.config.get("auditd_conf") or "/etc/audit/auditd.conf"
        rules_file = self.config.get("audit_rules_file") or "/etc/audit/audit.rules"
        if not any(os.path.exists(p) for p in (conf, rules_dir, rules_file)):
            raise FileNotFoundError("auditd configuration not present")
        rule_count = 0
        if os.path.isdir(rules_dir):
            for f in os.listdir(rules_dir):
                if f.endswith(".rules"):
                    with open(os.path.join(rules_dir, f), encoding="utf-8", errors="replace") as fh:
                        rule_count += self._count_rules(fh)
        if os.path.isfile(rules_file):
            with open(rules_file, encoding="utf-8", errors="replace") as fh:
                rule_count += self._count_rules(fh)
        settings: dict[str, str] = {}
        if os.path.isfile(conf):
            with open(conf, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "=" in line and not line.lstrip().startswith("#"):
                        k, v = line.split("=", 1)
                        settings[k.strip()] = v.strip()
        return {"audit_rule_count": rule_count, "auditd_settings": settings, "auditd_running": self._auditd_running()}


class ListeningServicesCollector(Collector):
    name = "linux_listening_services"
    evidence_type = "linux.listening_services"

    @staticmethod
    def parse_ss(output: str) -> list[dict]:
        listeners = []
        for line in output.splitlines():
            cols = line.split()
            if len(cols) < 5:
                continue
            proto, local = cols[0], cols[4]
            host, _, port = local.rpartition(":")
            if not port.isdigit():
                continue
            host = host.strip("[]")
            listeners.append(
                {
                    "proto": proto,
                    "address": host,
                    "port": int(port),
                    "loopback": host.startswith("127.") or host in ("::1", "localhost"),
                }
            )
        return listeners

    def gather(self) -> dict:
        result = subprocess.run(["ss", "-H", "-tuln"], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"ss failed: {result.stderr.strip() or result.returncode}")
        return {"listeners": self.parse_ss(result.stdout)}


class SysctlCollector(Collector):
    name = "linux_sysctl"
    evidence_type = "linux.sysctl"
    KEYS = ("kernel.randomize_va_space", "net.ipv4.ip_forward", "net.ipv4.conf.all.accept_redirects")

    def gather(self) -> dict:
        root = self.config.get("proc_sys_root", "/proc/sys")
        values: dict[str, str] = {}
        for key in self.KEYS:
            path = os.path.join(root, *key.split("."))
            try:
                with open(path, encoding="utf-8") as fh:
                    values[key] = fh.read().strip()
            except OSError:
                continue
        if not values:
            raise FileNotFoundError(f"no kernel parameters readable under {root}")
        return {"values": values}


class CryptoPolicyCollector(Collector):
    name = "linux_crypto_policy"
    evidence_type = "linux.crypto"

    def gather(self) -> dict:
        path = self.config.get("fips_flag_path", "/proc/sys/crypto/fips_enabled")
        with open(path, encoding="utf-8") as fh:
            return {"fips_enabled": int(fh.read().strip())}


class PackageUpdatesCollector(Collector):
    name = "linux_package_updates"
    evidence_type = "linux.patches"
    ttl_hours = 24.0

    def _run(self, cmd: list[str]) -> str:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        # These commands signal success with 0; a nonzero status is a coverage gap.
        if res.returncode != 0:
            raise RuntimeError(f"{cmd[0]} failed: {res.stderr.strip() or res.returncode}")
        return res.stdout

    def _index_updated_at(self, path: str) -> str | None:
        """Best-effort timestamp for the package metadata cache read by the tool."""
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    def gather(self) -> dict:
        if shutil.which("apt-get"):
            out = self._run(["apt-get", "-s", "upgrade"])
            inst = [l for l in out.splitlines() if l.startswith("Inst ")]
            lists_dir = self.config.get("apt_lists_dir") or "/var/lib/apt/lists"
            return {
                "manager": "apt",
                "pending_updates": len(inst),
                "pending_security_updates": sum(1 for l in inst if "-security" in l),
                "index_updated_at": self._index_updated_at(lists_dir),
            }
        if shutil.which("dnf"):
            out = self._run(["dnf", "-q", "updateinfo", "list", "security"])
            sec = [l for l in out.splitlines() if l.strip() and not l.startswith("Last metadata")]
            cache_dir = self.config.get("dnf_cache_dir") or "/var/cache/dnf"
            return {
                "manager": "dnf",
                "pending_updates": len(sec),
                "pending_security_updates": len(sec),
                "index_updated_at": self._index_updated_at(cache_dir),
            }
        raise RuntimeError("no supported package manager (apt-get, dnf) found")
