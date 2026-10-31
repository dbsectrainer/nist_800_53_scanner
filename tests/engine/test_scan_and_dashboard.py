"""scan.py report rendering, dashboard status handling, and the rate-limiter regression."""

import json
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from engine.collectors.base import Collector
from engine.models import Status
from engine.runner import run_assessment


class Dead(Collector):
    name, evidence_type = "dead", "linux.accounts"

    def gather(self):
        raise RuntimeError("host unreachable")


class Fw(Collector):
    name, evidence_type = "fw", "network.firewall_rules"

    def gather(self):
        return {"rules": [{"path": "p", "source": "0.0.0.0/0", "action": "allow"}], "unreadable": []}


@pytest.fixture
def run():
    return run_assessment({}, system_id="sys1", collectors=[Dead({"asset_id": "h"}), Fw({"asset_id": "h"})])


@pytest.fixture
def scan_mod():
    return pytest.importorskip("scan")


def _stub(scan_mod):
    import logging
    s = object.__new__(scan_mod.MultiTenantNISTComplianceScanner)
    s.tenant_id, s.logger = "t1", logging.getLogger("t")
    return s


@pytest.mark.parametrize("fmt,suffix", [("markdown", ".md"), ("json", ".json"), ("oscal", ".oscal.json")])
def test_generate_report_formats(scan_mod, run, tmp_path, fmt, suffix):
    path = _stub(scan_mod).generate_report(run, fmt=fmt, output_dir=str(tmp_path))
    assert path.endswith(suffix)
    text = open(path).read()
    if fmt == "markdown":
        assert "host unreachable" in text and "Other than satisfied" in text
        assert "Compliant" not in text.replace("Non-Compliant", "")  # no legacy pass/fail wording
        assert "not an authorization decision" in text
        assert "Asset coverage: unknown" in text
    else:
        doc = json.loads(text)
        assert doc  # parseable
    if fmt == "oscal":
        assert list(tmp_path.glob("*.poam.oscal.json"))  # open finding -> POA&M written
    with pytest.raises(ValueError):
        _stub(scan_mod).generate_report(run, fmt="html", output_dir=str(tmp_path))


def test_no_poam_file_when_nothing_open(scan_mod, tmp_path):
    clean = run_assessment({}, collectors=[Dead({"asset_id": "h"})], baseline="rules")
    _stub(scan_mod).generate_report(clean, fmt="oscal", output_dir=str(tmp_path))
    assert not list(tmp_path.glob("*.poam.oscal.json"))


# --- dashboard status handling -----------------------------------------
@pytest.fixture
def dm():
    return pytest.importorskip("dashboard.data_manager")


@pytest.mark.parametrize("raw,expected", [
    ({"status": "satisfied"}, "satisfied"),
    ({"status": "not_applicable"}, "not_applicable"),
    ({"compliant": True}, "satisfied"),
    ({"compliant": False}, "other_than_satisfied"),
    ({"compliant": None}, "not_assessed"),
    ({}, "not_assessed"),
    ({"status": "bogus", "compliant": True}, "satisfied"),
])
def test_result_status_normalisation(dm, raw, expected):
    assert dm._result_status(raw) == expected


def test_new_format_results_flatten_only_assessments(dm, run):
    meta = dm.ReportMeta("r1", datetime.now(timezone.utc), 0, 0, 0.0)
    calc = dm.MetricsCalculator(meta, run.to_dict())
    flat = calc.get_control_flat_list()
    assert len(flat) == len(run.assessments)  # evidence/errors lists are not control results
    assert not any(c.compliant for c in flat if c.status != "satisfied")
    assert {c.status for c in flat} <= {s.value for s in Status}
    assert calc.get_overall_compliance().ato_status == "not_determined"
    sg = [c for c in flat if c.control_id == "SC-7"][0]
    assert sg.status == "other_than_satisfied" and sg.remediation


def test_legacy_boolean_and_placeholder_results(dm):
    meta = dm.ReportMeta("r2", datetime.now(timezone.utc), 0, 0, 0.0)
    legacy = {"access_control": [{"control_id": "AC-2", "compliant": True},
                                 {"control_id": "AC-3", "compliant": None, "status": "not_assessed"}]}
    flat = dm.MetricsCalculator(meta, legacy).get_control_flat_list()
    assert [(c.control_id, c.status, c.compliant) for c in flat] == [
        ("AC-2", "satisfied", True), ("AC-3", "not_assessed", False)]


def test_report_reader_ingests_toplevel_engine_json(dm, run, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "engine-run.json").write_text(json.dumps(run.to_dict()))
    reader = dm.ReportReader(str(reports))

    metas = reader.list_reports()
    assert len(metas) == 1 and metas[0].total_controls == len(run.assessments)
    latest, results = reader.load_latest_report()
    assert results is not None
    assert len(dm.MetricsCalculator(latest, results).get_control_flat_list()) == len(run.assessments)


def test_report_reader_decrypts_versioned_engine_report(dm, run, tmp_path):
    encryption = pytest.importorskip("modules.encryption")
    versioning = pytest.importorskip("modules.report_versioning")
    handler = encryption.SecureDataHandler(
        encryption.SecureKeyStorage(str(tmp_path / "master.key")),
        keys_file=str(tmp_path / "keys.json"),
    )
    reports = tmp_path / "reports"
    versioning.ReportVersionManager(base_path=str(reports)).create_report_version(
        handler.encrypt_data(run.to_dict()), metadata={"tenant_id": "t1"}
    )
    reader = dm.ReportReader(str(reports), encryption_handler=handler)
    latest, results = reader.load_latest_report()
    assert results is not None
    assert len(dm.MetricsCalculator(latest, results).get_control_flat_list()) == len(run.assessments)


def test_run_scans_stores_a_decryptable_report(scan_mod, dm, run, tmp_path, monkeypatch):
    """run_scans must store the ciphertext envelope itself, not a {"results": ...} wrapper."""
    encryption = pytest.importorskip("modules.encryption")
    versioning = pytest.importorskip("modules.report_versioning")
    handler = encryption.SecureDataHandler(
        encryption.SecureKeyStorage(str(tmp_path / "master.key")),
        keys_file=str(tmp_path / "keys.json"),
    )
    scanner = object.__new__(scan_mod.MultiTenantNISTComplianceScanner)
    scanner.tenant_id = "t1"
    scanner.tenant_config = {}
    scanner.report_manager = versioning.ReportVersionManager(base_path=str(tmp_path / "reports"))
    scanner.encryption_handler = handler
    scanner.rate_limiter = SimpleNamespace(is_rate_limited=lambda *a: (False, None))
    scanner.compliance_scan_counter = SimpleNamespace(
        labels=lambda **k: SimpleNamespace(inc=lambda: None)
    )
    monkeypatch.setattr(scan_mod, "run_assessment", lambda *a, **k: run)

    assert scanner.run_scans() is run
    reader = dm.ReportReader(str(tmp_path / "reports"), encryption_handler=handler)
    latest, results = reader.load_latest_report()
    assert results is not None
    assert len(dm.MetricsCalculator(latest, results).get_control_flat_list()) == len(run.assessments)


# --- rate limiter regression -------------------------------------------
def test_rate_limiter_does_not_deadlock(tmp_path, monkeypatch):
    from modules.rate_limiter import RateLimit, RateLimiter
    monkeypatch.chdir(tmp_path)
    rl = RateLimiter({"default": RateLimit(max_requests=2, window_seconds=60)}, persistent=True)
    results = []
    t = threading.Thread(target=lambda: results.extend([rl.is_rate_limited("default", "k") for _ in range(3)]), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "is_rate_limited deadlocked"
    assert [r[0] for r in results] == [False, False, True]
