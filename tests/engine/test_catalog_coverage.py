import hashlib
import io
from datetime import timedelta

import pytest

from engine import catalog
from engine.collectors.base import Collector
from engine.coverage import summarize
from engine.models import AssessmentRun, Evidence, utcnow
from engine.runner import run_assessment


def test_baseline_sizes_match_published_rev5():
    assert len(catalog.baseline_ids("low")) == 149
    assert len(catalog.baseline_ids("moderate")) == 287
    assert len(catalog.baseline_ids("high")) == 370
    assert set(catalog.baseline_ids("moderate")) <= set(catalog.baseline_ids("all"))
    assert catalog.catalog_info()["catalog_version"] == "5.2.0"
    with pytest.raises(ValueError):
        catalog.baseline_ids("bogus")


class Stub(Collector):
    name, evidence_type = "stub", "linux.audit"

    def gather(self):
        return {"audit_rule_count": 2, "auditd_settings": {}}


def test_default_denominator_is_moderate_baseline_and_rules_are_unioned():
    run = run_assessment({}, collectors=[Stub({"asset_id": "h1"})])
    s = summarize(run)
    assert s["baseline"] == "moderate"
    assert s["controls_total"] >= 287
    assert s["controls_assessed"] < 10 and s["control_coverage_pct"] < 5  # honest, not inflated
    assert run_assessment({}, collectors=[], baseline="rules").baseline == "rules"
    assert len(run_assessment({}, collectors=[], baseline="rules").catalog_controls) < 40
    assert run_assessment({"engine": {"baseline": "low"}}, collectors=[]).baseline == "low"


def test_asset_coverage_unknown_without_inventory_and_measured_with_one():
    assert summarize(run_assessment({}, collectors=[Stub({"asset_id": "h1"})]))["asset_coverage"] is None
    cfg = {"engine": {"expected_assets": ["h1", "h2"]}}
    ac = summarize(run_assessment(cfg, collectors=[Stub({"asset_id": "h1"}), Stub({"asset_id": "h3"})]))["asset_coverage"]
    assert ac["expected"] == 2 and ac["with_fresh_evidence"] == 1 and ac["missing"] == ["h2"]
    assert ac["unexpected"] == ["h3"] and ac["coverage_pct"] == 50.0


def test_stale_evidence_does_not_count_for_asset_coverage():
    run = AssessmentRun(system_id="s", expected_assets=["h1"])
    run.evidence.append(Evidence(type="t", asset_id="h1", collector="c", payload={},
                                 collected_at=utcnow() - timedelta(hours=100), ttl_hours=24))
    assert summarize(run)["asset_coverage"]["with_fresh_evidence"] == 0


def test_fetch_catalog_verifies_hash(tmp_path, monkeypatch):
    body = b'{"catalog": {}}'
    monkeypatch.setattr(catalog.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(body))
    with pytest.raises(ValueError, match="hash mismatch"):
        catalog.fetch_catalog(str(tmp_path / "c.json"))
    assert not (tmp_path / "c.json").exists()
    info = catalog.catalog_info()
    monkeypatch.setitem(info["files"]["catalog"], "sha256", hashlib.sha256(body).hexdigest())
    assert catalog.fetch_catalog(str(tmp_path / "c.json")) == str(tmp_path / "c.json")
    assert (tmp_path / "c.json").read_bytes() == body
