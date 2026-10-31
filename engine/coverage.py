"""Coverage and roll-up metrics. No single aggregate 'compliance %'."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Optional

from .models import AssessmentRun, Status


def load_catalog_ids(path: str) -> list[str]:
    """Control IDs from an OSCAL catalog JSON (e.g. NIST SP 800-53 rev5)."""
    with open(path, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)["catalog"]
    ids: list[str] = []

    def walk(controls: list[dict]) -> None:
        for c in controls:
            ids.append(c["id"].upper())
            walk(c.get("controls", []))

    for group in catalog.get("groups", []):
        walk(group.get("controls", []))
    walk(catalog.get("controls", []))
    return ids


def control_rollup(run: AssessmentRun) -> dict[str, Status]:
    """Worst-state-wins per control; controls in the catalog without rules are not_assessed."""
    by_control: dict[str, list[Status]] = {}
    for a in run.assessments:
        by_control.setdefault(a.control_id, []).append(a.status)
    for cid in run.catalog_controls:
        by_control.setdefault(cid.upper(), [])
    result: dict[str, Status] = {}
    for cid, states in by_control.items():
        if not states:
            result[cid] = Status.NOT_ASSESSED
        elif Status.OTHER_THAN_SATISFIED in states:
            result[cid] = Status.OTHER_THAN_SATISFIED
        elif Status.NOT_ASSESSED in states:
            result[cid] = Status.NOT_ASSESSED
        elif all(s == Status.NOT_APPLICABLE for s in states):
            result[cid] = Status.NOT_APPLICABLE
        else:
            result[cid] = Status.SATISFIED
    return result


def summarize(run: AssessmentRun) -> dict[str, Any]:
    rollup = control_rollup(run)
    objective_counts = Counter(a.status.value for a in run.assessments)
    control_counts = Counter(s.value for s in rollup.values())
    total_controls = len(rollup)
    assessed = sum(1 for s in rollup.values() if s != Status.NOT_ASSESSED)
    ages = [e.age_hours() for e in run.evidence]
    stale = sum(1 for e in run.evidence if not e.is_fresh())
    assets = _asset_coverage(run)
    return {
        "baseline": run.baseline or None,
        "asset_coverage": assets,
        "objective_counts": dict(objective_counts),
        "control_counts": dict(control_counts),
        "controls_total": total_controls,
        "controls_assessed": assessed,
        "control_coverage_pct": round(assessed / total_controls * 100, 1) if total_controls else 0.0,
        "evidence_items": len(run.evidence),
        "evidence_stale": stale,
        "evidence_max_age_hours": round(max(ages), 2) if ages else None,
        "collection_errors": len(run.errors),
        "open_findings": [
            {"control": a.control_id, "rule": a.rule_id, "asset": a.asset_id}
            for a in run.assessments if a.status == Status.OTHER_THAN_SATISFIED
        ],
    }


def _asset_coverage(run: AssessmentRun) -> Optional[dict[str, Any]]:
    """Expected assets (from config inventory) vs. assets with fresh evidence.

    ``None`` when no inventory is configured: coverage is then unknown, not 100%.
    """
    if not run.expected_assets:
        return None
    fresh = {e.asset_id for e in run.evidence if e.is_fresh()}
    expected = set(run.expected_assets)
    covered = expected & fresh
    return {
        "expected": len(expected),
        "with_fresh_evidence": len(covered),
        "coverage_pct": round(len(covered) / len(expected) * 100, 1),
        "missing": sorted(expected - fresh),
        "unexpected": sorted(fresh - expected),
    }
