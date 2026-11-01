"""Orchestrates collect -> evaluate and persists the run."""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from .collectors import build_collectors
from .collectors.base import Collector
from .catalog import baseline_ids
from .coverage import load_catalog_ids
from .evaluate import evaluate_all
from .models import AssessmentRun
from .rules import Policy, RuleError, load_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logger = logging.getLogger(__name__)


def run_assessment(
    config: dict[str, Any],
    system_id: str = "default",
    rules_dir: Optional[str] = None,
    policy_path: Optional[str] = None,
    catalog_path: Optional[str] = None,
    baseline: Optional[str] = None,
    collectors: Optional[list[Collector]] = None,
    parallel: bool = False,
) -> AssessmentRun:
    rules = load_rules(rules_dir or os.path.join(ROOT, "rules"))
    if policy_path is not None and not os.path.exists(policy_path):
        raise RuleError(f"policy file not found: {policy_path}")
    policy = Policy.load(policy_path or os.path.join(ROOT, "parameters.yaml"))
    collectors = collectors if collectors is not None else build_collectors(config)

    engine_cfg = config.get("engine") or {}
    run = AssessmentRun(system_id=system_id)
    run.expected_assets = list(engine_cfg.get("expected_assets") or [])
    rule_controls = {r.control for r in rules}
    if catalog_path:
        run.catalog_controls = load_catalog_ids(catalog_path)
        run.baseline = "custom-catalog"
        known_controls = set(run.catalog_controls)
    else:
        # Denominator is a published baseline (default moderate); "rules" limits it to rule-referenced controls.
        run.baseline = baseline or engine_cfg.get("baseline") or "moderate"
        ids = [] if run.baseline == "rules" else baseline_ids(run.baseline)
        run.catalog_controls = sorted(set(ids) | rule_controls)
        known_controls = set(baseline_ids("all"))

    unknown = sorted(rule_controls - known_controls)
    if unknown:
        # A typo becomes a phantom control that is counted as assessed; make it visible.
        logger.warning("Rules reference controls outside the catalog: %s", ", ".join(unknown))

    if parallel and len(collectors) > 1:
        scan_options = config.get("scan_options") or {}
        configured = engine_cfg.get("max_concurrent_scans", scan_options.get("max_concurrent_scans", 8))
        try:
            max_workers = int(configured)
        except (TypeError, ValueError):
            max_workers = 8
        max_workers = max(1, min(len(collectors), max_workers))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(pool.map(lambda c: c.collect(), collectors))
    else:
        results = [c.collect() for c in collectors]
    for ev, errs in results:
        run.evidence.extend(ev)
        run.errors.extend(errs)

    return evaluate_all(run, rules, policy)
