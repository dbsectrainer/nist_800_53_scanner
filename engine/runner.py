"""Orchestrates collect -> evaluate and persists the run."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from .collectors import DEFAULT_COLLECTORS
from .collectors.base import Collector
from .coverage import load_catalog_ids
from .evaluate import evaluate_all
from .models import AssessmentRun
from .rules import Policy, load_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_assessment(
    config: dict[str, Any],
    system_id: str = "default",
    rules_dir: Optional[str] = None,
    policy_path: Optional[str] = None,
    catalog_path: Optional[str] = None,
    collectors: Optional[list[Collector]] = None,
    parallel: bool = False,
) -> AssessmentRun:
    rules = load_rules(rules_dir or os.path.join(ROOT, "rules"))
    policy = Policy.load(policy_path or os.path.join(ROOT, "parameters.yaml"))
    collectors = collectors if collectors is not None else [c(config) for c in DEFAULT_COLLECTORS]

    run = AssessmentRun(system_id=system_id)
    if catalog_path:
        run.catalog_controls = load_catalog_ids(catalog_path)
    else:
        run.catalog_controls = sorted({r.control for r in rules})

    if parallel and len(collectors) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(collectors))) as pool:
            results = list(pool.map(lambda c: c.collect(), collectors))
    else:
        results = [c.collect() for c in collectors]
    for ev, errs in results:
        run.evidence.extend(ev)
        run.errors.extend(errs)

    return evaluate_all(run, rules, policy)
