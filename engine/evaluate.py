"""Rule evaluation: rule x evidence -> Assessment.

Principles: missing, stale, incomplete or errored evidence is
``not_assessed``; it is never silently a pass.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from .expr import ExpressionError, evaluate
from .models import (
    Assessment,
    AssessmentRun,
    CollectionError,
    Evidence,
    Status,
    utcnow,
)
from .rules import Policy, Rule

_TEMPLATE = re.compile(r"\{([^{}]+)\}")


def _render(template: str, variables: dict[str, Any], now: datetime) -> str:
    def repl(match: re.Match) -> str:
        try:
            return str(evaluate(match.group(1), variables, now))
        except ExpressionError:
            return "?"

    return _TEMPLATE.sub(repl, template)


def evaluate_rule(
    rule: Rule,
    evidence: list[Evidence],
    errors: list[CollectionError],
    policy: Policy,
    system_id: str,
    now: Optional[datetime] = None,
) -> list[Assessment]:
    now = now or utcnow()
    base = dict(
        rule_id=rule.rule_id,
        control_id=rule.control,
        title=rule.title,
        method=rule.method,
        rule_version=rule.version,
        recommended_action=rule.remediation,
        assessed_at=now,
    )

    def make(status: Status, asset: str = "", **kw: Any) -> Assessment:
        return Assessment(status=status, asset_id=asset, **{**base, **kw})

    na = policy.find_not_applicable(rule, "")
    if na:
        return [make(Status.NOT_APPLICABLE, reason=f"{na['rationale']} (decided by {na['decided_by']})")]

    if not rule.automated:
        return [make(Status.NOT_ASSESSED, reason=f"method '{rule.method.value}' requires an assessor; no automated test")]

    relevant = [e for e in evidence if e.type == rule.evidence_type]
    relevant_errors = [e for e in errors if e.evidence_type == rule.evidence_type]
    if not relevant:
        detail = "; ".join(f"{e.collector}: {e.message}" for e in relevant_errors)
        reason = f"no evidence of type '{rule.evidence_type}' collected" + (f" ({detail})" if detail else "")
        return [make(Status.NOT_ASSESSED, reason=reason)]

    out: list[Assessment] = []
    for ev in relevant:
        asset = ev.asset_id
        na_asset = policy.find_not_applicable(rule, asset)
        if na_asset:
            out.append(make(Status.NOT_APPLICABLE, asset, evidence_refs=[ev.id],
                            reason=f"{na_asset['rationale']} (decided by {na_asset['decided_by']})"))
            continue
        if not ev.is_fresh(rule.max_age_hours, now):
            out.append(make(Status.NOT_ASSESSED, asset, evidence_refs=[ev.id],
                            reason=f"evidence stale ({ev.age_hours(now):.1f}h old)"))
            continue
        missing = [f for f in rule.required_fields if f not in ev.payload]
        if missing:
            out.append(make(Status.NOT_ASSESSED, asset, evidence_refs=[ev.id],
                            reason=f"evidence missing required fields: {', '.join(missing)}"))
            continue

        variables = {**policy.parameters_for(rule, system_id), **ev.payload}
        try:
            if rule.applicable_when and not evaluate(rule.applicable_when, variables, now):
                out.append(make(Status.NOT_APPLICABLE, asset, evidence_refs=[ev.id],
                                reason="rule scope not matched"))
                continue
            if rule.assessable_when and not evaluate(rule.assessable_when, variables, now):
                out.append(make(Status.NOT_ASSESSED, asset, evidence_refs=[ev.id],
                                reason="evidence incomplete for this assessment"))
                continue
            ok = bool(evaluate(rule.condition or "False", variables, now))
        except ExpressionError as exc:
            out.append(make(Status.NOT_ASSESSED, asset, evidence_refs=[ev.id],
                            reason=f"rule could not be evaluated: {exc}"))
            continue

        observed = _render(rule.observed_template, variables, now) if rule.observed_template else ""
        if ok:
            out.append(make(Status.SATISFIED, asset, evidence_refs=[ev.id], observed=observed))
            continue
        exception, expired = policy.find_exception(rule, asset, now)
        a = make(Status.OTHER_THAN_SATISFIED, asset, evidence_refs=[ev.id], observed=observed)
        if exception:
            a.exception = {k: str(v) for k, v in exception.items()}
        elif expired:
            a.reason = "a matching exception exists but is expired or incomplete"
        out.append(a)

    # An errored collector for some assets must not hide the gap.
    for err in relevant_errors:
        out.append(make(Status.NOT_ASSESSED, err.asset_id, reason=f"collection failed: {err.message}"))
    return out


def evaluate_all(run: AssessmentRun, rules: list[Rule], policy: Policy,
                 now: Optional[datetime] = None) -> AssessmentRun:
    run.assessments = []
    for rule in rules:
        run.assessments.extend(
            evaluate_rule(rule, run.evidence, run.errors, policy, run.system_id, now)
        )
    return run
