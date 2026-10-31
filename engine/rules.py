"""Policy-as-code rule loading, organizational parameters and exceptions.

The rule format is a proprietary representation (not an OSCAL schema).
Parameter values such as ``max_inactive_days`` are organizational choices,
not NIST-mandated requirements.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Optional

import yaml

from .expr import ExpressionError, validate
from .models import AUTOMATABLE_METHODS, Method

REQUIRED_KEYS = ("rule_id", "control", "title")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    rule_id: str
    control: str
    title: str
    evidence_type: str
    version: str = "1"
    framework: str = "NIST-800-53"
    catalog_revision: str = "5"
    method: Method = Method.TEST
    required_fields: list[str] = field(default_factory=list)
    max_age_hours: Optional[float] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    applicable_when: Optional[str] = None
    assessable_when: Optional[str] = None
    condition: Optional[str] = None
    observed_template: str = ""
    remediation: str = ""

    @property
    def automated(self) -> bool:
        return self.method in AUTOMATABLE_METHODS and self.condition is not None


def parse_rule(data: dict[str, Any], source: str = "<rule>") -> Rule:
    for key in REQUIRED_KEYS:
        if key not in data:
            raise RuleError(f"{source}: missing required key '{key}'")
    ev = data.get("evidence") or {}
    if data.get("condition") and "type" not in ev:
        raise RuleError(f"{source}: evidence.type is required for automated rules")
    try:
        method = Method(data.get("method", "test"))
    except ValueError as exc:
        raise RuleError(f"{source}: invalid method {data.get('method')!r}") from exc
    rule = Rule(
        rule_id=str(data["rule_id"]),
        control=str(data["control"]).upper(),
        title=str(data["title"]),
        evidence_type=str(ev.get("type", "")),
        version=str(data.get("version", "1")),
        framework=str(data.get("framework", "NIST-800-53")),
        catalog_revision=str(data.get("catalog_revision", "5")),
        method=method,
        required_fields=list(ev.get("required_fields", [])),
        max_age_hours=ev.get("max_age_hours"),
        parameters=dict(data.get("parameters") or {}),
        applicable_when=data.get("applicable_when"),
        assessable_when=data.get("assessable_when"),
        condition=data.get("condition"),
        observed_template=str(data.get("observed", "")),
        remediation=str(data.get("remediation", "")),
    )
    for name in ("applicable_when", "assessable_when", "condition"):
        expr = getattr(rule, name)
        if expr:
            try:
                validate(str(expr))
            except ExpressionError as exc:
                raise RuleError(f"{source}: {name}: {exc}") from exc
    return rule


def load_rules(directory: str) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        with open(path, "r", encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
        for doc in docs:
            if not doc:
                continue
            for item in doc if isinstance(doc, list) else [doc]:
                rule = parse_rule(item, source=os.path.basename(path))
                if rule.rule_id in seen:
                    raise RuleError(f"duplicate rule_id {rule.rule_id}")
                seen.add(rule.rule_id)
                rules.append(rule)
    return rules


@dataclass
class Policy:
    """Organizational parameters, exceptions and applicability decisions."""

    global_params: dict[str, Any] = field(default_factory=dict)
    system_params: dict[str, dict[str, Any]] = field(default_factory=dict)
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    not_applicable: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Optional[str]) -> "Policy":
        if not path or not os.path.exists(path):
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(
            global_params=dict(data.get("parameters") or {}),
            system_params=dict(data.get("systems") or {}),
            exceptions=list(data.get("exceptions") or []),
            not_applicable=list(data.get("not_applicable") or []),
        )

    def parameters_for(self, rule: Rule, system_id: str) -> dict[str, Any]:
        """Inheritance: rule defaults < global < system overrides."""
        merged = dict(rule.parameters)
        merged.update(self.global_params)
        merged.update((self.system_params.get(system_id) or {}))
        return merged

    def find_exception(self, rule: Rule, asset_id: str, now: datetime) -> tuple[Optional[dict], bool]:
        """Return (active_exception, expired_match_found)."""
        expired = False
        for exc in self.exceptions:
            if exc.get("rule_id") not in (rule.rule_id, rule.control):
                continue
            if exc.get("asset_id") not in (None, "", asset_id):
                continue
            expires = exc.get("expires")
            if expires is None or _as_datetime(expires) < now:
                expired = True  # exceptions must carry an unexpired date
                continue
            if not exc.get("owner") or not exc.get("approved_by"):
                continue
            return exc, False
        return None, expired

    def find_not_applicable(self, rule: Rule, asset_id: str) -> Optional[dict]:
        for item in self.not_applicable:
            if item.get("rule_id") not in (None, rule.rule_id) and item.get("control") != rule.control:
                continue
            if item.get("rule_id") is None and item.get("control") is None:
                continue
            if item.get("asset_id") not in (None, "", asset_id):
                continue
            if item.get("rationale") and item.get("decided_by"):
                return item
        return None


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, 23, 59, 59, tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
