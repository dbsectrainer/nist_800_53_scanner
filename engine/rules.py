"""Policy-as-code rule loading, organizational parameters and exceptions.

The rule format is a proprietary representation (not an OSCAL schema).
Parameter values such as ``max_inactive_days`` are organizational choices,
not NIST-mandated requirements.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Optional

import yaml

from .expr import ExpressionError, validate
from .models import AUTOMATABLE_METHODS, Method

REQUIRED_KEYS = ("rule_id", "control", "title")
# Rule controls become OSCAL target-id tokens, so parentheses and spaces are invalid.
CONTROL_ID_PATTERN = re.compile(r"^[A-Z_][A-Z0-9._-]*$")


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
    if not isinstance(data, dict):
        raise RuleError(f"{source}: rule entry must be a mapping")
    for key in REQUIRED_KEYS:
        if key not in data:
            raise RuleError(f"{source}: missing required key '{key}'")
        if not str(data[key]).strip():
            raise RuleError(f"{source}: '{key}' must not be empty")
    ev = data.get("evidence")
    if ev is None:
        ev = {}
    if not isinstance(ev, dict):
        raise RuleError(f"{source}: evidence must be a mapping")
    if data.get("condition") and "type" not in ev:
        raise RuleError(f"{source}: evidence.type is required for automated rules")
    if "type" in ev and not isinstance(ev["type"], str):
        raise RuleError(f"{source}: evidence.type must be a string")
    params = data.get("parameters")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise RuleError(f"{source}: parameters must be a mapping")
    required_fields = ev.get("required_fields")
    if required_fields is None:
        required_fields = []
    if not isinstance(required_fields, list) or not all(isinstance(f, str) for f in required_fields):
        raise RuleError(f"{source}: evidence.required_fields must be a list of strings")
    max_age = ev.get("max_age_hours")
    if max_age is not None:
        try:
            max_age = float(max_age)
        except (TypeError, ValueError) as exc:
            raise RuleError(f"{source}: evidence.max_age_hours must be a number") from exc
        if max_age < 0:
            raise RuleError(f"{source}: evidence.max_age_hours must be >= 0")
    control = str(data["control"]).upper()
    if not CONTROL_ID_PATTERN.match(control):
        raise RuleError(
            f"{source}: control id {control!r} is not a valid control identifier "
            "(letters, digits, '.', '_' or '-'; use AC-2.3, not AC-2(3))"
        )
    try:
        method = Method(data.get("method", "test"))
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{source}: invalid method {data.get('method')!r}") from exc
    rule = Rule(
        rule_id=str(data["rule_id"]),
        control=control,
        title=str(data["title"]),
        evidence_type=str(ev.get("type") or ""),
        version=str(data.get("version") or "1"),
        framework=str(data.get("framework") or "NIST-800-53"),
        catalog_revision=str(data.get("catalog_revision") or "5"),
        method=method,
        required_fields=list(required_fields),
        max_age_hours=max_age,
        parameters=dict(params),
        applicable_when=data.get("applicable_when"),
        assessable_when=data.get("assessable_when"),
        condition=data.get("condition"),
        observed_template=str(data.get("observed") or ""),
        remediation=str(data.get("remediation") or ""),
    )
    for name in ("applicable_when", "assessable_when", "condition"):
        expr = getattr(rule, name)
        if not expr:
            continue
        if not isinstance(expr, str):
            raise RuleError(f"{source}: {name} must be a string expression")
        try:
            validate(expr)
        except ExpressionError as exc:
            raise RuleError(f"{source}: {name}: {exc}") from exc
    return rule


def load_rules(directory: str) -> list[Rule]:
    if not os.path.isdir(directory):
        raise RuleError(f"rules directory not found: {directory}")
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except (yaml.YAMLError, ValueError) as exc:
            raise RuleError(f"{os.path.basename(path)}: invalid YAML: {exc}") from exc
        for doc in docs:
            if not doc:
                continue
            for item in doc if isinstance(doc, list) else [doc]:
                rule = parse_rule(item, source=os.path.basename(path))
                if rule.rule_id in seen:
                    raise RuleError(f"duplicate rule_id {rule.rule_id}")
                seen.add(rule.rule_id)
                rules.append(rule)
    if not rules:
        raise RuleError(f"no rules found in {directory}")
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
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (yaml.YAMLError, ValueError) as exc:
            raise RuleError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise RuleError(f"{path}: policy file must contain a mapping")

        global_params = data.get("parameters")
        systems = data.get("systems")
        exceptions = data.get("exceptions")
        not_applicable = data.get("not_applicable")

        if global_params is None:
            global_params = {}
        if systems is None:
            systems = {}
        if exceptions is None:
            exceptions = []
        if not_applicable is None:
            not_applicable = []

        if not isinstance(global_params, dict):
            raise RuleError(f"{path}: parameters must be a mapping")
        if not isinstance(systems, dict) or not all(isinstance(v, dict) for v in systems.values()):
            raise RuleError(f"{path}: systems must map system ids to parameter mappings")
        if not isinstance(exceptions, list) or not all(isinstance(e, dict) for e in exceptions):
            raise RuleError(f"{path}: exceptions must be a list of mappings")
        if not isinstance(not_applicable, list) or not all(isinstance(i, dict) for i in not_applicable):
            raise RuleError(f"{path}: not_applicable must be a list of mappings")

        for i, exc in enumerate(exceptions):
            if "rule_id" not in exc and "control" not in exc:
                raise RuleError(f"{path}: exceptions[{i}] needs rule_id or control")
            expires = exc.get("expires")
            if expires is not None:
                try:
                    _as_datetime(expires)
                except (TypeError, ValueError) as err:
                    raise RuleError(f"{path}: exceptions[{i}].expires is not a valid date: {err}") from err
        for i, item in enumerate(not_applicable):
            if "rule_id" not in item and "control" not in item:
                raise RuleError(f"{path}: not_applicable[{i}] needs rule_id or control")

        return cls(
            global_params=dict(global_params),
            system_params=dict(systems),
            exceptions=list(exceptions),
            not_applicable=list(not_applicable),
        )

    def parameters_for(self, rule: Rule, system_id: str) -> dict[str, Any]:
        """Inheritance: rule defaults < global < system overrides."""
        merged = dict(rule.parameters)
        merged.update(self.global_params)
        override = self.system_params.get(system_id) or {}
        if isinstance(override, dict):
            merged.update(override)
        return merged

    def find_exception(self, rule: Rule, asset_id: str, now: datetime) -> tuple[Optional[dict], bool]:
        """Return (active_exception, expired_or_incomplete_match_found)."""
        expired = False
        for exc in self.exceptions:
            if not isinstance(exc, dict):
                continue
            # Accept either rule_id or control as the selector.
            if not ({exc.get("rule_id"), exc.get("control")} & {rule.rule_id, rule.control}):
                continue
            if exc.get("asset_id") not in (None, "", asset_id):
                continue
            expires = exc.get("expires")
            if expires is None:
                expired = True  # exceptions must carry an unexpired date
                continue
            try:
                expires_at = _as_datetime(expires)
            except (TypeError, ValueError):
                expired = True
                continue
            if expires_at < now:
                expired = True
                continue
            if not exc.get("owner") or not exc.get("approved_by"):
                expired = True  # incomplete exception: surface it, never hide it
                continue
            return exc, False
        return None, expired

    def find_not_applicable(self, rule: Rule, asset_id: str) -> Optional[dict]:
        for item in self.not_applicable:
            if not isinstance(item, dict):
                continue
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
