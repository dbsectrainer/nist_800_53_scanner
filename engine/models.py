"""Core data model: statuses, assessment methods, evidence and assessments."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    """Assessment-objective outcome (aligned with OSCAL finding states)."""

    SATISFIED = "satisfied"
    OTHER_THAN_SATISFIED = "other_than_satisfied"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class Method(str, Enum):
    """NIST SP 800-53A assessment methods."""

    EXAMINE = "examine"
    INTERVIEW = "interview"
    TEST = "test"


# Methods the scanner can execute without a human assessor.
AUTOMATABLE_METHODS = {Method.EXAMINE, Method.TEST}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class Evidence:
    """One collected, hashed, timestamped fact about an asset."""

    type: str  # e.g. "linux.accounts"
    asset_id: str
    collector: str
    payload: dict[str, Any]
    collector_version: str = "1"
    method: str = "examine"  # NIST SP 800-53A method: examine | interview | test
    collected_at: datetime = field(default_factory=utcnow)
    ttl_hours: float = 24.0
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sha256: str = ""

    def __post_init__(self) -> None:
        if self.method not in {m.value for m in Method}:
            raise ValueError(f"unknown assessment method: {self.method!r}")
        if not self.sha256:
            self.sha256 = hashlib.sha256(canonical_json(self._provenance()).encode()).hexdigest()

    def _provenance(self) -> dict[str, Any]:
        """Everything that identifies the observation, not just its payload."""
        return {
            "type": self.type,
            "asset_id": self.asset_id,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "method": self.method,
            "payload": self.payload,
            "collected_at": self.collected_at.isoformat(),
        }

    def age_hours(self, now: Optional[datetime] = None) -> float:
        return ((now or utcnow()) - self.collected_at).total_seconds() / 3600.0

    def is_fresh(self, max_age_hours: Optional[float] = None, now: Optional[datetime] = None) -> bool:
        limit = self.ttl_hours if max_age_hours is None else max_age_hours
        return self.age_hours(now) <= limit

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["collected_at"] = self.collected_at.isoformat()
        return d


@dataclass
class CollectionError:
    """A collector could not gather evidence: a coverage gap, not a pass."""

    collector: str
    evidence_type: str
    message: str
    asset_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Assessment:
    """Result of evaluating one rule against one asset's evidence."""

    rule_id: str
    control_id: str
    title: str
    status: Status
    method: Method
    asset_id: str = ""
    observed: str = ""
    recommended_action: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    reason: str = ""  # why not_assessed / not_applicable
    exception: Optional[dict[str, Any]] = None
    rule_version: str = ""
    assessed_at: datetime = field(default_factory=utcnow)

    @property
    def legacy_compliant(self) -> Optional[bool]:
        """Tri-state view for legacy consumers (None = unknown, never True)."""
        if self.status == Status.SATISFIED:
            return True
        if self.status == Status.OTHER_THAN_SATISFIED:
            return False
        return None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["method"] = self.method.value
        d["assessed_at"] = self.assessed_at.isoformat()
        return d


@dataclass
class AssessmentRun:
    """Everything produced by one scan: evidence, errors, assessments."""

    system_id: str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[CollectionError] = field(default_factory=list)
    assessments: list[Assessment] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    catalog_controls: list[str] = field(default_factory=list)
    expected_assets: list[str] = field(default_factory=list)
    baseline: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "system_id": self.system_id,
            "started_at": self.started_at.isoformat(),
            "evidence": [e.to_dict() for e in self.evidence],
            "errors": [e.to_dict() for e in self.errors],
            "assessments": [a.to_dict() for a in self.assessments],
            "catalog_controls": self.catalog_controls,
            "expected_assets": self.expected_assets,
            "baseline": self.baseline,
        }
