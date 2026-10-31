"""OSCAL assessment-results and POA&M export (OSCAL 1.1.x JSON)."""

from __future__ import annotations

import uuid
from typing import Any

from .models import AssessmentRun, Status

OSCAL_VERSION = "1.1.2"

_STATE = {  # OSCAL finding target status state
    Status.SATISFIED: "satisfied",
    Status.OTHER_THAN_SATISFIED: "not-satisfied",
    Status.NOT_ASSESSED: "not-satisfied",  # OSCAL has no 'not assessed' state; reason documents it
    # NOT_APPLICABLE findings are omitted from OSCAL: 'satisfied' would overstate them.
}


def _iso(dt: Any) -> str:
    return dt.isoformat().replace("+00:00", "Z") if hasattr(dt, "isoformat") else str(dt)


def _stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(parts)))


def _occurrence(seen: dict[tuple[str, ...], int], key: tuple[str, ...]) -> str:
    """Return a stable ordinal for repeated (rule, asset) or evidence keys."""
    index = seen.get(key, 0)
    seen[key] = index + 1
    return str(index)


def to_assessment_results(run: AssessmentRun, title: str = "NIST SP 800-53 Assessment Results") -> dict[str, Any]:
    observations = []
    obs_ids: dict[str, str] = {}
    obs_seen: dict[tuple[str, ...], int] = {}
    for e in run.evidence:
        key = (e.type, e.asset_id, e.sha256)
        obs_uuid = _stable_uuid("obs", *key, _occurrence(obs_seen, key))
        obs_ids[e.id] = obs_uuid
        observations.append(
            {
                "uuid": obs_uuid,
                "title": f"{e.type} on {e.asset_id}",
                "description": f"Evidence collected by {e.collector} v{e.collector_version}",
                "methods": [e.method.upper()],
                "types": ["finding"],
                "collected": _iso(e.collected_at),
                "props": [
                    {"name": "sha256", "value": e.sha256},
                    {"name": "evidence-type", "value": e.type},
                    {"name": "asset-id", "value": e.asset_id},
                ],
            }
        )

    findings = []
    finding_seen: dict[tuple[str, ...], int] = {}
    for a in run.assessments:
        if a.status == Status.NOT_APPLICABLE:
            # N/A is a documented scope decision, not evidence of satisfaction.
            # It stays in the scanner's own report; OSCAL has no equivalent state.
            continue
        status = {"state": _STATE[a.status]}
        props = [
            {"name": "assessment-status", "value": a.status.value},
            {"name": "assessment-method", "value": a.method.value},
            {"name": "rule-id", "value": a.rule_id},
        ]
        if a.asset_id:
            props.append({"name": "asset-id", "value": a.asset_id})
        if a.status in (Status.NOT_ASSESSED, Status.NOT_APPLICABLE) or a.reason:
            # OSCAL's reason field is a token; the human explanation goes in remarks.
            status["reason"] = "other"
            status["remarks"] = a.reason or a.status.value
        finding = {
            "uuid": _stable_uuid("finding", a.rule_id, a.asset_id, _occurrence(finding_seen, (a.rule_id, a.asset_id))),
            "title": a.title,
            "description": a.observed or a.reason or a.title,
            "props": props,
            "target": {
                "type": "objective-id",
                "target-id": a.control_id.lower(),
                "status": status,
            },
        }
        related = [{"observation-uuid": obs_ids[r]} for r in a.evidence_refs if r in obs_ids]
        if related:
            finding["related-observations"] = related
        findings.append(finding)

    doc = {
        "assessment-results": {
            "uuid": _stable_uuid("ar", run.run_id),
            "metadata": {
                "title": title,
                "last-modified": _iso(run.started_at),
                "version": "1.0",
                "oscal-version": OSCAL_VERSION,
                "remarks": "Scanner output provides evidence and recommendations only; "
                "authorization decisions are made by the authorizing official.",
            },
            "import-ap": {
                "href": "urn:nist-scanner:assessment-plan:not-provided",
                "remarks": "No assessment plan was supplied; findings are generated from collected evidence.",
            },
            "results": [
                {
                    "uuid": _stable_uuid("result", run.run_id),
                    "title": f"Scan of {run.system_id}",
                    "description": "Automated evidence-based assessment",
                    "start": _iso(run.started_at),
                    "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                    "props": [{"name": "collection-errors", "value": str(len(run.errors))}],
                }
            ],
        }
    }
    result = doc["assessment-results"]["results"][0]
    # OSCAL rejects empty arrays, so include these only when populated.
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings
    return doc


def to_poam(run: AssessmentRun, title: str = "NIST SP 800-53 POA&M") -> dict[str, Any]:
    items = []
    tool_uuid = _stable_uuid("tool", "nist-scanner")
    seen: dict[tuple[str, ...], int] = {}
    for a in run.assessments:
        if a.status != Status.OTHER_THAN_SATISFIED:
            continue
        # OSCAL props require a non-empty value, so omit empty fields entirely.
        props = []
        control_id = (a.control_id or "").strip()
        if control_id:
            props.append({"name": "control-id", "value": control_id})
        action = (a.recommended_action or "").strip()
        if action:
            props.append({"name": "recommended-action", "value": action})
        item = {
            "uuid": _stable_uuid("poam", a.rule_id, a.asset_id, _occurrence(seen, (a.rule_id, a.asset_id))),
            "title": a.title,
            "description": a.observed or a.title,
            "origins": [{"actors": [{"type": "tool", "actor-uuid": tool_uuid}]}],
        }
        if props:
            item["props"] = props
        items.append(item)
    return {
        "plan-of-action-and-milestones": {
            "uuid": _stable_uuid("poam-doc", run.run_id),
            "metadata": {
                "title": title,
                "last-modified": _iso(run.started_at),
                "version": "1.0",
                "oscal-version": OSCAL_VERSION,
            },
            "import-ssp": {
                "href": "urn:nist-scanner:ssp:not-provided",
                "remarks": "No system security plan was supplied with this assessment.",
            },
            # Resolve the tool actor referenced by every POA&M item.
            "local-definitions": {
                "components": [
                    {
                        "uuid": tool_uuid,
                        "type": "software",
                        "title": "nist-800-53-scanner",
                        "description": "Automated evidence collection and assessment engine",
                        "status": {"state": "operational"},
                    }
                ]
            },
            "poam-items": items,
        }
    }
