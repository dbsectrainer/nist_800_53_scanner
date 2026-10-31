# Assessment model

NIST SP 800-53 defines controls; it is not a scanning specification. This
scanner follows the SP 800-53A idea of assessment methods and objective
outcomes, and keeps **evidence collection** separate from **control
evaluation**.

```
collectors (read-only) -> Evidence (hashed, timestamped) -> rules (policy-as-code) -> Assessments -> OSCAL / reports
```

## Statuses

| Status | Meaning |
|---|---|
| `satisfied` | Sufficient, fresh evidence shows the objective is met |
| `other_than_satisfied` | Evidence shows the objective is not met |
| `not_assessed` | Not adequately evaluated: no/stale/incomplete evidence, collector failure, rule error, or a method needing an assessor |
| `not_applicable` | A documented decision (rationale + decider) or rule scope excludes it |

Missing evidence never becomes a pass. An unreachable host or expired
credential is a coverage gap (`not_assessed`), not proof of compliance.
OSCAL has no "not assessed" state, so those findings are exported as
`not-satisfied` with `reason: other` and an explanation in `remarks`; the
scanner's own status is kept in the `assessment-status` property.

Methods (`examine`, `interview`, `test`) are recorded per rule. A rule with
no condition, or a method requiring a human, is always `not_assessed` until
an assessor supplies evidence.

## Rules (`rules/*.yaml`)

A proprietary format (not OSCAL). Conditions are a restricted, deterministic
expression language (no `eval`, no attribute access, whitelisted functions
`len any all sum min max abs exists age_days`). Rule `parameters` are
organizational example values (for example a 90-day inactivity limit), not
NIST requirements. Override them in `parameters.yaml`:
rule defaults < `parameters` (global) < `systems.<system_id>`.

## Exceptions and applicability (`parameters.yaml`)

- Exceptions need `owner`, `approved_by` and an unexpired `expires`; they are
  recorded on the assessment but the status stays `other_than_satisfied`.
  Risk acceptance is a human authorizing-official decision.
- `not_applicable` entries need `rationale` and `decided_by`.

## Coverage

Without `--catalog`, coverage is measured against the controls referenced by
loaded rules only, which overstates coverage. Pass an OSCAL catalog
(`--catalog`) to count every catalog control without a rule as `not_assessed`.
There is intentionally no single aggregate "compliance %", and the dashboard
reports `ato_status: not_determined`: the scanner supplies evidence, it does
not authorize.

## Adding a collector

Subclass `engine.collectors.base.Collector`, set `evidence_type`, implement
`gather()` returning a payload dict (raise on failure), and register it in
`engine/collectors/__init__.py`. Then write a rule against that evidence type.
