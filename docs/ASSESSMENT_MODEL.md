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
`len any all sum min max abs exists age_days split lower get int`). Rule `parameters` are
organizational example values (for example a 90-day inactivity limit), not
NIST requirements. Override them in `parameters.yaml`:
rule defaults < `parameters` (global) < `systems.<system_id>`.

## Exceptions and applicability (`parameters.yaml`)

- Exceptions need `owner`, `approved_by` and an unexpired `expires`; they are
  recorded on the assessment but the status stays `other_than_satisfied`.
  Risk acceptance is a human authorizing-official decision.
- `not_applicable` entries need `rationale` and `decided_by`.

## Coverage

Coverage is measured against a published baseline (default `moderate`;
`--baseline low|moderate|high|all`, or `engine.baseline` in the config). Control
IDs for Rev. 5 (catalog 5.2.0) and the three baselines ship in
`engine/data/rev5_control_ids.json`, extracted from NIST's OSCAL content at a
pinned commit. Every baseline control without a rule is `not_assessed`, so the
control-coverage figure is deliberately low until more rules exist. Enhancements
such as `AC-2.1` are separate controls: a rule on `AC-2` does not cover them.
`--baseline rules` limits the denominator to rule-referenced controls (an
optimistic view). `--catalog FILE` uses a full OSCAL catalog instead;
`--fetch-catalog DEST` downloads the pinned one and verifies its SHA-256.

Asset coverage compares `engine.expected_assets` in the config with assets that
have fresh evidence. With no inventory configured it is reported as unknown,
never 100%.

There is intentionally no single aggregate "compliance %", and the dashboard
reports `ato_status: not_determined`: the scanner supplies evidence, it does
not authorize.

## Adding a collector

Subclass `engine.collectors.base.Collector`, set `evidence_type`, implement
`gather()` returning a payload dict (raise on failure), and register it in
`engine/collectors/__init__.py`. Then write a rule against that evidence type.

## Collectors and the configuration that enables them

Always attempted (a collector that cannot gather its evidence is a coverage
gap): Linux accounts, SSH keys, sshd config, auditd, listening services
(`ss`), kernel parameters, FIPS flag, pending package updates (apt/dnf),
scanner logging config.

Enabled by config:

| Config | Collector | Evidence type |
|---|---|---|
| `firewall.config_paths: [...]` | JSON firewall exports (unreadable files are recorded, never treated as permissive) | `network.firewall_rules` |
| `vulnerability_scan.report_path` | Imported scan report (`completed_at`, `findings[].severity`) | `vuln.scan_report` |
| `cloud_providers.aws.enabled` | IAM root MFA, admin users, console users without MFA | `aws.iam` |
| `cloud_providers.azure.enabled` | Global Administrators, guest accounts | `azure.directory` |
| `cloud_providers.gcp.enabled` + `projects` | Service accounts, public IAM members (one asset per project) | `gcp.iam` |
| `windows.enabled` | Local admins, disabled accounts, minimum password length (local PowerShell) | `windows.accounts` |

`engine.baseline` and `engine.expected_assets` set the coverage universe.
Cloud SDKs are imported lazily; clients and fetchers are injectable in tests, so
no credentials are needed. The Windows collector has only been exercised with a
fake runner, not on a real Windows host.
