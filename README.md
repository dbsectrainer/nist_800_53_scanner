# NIST 800-53 Compliance Scanner

> Comprehensive NIST 800-53 Rev. 5 compliance scanner supporting AWS, Azure, GCP, and on-premise environments — with Grafana dashboards and automated alerting.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/) [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/) [![Grafana](https://img.shields.io/badge/grafana-dashboards-orange.svg)](https://grafana.com/) [![NIST 800-53](https://img.shields.io/badge/NIST-800--53%20Rev%205-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) [![FedRAMP](https://img.shields.io/badge/FedRAMP-Moderate%20Aligned-blue.svg)](https://www.fedramp.gov/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

1. Scans AWS, Azure, GCP, and on-premise environments against all 18 NIST 800-53 Rev. 5 control families, covering Low, Moderate, and High impact baselines.
2. Produces compliance reports in JSON, Markdown, and HTML formats with per-control pass/fail status and remediation guidance.
3. Exposes Prometheus metrics from the Flask dashboard and provisions a Grafana overview dashboard via configuration-as-code.
4. Enforces alert rules through `alert_rules.yml` so teams receive notifications when compliance posture drops below defined thresholds.
5. Supports multi-tenant operation, rate limiting, encrypted storage of scan results, and OpenTelemetry distributed tracing for production-grade observability.
6. Provides startup and shutdown lifecycle scripts, a suite of example configurations, and a POA&M generator for tracking remediation of non-compliant controls.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Configuration Layer                         │
│              config.yaml  /  config_examples/                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Scanner Engine (scan.py)                    │
│         MultiTenantNISTComplianceScanner                        │
│   Input Validation  │  Rate Limiting  │  Auth Manager           │
└──────┬──────────────┴──────────────────┴──────────┬────────────┘
       │                                             │
       ▼                                             ▼
┌──────────────────────────┐          ┌──────────────────────────┐
│    Cloud Adapters        │          │   On-Premise Adapter     │
│  ┌──────┐ ┌──────┐      │          │  SSH / WinRM / Network   │
│  │ AWS  │ │Azure │ GCP  │          │  Paramiko / pywinrm      │
│  └──────┘ └──────┘      │          └──────────────────────────┘
└──────────────────────────┘
       │                                             │
       └──────────────────┬──────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│               18 NIST 800-53 Control Family Modules             │
│  AC  AU  CM  IA  IR  SC  SI  AT  CA  CP  MA  MP  PE  PL        │
│  PM  PS  RA  SA                                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Results & Reporting                       │
│          JSON  │  Markdown  │  HTML  │  POA&M Generator         │
│          Report Versioning  │  Encrypted Storage                │
└──────┬──────────────────────────────────────────┬───────────────┘
       │                                          │
       ▼                                          ▼
┌────────────────────────┐          ┌─────────────────────────────┐
│  Flask Dashboard       │          │  Alert Rules                │
│  dashboard/app.py      │          │  alert_rules.yml            │
│  GET /metrics          │          │  Prometheus Alertmanager    │
│  GET /api/v2/posture   │          └─────────────────────────────┘
└──────────┬─────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────┐
│            Observability Stack                               │
│   Prometheus (port 9090)  ─────►  Grafana (port 3000)       │
│   prometheus.yml / grafana/provisioning/                     │
└──────────────────────────────────────────────────────────────┘
```

---

## Key Features

### Control Family Coverage

The scanner evaluates all 18 NIST 800-53 Rev. 5 control families. The table below lists the primary families with dedicated modules:

| Family | Identifier | Description |
| --- | --- | --- |
| Access Control | AC | IAM policies, least privilege, separation of duties, information flow |
| Audit and Accountability | AU | Event logging, audit records, log retention, analysis and review |
| Configuration Management | CM | Baseline configuration, change control, security impact analysis |
| Identification and Authentication | IA | MFA enforcement, credential management, authenticator lifecycle |
| Incident Response | IR | Detection mechanisms, response plans, testing and preparedness |
| System and Communications Protection | SC | Boundary protection, TLS enforcement, encryption at rest and in transit |
| System and Information Integrity | SI | Malware protection, security alerts, software patching verification |
| Awareness and Training | AT | Training records, role-based security awareness |
| Risk Assessment | RA | Vulnerability scanning, risk scoring, remediation prioritization |

Additional families (CA, CP, MA, MP, PE, PL, PM, PS, SA) are evaluated through cloud provider configuration checks and policy document analysis.

### Multi-Cloud and On-Premise Support

The scanner connects to cloud environments using provider-native SDKs and to on-premise hosts over SSH (Paramiko) or WinRM (pywinrm).

- AWS: IAM, CloudTrail, GuardDuty, Security Hub, Config, S3, RDS, KMS, VPC
- Azure: Service principal authentication, subscription-level security assessments
- GCP: Service account credentials, project-level IAM and audit log checks
- On-Premise: Linux SSH, Windows WinRM, network infrastructure scanning via scan_targets/ scenario files

### Observability Stack

The Flask application in `dashboard/` exposes Prometheus metrics at `GET /metrics` and a JSON posture endpoint at `GET /api/v2/posture`. Grafana is provisioned automatically from `grafana/provisioning/` and `grafana/dashboards/`.

Exported metric series (prefix `nist_dashboard_`):

- `nist_dashboard_compliance_pct` — overall compliance percentage
- `nist_dashboard_controls_total`, `nist_dashboard_controls_compliant`, `nist_dashboard_controls_non_compliant`
- `nist_dashboard_poam_open`, `nist_dashboard_poam_critical_open`
- `nist_dashboard_family_compliance_pct{family="AC"}` (one series per NIST family)
- `nist_dashboard_data_available` — 1 when scan results are loaded, 0 otherwise
- `nist_dashboard_latest_report_info` — info metric with `report_id` and `last_scan_date` labels

### Automated Alerting

Alert rules in `alert_rules.yml` integrate with Prometheus Alertmanager to notify teams when:

- Overall compliance percentage falls below configured thresholds
- Critical POA&M items remain open beyond their scheduled remediation dates
- Scan data becomes unavailable or stale

### Reporting and POA&M

- JSON, Markdown, and HTML output formats from `scan.py --report`
- Report versioning via `dashboard/report_versioning.py` tracks history over time
- `dashboard/poam_generator.py` produces Plan of Action and Milestones documents for non-compliant controls, supporting FedRAMP continuous monitoring requirements

### Security and Compliance

- NIST 800-53 Rev. 5 — Low, Moderate, and High impact baselines
- FedRAMP Moderate alignment (see `docs/fedramp-baseline.md`)
- AWS Config conformance pack mapping (50+ rules documented in `docs/aws-config-mapping.md`)
- AES-256-GCM encryption for scan results at rest; TLS 1.3 for data in transit
- API key authentication with rotation policy, rate limiting per IP and per key
- OpenTelemetry distributed tracing with OTLP export
- Bandit static analysis, Ruff linting, mypy type checking enforced in CI
- Secrets baseline managed via detect-secrets (`.secrets.baseline`)

---

## Quick Start

### Prerequisites

- Python 3.12 or later
- Docker and Docker Compose (for the containerized stack)
- Cloud provider credentials (AWS, Azure, or GCP) configured as environment variables or assume-role
- Network access to any on-premise hosts to be scanned

### Local Development

```bash
# Clone the repository
git clone https://github.com/dbsectrainer/nist_800_53_scanner.git
cd nist_800_53_scanner

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and edit the configuration
cp config_examples/basic_config.yaml config.yaml
# Edit config.yaml to supply cloud credentials and scan targets

# Run a scan
python scan.py --config config.yaml --environment cloud

# Generate a Markdown compliance report
python scan.py --config config.yaml --report markdown
```

### Docker Deployment

```bash
# Start the full observability stack (scanner, dashboard, Prometheus, Grafana)
docker-compose up -d
```

| Service | URL | Notes |
| --- | --- | --- |
| Compliance Dashboard | http://localhost:8000 | Web UI; `/dashboard` requires login |
| Prometheus | http://localhost:9090 | Scrapes `nist_compliance_scanner:8000/metrics` |
| Grafana | http://localhost:3000 | Default credentials `admin` / `admin` — change `GF_SECURITY_ADMIN_PASSWORD` before any non-local use |

```bash
# Use lifecycle scripts
./startup.sh    # start services
./shutdown.sh   # stop services

# Run without Docker
export DASHBOARD_PORT=8000
python dashboard/app.py
curl -s http://127.0.0.1:8000/metrics | head
```

Security note: expose `/metrics` only on trusted networks. For production, terminate TLS on a reverse proxy and restrict access to Prometheus and the scrape port.

---

## Production Ready Status

**Core scanning, observability, and CI pipeline are operational.**

- NIST 800-53 Rev. 5 control family modules implemented for AC, AU, CM, IA, IR, SC, and SI
- Multi-cloud adapters for AWS (boto3), Azure (azure-identity), and GCP (google-cloud-iam)
- On-premise scanning via SSH (Paramiko) and WinRM (pywinrm)
- Flask dashboard with Prometheus metrics endpoint and Grafana provisioning
- Alert rules file (`alert_rules.yml`) and Prometheus scrape config (`prometheus.yml`) included
- Docker Compose stack for one-command local deployment
- Report versioning, POA&M generator, and encrypted result storage implemented
- GitHub Actions CI pipeline with linting (Ruff), type checking (mypy), and security scanning (Bandit)
- Pre-commit hooks and secrets baseline enforced
- Test suite covering access control, audit logging, network security, configuration management, incident response, encryption, authentication, and end-to-end flows

### Verification

```bash
# Install dependencies and run tests
pip install -r requirements.txt
pip install -r requirements-dev.txt
python -m pytest tests/ -v

# Lint and type check
ruff check .
mypy scan.py dashboard/app.py

# Run a scan against config
python scan.py --config config.yaml --environment cloud --report markdown

# Verify Prometheus metrics are exposed
docker-compose up -d
curl -s http://localhost:8000/metrics | grep nist_dashboard_compliance_pct
```

Expected output from metrics endpoint:

```
nist_dashboard_compliance_pct 87.3
nist_dashboard_controls_total 325
nist_dashboard_controls_compliant 283
nist_dashboard_data_available 1
```

---

## Project Structure

```
nist_800_53_scanner/
├── scan.py                        # Main scanner entry point
├── config.yaml                    # Active configuration
├── config_examples/               # Example configurations (basic, enterprise, healthcare, cloud-native)
├── modules/                       # NIST control family scanner modules
│   ├── access_control.py
│   ├── audit_logging.py
│   ├── configuration_management.py
│   ├── incident_response.py
│   ├── network_security.py
│   ├── authentication.py
│   ├── encryption.py
│   ├── monitoring.py
│   ├── rate_limiter.py
│   ├── input_validator.py
│   └── report_versioning.py
├── dashboard/                     # Flask web dashboard + Prometheus metrics
│   ├── app.py
│   ├── data_manager.py
│   ├── models.py
│   ├── poam_generator.py
│   ├── config/                    # Dashboard environment configs
│   ├── static/                    # CSS and JavaScript assets
│   └── templates/                 # HTML templates
├── grafana/                       # Grafana provisioning and dashboard JSON
│   ├── provisioning/
│   └── dashboards/
├── prometheus.yml                 # Prometheus scrape configuration
├── alert_rules.yml                # Prometheus alert rules
├── scan_targets/                  # Scan scenario YAML files (cloud, kubernetes, network, web)
├── security_policies/             # Policy documents for AC, AU, IR, SC, AT families
├── docs/                          # Architecture, FedRAMP baseline, AWS Config mapping, user guide
├── examples/                      # Advanced scanning examples (ML, adaptive, dynamic policy)
├── tests/                         # Test suite (unit, integration, end-to-end)
├── scripts/                       # Utility scripts
├── Dockerfile
├── docker-compose.yml
├── startup.sh
├── shutdown.sh
├── requirements.txt
└── requirements-dev.txt
```

---

## BE EASY ENTERPRISES Federal Portfolio

| Showcase Project | Repository | Description |
| --- | --- | --- |
| **Secure RAG Pipeline** | [Secure-Generative-AI-Platform-on-AWS](https://github.com/dbsectrainer/Secure-Generative-AI-Platform-on-AWS) | AWS Bedrock + RAG with FedRAMP High alignment |
| **DevSecOps CI/CD** | [dod-cybersec-ops-framework](https://github.com/dbsectrainer/dod-cybersec-ops-framework) | DoD 8570 / NIST RMF aligned pipeline |
| **Zero Trust Architecture** | [AEGIS](https://github.com/dbsectrainer/AEGIS) | FedRAMP High + NIST 800-207 Zero Trust |
| **FedRAMP Control Automation** | **[nist_800_53_scanner](https://github.com/dbsectrainer/nist_800_53_scanner)** | **This repo** |
| **Federal AI Governance** | [ai-safety-governance](https://github.com/dbsectrainer/ai-safety-governance) | EO 14110 / OMB M-24-10 aligned |
| **CMMC 2.0 Dashboard** | [integrated-cyber-risk-compliance](https://github.com/dbsectrainer/integrated-cyber-risk-compliance) | CMMC 2.0 readiness assessment |
| **FedRAMP 30-Day Guide** | [cloud-security-best-practices](https://github.com/dbsectrainer/cloud-security-best-practices) | Day-by-day FedRAMP implementation roadmap |
| **Agentic AI Workflow** | [federal-doc-triage-agent](https://github.com/dbsectrainer/federal-doc-triage-agent) | Production-ready LangGraph + Bedrock triage agent |

---

## Author

**Donnivis Baker** — [github.com/dbsectrainer](https://github.com/dbsectrainer)
**BE EASY ENTERPRISES** — Federal IT Modernization & Cybersecurity

For questions, partnerships, or federal engagement inquiries, open an issue or reach out directly.

**Document Version:** 1.0 | **Last Updated:** 2026-06-15 | **NIST 800-53 Rev. 5:** Moderate Baseline
