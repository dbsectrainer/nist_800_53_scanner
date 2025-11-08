# NIST 800-53 Security Compliance Scanner

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This tool provides a **comprehensive security compliance scanning solution** based on NIST 800-53 Rev. 5 control requirements, updated to 2025 standards. It supports multiple cloud providers (AWS, Azure, GCP) and on-premise environments, offering in-depth security assessments across various control categories with modern Python 3.12+ features and best practices.

## NIST 800-53 Framework

```mermaid
classDiagram
    class NIST800_53 {
        <<NIST 800-53 Rev. 5>>
        Security and Privacy Controls
    }
    
    class SecurityBaselines {
        Low Impact
        Moderate Impact
        High Impact
    }
    
    class ImplementationLevels {
        Organization
        System
        Component
    }
    
    class ScannerCoverage {
        Cloud (AWS, Azure, GCP)
        On-Premise Systems
        Network Infrastructure
        Application Security
    }
    
    NIST800_53 --> AccessControl : AC
    NIST800_53 --> AuditAccountability : AU
    NIST800_53 --> ConfigManagement : CM
    NIST800_53 --> IncidentResponse : IR
    NIST800_53 --> SystemCommsProtection : SC
    NIST800_53 --> OtherControls : "15 more families"
    
    class AccessControl {
        <<AC>>
        Account Management
        Access Enforcement
        Least Privilege
        Separation of Duties
        Information Flow
    }
    
    class AuditAccountability {
        <<AU>>
        Event Logging
        Audit Records
        Monitoring
        Analysis & Reporting
    }
    
    class ConfigManagement {
        <<CM>>
        Baseline Configuration
        Change Control
        Security Impact Analysis
        Configuration Settings
    }
    
    class IncidentResponse {
        <<IR>>
        Incident Handling
        Monitoring
        Reporting
        Response Testing
    }
    
    class SystemCommsProtection {
        <<SC>>
        Boundary Protection
        Cryptography
        Information in Transit
        Information at Rest
    }
    
    class OtherControls {
        AT - Awareness & Training
        IA - Identification & Authentication
        RA - Risk Assessment
        SI - System & Information Integrity
        And others...
    }
    
    SecurityBaselines --> NIST800_53 : implements
    ImplementationLevels --> NIST800_53 : applies to
    NIST800_53 --> ScannerCoverage : scanned by
```

## Features

### Core Capabilities
- **Multi-cloud and on-premise support** - AWS, Azure, GCP, and hybrid environments
- **Modular security control scanning** - Flexible architecture for custom controls
- **Detailed compliance reporting** - Multiple output formats (JSON, Markdown, HTML)
- **Real-time monitoring** - Continuous compliance tracking with Prometheus/Grafana
- **Modern Python 3.12+** - Type-safe, async-first, with latest security features

### NIST 800-53 Control Families
- **AC** - Access Control
- **AU** - Audit and Accountability
- **SC** - System and Communications Protection
- **CM** - Configuration Management
- **IR** - Incident Response
- **IA** - Identification and Authentication
- **RA** - Risk Assessment
- **SI** - System and Information Integrity

### 2025 Technology Stack
- **FastAPI** - Modern async web framework
- **Pydantic v2** - Advanced data validation
- **SQLAlchemy 2.0** - Modern ORM with async support
- **OpenTelemetry** - Distributed tracing and observability
- **Ruff** - Ultra-fast Python linting and formatting
- **Docker & Kubernetes** - Cloud-native deployment

## Prerequisites

- **Python 3.12+** (Latest Python for 2025 standards)
- Cloud provider credentials (as applicable)
- Network access to scanned environments
- Docker (optional, for containerized deployment)
- Git (for version control)

## Installation

### Using pip (recommended)

```bash
# Install with all dependencies
pip install -e ".[all]"

# Install for production use
pip install .

# Install for development
pip install -e ".[dev]"
```

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Build standalone container
docker build -t nist-compliance-scanner .
```

### For Development

```bash
# Clone the repository
git clone https://github.com/your-org/nist-800-53-scanner.git
cd nist-800-53-scanner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Configuration

Edit the `config.yaml` file to configure:
- Cloud provider credentials
- On-premise environment details
- Scanning options
- Reporting preferences

### Example Configuration Sections

```yaml
# Cloud Provider Configuration
aws:
  enabled: true
  access_key: ${AWS_ACCESS_KEY}
  secret_key: ${AWS_SECRET_KEY}

# On-Premise Configuration
on_premise:
  linux:
    enabled: true
    hosts:
      - 192.168.1.100
    ssh_key_path: /path/to/ssh/key
```

## Usage

```bash
# Run a comprehensive scan
python scan.py --config config.yaml --environment cloud

# Generate a compliance report
python scan.py --config config.yaml --report markdown
```

## Scanning Categories

1. **Access Control**
   - IAM policy review
   - Account management checks
   - Privilege escalation prevention

2. **Audit Logging**
   - Cloud trail logging
   - System event monitoring
   - Log retention and analysis

3. **Network Security**
   - Firewall configuration
   - Network segmentation
   - Boundary protection

4. **Configuration Management**
   - System hardening
   - Configuration baseline
   - Change management

5. **Incident Response**
   - Incident detection mechanisms
   - Response plan evaluation
   - Training and preparedness

## Reporting

The scanner generates reports in:
- Markdown
- JSON
- Optional email notifications

## Security and Compliance

- Follows NIST 800-53 Rev. 5 guidelines
- Supports comprehensive and targeted scanning
- Provides actionable remediation guidance

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License

## Disclaimer

This tool provides guidance and should be used as part of a comprehensive security strategy. Always consult security professionals for critical infrastructure.
