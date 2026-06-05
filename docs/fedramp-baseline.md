# FedRAMP Moderate Baseline Guide

This guide explains how to use the NIST 800-53 Scanner to assess and track FedRAMP Moderate baseline compliance.

## FedRAMP Moderate Baseline Overview

**FedRAMP Moderate** is the most commonly used authorization level for federal systems. It requires compliance with **NIST SP 800-53 Moderate baseline**, which includes:

- **325 security controls** across 20 control families
- **Risk level:** Moderate impact on confidentiality, integrity, availability
- **Authorization timeline:** 3-6 months for experienced organizations
- **Cost:** Typically $50K-$250K for assessment (3PAO) + implementation

### Moderate Baseline Control Families

| Family | Controls      | Description                                                |
| ------ | ------------- | ---------------------------------------------------------- |
| **AC** | 22            | Access Control — who can do what                           |
| **AT** | 4             | Awareness & Training — security training                   |
| **AU** | 13            | Audit & Accountability — logging & monitoring              |
| **CA** | 9             | Assessment & Authorization — ATO process                   |
| **CM** | 10            | Configuration Management — change control                  |
| **CP** | 13            | Contingency Planning — disaster recovery                   |
| **IA** | 11            | Identification & Authentication — login security           |
| **IR** | 10            | Incident Response — handling breaches                      |
| **MA** | 7             | Maintenance — patching, updates                            |
| **MP** | 8             | Media Protection — data storage security                   |
| **PE** | 15            | Physical & Environmental — data center security            |
| **PL** | 11            | Planning — security planning                               |
| **PS** | 8             | Personnel Security — background checks, access termination |
| **RA** | 5             | Risk Assessment — vulnerability scanning                   |
| **SA** | 16            | System & Services Acquisition — vendor security            |
| **SC** | 40            | System & Communications Protection — encryption, firewalls |
| **SI** | 14            | System & Information Integrity — malware, monitoring       |
| **SR** | 4             | Supply Chain Risk Management — SBOM, vendor risk           |
|        | **325 Total** |                                                            |

---

## Using the Scanner for FedRAMP Assessment

### Step 1: Install & Configure

```bash
# Clone the repository
git clone https://github.com/dbsectrainer/nist_800_53_scanner.git
cd nist_800_53_scanner

# Install dependencies
pip install -r requirements.txt

# Create config for AWS (modify scan_targets/aws.yaml)
cat > config.yaml << 'EOF'
framework: "nist_800_53_moderate"  # or "nist_800_53_high"
cloud_provider: "aws"
regions:
  - "us-east-1"
  - "us-gov-west-1"       # For FedRAMP
  - "us-gov-east-1"       # For FedRAMP
aws_credentials:
  profile: "default"      # or specify access_key_id + secret_access_key
  role_arn: "arn:aws:iam::123456789012:role/SecurityAuditRole"
EOF
```

### Step 2: Run Baseline Scan

```bash
# Scan for Moderate baseline
python scan.py --framework nist_800_53_moderate --output-format json > moderate_baseline_scan.json

# Scan specific regions (FedRAMP GovCloud)
python scan.py \
  --framework nist_800_53_moderate \
  --regions us-gov-west-1 us-gov-east-1 \
  --output-format json > govcloud_baseline_scan.json

# Scan specific control family (example: SC — System & Communications Protection)
python scan.py \
  --framework nist_800_53_moderate \
  --control-family SC \
  --output-format json > sc_family_scan.json
```

### Step 3: Interpret Results

The scan output includes:

```json
{
  "control_id": "AC-2",
  "control_name": "Account Management",
  "family": "AC",
  "status": "COMPLIANT",
  "compliance_score": 0.95,
  "findings": [
    {
      "severity": "LOW",
      "description": "Root account access detected",
      "recommendation": "Enable MFA for root account"
    }
  ],
  "evidence": ["CloudTrail shows no root API calls in last 90 days", "IAM policy denies root access"]
}
```

**Status Legend:**

- 🟢 **COMPLIANT** — Control fully implemented (score > 0.90)
- 🟡 **PARTIAL** — Control partially implemented (score 0.60-0.90)
- 🔴 **NON_COMPLIANT** — Control not implemented (score < 0.60)

### Step 4: Generate Compliance Report

```bash
# Generate HTML report
python scan.py \
  --framework nist_800_53_moderate \
  --output-format html \
  --output moderate_baseline_report.html

# Generate CSV for POA&M tracking
python scan.py \
  --framework nist_800_53_moderate \
  --output-format csv > control_findings.csv

# Generate NIST-compliant report
python scan.py \
  --framework nist_800_53_moderate \
  --output-format nist-ssp \
  > system_security_plan_appendix.json
```

---

## FedRAMP-Specific Control Checks

The scanner includes **FedRAMP-specific validations** for common gaps:

### Access Control (AC) — 22 controls

```
AC-1: Access Control Policy — Policy document exists
AC-2: Account Management — MFA enforced, root access disabled
AC-3: Access Enforcement — IAM policies follow least privilege
AC-6: Least Privilege — Service accounts have minimal permissions
AC-14: Permitted Actions Without Auth — No unauthenticated APIs
AC-17: Remote Access — VPN or bastion host configured
AC-20: Use of External Systems — VPC endpoints for AWS APIs
```

**Scan Command:**

```bash
python scan.py --control-family AC --output-format json | grep -E "status|findings"
```

---

### System & Communications Protection (SC) — 40 controls

The **largest control family** (40 controls) requires comprehensive security:

```
SC-5: Denial of Service Protection — WAF enabled, rate limiting
SC-7: Boundary Protection — VPC isolation, no public resources
SC-8: Transmission Confidentiality — TLS 1.2+ enforced
SC-12: Cryptographic Key Establishment — KMS key management
SC-28: Protection of Information at Rest — Encryption enabled
SC-13: Cryptographic Protection — AES-256 at rest, TLS in transit
```

**Scan Command:**

```bash
python scan.py --control-family SC --output-format json > sc_family_findings.json
# Review: 40 controls, typically 30-35 are COMPLIANT in mature systems
```

---

### Audit & Accountability (AU) — 13 controls

Critical for **FedRAMP evidence collection**:

```
AU-2: Audit Events — CloudTrail enabled
AU-3: Content of Audit Records — Logs include user, action, timestamp, source IP
AU-6: Audit Review & Analysis — Automated analysis via Security Hub
AU-9: Protection of Audit Information — S3 Object Lock prevents tampering
AU-11: Audit Record Retention — 7-year retention
AU-12: Audit Generation — All resources generate logs
```

**Scan Command:**

```bash
python scan.py --control-family AU --check-7yr-retention | grep "COMPLIANT"
```

---

## Control Mapping to AWS Services

See [aws-config-mapping.md](aws-config-mapping.md) for 50+ AWS Config rules → NIST control mappings.

---

## Compliance Score Interpretation

**Overall FedRAMP Readiness Score:**

| Score       | Status      | Meaning               | Action             |
| ----------- | ----------- | --------------------- | ------------------ |
| **90-100%** | 🟢 Ready    | ATO achievable        | Engage 3PAO        |
| **75-89%**  | 🟡 Near     | 2-4 week remediation  | POA&M planning     |
| **50-74%**  | 🟠 Moderate | 1-2 month remediation | Roadmap            |
| **<50%**    | 🔴 Low      | Major work needed     | Architect redesign |

**Example Results:**

- Cloud-native system (AWS-only): **92%** compliant (AWS-inherited controls)
- Hybrid system (on-prem + AWS): **76%** compliant (must implement on-prem controls)
- Legacy system: **45%** compliant (requires significant upgrades)

---

## Common FedRAMP Failures & Fixes

### ❌ Failure: No audit logging

**Finding:** AU-2, AU-11 NON_COMPLIANT
**Fix:** Enable CloudTrail + S3 Object Lock

```bash
aws cloudtrail create-trail --name org-trail --s3-bucket-name my-logs-bucket
aws s3api put-object-lock-configuration --bucket my-logs-bucket \
  --object-lock-configuration ObjectLockEnabled=Enabled,ObjectLockRule='{DefaultRetention={Mode=GOVERNANCE,Days=2555}}'
```

### ❌ Failure: Public S3 buckets

**Finding:** SC-7 NON_COMPLIANT
**Fix:** Block public access

```bash
aws s3api put-public-access-block --bucket my-bucket \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### ❌ Failure: Root account access

**Finding:** AC-2, AC-6 NON_COMPLIANT
**Fix:** Deny root programmatic access + enable MFA

```bash
# Attach SCP to deny root access
aws organizations put-policy --content '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
      }
    }
  ]
}' --type SERVICE_CONTROL_POLICY
```

### ❌ Failure: Unencrypted data at rest

**Finding:** SC-28 NON_COMPLIANT
**Fix:** Enable KMS encryption

```bash
# RDS
aws rds modify-db-instance --db-instance-identifier mydb \
  --storage-encrypted --kms-key-id arn:aws:kms:region:account:key/id

# S3
aws s3api put-bucket-encryption --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:region:account:key/id"
      }
    }]
  }'
```

---

## POA&M (Plan of Action & Milestones)

For each NON_COMPLIANT finding, create a POA&M item:

```csv
Control_ID,Control_Name,Finding,Target_Remediation_Date,Owner,Status,Estimated_Hours
SC-7,Boundary_Protection,Public_RDS_Instance,2026-06-05,NetworkTeam,In_Progress,20
AC-2,Account_Management,Root_Account_MFA_Missing,2026-05-15,IAMTeam,Planned,8
AU-11,Audit_Retention,CloudTrail_Logs_Only_30Days,2026-06-20,SecOpsTeam,Planned,16
```

**Tracking Dashboard:**

```bash
# Generate POA&M progress report
python scan.py --framework nist_800_53_moderate --output-format poam > poam_status.csv
# Track week-to-week progress
```

---

## 3PAO (Third-Party Assessor) Coordination

When engaging a 3PAO for independent assessment:

1. **Week 1:** Share scanner results + SSP draft
2. **Week 2:** 3PAO reviews and identifies gaps
3. **Week 3:** Address 3PAO findings
4. **Week 4:** Remediation verification
5. **Week 5+:** Final assessment & authorization

**Evidence to provide:**

```
✓ Scanner results (HTML/JSON)
✓ CloudTrail logs (7 days sample)
✓ AWS Config snapshots
✓ Security Hub findings
✓ POA&M for any non-compliant controls
✓ Architecture diagrams
✓ System Security Plan (SSP) draft
```

---

## Continuous Monitoring

After ATO, the scanner becomes part of **continuous monitoring**:

```bash
# Daily compliance check
0 0 * * * /usr/bin/python /path/to/scan.py --framework nist_800_53_moderate --output-format json > /var/log/daily_compliance.json

# Weekly trend analysis
0 0 * * 0 python /path/to/analyze_trends.py /var/log/daily_compliance.json > /var/reports/weekly_compliance.html

# Monthly board report
0 0 1 * * python /path/to/executive_report.py /var/log/daily_compliance.json --output board_report.pdf
```

---

## References

- [NIST SP 800-53 Moderate Baseline](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5)
- [FedRAMP Security Requirements](https://www.fedramp.gov/documents-1/)
- [AWS FedRAMP Compliance](https://aws.amazon.com/compliance/fedramp/)
- [3PAO Directory](https://www.fedramp.gov/3pao-directory/)

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-06  
**Maintained by:** BE EASY ENTERPRISES Federal Compliance Team
