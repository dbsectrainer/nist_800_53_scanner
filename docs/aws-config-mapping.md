# AWS Config Rules to NIST 800-53 Control Mapping

This document maps 50+ AWS Config rules to NIST SP 800-53 Revision 5 controls, enabling automated compliance verification for FedRAMP Moderate and High baselines.

## Overview

AWS Config Rules enable **continuous monitoring** of AWS resource configurations against desired standards. Each rule checks whether resources comply with specific configurations, providing evidence for NIST 800-53 controls.

**Benefits:**
- Automated evidence collection for FedRAMP assessments
- Real-time compliance status visibility
- Remediation tracking via POA&M
- Integration with Security Hub for centralized reporting

---

## Access Control (AC) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **root-mfa-enabled** | AWS Managed | AC-2, IA-2, IA-2(1) | Detects root account without MFA |
| **mfa-enabled-for-iam-console-access** | AWS Managed | AC-2, IA-2(1) | Enforces MFA for IAM users accessing console |
| **iam-policy-no-statements-with-admin-access** | AWS Managed | AC-3, AC-6 | Detects overly permissive IAM policies |
| **iam-user-no-policies-check** | AWS Managed | AC-2, AC-6 | Prevents direct user policies (use groups/roles) |
| **iam-policy-blacklist-check** | AWS Managed | AC-3 | Blocks dangerous actions (e.g., `*:*`) |
| **iam-root-access-key-check** | AWS Managed | AC-2, AC-6 | Detects root access keys (should use STS) |
| **iam-user-outside-organization-check** | AWS Managed | AC-2 | Detects IAM users outside trusted org |
| **iam-customer-policy-blocked-kms-actions** | AWS Managed | SC-12, AC-3 | Prevents unauthorized KMS key deletion |
| **ec2-security-group-managed-by-cloudformation** | AWS Managed | AC-3, CM-2 | Ensures security groups are IaC-managed |

---

## Audit & Accountability (AU) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **cloudtrail-enabled** | AWS Managed | AU-2, AU-12 | Verifies CloudTrail is enabled |
| **cloudtrail-logs-s3-bucket-public-read-disabled** | AWS Managed | AU-9, SC-7 | Prevents public access to CloudTrail logs |
| **cloudtrail-log-file-validation-enabled** | AWS Managed | AU-9 | Verifies log file validation is enabled |
| **s3-bucket-logging-enabled** | AWS Managed | AU-2, AU-3 | Confirms S3 bucket logging enabled |
| **cloudwatch-log-group-encrypted** | AWS Managed | AU-2, SC-28(1) | Encrypts CloudWatch Logs with KMS |
| **multi-region-cloudtrail-enabled** | AWS Managed | AU-2 | Detects CloudTrail in all regions |
| **api-gw-execution-logging-enabled** | AWS Managed | AU-2, AU-3 | Enables API Gateway request/response logging |

---

## Configuration Management (CM) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **ec2-instance-imdsv2-check** | AWS Managed | CM-2, CM-6 | Enforces IMDSv2 (vs. vulnerable IMDSv1) |
| **ec2-launch-template-public-ipv4-disabled** | AWS Managed | CM-6, SC-7 | Prevents public IPs on launch templates |
| **ec2-no-amazon-linux-ami** | AWS Managed | CM-2 | Enforces approved OS images (not Amazon Linux) |
| **approved-amis-by-tag** | AWS Managed | CM-2, CM-3 | Restricts instances to approved AMIs |
| **required-tags** | AWS Managed | CM-2, CA-7 | Enforces mandatory resource tagging |
| **cloudformation-stack-drift-detection-check** | AWS Managed | CM-2, CM-3 | Detects unapproved manual changes (drift) |
| **s3-bucket-versioning-enabled** | AWS Managed | CM-3, CP-2 | Enables version history for recovery |
| **autoscaling-group-elb-healthcheck-required** | AWS Managed | CM-2, CP-2 | Ensures health check for auto-scaling |

---

## Identification & Authentication (IA) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **iam-password-policy-check** | AWS Managed | IA-5 | Enforces password complexity (min 14 chars, symbols) |
| **iam-password-policy-expiration-check** | AWS Managed | IA-5 | Requires 90-day password rotation |
| **iam-user-unused-credentials-check** | AWS Managed | IA-4 | Detects unused access keys (>45 days) |
| **iam-access-key-age-check** | AWS Managed | IA-4 | Alerts if access key age >90 days |
| **iam-policy-no-multi-account-role-trust** | AWS Managed | IA-2, AC-3 | Restricts cross-account role assumptions |
| **iam-role-managed-policy-check** | AWS Managed | IA-2 | Prevents direct user attachment of AWS-managed policies |

---

## Incident Response (IR) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **securityhub-enabled** | AWS Managed | IR-4, CA-7 | Verifies Security Hub is enabled |
| **guardduty-enabled-centralized** | AWS Managed | IR-4, SI-4 | Checks GuardDuty enabled in all accounts |
| **macie-enabled** | AWS Managed | IR-4, SI-4 | Confirms Macie is enabled for S3 scanning |
| **lambda-dlq-check** | AWS Managed | IR-6 | Ensures failed Lambda invocations are logged |

---

## System & Communications Protection (SC) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **s3-bucket-server-side-encryption-enabled** | AWS Managed | SC-28(1) | Requires encryption at rest (SSE-S3 or SSE-KMS) |
| **s3-bucket-default-lock-enabled** | AWS Managed | SC-28(1) | Enables Object Lock for WORM compliance |
| **s3-bucket-public-read-disabled** | AWS Managed | SC-7 | Blocks public read access on buckets |
| **s3-bucket-public-write-disabled** | AWS Managed | SC-7 | Blocks public write access on buckets |
| **s3-bucket-ssl-requests-only** | AWS Managed | SC-8 | Requires HTTPS (denies HTTP) |
| **s3-bucket-all-access-blocked** | AWS Managed | SC-7 | Blocks all public access (4-setting check) |
| **rds-encryption-enabled** | AWS Managed | SC-28(1) | Verifies RDS encryption at rest |
| **rds-storage-encrypted** | AWS Managed | SC-28(1) | Enforces EBS encryption for RDS |
| **rds-enhanced-monitoring-enabled** | AWS Managed | SI-4, AU-2 | Enables detailed RDS performance logs |
| **ebs-encryption-by-default** | AWS Managed | SC-28(1) | Ensures EBS encryption is default |
| **ebs-encrypted-volumes** | AWS Managed | SC-28(1) | Detects unencrypted EBS volumes |
| **encrypted-volumes-attached-to-running-instances** | AWS Managed | SC-28(1) | Verifies running instances use encrypted volumes |
| **ec2-ebs-encryption-by-default-enabled** | AWS Managed | SC-28(1) | Checks EBS encryption default enabled |
| **dynamodb-encryption-enabled** | AWS Managed | SC-28(1) | Verifies DynamoDB encryption (at-rest + in-transit) |
| **dynamodb-point-in-time-recovery-enabled** | AWS Managed | CP-2, SC-28 | Enables DynamoDB point-in-time recovery |
| **rds-backup-enabled** | AWS Managed | CP-2, CP-9 | Confirms automated RDS backups enabled |
| **rds-backup-retention-check** | AWS Managed | CP-9, AU-11 | Verifies backup retention meets min. days |
| **s3-bucket-versioning-enabled** | AWS Managed | SC-28, CP-2 | Enables S3 object versions for recovery |

---

## VPC & Network Security Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **vpc-flow-logs-enabled** | AWS Managed | SI-4, AU-2, AU-11 | Enables VPC Flow Logs for network monitoring |
| **vpc-network-acl-unused-check** | AWS Managed | CM-2 | Detects unused Network ACLs |
| **vpc-sg-open-only-to-authorized-ports** | AWS Managed | SC-7 | Restricts security group ports (no 0.0.0.0/0) |
| **ec2-no-invalid-default-route** | AWS Managed | SC-7 | Prevents route to 0.0.0.0/0 without control |
| **restricted-ssh** | AWS Managed | SC-7, AC-17 | Blocks SSH from 0.0.0.0/0 (non-bastion) |
| **restricted-rdp** | AWS Managed | SC-7, AC-17 | Blocks RDP from 0.0.0.0/0 (non-bastion) |
| **ec2-subnet-auto-assign-public-ip-disabled** | AWS Managed | SC-7 | Disables automatic public IP assignment |
| **nacl-no-unrestricted-ssh-rdp** | AWS Managed | SC-7 | Network ACL: no unrestricted SSH/RDP |

---

## Key Management (KMS & Secrets) Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **cmk-backing-key-rotation-enabled** | AWS Managed | SC-12(1) | Verifies KMS key rotation enabled (annual) |
| **cmk-key-policy-allows-deletion** | AWS Managed | SC-12(1), AC-3 | Prevents overly permissive key deletion policies |
| **kms-key-rotation-enabled** | AWS Managed | SC-12(1) | Checks all CMKs have rotation enabled |
| **secretsmanager-rotation-enabled-check** | AWS Managed | IA-5(1), SC-12 | Verifies Secrets Manager rotation enabled |
| **secretsmanager-secret-unused-check** | AWS Managed | IA-4 | Detects unused secrets (>90 days) |

---

## Compliance & Monitoring Rules

| AWS Config Rule | Rule Type | NIST Controls | Purpose |
|---|---|---|---|
| **compliance-tag-requirements** | AWS Managed | CM-2 | Enforces compliance-related tags |
| **ec2-instance-public-ip-check** | AWS Managed | SC-7 | Detects EC2 instances with public IPs |
| **ec2-instance-has-iam-role** | AWS Managed | AC-2, AC-6 | Requires IAM roles (not keys) on instances |
| **ec2-instance-should-use-iam-instance-profile** | AWS Managed | AC-2, AC-6 | Confirms IAM instance profiles used |
| **elasticache-replication-enabled** | AWS Managed | CP-2, CP-6 | Enables ElastiCache replication for HA |
| **rds-multi-az-support** | AWS Managed | CP-2, CP-6 | Requires Multi-AZ for production RDS |
| **alb-https-ssl-policy-check** | AWS Managed | SC-8, SC-13 | Enforces modern SSL/TLS policies (no < TLS 1.2) |
| **elb-tls-https-listeners-only** | AWS Managed | SC-8 | Requires HTTPS on all Classic ELB listeners |
| **acm-certificate-expiration-check** | AWS Managed | SC-8, SC-13 | Alerts if SSL cert expires in <30 days |

---

## Automated Remediation Rules

Some AWS Config rules support **automated remediation** via SSM Documents. Example:

| Rule | Remediation SSM Document | Action |
|---|---|---|
| s3-bucket-server-side-encryption-enabled | AWS-EnableS3BucketEncryption | Auto-enable SSE-S3 |
| ec2-subnet-auto-assign-public-ip-disabled | AWS-DisableSubnetAutoPublicIP | Auto-disable public IP assignment |
| rds-backup-enabled | AWS-EnableRDSBackup | Auto-enable RDS automated backups |
| vpc-flow-logs-enabled | AWS-EnableVPCFlowLogs | Auto-enable VPC Flow Logs |

---

## Custom Rules for Federal Compliance

For **FedRAMP-specific** requirements not covered by AWS Managed Rules, create Custom Config Rules:

```python
# Example: Custom rule to enforce federal tagging
def lambda_handler(event, context):
    """Check if EC2 instances have required federal tags."""
    
    config = boto3.client('config')
    ec2 = boto3.client('ec2')
    
    compliant = []
    non_compliant = []
    
    required_tags = ['Environment', 'CostCenter', 'Owner', 'Compliance']
    
    # Check all EC2 instances
    instances = ec2.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            
            # Check required tags
            missing = [t for t in required_tags if t not in tags]
            
            if missing:
                non_compliant.append({
                    'resourceId': instance_id,
                    'resourceType': 'AWS::EC2::Instance',
                    'compliance': 'NON_COMPLIANT',
                    'annotation': f"Missing tags: {', '.join(missing)}"
                })
            else:
                compliant.append({
                    'resourceId': instance_id,
                    'resourceType': 'AWS::EC2::Instance',
                    'compliance': 'COMPLIANT'
                })
    
    # Report results
    return {
        'evaluations': compliant + non_compliant,
        'evaluationsLength': len(compliant) + len(non_compliant)
    }
```

---

## Integration with Security Hub

AWS Config rules integrate with Security Hub for **centralized compliance reporting**:

1. **Enable Config Rules** — Deploy 20-30 rules covering AC, AU, CM, SC families
2. **Enable Security Hub** — Aggregates Config findings
3. **Configure standards** — FedRAMP Best Practices in Security Hub
4. **Set up automation** — EventBridge → SNS for CRITICAL findings
5. **Generate reports** — Weekly compliance score + POA&M tracking

**Security Hub Compliance Score Example:**
```
FedRAMP Best Practices: 87% Compliant
├─ Pass: 87 controls
├─ Fail: 13 controls (all in POA&M)
└─ Exempt: 0 controls
```

---

## POA&M Integration

For non-compliant findings:

1. **Create POA&M item** — Reference Config rule + resource ID
2. **Assign owner** — Team responsible for remediation
3. **Set target date** — 30-90 days typical for federal systems
4. **Track progress** — Weekly Config compliance reports
5. **Close when remediated** — Config rule returns COMPLIANT

**Example POA&M CSV:**
```csv
Control_ID,Rule_Name,Resource_ID,Severity,Target_Date,Status,Owner
SC-7,restricted-ssh,sg-12345,MEDIUM,2026-06-15,In_Review,Network_Team
SC-28,s3-encryption-enabled,bucket-name,HIGH,2026-05-20,Remediated,Storage_Team
IA-5,iam-password-policy,N/A,MEDIUM,2026-05-30,Closed,IAM_Team
```

---

## Best Practices

### ✅ DO:
1. **Deploy 20-30 core rules** first (SC, AC, AU, CM families)
2. **Enable Security Hub** for centralized scoring
3. **Automate remediation** for safe rules (encryption, tagging)
4. **Create custom rules** for agency-specific requirements
5. **Review monthly** — Compliance trends + new findings
6. **Track remediation** — Use AWS Config snapshots in POA&M

### ❌ DON'T:
1. **Enable auto-remediation** for access control rules (requires review)
2. **Ignore findings** — Report to management weekly
3. **Delay updates** — Apply patches for rules within 30 days
4. **Create duplicate rules** — Consolidate via Config Rule Groups
5. **Assume inherited controls** — Document in SSP + ATO package

---

## References

- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [Config Rules for FedRAMP](https://aws.amazon.com/blogs/govcloud/)
- [NIST 800-53 Mappings](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5)
- [FedRAMP Control Family Matrix](https://www.fedramp.gov/documents-1/)

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-06  
**Maintained by:** BE EASY ENTERPRISES Federal Compliance Team
