# Starlings AWS Security Scanner

A lightweight, transparent security scanner that runs **locally in your environment**. Your AWS credentials never leave your machine.

## Quick Start

```bash
# Download the scanner
curl -sL https://raw.githubusercontent.com/Starlings-Data/aws-scanner/main/starlings-aws-scan.sh -o starlings-aws-scan.sh
chmod +x starlings-aws-scan.sh

# Run the scan (default credentials)
./starlings-aws-scan.sh

# For AWS SSO users - specify your profile
./starlings-aws-scan.sh --profile YOUR_SSO_PROFILE
```

## Requirements

- **AWS CLI** installed and configured (`aws configure`)
- **Bash** (macOS, Linux, or WSL on Windows)
- **jq** (optional, for prettier output)

## Usage

```bash
# Scan default region (from AWS CLI config)
./starlings-aws-scan.sh

# Scan using an SSO or named profile
./starlings-aws-scan.sh --profile my-sso-profile

# Scan specific region
./starlings-aws-scan.sh --region us-west-2

# Combine profile and region
./starlings-aws-scan.sh --profile prod-admin --region us-east-1

# Custom output file
./starlings-aws-scan.sh --output my-report.json

# Verbose output
./starlings-aws-scan.sh --verbose

# Show help
./starlings-aws-scan.sh --help
```

### Using with AWS SSO

If you use AWS SSO (IAM Identity Center), first login then run with your profile:

```bash
# Login to SSO
aws sso login --profile my-sso-profile

# Run scan with that profile
./starlings-aws-scan.sh --profile my-sso-profile
```

## What It Checks

The scanner runs **45+ read-only checks** across 14 security domains:

| Domain | Checks | Examples |
|--------|--------|----------|
| IAM & Access | 8 | Root MFA, root access keys, password policy, user MFA, access key age, inactive users, admin policies, support role |
| S3 Security | 5 | Public buckets, encryption, versioning, logging, SSL/TLS enforcement |
| EC2 & Network | 10 | Open SSH/RDP, security groups, default SGs, EBS encryption, public IPs, IMDSv2, snapshot public access, VPC Flow Logs, default encryption |
| RDS & Database | 4 | Public access, encryption, backup retention, deletion protection |
| Logging & Monitoring | 8 | CloudTrail, multi-region trails, log validation, KMS encryption, GuardDuty, AWS Config, Security Hub, Access Analyzer |
| CloudWatch | 3 | Log retention policies, CloudTrail integration, CIS security alarms |
| KMS | 1 | Key rotation |
| Secrets Manager | 1 | Secret rotation |
| ECR | 1 | Image scanning |
| Lambda | 1 | Deprecated runtimes |
| Inspector | 1 | Vulnerability scanning enabled |
| AWS Backup | 1 | Backup plans configured |
| ACM | 1 | Certificate expiration |
| SSM | 1 | Document public sharing |

## Compliance Framework Coverage

Each finding maps to relevant compliance frameworks:

| Framework | Coverage |
|-----------|----------|
| **CIS AWS Foundations Benchmark** | Full coverage of applicable controls |
| **ISO 27001** | Annex A controls mapped |
| **SOC 2** | Trust Services Criteria (CC) mapped |
| **CCSS** | Cryptocurrency Security Standard for digital asset compliance |

Example finding with framework references:
```json
{
  "check_id": "IAM-001",
  "severity": "critical",
  "title": "Root account MFA not enabled",
  "frameworks": ["CIS 1.5", "ISO27001 A.9.4.2", "SOC2 CC6.1", "CCSS 4.1"]
}
```

## Minimal IAM Policy

For least-privilege access, create an IAM user with the policy in `scan-policy.json`:

```bash
# Create the policy
aws iam create-policy \
  --policy-name StarlingsSecurityScan \
  --policy-document file://scan-policy.json

# Create a user and attach the policy
aws iam create-user --user-name starlings-scanner
aws iam attach-user-policy \
  --user-name starlings-scanner \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/StarlingsSecurityScan

# Create access keys
aws iam create-access-key --user-name starlings-scanner
```

After the scan, you can delete this user:
```bash
aws iam delete-access-key --user-name starlings-scanner --access-key-id ACCESS_KEY_ID
aws iam detach-user-policy --user-name starlings-scanner --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/StarlingsSecurityScan
aws iam delete-user --user-name starlings-scanner
aws iam delete-policy --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/StarlingsSecurityScan
```

## Output

The scanner generates a JSON report (`aws-security-report.json`) with:

```json
{
  "scanner_version": "1.1.0",
  "scan_date": "2026-01-30T10:30:00Z",
  "region": "us-east-1",
  "score": {
    "overall": 72,
    "interpretation": "Good"
  },
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "passed": 34,
    "total_checks": 45
  },
  "compliance_coverage": {
    "cis_aws_foundations": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [
    {
      "domain": "iam",
      "check_id": "IAM-001",
      "severity": "critical",
      "title": "Root account MFA not enabled",
      "description": "...",
      "resources": [],
      "remediation": "...",
      "frameworks": ["CIS 1.5", "ISO27001 A.9.4.2", "SOC2 CC6.1", "CCSS 4.1"]
    }
  ]
}
```

### Automatic Redaction

The scanner automatically redacts:
- AWS account IDs (12-digit numbers → `REDACTED`)

**Always review the output** before sharing to ensure no sensitive information is included.

## Scoring

| Score | Interpretation |
|-------|----------------|
| 90-100 | Excellent - Minor improvements recommended |
| 70-89 | Good - Some important gaps to address |
| 50-69 | Fair - Significant security improvements needed |
| Below 50 | Needs Attention - Critical issues require immediate action |

## Detailed Check Descriptions

### IAM & Access (8 checks)
- **IAM-001**: Root account MFA - Verifies MFA is enabled on root
- **IAM-002**: Root access keys - Ensures root has no access keys
- **IAM-003**: Password policy - Checks complexity requirements
- **IAM-004**: User MFA - Identifies users without MFA
- **IAM-005**: Access key age - Flags keys older than 90 days
- **IAM-006**: Inactive users - Finds unused credentials
- **IAM-007**: Admin access - Identifies overprivileged users
- **IAM-008**: Support role - Checks for AWS Support role

### S3 Security (5 checks)
- **S3-001**: Public access - Finds publicly accessible buckets
- **S3-002**: Encryption - Verifies default encryption
- **S3-003**: Logging - Checks access logging
- **S3-004**: Versioning - Verifies object versioning
- **S3-005**: SSL/TLS - Confirms secure transport required

### EC2 & Network (9 checks)
- **EC2-001**: SSH access - Finds 0.0.0.0/0 on port 22
- **EC2-002**: RDP access - Finds 0.0.0.0/0 on port 3389
- **EC2-003**: Wide open SGs - Finds all-traffic rules
- **EC2-004**: Default SGs - Checks for rules on default SGs
- **EC2-005**: EBS encryption - Finds unencrypted volumes
- **EC2-006**: Public IPs - Identifies exposed instances
- **EC2-007**: IMDSv2 - Checks metadata service version
- **EC2-008**: Snapshot sharing - Verifies block public access
- **EC2-009**: VPC Flow Logs - Checks network logging

### RDS (4 checks)
- **RDS-001**: Public access - Finds publicly accessible DBs
- **RDS-002**: Encryption - Verifies storage encryption
- **RDS-003**: Backups - Checks backup retention
- **RDS-004**: Deletion protection - Verifies protection enabled

### Logging & Monitoring (8 checks)
- **LOG-001**: CloudTrail - Verifies trail exists
- **LOG-002**: Multi-region - Checks trail scope
- **LOG-003**: Log validation - Verifies integrity
- **LOG-004**: KMS encryption - Checks trail encryption
- **LOG-005**: GuardDuty - Verifies threat detection
- **LOG-006**: AWS Config - Checks configuration recording
- **LOG-007**: Security Hub - Verifies centralized findings
- **LOG-008**: Access Analyzer - Checks external access analysis

### CloudWatch (3 checks)
- **CW-001**: Log retention - Identifies log groups without retention policies
- **CW-002**: CloudTrail integration - Verifies CloudTrail sends to CloudWatch Logs
- **CW-003**: CIS alarms - Checks for essential CIS security alarms

### Other Checks
- **KMS-001**: Key rotation - Verifies automatic rotation
- **SEC-001**: Secret rotation - Checks Secrets Manager rotation
- **ECR-001**: Image scanning - Verifies scan on push
- **LAM-001**: Runtime versions - Flags deprecated runtimes
- **INS-001**: Inspector - Verifies vulnerability scanning enabled
- **BAK-001**: Backup plans - Checks AWS Backup configuration
- **ACM-001**: Certificate expiry - Flags certs expiring within 30 days
- **EC2-010**: EBS default encryption - Verifies default encryption enabled
- **SSM-001**: Document sharing - Checks for publicly shared documents

## Next Steps

1. **Review** the generated report
2. **Share** at [scamshield.app/audit](https://scamshield.app/audit)
3. **Get** your personalized remediation plan

## Security & Privacy

- ✅ **Runs locally** - Your credentials never leave your machine
- ✅ **Read-only** - No modifications to your AWS environment
- ✅ **Transparent** - Full source code available for review
- ✅ **Auto-redacts** - Sensitive data removed from output

## Changelog

### v1.2.0
- Added 7 new check categories from real-world security audits
- Added CloudWatch log retention check (CW-001)
- Added CloudTrail to CloudWatch Logs integration check (CW-002)
- Added CIS CloudWatch alarms check (CW-003)
- Added Amazon Inspector vulnerability scanning check (INS-001)
- Added AWS Backup plans check (BAK-001)
- Added ACM certificate expiration check (ACM-001)
- Added EBS default encryption check (EC2-010)
- Added SSM document public sharing check (SSM-001)
- Total checks now: 45+

### v1.1.1
- Added `--profile` flag for AWS SSO and named profile support
- Improved credential error messages with specific troubleshooting guidance
- Better handling of expired tokens and invalid credentials

### v1.1.0
- Added 12+ new security checks
- Added compliance framework mapping (ISO 27001, SOC 2, CIS, CCSS)
- Added Secrets Manager rotation check
- Added ECR image scanning check
- Added Lambda runtime check
- Added VPC Flow Logs check
- Added EBS snapshot block public access check
- Added default security group rules check
- Added S3 SSL/TLS enforcement check
- Added IAM Access Analyzer check
- Added root access keys check
- Added AWS Support role check
- Improved password policy analysis
- Added `--verbose` flag

### v1.0.0
- Initial release with 33 security checks

## License

MIT License - See [LICENSE](LICENSE) for details.

## Support

- 📧 Email: security@starlingsdata.com
- 🌐 Web: [starlingsdata.com](https://starlingsdata.com)
- 💬 Issues: [GitHub Issues](https://github.com/Starlings-Data/aws-scanner/issues)
