# Starlings AWS Security Scanner

A lightweight, transparent security scanner that runs **locally in your environment**. Your AWS credentials never leave your machine.

## Quick Start

```bash
# Download the scanner
curl -sL https://raw.githubusercontent.com/Starlings-Data/aws-scanner/main/starlings-aws-scan.sh -o starlings-aws-scan.sh

# Make it executable
chmod +x starlings-aws-scan.sh

# Run the scan
./starlings-aws-scan.sh
```

## Requirements

- **AWS CLI** installed and configured (`aws configure`)
- **Bash** (macOS, Linux, or WSL on Windows)
- **jq** (optional, for prettier output)

## Usage

```bash
# Scan default region (from AWS CLI config)
./starlings-aws-scan.sh

# Scan specific region
./starlings-aws-scan.sh --region us-west-2

# Custom output file
./starlings-aws-scan.sh --output my-report.json

# Show help
./starlings-aws-scan.sh --help
```

## What It Checks

The scanner runs **33 read-only checks** across 6 security domains:

| Domain | Checks | Examples |
|--------|--------|----------|
| IAM & Access | 7 | Root MFA, password policy, user MFA, access key age |
| S3 Security | 5 | Public buckets, encryption, versioning, logging |
| EC2 & Network | 7 | Open SSH/RDP, security groups, EBS encryption, IMDSv2 |
| RDS & Database | 5 | Public access, encryption, backup retention |
| Logging | 7 | CloudTrail, GuardDuty, AWS Config, Security Hub |
| KMS | 2 | Key rotation |

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
  "scanner_version": "1.0.0",
  "scan_date": "2025-01-15T10:30:00Z",
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
    "passed": 22,
    "total_checks": 33
  },
  "findings": [
    {
      "domain": "iam",
      "check_id": "IAM-001",
      "severity": "critical",
      "title": "Root account MFA not enabled",
      "description": "...",
      "resources": [],
      "remediation": "..."
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

## Next Steps

1. **Review** the generated report
2. **Share** at [scamshield.app/audit](https://scamshield.app/audit)
3. **Get** your personalized remediation plan

## Security & Privacy

- ✅ **Runs locally** - Your credentials never leave your machine
- ✅ **Read-only** - No modifications to your AWS environment
- ✅ **Transparent** - Full source code available for review
- ✅ **Auto-redacts** - Sensitive data removed from output

## License

MIT License - See [LICENSE](LICENSE) for details.

## Support

- 📧 Email: security@starlingsdata.com
- 🌐 Web: [starlingsdata.com](https://starlingsdata.com)
- 💬 Issues: [GitHub Issues](https://github.com/Starlings-Data/aws-scanner/issues)
