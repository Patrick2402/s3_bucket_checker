# AWS S3 Security Audit Tool

A comprehensive Python utility designed to analyze Amazon S3 buckets for security best practices, vulnerabilities, and compliance with AWS security recommendations.

## Overview

The AWS S3 Security Audit Tool performs a thorough analysis of all S3 buckets in your AWS account, evaluating multiple security aspects and providing detailed, actionable recommendations to improve your cloud storage security posture.

## Key Features

- **Comprehensive Security Analysis**:
  - Public access settings and block configurations
  - Bucket ACL permissions assessment
  - Encryption configuration (SSE, KMS)
  - Versioning status
  - Access logging setup
  - Bucket policy analysis with deep security validation
  - Lifecycle configuration review
  - CORS settings examination
  - Object Lock configuration
  - Empty bucket detection

- **Enhanced Policy Analysis**:
  - Detection of overly permissive actions (`s3:*`, `*`)
  - Identification of dangerous actions (bucket deletion, policy modification)
  - Wildcard principal detection
  - Secure transport (HTTPS) requirement check
  - Encryption requirement validation
  - IP restriction evaluation

- **Rich Output Options**:
  - Color-coded terminal output for quick review
  - Detailed text report export
  - Comprehensive JSON format for integration with other tools
  - Visual security scoring system (0-100)

- **Actionable Recommendations**:
  - Specific, prioritized security recommendations for each bucket
  - Detailed explanation of security issues
  - Best practices guidance

## Requirements

- Python 3.13+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  ```
  pip install boto3 tabulate colorama
  ```

## Permissions Required

The tool requires an AWS IAM user/role with the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketLifecycleConfiguration",
                "s3:GetBucketCORS",
                "s3:GetObjectLockConfiguration",
                "s3:ListBucket"
            ],
            "Resource": "*"
        }
    ]
}

## Installation

1. Clone or download this repository:
   ```
   git clone https://github.com/Patrick2402/s3_bucket_checker.git
   cd aws-s3-security-audit
   ```

2. Install the required dependencies:
   ```
   pip install boto3 tabulate colorama
   ```

## Usage

```bash
# Basic usage
python s3_security_audit.py

# Verbose output (shows detailed analysis progress)
python s3_security_audit.py --verbose
```

## Security Scoring System

Each bucket receives a security score (0-100) based on:

| Security Aspect | Maximum Points |
|-----------------|----------------|
| Public access controls | 20 points |
| Encryption | 15 points |
| Versioning | 10 points |
| Access logging | 10 points |
| Bucket policy | 15 points |
| Lifecycle configuration | 10 points |
| CORS configuration | 10 points |
| Object Lock | 10 points |
| ACL configuration | 5 points |
| Empty status | 5 points |

## Output Examples

### Terminal Output
The tool provides color-coded output in the terminal:
- Critical issues in red
- Warnings in yellow
- Secure configurations in green
- Informational data in cyan

### Report Files
The script automatically generates two report files:
- Text report: `s3_security_audit_[timestamp].txt`
- JSON report: `s3_security_audit_[timestamp].json`

## Example Output

The terminal report includes:
1. **Security Summary** - A tabular overview of all buckets with security scores
2. **Critical Buckets** - Detailed analysis of buckets with low security scores
3. **Overall Statistics** - Summary statistics of security findings
4. **Common Security Issues** - Most frequent security issues detected

## Best Practices

The tool checks for alignment with AWS security best practices including:
- Blocking all public access
- Using server-side encryption
- Enabling versioning
- Configuring access logging
- Implementing secure bucket policies
- Setting up lifecycle management
- Restricting CORS configurations
- Enabling Object Lock for sensitive data
- Removing empty buckets when not needed
- Avoiding wildcard principals in policies
- Enforcing HTTPS (secure transport)

## Use Cases

- Security audits and assessments
- Compliance verification
- DevSecOps pipeline integration
- Pre-deployment security validation
- Regular security posture monitoring

## License

This tool is provided for educational and professional security assessment purposes only.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is meant for legitimate security assessment purposes only. Always ensure you have proper authorization before scanning AWS resources.