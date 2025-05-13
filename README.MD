# AWS S3 Security Audit Tool

A simple Python script to analyze S3 buckets for security best practices and generate comprehensive reports.

## Features

- Analyzes all S3 buckets in your AWS account
- Generates color-coded terminal output
- Exports reports to TXT and JSON formats
- Checks:
  - Public access settings
  - Encryption
  - Versioning
  - Access logging
  - Bucket policies
  - Lifecycle configurations
  - CORS settings
  - Object Lock

## Requirements

- Python 3.13+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  ```
  pip install boto3 tabulate colorama
  ```

## Usage

```bash
# Basic usage
python s3_security_audit.py

# Verbose output
python s3_security_audit.py --verbose
```

## Example Output

The script generates three outputs:
1. Colorized terminal report
2. Plain text report (s3_security_audit_[timestamp].txt)
3. JSON report (s3_security_audit_[timestamp].json)

## Security Score

Each bucket receives a security score (0-100) based on:
- Public access controls (20 points)
- Encryption (15 points)
- Versioning (10 points)
- Access logging (10 points)
- Bucket policy (15 points)
- Lifecycle configuration (10 points)
- CORS configuration (10 points)
- Object Lock (10 points)

## License

For educational and professional security assessment purposes only.