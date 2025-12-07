# Git-Captain Boto3 Automation Scripts

Python scripts for managing AWS resources using Boto3 SDK.

## Installation

```bash
cd boto3-scripts
pip install -r requirements.txt
```

## Prerequisites

- Python 3.9+
- AWS CLI configured with credentials
- boto3, tabulate packages

## Scripts Overview

| Script | Purpose | Usage |
|--------|---------|-------|
| `setup_secrets.py` | Manage AWS Secrets Manager | Store `.env` variables securely |
| `s3_manager.py` | S3 bucket operations | Create buckets, upload files |
| `ec2_operations.py` | EC2 instance management | List, start, stop instances |
| `lambda_test.py` | Lambda testing | Test S3 logger, check logs |

---

## 1. setup_secrets.py

**Purpose**: Reads `.env` file and stores variables in AWS Secrets Manager.

### Usage

```bash
# Basic usage (reads ../env)
python3 setup_secrets.py

# Script will:
# 1. Read all variables from .env
# 2. Create/update secret 'git-captain/prod'
# 3. Store in us-east-2 region
# 4. Verify storage
```

### Example Output

```
============================================================
Git-Captain AWS Secrets Manager Setup
============================================================

[1/3] Reading environment variables from ../.env...
✓ Found 15 environment variables

Environment variables to store:
  - client_id
  - client_secret
  - GITHUB_ORG_NAME
  - GIT_PORT_ENDPOINT
  ... (11 more)

[2/3] Storing secrets in AWS Secrets Manager...
Secret name: git-captain/prod
Region: us-east-2
✓ Secret 'git-captain/prod' created successfully!

[3/3] Verifying secret...
✓ Verified 15 keys in secret

============================================================
✓ AWS Secrets Manager setup complete!
============================================================

Secret ARN: arn:aws:secretsmanager:us-east-2:123456789012:secret:git-captain/prod-AbCdEf

Your EC2 instances can now retrieve secrets using:
  aws secretsmanager get-secret-value --secret-id git-captain/prod --region us-east-2
```

### Environment Variables

Can be customized via environment:
- `AWS_REGION`: AWS region (default: us-east-2)

---

## 2. s3_manager.py

**Purpose**: Create S3 buckets, upload files, configure lifecycle policies.

### Usage

```bash
# Run with defaults
python3 s3_manager.py

# Creates these buckets:
# - git-captain-static-assets (for CSS/JS/images)
# - git-captain-logs-bucket (for application logs)
# - git-captain-ssl-certs (for SSL certificates)

# Uploads ../public/ directory to static assets bucket
```

### Example Output

```
============================================================
Git-Captain S3 Bucket Management
============================================================

[1/4] Creating S3 buckets...

STATIC-ASSETS Bucket:
Creating S3 bucket: git-captain-static-assets...
✓ Bucket 'git-captain-static-assets' created successfully!

LOGS Bucket:
Creating S3 bucket: git-captain-logs-bucket...
✓ Bucket 'git-captain-logs-bucket' created successfully!

SSL-CERTS Bucket:
Creating S3 bucket: git-captain-ssl-certs...
✓ Bucket 'git-captain-ssl-certs' created successfully!

[2/4] Configuring lifecycle policies...
✓ Lifecycle policy configured for 'git-captain-logs-bucket'

[3/4] Uploading static assets...
Uploading files from '../public' to s3://git-captain-static-assets/public

  ✓ Uploaded: public/css/styles.css (text/css)
  ✓ Uploaded: public/js/tools.js (application/javascript)
  ✓ Uploaded: public/js/branchUtils.js (application/javascript)
  ✓ Uploaded: public/js/viewUtils.js (application/javascript)
  ✓ Uploaded: public/js/jquery-3.3.1.min.js (application/javascript)
  ✓ Uploaded: public/images/titaniccaptainMedium.png (image/png)
  ... (more files)

✓ Uploaded 15 files

[4/4] Verifying uploads...

Contents of s3://git-captain-static-assets/:
  - public/css/styles.css (0.05 MB)
  - public/js/tools.js (0.02 MB)
  ... (more)

============================================================
✓ S3 Bucket Management Complete!
============================================================

Bucket URLs:
  static-assets: s3://git-captain-static-assets
  logs: s3://git-captain-logs-bucket
  ssl-certs: s3://git-captain-ssl-certs
```

### Functions

- `create_s3_bucket(bucket_name, region)`: Creates bucket with encryption and versioning
- `upload_directory_to_s3(local_dir, bucket, prefix)`: Recursive directory upload
- `set_lifecycle_policy(bucket_name)`: Configure log expiration
- `list_bucket_contents(bucket_name, prefix)`: List objects

---

## 3. ec2_operations.py

**Purpose**: Manage EC2 instances, Auto Scaling Groups, and key pairs.

### Usage

```bash
# List all instances
python3 ec2_operations.py --list

# List instances with filter
python3 ec2_operations.py --list --filter Project=git-captain

# Get instance metadata
python3 ec2_operations.py --metadata i-0123456789abcdef0

# Start instance
python3 ec2_operations.py --start i-0123456789abcdef0

# Stop instance
python3 ec2_operations.py --stop i-0123456789abcdef0

# Create key pair
python3 ec2_operations.py --create-key git-captain-key

# Get Auto Scaling Group info
python3 ec2_operations.py --asg git-captain-prod-asg

# Use different region
python3 ec2_operations.py --list --region us-west-2
```

### Example: List Instances

```bash
python3 ec2_operations.py --list --filter Project=git-captain
```

**Output:**
```
============================================================
Git-Captain EC2 Operations
============================================================

┌──────────────────────┬────────────────────────┬────────────┬──────────┬──────────────┬───────────────┬─────────────────────┐
│ Instance ID          │ Name                   │ Type       │ State    │ Private IP   │ Public IP     │ Launch Time         │
├──────────────────────┼────────────────────────┼────────────┼──────────┼──────────────┼───────────────┼─────────────────────┤
│ i-0123456789abcdef0  │ git-captain-prod-inst1 │ t3.micro   │ running  │ 10.0.10.45   │ N/A           │ 2025-11-15 10:30:22 │
│ i-0123456789abcdef1  │ git-captain-prod-inst2 │ t3.micro   │ running  │ 10.0.11.67   │ N/A           │ 2025-11-15 10:30:45 │
└──────────────────────┴────────────────────────┴────────────┴──────────┴──────────────┴───────────────┴─────────────────────┘

Total instances: 2
```

### Example: Get Instance Metadata

```bash
python3 ec2_operations.py --metadata i-0123456789abcdef0
```

**Output:**
```
============================================================
Instance Metadata: i-0123456789abcdef0
============================================================

Basic Information:
  Instance ID:     i-0123456789abcdef0
  Instance Type:   t3.micro
  State:           running
  AMI ID:          ami-0c02fb55b21a60ed4
  Launch Time:     2025-11-15 10:30:22.000000+00:00

Network Information:
  Private IP:      10.0.10.45
  Public IP:       N/A
  VPC ID:          vpc-0123456789abcdef0
  Subnet ID:       subnet-0123456789abcdef0

Security Groups:
  - git-captain-prod-ec2-sg (sg-0123456789abcdef1)

Tags:
  Name: git-captain-prod-instance
  Project: git-captain
  Environment: prod
```

### Example: Auto Scaling Group Info

```bash
python3 ec2_operations.py --asg git-captain-prod-asg
```

**Output:**
```
============================================================
Auto Scaling Group: git-captain-prod-asg
============================================================

Capacity:
  Min Size:        2
  Max Size:        6
  Desired:         2
  Current:         2

Instances:
  - i-0123456789abcdef0: InService (Healthy)
  - i-0123456789abcdef1: InService (Healthy)
```

---

## 4. lambda_test.py

**Purpose**: Test Lambda functions and check CloudWatch logs.

### Usage

```bash
# Test S3 upload logger with simulated event
python3 lambda_test.py --test-s3-logger

# Upload real test file to S3 (triggers Lambda)
python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket

# Check CloudWatch logs for S3 uploads
python3 lambda_test.py --check-logs

# Get Lambda function logs
python3 lambda_test.py --lambda-logs git-captain-prod-s3-upload-logger

# Custom bucket and key
python3 lambda_test.py --upload-test --bucket my-bucket --key test/file.txt
```

### Example: Test S3 Logger

```bash
python3 lambda_test.py --test-s3-logger --bucket git-captain-logs-bucket --key test/upload.txt
```

**Output:**
```
============================================================
Testing S3 Upload Logger Lambda
============================================================

Simulating S3 upload event:
  Bucket: git-captain-logs-bucket
  Object: test/upload.txt
  Function: git-captain-prod-s3-upload-logger

Invoking Lambda function: git-captain-prod-s3-upload-logger
Payload: {
  "Records": [
    {
      "eventVersion": "2.1",
      "eventSource": "aws:s3",
      "awsRegion": "us-east-2",
      "eventTime": "2025-11-15T12:34:56Z",
      "eventName": "s3:ObjectCreated:Put",
      "s3": {
        "bucket": {"name": "git-captain-logs-bucket"},
        "object": {"key": "test/upload.txt", "size": 1024}
      }
    }
  ]
}

✓ Lambda invoked successfully!
  Status Code: 200
  Response:
{
  "statusCode": 200,
  "body": "\"Processed 1 S3 upload events\""
}
```

### Example: Upload Test File

```bash
python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket
```

**Output:**
```
============================================================
Git-Captain Lambda Testing
============================================================

Uploading test file to s3://git-captain-logs-bucket/test/test-upload.txt...
✓ Test file uploaded successfully!

This should trigger the Lambda function.
Wait a few seconds, then check CloudWatch Logs:
  Log Group: /aws/s3-uploads/git-captain
```

### Example: Check CloudWatch Logs

```bash
python3 lambda_test.py --check-logs
```

**Output:**
```
Recent S3 upload logs:
============================================================

Timestamp: 2025-11-15T12:35:02Z
  Bucket:   git-captain-logs-bucket
  Key:      test/test-upload.txt
  Size:     0.00 MB
  Type:     text/plain

Timestamp: 2025-11-15T12:30:15Z
  Bucket:   git-captain-logs-bucket
  Key:      logs/application-2025-11-15.log
  Size:     1.23 MB
  Type:     text/plain

============================================================
```

---

## Common Workflows

### Initial Setup (First Deployment)

```bash
# 1. Setup secrets
python3 setup_secrets.py

# 2. Create S3 buckets and upload static assets
python3 s3_manager.py

# 3. Upload SSL certificates to S3
aws s3 cp ../controllers/theKey.key s3://git-captain-ssl-certs/
aws s3 cp ../controllers/theCert.cert s3://git-captain-ssl-certs/

# 4. Create EC2 key pair
python3 ec2_operations.py --create-key git-captain-key
```

### Daily Operations

```bash
# Check running instances
python3 ec2_operations.py --list --filter Project=git-captain

# Check Auto Scaling Group
python3 ec2_operations.py --asg git-captain-prod-asg

# Test Lambda logging
python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket
python3 lambda_test.py --check-logs
```

### Troubleshooting

```bash
# Get detailed instance info
python3 ec2_operations.py --metadata i-0123456789abcdef0

# Check Lambda logs
python3 lambda_test.py --lambda-logs git-captain-prod-s3-upload-logger

# Verify S3 uploads
aws s3 ls s3://git-captain-static-assets/public/ --recursive
```

---

## Error Handling

All scripts include comprehensive error handling:
- ✅ AWS credentials validation
- ✅ Resource existence checks
- ✅ Clear error messages
- ✅ Graceful failures
- ✅ Rollback on errors (where applicable)

### Common Errors

**Error**: `NoCredentialsError`
```
Solution: Run `aws configure` to set up AWS credentials
```

**Error**: `AccessDenied`
```
Solution: Check IAM user permissions
Required policies:
- SecretsManagerFullAccess
- AmazonS3FullAccess
- AmazonEC2FullAccess
- AWSLambdaFullAccess
- CloudWatchFullAccess
```

**Error**: `ResourceNotFoundException`
```
Solution: Ensure infrastructure is deployed with Terraform/CloudFormation first
```

---

## Advanced Configuration

### Custom Region

Set via environment variable:
```bash
export AWS_REGION=us-west-2
python3 setup_secrets.py
```

Or use command-line flag:
```bash
python3 ec2_operations.py --list --region us-west-2
```

### Custom Secret Name

Edit `setup_secrets.py`:
```python
secret_name = 'my-app/prod'  # Line 92
```

### Custom Bucket Names

Edit `s3_manager.py`:
```python
buckets = {
    'static-assets': 'my-static-bucket',
    'logs': 'my-logs-bucket',
    'ssl-certs': 'my-ssl-bucket'
}
```

---

## Security Best Practices

1. **Never commit secrets**: `.env` and `.pem` files are in `.gitignore`
2. **Use IAM roles**: EC2 instances use IAM roles, not access keys
3. **Encrypt S3 buckets**: All buckets use AES-256 encryption
4. **Restrict access**: Security groups limit network access
5. **Rotate credentials**: Regularly rotate AWS access keys and passwords
6. **Enable MFA**: Use MFA for AWS console access
7. **Audit logs**: Review CloudTrail logs regularly

---

## Testing

### Unit Tests (Future Enhancement)

```bash
# Run tests
pytest tests/

# Coverage
pytest --cov=. tests/
```

### Integration Tests

```bash
# Test full workflow
./test_workflow.sh

# Steps:
# 1. Setup secrets
# 2. Create buckets
# 3. Upload files
# 4. List instances
# 5. Test Lambda
# 6. Cleanup
```

---

## Contributing

When adding new scripts:
1. Follow existing code structure
2. Add comprehensive error handling
3. Include docstrings
4. Update this README
5. Add example usage
6. Test in isolated environment

---

## Support

- **Issues**: Open GitHub issue
- **Questions**: Contact joe@example.com
- **Documentation**: See [../docs/aws/](../docs/aws/)

---

**Last Updated**: November 15, 2025
**Python Version**: 3.9+
**Boto3 Version**: 1.34+
