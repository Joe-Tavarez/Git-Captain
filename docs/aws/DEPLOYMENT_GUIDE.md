# Git-Captain AWS Deployment Guide

Complete step-by-step guide to deploy Git-Captain on AWS using Terraform and CloudFormation.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [AWS Account Setup](#aws-account-setup)
3. [Local Environment Setup](#local-environment-setup)
4. [Deploy Networking with Terraform](#deploy-networking-with-terraform)
5. [Deploy Application with CloudFormation](#deploy-application-with-cloudformation)
6. [Configure GitHub OAuth](#configure-github-oauth)
7. [Deploy Application Code](#deploy-application-code)
8. [Verify Deployment](#verify-deployment)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools
- **AWS CLI** v2.x: [Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **Terraform** v1.5+: [Installation Guide](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
- **Python** 3.9+: [Download](https://www.python.org/downloads/)
- **Git**: [Download](https://git-scm.com/downloads)
- **Node.js** 18+: [Download](https://nodejs.org/)

### Required Knowledge
- Basic AWS concepts (VPC, EC2, S3, IAM)
- Command line / terminal usage
- Git basics

### Estimated Time
- **First-time deployment**: 45-60 minutes
- **Subsequent deployments**: 15-20 minutes

---

## AWS Account Setup

### Step 1: Create AWS Account
1. Go to https://aws.amazon.com
2. Click "Create an AWS Account"
3. Follow the registration process
4. Verify your email and phone number
5. Add a payment method

### Step 2: Create IAM User for Deployment
```bash
# Login to AWS Console
# Navigate to IAM → Users → Create User

# User Details
User name: git-captain-deployer
Access type: Programmatic access (for CLI/API)

# Attach Policies (or create custom policy)
- AdministratorAccess (for testing)
# OR for production, attach custom policy with minimum permissions:
- AmazonEC2FullAccess
- AmazonVPCFullAccess
- AmazonS3FullAccess
- AmazonRDSFullAccess
- AWSLambdaFullAccess
- CloudFormationFullAccess
- IAMFullAccess
- SecretsManagerFullAccess
- CloudWatchFullAccess
```

### Step 3: Configure AWS CLI
```bash
# Configure AWS credentials
aws configure

# Enter the following:
AWS Access Key ID: <from IAM user>
AWS Secret Access Key: <from IAM user>
Default region name: us-east-2
Default output format: json

# Verify configuration
aws sts get-caller-identity
```

**Expected Output:**
```json
{
    "UserId": "AIDAI...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/git-captain-deployer"
}
```

### Step 4: Create S3 Bucket for Terraform State (Optional but Recommended)
```bash
# Create bucket
aws s3 mb s3://git-captain-terraform-state --region us-east-2

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket git-captain-terraform-state \
    --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
    --bucket git-captain-terraform-state \
    --server-side-encryption-configuration '{
      "Rules": [{
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }]
    }'
```

---

## Local Environment Setup

### Step 1: Clone Repository
```bash
git clone https://github.com/Joe-Tavarez/Git-Captain.git
cd Git-Captain
```

### Step 2: Install Node.js Dependencies
```bash
npm install
```

### Step 3: Install Python Dependencies for Boto3 Scripts
```bash
cd boto3-scripts
pip install -r requirements.txt
cd ..
```

### Step 4: Create and Configure .env File
```bash
# Copy example
cp .env.example .env

# Edit .env with your values
nano .env
```

**Required .env Variables:**
```bash
# GitHub OAuth (get from https://github.com/settings/developers)
client_id=your_github_oauth_client_id
client_secret=your_github_oauth_client_secret
GITHUB_ORG_NAME=your_github_username_or_org

# Server Configuration
GIT_PORT_ENDPOINT=https://your-domain.com
PORT=3000

# SSL Certificate Paths (will be stored in S3)
privateKeyPath=./controllers/theKey.key
certificatePath=./controllers/theCert.cert

# Optional Settings
NODE_ENV=production
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX=600
```

### Step 5: Generate or Upload SSL Certificates
```bash
# Option 1: Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout controllers/theKey.key -out controllers/theCert.cert -days 365 -nodes

# Option 2: Use existing certificate
# Copy your .key and .cert files to controllers/ directory

# Note: For production, use AWS Certificate Manager (ACM) instead
```

---

## Deploy Networking with Terraform

### Step 1: Review Terraform Configuration
```bash
cd terraform

# Review variables
cat variables.tf

# Customize if needed
nano variables.tf
# Change aws_region, vpc_cidr, allowed_ssh_cidr, etc.
```

### Step 2: Initialize Terraform
```bash
terraform init

# If using S3 backend (recommended), uncomment backend config in main.tf and run:
# terraform init -backend-config="bucket=git-captain-terraform-state"
```

**Expected Output:**
```
Terraform has been successfully initialized!
```

### Step 3: Plan Infrastructure
```bash
terraform plan

# Save plan to file
terraform plan -out=tfplan
```

**Review the plan output carefully:**
- VPC creation
- 2 public subnets
- 2 private subnets
- Internet Gateway
- NAT Gateway
- Route tables
- 4 security groups
- SSM parameters

### Step 4: Apply Infrastructure
```bash
terraform apply tfplan

# Or without saved plan:
# terraform apply
```

**Expected Output:**
```
Apply complete! Resources: 25 added, 0 changed, 0 destroyed.

Outputs:

alb_security_group_id = "sg-0123456789abcdef0"
ec2_security_group_id = "sg-0123456789abcdef1"
nat_gateway_eip = "3.149.116.57"
nat_gateway_id = "nat-0123456789abcdef0"
private_subnet_ids = [
  "subnet-0123456789abcdef0",
  "subnet-0123456789abcdef1",
]
public_subnet_ids = [
  "subnet-0123456789abcdef2",
  "subnet-0123456789abcdef3",
]
rds_security_group_id = "sg-0123456789abcdef2"
vpc_id = "vpc-0123456789abcdef0"
```

**Save these outputs - they're stored in SSM Parameter Store.**

### Step 5: Verify Terraform Deployment
```bash
# Check VPC
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=git-captain-prod-vpc"

# Check subnets
aws ec2 describe-subnets --filters "Name=tag:Project,Values=git-captain"

# Check NAT Gateway
aws ec2 describe-nat-gateways --filter "Name=tag:Name,Values=git-captain-prod-nat-gateway"

# Verify SSM parameters
aws ssm get-parameter --name /git-captain/infrastructure/vpc-id
```

---

## Deploy Application with CloudFormation

### Step 1: Upload Secrets to AWS Secrets Manager
```bash
cd ../boto3-scripts

# Run setup script (reads .env and creates secret)
python3 setup_secrets.py
```

**Expected Output:**
```
============================================================
Git-Captain AWS Secrets Manager Setup
============================================================

[1/3] Reading environment variables from ../.env...
✓ Found 15 environment variables

[2/3] Storing secrets in AWS Secrets Manager...
Secret name: git-captain/prod
Region: us-east-2
✓ Secret 'git-captain/prod' created successfully!

[3/3] Verifying secret...
✓ Verified 15 keys in secret

============================================================
✓ AWS Secrets Manager setup complete!
============================================================
```

### Step 2: Create and Upload S3 Buckets
```bash
# Run S3 manager script
python3 s3_manager.py
```

**Expected Output:**
```
============================================================
Git-Captain S3 Bucket Management
============================================================

[1/4] Creating S3 buckets...
✓ Bucket 'git-captain-static-assets' created successfully!
✓ Bucket 'git-captain-logs-bucket' created successfully!
✓ Bucket 'git-captain-ssl-certs' created successfully!

[2/4] Configuring lifecycle policies...
✓ Lifecycle policy configured for 'git-captain-logs-bucket'

[3/4] Uploading static assets...
  ✓ Uploaded: public/css/styles.css (text/css)
  ✓ Uploaded: public/js/tools.js (application/javascript)
  ... (more files)
✓ Uploaded 15 files

[4/4] Verifying uploads...
```

### Step 3: Upload SSL Certificates to S3
```bash
# Upload SSL certificates to S3
aws s3 cp ../controllers/theKey.key s3://git-captain-ssl-certs/theKey.key
aws s3 cp ../controllers/theCert.cert s3://git-captain-ssl-certs/theCert.cert

# Verify
aws s3 ls s3://git-captain-ssl-certs/
```

### Step 4: Deploy RDS Stack
```bash
cd ../cloudformation

# Set database credentials (replace with strong passwords)
export DB_USERNAME="dbadmin"
export DB_PASSWORD="YourStrongPassword123!"

# Deploy RDS stack
aws cloudformation create-stack \
    --stack-name git-captain-rds \
    --template-body file://rds.yaml \
    --parameters \
        ParameterKey=DBUsername,ParameterValue=$DB_USERNAME \
        ParameterKey=DBPassword,ParameterValue=$DB_PASSWORD \
    --capabilities CAPABILITY_NAMED_IAM \
    --region us-east-2

# Wait for stack creation (5-10 minutes)
aws cloudformation wait stack-create-complete --stack-name git-captain-rds --region us-east-2
```

**Monitor Progress:**
```bash
# Check stack status
aws cloudformation describe-stacks --stack-name git-captain-rds --query 'Stacks[0].StackStatus'

# View events
aws cloudformation describe-stack-events --stack-name git-captain-rds --max-items 10
```

### Step 5: Deploy Lambda and S3 Stack
```bash
# Deploy Lambda stack
aws cloudformation create-stack \
    --stack-name git-captain-lambda \
    --template-body file://lambda-s3-logging.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --region us-east-2

# Wait for completion (2-3 minutes)
aws cloudformation wait stack-create-complete --stack-name git-captain-lambda --region us-east-2
```

### Step 6: Create EC2 Key Pair (for SSH access)
```bash
# Create key pair
aws ec2 create-key-pair \
    --key-name git-captain-key \
    --query 'KeyMaterial' \
    --output text \
    --region us-east-2 > git-captain-key.pem

# Set permissions
chmod 400 git-captain-key.pem

# Save this file securely!
```

### Step 7: Request ACM Certificate (Optional but Recommended)
```bash
# If you have a domain, request a certificate
aws acm request-certificate \
    --domain-name your-domain.com \
    --validation-method DNS \
    --region us-east-2

# Note the CertificateArn from output
# Complete DNS validation in your DNS provider

# Wait for validation
aws acm wait certificate-validated \
    --certificate-arn arn:aws:acm:us-east-2:123456789012:certificate/xxxxx \
    --region us-east-2
```

### Step 8: Deploy EC2 and Auto Scaling Stack
```bash
# Set ACM certificate ARN (if using custom domain)
export ACM_CERT_ARN="arn:aws:acm:us-east-2:123456789012:certificate/xxxxx"

# Deploy EC2 stack
aws cloudformation create-stack \
    --stack-name git-captain-ec2-asg \
    --template-body file://ec2-alb-autoscaling.yaml \
    --parameters \
        ParameterKey=KeyName,ParameterValue=git-captain-key \
        ParameterKey=ACMCertificateArn,ParameterValue=$ACM_CERT_ARN \
    --capabilities CAPABILITY_NAMED_IAM \
    --region us-east-2

# Wait for completion (10-15 minutes)
aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-asg --region us-east-2
```

**This stack creates:**
- IAM role for EC2 instances
- Launch template with user data script
- Auto Scaling Group (2-6 instances)
- Application Load Balancer
- Target Group
- HTTPS and HTTP listeners

### Step 9: Get ALB DNS Name
```bash
# Get ALB DNS
aws cloudformation describe-stacks \
    --stack-name git-captain-ec2-asg \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
    --output text \
    --region us-east-2
```

**Output Example:**
```
git-captain-prod-alb-1234567890.us-east-2.elb.amazonaws.com
```

**Save this DNS name!**

### Step 10: Deploy Monitoring Stack
```bash
# Get ALB and ASG details
export ALB_NAME=$(aws cloudformation describe-stacks \
    --stack-name git-captain-ec2-asg \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerArn`].OutputValue' \
    --output text | cut -d'/' -f2-4)

export TG_NAME=$(aws cloudformation describe-stacks \
    --stack-name git-captain-ec2-asg \
    --query 'Stacks[0].Outputs[?OutputKey==`TargetGroupArn`].OutputValue' \
    --output text | cut -d':' -f6)

export ASG_NAME=$(aws cloudformation describe-stacks \
    --stack-name git-captain-ec2-asg \
    --query 'Stacks[0].Outputs[?OutputKey==`AutoScalingGroupName`].OutputValue' \
    --output text)

# Deploy monitoring stack
aws cloudformation create-stack \
    --stack-name git-captain-monitoring \
    --template-body file://cloudwatch-monitoring.yaml \
    --parameters \
        ParameterKey=EmailAddress,ParameterValue=your-email@example.com \
        ParameterKey=LoadBalancerFullName,ParameterValue=$ALB_NAME \
        ParameterKey=TargetGroupFullName,ParameterValue=$TG_NAME \
        ParameterKey=AutoScalingGroupName,ParameterValue=$ASG_NAME \
    --capabilities CAPABILITY_IAM \
    --region us-east-2

# Wait for completion
aws cloudformation wait stack-create-complete --stack-name git-captain-monitoring --region us-east-2
```

**Note**: Check your email and confirm SNS subscription!

### Step 11: Deploy WAF Stack
```bash
# Get ALB ARN
export ALB_ARN=$(aws cloudformation describe-stacks \
    --stack-name git-captain-ec2-asg \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerArn`].OutputValue' \
    --output text)

# Deploy WAF stack
aws cloudformation create-stack \
    --stack-name git-captain-waf \
    --template-body file://waf.yaml \
    --parameters \
        ParameterKey=LoadBalancerArn,ParameterValue=$ALB_ARN \
    --capabilities CAPABILITY_IAM \
    --region us-east-2

# Wait for completion
aws cloudformation wait stack-create-complete --stack-name git-captain-waf --region us-east-2
```

---

## Configure GitHub OAuth

### Step 1: Create GitHub OAuth App
1. Go to https://github.com/settings/developers
2. Click "OAuth Apps" → "New OAuth App"
3. Fill in details:
   - **Application name**: Git-Captain
   - **Homepage URL**: `https://YOUR_ALB_DNS` (from Step 9)
   - **Authorization callback URL**: `https://YOUR_ALB_DNS/authenticated.html`
4. Click "Register application"
5. Note the **Client ID** and **Client Secret**

### Step 2: Update Secrets Manager with GitHub OAuth
```bash
# Update .env file with GitHub credentials
nano ../.env
# Add:
# client_id=your_github_client_id
# client_secret=your_github_client_secret

# Update Secrets Manager
cd ../boto3-scripts
python3 setup_secrets.py
```

### Step 3: Restart EC2 Instances to Pick Up New Secrets
```bash
# Trigger Auto Scaling Group instance refresh
aws autoscaling start-instance-refresh \
    --auto-scaling-group-name $ASG_NAME \
    --preferences MinHealthyPercentage=50,InstanceWarmup=300
```

---

## Verify Deployment

### Step 1: Check EC2 Instances
```bash
# List instances
python3 ec2_operations.py --list --filter Project=git-captain

# Check specific instance
python3 ec2_operations.py --metadata i-0123456789abcdef0
```

### Step 2: Verify Health Check
```bash
# Using ALB DNS
curl https://YOUR_ALB_DNS/health

# Expected response:
# {
#   "status": "healthy",
#   "uptime": 123.456,
#   "memory": {...},
#   "timestamp": "2025-11-15T..."
# }
```

### Step 3: Test Application
```bash
# Open in browser
https://YOUR_ALB_DNS

# Or using curl
curl https://YOUR_ALB_DNS
```

### Step 4: Test Lambda Function
```bash
# Upload test file to S3
python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket

# Check CloudWatch logs
python3 lambda_test.py --check-logs
```

### Step 5: View CloudWatch Dashboard
```bash
# Get dashboard URL
aws cloudformation describe-stacks \
    --stack-name git-captain-monitoring \
    --query 'Stacks[0].Outputs[?OutputKey==`DashboardURL`].OutputValue' \
    --output text

# Open URL in browser
```

---

## Troubleshooting

### EC2 Instances Not Starting
```bash
# Check user data logs
aws ec2 get-console-output --instance-id i-0123456789abcdef0

# SSH into instance (if accessible)
ssh -i git-captain-key.pem ec2-user@PRIVATE_IP

# Check logs
sudo tail -f /var/log/user-data.log
sudo tail -f /opt/git-captain/logs/application-*.log
```

### Health Check Failing
```bash
# Check target group health
aws elbv2 describe-target-health \
    --target-group-arn arn:aws:elasticloadbalancing:... \
    --region us-east-2

# Check application logs in CloudWatch
aws logs tail /aws/ec2/git-captain/application --follow
```

### Cannot Access Application
```bash
# Verify ALB is active
aws elbv2 describe-load-balancers \
    --names git-captain-prod-alb \
    --region us-east-2

# Check security group rules
aws ec2 describe-security-groups \
    --filters "Name=tag:Name,Values=git-captain-prod-alb-sg"

# Test ALB endpoint
curl -v https://YOUR_ALB_DNS
```

### Secrets Not Loading
```bash
# Verify secret exists
aws secretsmanager get-secret-value \
    --secret-id git-captain/prod \
    --region us-east-2

# Check EC2 IAM role permissions
aws iam get-role-policy \
    --role-name git-captain-prod-ec2-role \
    --policy-name GitCaptainEC2Policy
```

---

## Next Steps

1. **Configure Domain Name**: Point your domain to ALB DNS using CNAME record
2. **Setup CI/CD**: Configure GitHub Actions workflows for automated deployment
3. **Enable Multi-AZ RDS**: For production high availability
4. **Configure CloudFront**: For better static asset delivery
5. **Implement Database Migrations**: Create database schema
6. **Setup Backup Strategy**: Configure AWS Backup for automated backups

---

**Deployment Complete! 🎉**

Your Git-Captain application is now running on AWS with:
- ✅ High availability across 2 AZs
- ✅ Auto scaling (2-6 instances)
- ✅ Load balancing with HTTPS
- ✅ Database for future use
- ✅ Logging and monitoring
- ✅ WAF protection
- ✅ Automated instance bootstrapping

**Access your application at**: `https://YOUR_ALB_DNS`

---

**Support**: Open an issue on GitHub or contact joe@example.com
**Documentation**: See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed architecture info
**Last Updated**: November 15, 2025
