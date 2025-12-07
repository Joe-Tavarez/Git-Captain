# Git-Captain AWS Deployment Checklist

**Use this checklist to ensure successful deployment**

---

## ✅ Pre-Deployment Checklist

### Prerequisites Installation
- [ ] AWS CLI installed and configured (`aws --version`)
- [ ] Terraform 1.5.0+ installed (`terraform version`)
- [ ] Python 3.9+ installed (`python3 --version`)
- [ ] Node.js 18+ installed (`node --version`)
- [ ] Git installed (`git --version`)
- [ ] boto3 installed (`pip3 install boto3 tabulate`)

### AWS Account Setup
- [ ] AWS account created
- [ ] IAM user created with programmatic access
- [ ] IAM user has required permissions:
  - [ ] VPCFullAccess
  - [ ] EC2FullAccess
  - [ ] RDSFullAccess
  - [ ] S3FullAccess
  - [ ] LambdaFullAccess
  - [ ] CloudWatchFullAccess
  - [ ] SecretsManagerFullAccess
  - [ ] IAMFullAccess (for role creation)
  - [ ] CloudFormationFullAccess
- [ ] AWS CLI configured (`aws configure`)
- [ ] AWS credentials verified (`aws sts get-caller-identity`)

### Local Environment Setup
- [ ] Repository cloned
- [ ] `.env` file created in `controllers/` directory with:
  - [ ] `client_id` (GitHub OAuth)
  - [ ] `client_secret` (GitHub OAuth)
  - [ ] `GITHUB_ORG_NAME`
  - [ ] `GIT_PORT_ENDPOINT`
  - [ ] All other required variables
- [ ] SSL certificates available:
  - [ ] `controllers/theKey.key`
  - [ ] `controllers/theCert.cert`
- [ ] `terraform/terraform.tfvars` created with:
  - [ ] `project_name = "git-captain"`
  - [ ] `environment = "prod"`
  - [ ] `aws_region = "us-east-2"`
  - [ ] `vpc_cidr`, subnet CIDRs, availability zones

---

## 🚀 Deployment Steps

### Step 1: Store Secrets in AWS Secrets Manager
- [ ] Navigate to `boto3-scripts/` directory
- [ ] Run `python3 setup_secrets.py`
- [ ] Verify secret created: `aws secretsmanager describe-secret --secret-id git-captain/prod`
- [ ] **Expected Output**: Secret ARN displayed

### Step 2: Deploy Networking with Terraform
- [ ] Navigate to `terraform/` directory
- [ ] Run `terraform init`
- [ ] **Expected Output**: "Terraform has been successfully initialized!"
- [ ] Run `terraform validate`
- [ ] **Expected Output**: "Success! The configuration is valid."
- [ ] Run `terraform plan`
- [ ] **Expected Output**: "Plan: 26 to add, 0 to change, 0 to destroy"
- [ ] Review plan output
- [ ] Run `terraform apply`
- [ ] Type `yes` when prompted
- [ ] **Expected Output**: 26 resources created
- [ ] Verify VPC created: `aws ec2 describe-vpcs --filters "Name=tag:Name,Values=git-captain-prod-vpc"`
- [ ] **Expected Output**: VPC details with ID vpc-xxxxx

### Step 3: Create S3 Buckets
- [ ] Navigate to `boto3-scripts/` directory
- [ ] Run `python3 s3_manager.py`
- [ ] Verify buckets created: `aws s3 ls | grep git-captain`
- [ ] **Expected Output**: 3 buckets listed
- [ ] Upload SSL certificates: `aws s3 cp ../controllers/theKey.key s3://git-captain-ssl-certs/`
- [ ] Upload SSL certificates: `aws s3 cp ../controllers/theCert.cert s3://git-captain-ssl-certs/`

### Step 4: Deploy RDS Database
- [ ] Navigate to `cloudformation/` directory
- [ ] Run:
  ```bash
  aws cloudformation create-stack --stack-name git-captain-rds \
    --template-body file://rds.yaml \
    --capabilities CAPABILITY_IAM
  ```
- [ ] **Expected Output**: StackId displayed
- [ ] Wait for stack creation: `aws cloudformation wait stack-create-complete --stack-name git-captain-rds`
- [ ] Verify stack: `aws cloudformation describe-stacks --stack-name git-captain-rds`
- [ ] **Expected Output**: StackStatus = CREATE_COMPLETE
- [ ] Get RDS endpoint from stack outputs

### Step 5: Deploy Lambda S3 Logger
- [ ] Run:
  ```bash
  aws cloudformation create-stack --stack-name git-captain-lambda \
    --template-body file://lambda-s3-logging.yaml \
    --capabilities CAPABILITY_IAM
  ```
- [ ] **Expected Output**: StackId displayed
- [ ] Wait for stack creation: `aws cloudformation wait stack-create-complete --stack-name git-captain-lambda`
- [ ] Verify Lambda: `aws lambda list-functions | grep git-captain`
- [ ] **Expected Output**: Lambda function listed

### Step 6: Deploy EC2/ALB/Auto Scaling
- [ ] Run:
  ```bash
  aws cloudformation create-stack --stack-name git-captain-ec2-alb \
    --template-body file://ec2-alb-autoscaling.yaml \
    --capabilities CAPABILITY_IAM
  ```
- [ ] **Expected Output**: StackId displayed
- [ ] Wait for stack creation (10-15 minutes): `aws cloudformation wait stack-create-complete --stack-name git-captain-ec2-alb`
- [ ] Verify ALB: `aws elbv2 describe-load-balancers --names git-captain-prod-alb`
- [ ] **Expected Output**: ALB details with DNS name
- [ ] Get ALB DNS name from output
- [ ] Verify EC2 instances: `aws ec2 describe-instances --filters "Name=tag:Project,Values=git-captain"`
- [ ] **Expected Output**: 2 running instances

### Step 7: Deploy CloudWatch Monitoring
- [ ] Run:
  ```bash
  aws cloudformation create-stack --stack-name git-captain-monitoring \
    --template-body file://cloudwatch-monitoring.yaml \
    --capabilities CAPABILITY_IAM
  ```
- [ ] **Expected Output**: StackId displayed
- [ ] Wait for stack creation: `aws cloudformation wait stack-create-complete --stack-name git-captain-monitoring`
- [ ] Verify alarms: `aws cloudwatch describe-alarms --alarm-name-prefix git-captain`
- [ ] **Expected Output**: 7 alarms listed

### Step 8: Deploy AWS WAF
- [ ] Run:
  ```bash
  aws cloudformation create-stack --stack-name git-captain-waf \
    --template-body file://waf.yaml \
    --capabilities CAPABILITY_IAM
  ```
- [ ] **Expected Output**: StackId displayed
- [ ] Wait for stack creation: `aws cloudformation wait stack-create-complete --stack-name git-captain-waf`
- [ ] Verify WAF: `aws wafv2 list-web-acls --scope REGIONAL --region us-east-2`
- [ ] **Expected Output**: WebACL listed

### Step 9: Configure GitHub OAuth
- [ ] Go to GitHub Settings → Developer settings → OAuth Apps
- [ ] Update OAuth app callback URL with ALB DNS name:
  - [ ] Homepage URL: `http://<ALB-DNS-NAME>`
  - [ ] Authorization callback URL: `http://<ALB-DNS-NAME>/authenticated.html`
- [ ] Save changes

---

## ✅ Verification Steps

### Health Check Verification
- [ ] Get ALB DNS: `aws elbv2 describe-load-balancers --names git-captain-prod-alb --query 'LoadBalancers[0].DNSName' --output text`
- [ ] Test health endpoint: `curl http://<ALB-DNS>/health`
- [ ] **Expected Output**: JSON with status: "healthy"

### ALB Target Health
- [ ] Get target group ARN from CloudFormation outputs
- [ ] Check target health:
  ```bash
  aws elbv2 describe-target-health --target-group-arn <TARGET-GROUP-ARN>
  ```
- [ ] **Expected Output**: All targets show HealthStatus = "healthy"

### Application Access
- [ ] Open browser to `http://<ALB-DNS>`
- [ ] **Expected Output**: Git-Captain home page loads
- [ ] Click "Login with GitHub"
- [ ] **Expected Output**: GitHub OAuth page loads
- [ ] Authorize application
- [ ] **Expected Output**: Redirected back to application

### Lambda Verification
- [ ] Navigate to `boto3-scripts/` directory
- [ ] Test Lambda: `python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket`
- [ ] **Expected Output**: File uploaded successfully
- [ ] Check logs: `python3 lambda_test.py --check-logs`
- [ ] **Expected Output**: Recent upload log displayed

### CloudWatch Dashboard
- [ ] Open AWS Console → CloudWatch → Dashboards
- [ ] Select `git-captain-prod-dashboard`
- [ ] **Expected Output**: Dashboard with 12 widgets showing metrics

### RDS Connection (Optional)
- [ ] SSH to EC2 instance
- [ ] Install PostgreSQL client: `sudo yum install -y postgresql15`
- [ ] Get RDS endpoint from stack outputs
- [ ] Get password from Secrets Manager
- [ ] Connect: `psql -h <RDS-ENDPOINT> -U postgres -d gitcaptain`
- [ ] **Expected Output**: PostgreSQL prompt

---

## 🧪 Smoke Testing

### Test 1: Search for Repositories
- [ ] Login to application
- [ ] Click "Search for Repositories"
- [ ] **Expected Output**: List of repositories from your organization

### Test 2: Create Branch
- [ ] Select a repository
- [ ] Enter branch name: `test/deployment-verification`
- [ ] Click "Create Branch"
- [ ] **Expected Output**: Success message

### Test 3: Search for Branch
- [ ] Enter branch name: `test/deployment-verification`
- [ ] Click "Search for Branch"
- [ ] **Expected Output**: Branch found in selected repository

### Test 4: Delete Branch
- [ ] Select the test branch
- [ ] Click "Delete Branch"
- [ ] **Expected Output**: Branch deleted successfully

---

## 📊 Monitoring Verification

### CloudWatch Logs
- [ ] Verify application logs: `aws logs tail /aws/ec2/git-captain --follow`
- [ ] **Expected Output**: Application logs streaming
- [ ] Verify Lambda logs: `aws logs tail /aws/lambda/git-captain-prod-s3-upload-logger --follow`
- [ ] **Expected Output**: Lambda execution logs

### CloudWatch Alarms
- [ ] Check alarm status: `aws cloudwatch describe-alarms --alarm-name-prefix git-captain`
- [ ] **Expected Output**: All alarms in "OK" state (not ALARM)

### WAF Metrics
- [ ] Check WAF metrics in CloudWatch console
- [ ] **Expected Output**: Request count metrics visible

---

## 🔒 Security Verification

### Security Groups
- [ ] Verify ALB security group allows HTTP 80, HTTPS 443 from 0.0.0.0/0
- [ ] Verify EC2 security group allows traffic only from ALB
- [ ] Verify RDS security group allows traffic only from EC2 and Lambda
- [ ] Verify Lambda security group allows HTTPS outbound

### Secrets Manager
- [ ] Verify secret exists: `aws secretsmanager describe-secret --secret-id git-captain/prod`
- [ ] Verify EC2 instances can retrieve secret (check CloudWatch logs)

### IAM Roles
- [ ] Verify EC2 IAM role has correct policies attached
- [ ] Verify Lambda IAM role has correct policies attached

---

## 💰 Cost Verification

### Review AWS Billing
- [ ] Go to AWS Console → Billing Dashboard
- [ ] Check "Cost Explorer" for current month spending
- [ ] **Expected Cost**: ~$93/month for full deployment
- [ ] Set up billing alerts for unexpected costs

---

## 📝 Documentation Review

- [ ] Review `docs/aws/ARCHITECTURE.md` for architecture understanding
- [ ] Review `docs/aws/DEPLOYMENT_GUIDE.md` for troubleshooting
- [ ] Review `terraform/README.md` for Terraform operations
- [ ] Review `boto3-scripts/README.md` for automation scripts
- [ ] Review `AWS_QUICK_REFERENCE.md` for common commands

---

## 🐛 Troubleshooting Checklist

### If EC2 Instances Not Starting
- [ ] Check CloudFormation events: `aws cloudformation describe-stack-events --stack-name git-captain-ec2-alb`
- [ ] Check EC2 system logs: `aws ec2 get-console-output --instance-id <INSTANCE-ID>`
- [ ] Verify user data script in Launch Template
- [ ] Check IAM role permissions

### If Health Checks Failing
- [ ] SSH to EC2 instance
- [ ] Check PM2 status: `pm2 status`
- [ ] Check application logs: `pm2 logs`
- [ ] Test health endpoint locally: `curl http://localhost:3000/health`
- [ ] Verify security group rules

### If Secrets Not Loading
- [ ] Verify secret exists in Secrets Manager
- [ ] Check EC2 IAM role has SecretsManager permissions
- [ ] Check CloudWatch logs for secret retrieval errors
- [ ] Manually test secret retrieval from EC2

### If RDS Connection Failing
- [ ] Check RDS status: `aws rds describe-db-instances --db-instance-identifier git-captain-prod-db`
- [ ] Verify RDS security group allows EC2 access
- [ ] Check RDS endpoint in application configuration
- [ ] Test connection from EC2: `nc -zv <RDS-ENDPOINT> 5432`

### If Lambda Not Triggering
- [ ] Verify S3 event notification: `aws s3api get-bucket-notification-configuration --bucket git-captain-logs-bucket`
- [ ] Check Lambda permissions: `aws lambda get-policy --function-name git-captain-prod-s3-upload-logger`
- [ ] Check CloudWatch Logs for Lambda errors
- [ ] Manually invoke Lambda for testing

---

## ✅ Post-Deployment Tasks

### Optional Enhancements
- [ ] Set up CloudTrail for audit logging
- [ ] Configure SNS email subscriptions for CloudWatch alarms
- [ ] Set up Route 53 custom domain name
- [ ] Configure ACM SSL certificate for HTTPS
- [ ] Enable RDS automated snapshots
- [ ] Set up AWS Backup for EC2 volumes
- [ ] Configure CloudFront CDN for static assets
- [ ] Implement database schema (if needed)

### Documentation Updates
- [ ] Update `controllers/.env` with RDS endpoint (if using database)
- [ ] Document custom configurations
- [ ] Create runbook for common operations
- [ ] Document backup/restore procedures

---

## 📅 Regular Maintenance Checklist

### Daily
- [ ] Check CloudWatch alarms
- [ ] Review application logs for errors
- [ ] Monitor AWS billing

### Weekly
- [ ] Review CloudWatch dashboard
- [ ] Check Auto Scaling activity
- [ ] Review RDS performance metrics
- [ ] Check S3 storage usage

### Monthly
- [ ] Review and optimize costs
- [ ] Test disaster recovery procedures
- [ ] Update documentation
- [ ] Review security groups and IAM policies
- [ ] Update dependencies (npm, Python packages)

---

## 🎓 Submission Checklist (for Educational Projects)

### Required Deliverables
- [ ] Architecture diagram (✅ in `docs/aws/ARCHITECTURE.md`)
- [ ] Terraform scripts (✅ in `terraform/`)
- [ ] CloudFormation templates (✅ in `cloudformation/`)
- [ ] Lambda function code (✅ in `cloudformation/lambda-s3-logging.yaml`)
- [ ] Python Boto3 scripts (✅ in `boto3-scripts/`)
- [ ] GitHub repository link (✅)
- [ ] Screenshots of:
  - [ ] AWS Console showing VPC
  - [ ] EC2 instances running
  - [ ] ALB with healthy targets
  - [ ] RDS database
  - [ ] Lambda function
  - [ ] CloudWatch dashboard
  - [ ] Application working (login + operations)
- [ ] Implementation report (✅ `AWS_IMPLEMENTATION_SUMMARY.md`)
- [ ] Step-by-step deployment guide (✅ `docs/aws/DEPLOYMENT_GUIDE.md`)

### Bonus Points Documentation
- [ ] CI/CD pipeline (✅ GitHub Actions in `.github/workflows/`)
- [ ] Cost optimization strategies (✅ documented in ARCHITECTURE.md)
- [ ] Security best practices (✅ documented throughout)
- [ ] Monitoring and alerting (✅ CloudWatch implementation)

---

## ✅ Final Sign-Off

**Deployment Status**: ⬜ Not Started / ⬜ In Progress / ⬜ Complete

**Deployed By**: ________________  
**Date**: ________________  
**Region**: us-east-2 (Ohio)  
**Estimated Monthly Cost**: ~$93  

**Notes**:
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

**Known Issues**:
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

---

**Checklist Version**: 1.0  
**Last Updated**: November 15, 2025  
**For Questions**: See `docs/aws/DEPLOYMENT_GUIDE.md` troubleshooting section
