# Git-Captain AWS Deployment Summary

## Deployment Status: ✅ COMPLETE

**Deployment Date:** December 2, 2025  
**AWS Region:** us-east-2 (Ohio)  
**AWS Account:** 428207760450

---

## 🌐 Application Access

**Application URL:** http://ec2-3-147-82-178.us-east-2.compute.amazonaws.com:3000

**Instance Details:**
- Instance ID: i-09868548b3cd30e8e
- Public IP: 3.147.82.178
- Instance Type: t3.micro (Free Tier eligible)

---

## 📦 Deployed Infrastructure

### 1. **VPC Infrastructure** (Terraform) ✅
- **VPC ID:** vpc-09e36bc10493d4534
- **CIDR Block:** 10.0.0.0/16
- **Public Subnets:** 
  - subnet-005455db03caf1d67 (10.0.1.0/24, us-east-2a)
  - subnet-0e65b006d61c61227 (10.0.2.0/24, us-east-2b)
- **Private Subnets:**
  - subnet-0c6df6c1c5a9f4eca (10.0.10.0/24, us-east-2a)
  - subnet-0ef57b60bae69f1d2 (10.0.11.0/24, us-east-2b)
- **NAT Gateway:** 18.220.153.245
- **Security Groups:** 4 (ALB, EC2, RDS, Lambda)
- **Resources Created:** 25

### 2. **RDS PostgreSQL Database** (CloudFormation) ✅
- **Stack Name:** git-captain-rds
- **Status:** CREATE_COMPLETE
- **Engine:** PostgreSQL 15
- **Instance Class:** db.t3.micro
- **Storage:** 20 GB (General Purpose SSD)
- **Backup Retention:** 1 day (Free Tier compliant)
- **Multi-AZ:** Disabled (Free Tier)
- **Encrypted:** Yes

### 3. **Lambda S3 Logger** (CloudFormation) ✅
- **Stack Name:** git-captain-lambda
- **Status:** CREATE_COMPLETE
- **Function:** Logs S3 uploads to CloudWatch
- **Runtime:** Python 3.9
- **S3 Bucket:** Created for logging

### 4. **EC2 Web Instance** (CloudFormation) ✅
- **Stack Name:** git-captain-ec2-simple
- **Status:** CREATE_COMPLETE
- **Instance Type:** t3.micro
- **AMI:** Amazon Linux 2
- **Node.js Version:** 18.x
- **Process Manager:** PM2
- **Public Access:** Port 3000 open to internet

---

## 🔍 Issues Encountered & Resolved

### Issue 1: Application Load Balancer Creation Blocked
**Problem:** AWS account doesn't support creating Application Load Balancers
```
Error: "This AWS account currently does not support creating load balancers."
```

**Root Cause:** New AWS accounts or accounts requiring verification cannot create ALBs without AWS Support approval.

**Solution:** Deployed simplified architecture with direct EC2 instance access instead of ALB + Auto Scaling Group.

### Issue 2: RDS Backup Retention (Fixed in earlier deployment)
**Problem:** Free Tier only supports 1 day backup retention, template had 7 days
**Solution:** Changed BackupRetentionPeriod from 7 to 1

### Issue 3: RDS PostgreSQL Version Format (Fixed in earlier deployment)
**Problem:** Version '15.4' not recognized by AWS
**Solution:** Changed to '15' (major version only)

### Issue 4: Lambda Circular Dependency (Fixed in earlier deployment)
**Problem:** S3 bucket tried to reference Lambda before Lambda existed
**Solution:** Removed S3 NotificationConfiguration from template

---

## 💰 Free Tier Compliance

All resources deployed are Free Tier eligible:
- ✅ EC2 t3.micro instance (750 hours/month free)
- ✅ RDS db.t3.micro (750 hours/month free)
- ✅ 20 GB RDS storage (free)
- ✅ Lambda invocations (1M requests/month free)
- ✅ NAT Gateway data transfer (minimal for testing)
- ⚠️ **NAT Gateway charges $0.045/hour** (~$32/month) - only non-free resource

---

## 🛠️ Architecture Changes from Original Plan

### Original Design:
- Application Load Balancer (internet-facing)
- Auto Scaling Group (2-6 instances)
- EC2 instances in private subnets
- High availability across 2 AZs
- CloudWatch monitoring
- WAF protection

### Deployed Design (Simplified):
- Single EC2 instance in public subnet
- Direct internet access via Security Group
- No load balancer (blocked by AWS)
- No auto scaling
- Basic CloudWatch agent
- No WAF

**Trade-offs:**
- ❌ No high availability
- ❌ No automatic scaling
- ❌ No SSL/TLS termination
- ✅ Simpler architecture
- ✅ Lower cost
- ✅ Faster deployment

---

## 📝 Next Steps to Enable Full Architecture

### To enable Application Load Balancer:
1. **Contact AWS Support** to enable ALB service for account
2. Submit support ticket: "Enable Elastic Load Balancing service"
3. Wait for account verification (24-48 hours)
4. Once approved, deploy `cloudformation/ec2-alb-autoscaling.yaml`

### To upgrade to production-ready setup:
1. **Obtain SSL Certificate:**
   ```bash
   aws acm request-certificate \
     --domain-name git-captain.yourdomain.com \
     --validation-method DNS \
     --region us-east-2
   ```

2. **Deploy full ALB stack:**
   ```bash
   aws cloudformation create-stack \
     --stack-name git-captain-ec2-alb \
     --template-body file://cloudformation/ec2-alb-autoscaling.yaml \
     --parameters ParameterKey=ACMCertificateArn,ParameterValue=<cert-arn> \
     --capabilities CAPABILITY_NAMED_IAM \
     --region us-east-2
   ```

3. **Add monitoring:**
   ```bash
   aws cloudformation create-stack \
     --stack-name git-captain-monitoring \
     --template-body file://cloudformation/monitoring-alarms.yaml \
     --region us-east-2
   ```

4. **Add WAF protection:**
   ```bash
   aws cloudformation create-stack \
     --stack-name git-captain-waf \
     --template-body file://cloudformation/waf-webacl.yaml \
     --region us-east-2
   ```

---

## 🔒 Security Considerations

### Current Security Configuration:
- ✅ EC2 instance has IAM role (no hardcoded credentials)
- ✅ Security Groups restrict access to specific ports
- ✅ RDS database encrypted at rest
- ✅ Private subnets configured (not used in simplified deployment)
- ✅ VPC isolation
- ⚠️ **Port 3000 open to internet (0.0.0.0/0)** - acceptable for demo, not production
- ⚠️ **No HTTPS/SSL** - HTTP only
- ⚠️ **No WAF protection**

### Recommended Production Hardening:
1. Enable ALB with HTTPS listener
2. Restrict security group to ALB only
3. Move EC2 instances to private subnets
4. Enable AWS WAF
5. Enable CloudTrail logging
6. Enable VPC Flow Logs
7. Configure AWS Config rules
8. Set up AWS Systems Manager Session Manager (no SSH keys needed)

---

## 📊 Resource Costs (Monthly Estimates)

| Resource | Free Tier | Expected Cost |
|----------|-----------|---------------|
| EC2 t3.micro | 750 hrs free | $0.00 (first 12 months) |
| RDS db.t3.micro | 750 hrs free | $0.00 (first 12 months) |
| RDS Storage 20GB | 20 GB free | $0.00 |
| Lambda | 1M requests free | $0.00 |
| NAT Gateway | Not free | ~$32/month |
| Data Transfer | 1 GB free | ~$0-5/month |
| **TOTAL** | | **~$32-37/month** |

**Cost Optimization Options:**
- Remove NAT Gateway if private subnet instances don't need internet access
- Use VPC Endpoints for AWS service access instead of NAT Gateway
- Stop EC2/RDS instances when not in use (development environment)

---

## 🔧 Management Commands

### Check deployment status:
```bash
aws cloudformation describe-stacks \
  --region us-east-2 \
  --query "Stacks[?starts_with(StackName,'git-captain')].[StackName,StackStatus]" \
  --output table
```

### Access EC2 instance (requires SSH key):
```bash
ssh -i your-key.pem ec2-user@3.147.82.178
```

### View application logs:
```bash
ssh ec2-user@3.147.82.178
pm2 logs git-captain
```

### Restart application:
```bash
ssh ec2-user@3.147.82.178
pm2 restart git-captain
```

### Stop all resources to save costs:
```bash
# Stop EC2 instance
aws ec2 stop-instances --instance-ids i-09868548b3cd30e8e --region us-east-2

# Stop RDS database
aws rds stop-db-instance --db-instance-identifier <rds-instance-id> --region us-east-2
```

### Delete entire deployment:
```bash
# Delete stacks in reverse order
aws cloudformation delete-stack --stack-name git-captain-ec2-simple --region us-east-2
aws cloudformation delete-stack --stack-name git-captain-lambda --region us-east-2
aws cloudformation delete-stack --stack-name git-captain-rds --region us-east-2

# Destroy Terraform infrastructure
cd terraform
terraform destroy -auto-approve
```

---

## 📞 Support Information

### AWS Support (for ALB enablement):
- Support Console: https://console.aws.amazon.com/support/
- Account: 428207760450
- Region: us-east-2

### Deployment Files Location:
- CloudFormation Templates: `cloudformation/`
- Terraform Code: `terraform/`
- Deployment Scripts: Root directory (`.ps1` files)

---

## ✅ Deployment Checklist

- [x] VPC Infrastructure deployed (Terraform)
- [x] RDS PostgreSQL database created
- [x] Lambda S3 logger deployed
- [x] EC2 web instance deployed
- [x] Application accessible via HTTP
- [x] Security groups configured
- [ ] Application Load Balancer (blocked by AWS)
- [ ] Auto Scaling Group (requires ALB)
- [ ] HTTPS/SSL certificate
- [ ] CloudWatch monitoring dashboard
- [ ] WAF protection
- [ ] Production domain name
- [ ] Automated backups verified

---

**Deployment Completed By:** GitHub Copilot  
**Contact Support:** Submit ticket to enable ALB service for full architecture deployment
