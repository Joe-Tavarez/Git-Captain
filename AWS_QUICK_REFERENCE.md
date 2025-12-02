# Git-Captain AWS Quick Reference

**One-page reference for common AWS operations**

---

## 🚀 Quick Deploy Commands

### Initial Setup
```bash
# 1. Configure AWS CLI
aws configure

# 2. Store secrets
cd boto3-scripts
python3 setup_secrets.py

# 3. Deploy networking with Terraform
cd ../terraform
terraform init
terraform apply -auto-approve

# 4. Deploy application with CloudFormation
cd ../cloudformation
aws cloudformation create-stack --stack-name git-captain-rds \
  --template-body file://rds.yaml --capabilities CAPABILITY_IAM

aws cloudformation create-stack --stack-name git-captain-ec2-alb \
  --template-body file://ec2-alb-autoscaling.yaml --capabilities CAPABILITY_IAM

aws cloudformation create-stack --stack-name git-captain-lambda \
  --template-body file://lambda-s3-logging.yaml --capabilities CAPABILITY_IAM

aws cloudformation create-stack --stack-name git-captain-monitoring \
  --template-body file://cloudwatch-monitoring.yaml --capabilities CAPABILITY_IAM

aws cloudformation create-stack --stack-name git-captain-waf \
  --template-body file://waf.yaml --capabilities CAPABILITY_IAM
```

---

## 🔍 Common Verification Commands

### Check Infrastructure Status
```bash
# Get VPC ID
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=git-captain-prod-vpc" --query 'Vpcs[0].VpcId' --output text

# List running EC2 instances
aws ec2 describe-instances --filters "Name=tag:Project,Values=git-captain" "Name=instance-state-name,Values=running"

# Get ALB DNS name
aws elbv2 describe-load-balancers --names git-captain-prod-alb --query 'LoadBalancers[0].DNSName' --output text

# Check RDS status
aws rds describe-db-instances --db-instance-identifier git-captain-prod-db --query 'DBInstances[0].DBInstanceStatus' --output text

# List S3 buckets
aws s3 ls | grep git-captain
```

### Check Application Health
```bash
# Get ALB DNS
ALB_DNS=$(aws elbv2 describe-load-balancers --names git-captain-prod-alb --query 'LoadBalancers[0].DNSName' --output text)

# Health check
curl http://$ALB_DNS/health

# Check application logs
aws logs tail /aws/ec2/git-captain --follow
```

### Check CloudFormation Stacks
```bash
# List all stacks
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE

# Get stack status
aws cloudformation describe-stacks --stack-name git-captain-ec2-alb --query 'Stacks[0].StackStatus'

# Get stack outputs
aws cloudformation describe-stacks --stack-name git-captain-ec2-alb --query 'Stacks[0].Outputs'
```

---

## 🛠️ Boto3 Script Quick Reference

### Setup Secrets
```bash
cd boto3-scripts
python3 setup_secrets.py
```

### Manage S3 Buckets
```bash
# Create buckets and upload files
python3 s3_manager.py

# Manual S3 operations
aws s3 cp public/ s3://git-captain-static-assets/public/ --recursive
aws s3 ls s3://git-captain-logs-bucket/ --recursive
```

### Manage EC2 Instances
```bash
# List all instances
python3 ec2_operations.py --list

# List with filter
python3 ec2_operations.py --list --filter Project=git-captain

# Get instance details
python3 ec2_operations.py --metadata i-0123456789abcdef0

# Start instance
python3 ec2_operations.py --start i-0123456789abcdef0

# Stop instance
python3 ec2_operations.py --stop i-0123456789abcdef0

# Check Auto Scaling Group
python3 ec2_operations.py --asg git-captain-prod-asg
```

### Test Lambda
```bash
# Test with simulated event
python3 lambda_test.py --test-s3-logger --bucket git-captain-logs-bucket

# Upload test file
python3 lambda_test.py --upload-test --bucket git-captain-logs-bucket

# Check logs
python3 lambda_test.py --check-logs

# Get Lambda function logs
python3 lambda_test.py --lambda-logs git-captain-prod-s3-upload-logger
```

---

## 📊 CloudWatch Quick Commands

### View Logs
```bash
# List log groups
aws logs describe-log-groups --log-group-name-prefix /aws

# Tail application logs
aws logs tail /aws/ec2/git-captain --follow

# Tail Lambda logs
aws logs tail /aws/lambda/git-captain-prod-s3-upload-logger --follow

# Tail S3 upload logs
aws logs tail /aws/s3-uploads/git-captain --follow
```

### Check Alarms
```bash
# List all alarms
aws cloudwatch describe-alarms --alarm-name-prefix git-captain

# Get alarm state
aws cloudwatch describe-alarms --alarm-names git-captain-prod-high-cpu --query 'MetricAlarms[0].StateValue'

# View recent alarm history
aws cloudwatch describe-alarm-history --alarm-name git-captain-prod-high-cpu --max-records 10
```

### View Metrics
```bash
# EC2 CPU utilization
aws cloudwatch get-metric-statistics --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=AutoScalingGroupName,Value=git-captain-prod-asg \
  --start-time 2025-11-15T00:00:00Z --end-time 2025-11-15T23:59:59Z \
  --period 3600 --statistics Average

# ALB request count
aws cloudwatch get-metric-statistics --namespace AWS/ApplicationELB \
  --metric-name RequestCount \
  --dimensions Name=LoadBalancer,Value=app/git-captain-prod-alb/1234567890abcdef \
  --start-time 2025-11-15T00:00:00Z --end-time 2025-11-15T23:59:59Z \
  --period 3600 --statistics Sum
```

---

## 🔄 Update/Deployment Commands

### Update Application Code
```bash
# SSH to EC2 instance
EC2_IP=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=git-captain-prod-instance" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
ssh -i ~/.ssh/git-captain-key.pem ec2-user@$EC2_IP

# On EC2 instance
cd /opt/git-captain
git pull origin main
npm install
pm2 restart git-captain
```

### Update Auto Scaling Configuration
```bash
# Create new launch template version
aws ec2 create-launch-template-version \
  --launch-template-id lt-0123456789abcdef0 \
  --source-version 1 \
  --launch-template-data '{"ImageId":"ami-new123456789"}'

# Update Auto Scaling Group
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name git-captain-prod-asg \
  --launch-template LaunchTemplateId=lt-0123456789abcdef0,Version='$Latest'

# Start instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name git-captain-prod-asg
```

### Update CloudFormation Stack
```bash
# Update stack
aws cloudformation update-stack --stack-name git-captain-ec2-alb \
  --template-body file://cloudformation/ec2-alb-autoscaling.yaml \
  --capabilities CAPABILITY_IAM

# Check update status
aws cloudformation describe-stacks --stack-name git-captain-ec2-alb \
  --query 'Stacks[0].StackStatus'
```

---

## 🔒 Security Commands

### Secrets Manager
```bash
# Get secret
aws secretsmanager get-secret-value --secret-id git-captain/prod

# Update secret
aws secretsmanager update-secret --secret-id git-captain/prod \
  --secret-string file://.env

# List secrets
aws secretsmanager list-secrets
```

### Security Groups
```bash
# List security groups
aws ec2 describe-security-groups --filters "Name=tag:Project,Values=git-captain"

# Add inbound rule to EC2 security group (SSH from your IP)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp --port 22 --cidr YOUR_IP/32

# Remove inbound rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp --port 22 --cidr YOUR_IP/32
```

### WAF
```bash
# Get WAF WebACL
aws wafv2 get-web-acl --scope REGIONAL --region us-east-2 \
  --id 12345678-1234-1234-1234-123456789012 \
  --name git-captain-prod-waf

# Get sampled requests (recent traffic)
aws wafv2 get-sampled-requests --scope REGIONAL --region us-east-2 \
  --web-acl-arn arn:aws:wafv2:us-east-2:123456789012:regional/webacl/git-captain-prod-waf/12345678-1234-1234-1234-123456789012 \
  --rule-metric-name ALL \
  --time-window StartTime=2025-11-15T12:00:00Z,EndTime=2025-11-15T13:00:00Z \
  --max-items 100
```

---

## 🧹 Cleanup Commands

### Delete CloudFormation Stacks (in order)
```bash
# 1. Delete WAF (remove from ALB first)
aws cloudformation delete-stack --stack-name git-captain-waf

# 2. Delete monitoring
aws cloudformation delete-stack --stack-name git-captain-monitoring

# 3. Delete Lambda
aws cloudformation delete-stack --stack-name git-captain-lambda

# 4. Delete EC2/ALB/ASG
aws cloudformation delete-stack --stack-name git-captain-ec2-alb

# 5. Delete RDS
aws cloudformation delete-stack --stack-name git-captain-rds

# Wait for all stacks to delete
aws cloudformation wait stack-delete-complete --stack-name git-captain-rds
```

### Delete Terraform Resources
```bash
cd terraform
terraform destroy -auto-approve
```

### Delete S3 Buckets (must be empty)
```bash
# Empty buckets
aws s3 rm s3://git-captain-static-assets --recursive
aws s3 rm s3://git-captain-logs-bucket --recursive
aws s3 rm s3://git-captain-ssl-certs --recursive

# Delete buckets
aws s3 rb s3://git-captain-static-assets
aws s3 rb s3://git-captain-logs-bucket
aws s3 rb s3://git-captain-ssl-certs
```

---

## 🐛 Troubleshooting Commands

### EC2 Not Starting
```bash
# Check instance status
aws ec2 describe-instance-status --instance-ids i-0123456789abcdef0

# Get system log
aws ec2 get-console-output --instance-id i-0123456789abcdef0

# Check user data script
aws ec2 describe-instance-attribute --instance-id i-0123456789abcdef0 --attribute userData
```

### Health Check Failing
```bash
# Check target health
aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/git-captain-prod-tg/1234567890abcdef

# Test health endpoint directly from EC2
ssh -i ~/.ssh/git-captain-key.pem ec2-user@EC2_IP
curl http://localhost:3000/health
```

### Secrets Not Loading
```bash
# Verify secret exists
aws secretsmanager describe-secret --secret-id git-captain/prod

# Check EC2 IAM role permissions
aws iam get-role-policy --role-name GitCaptainEC2Role --policy-name SecretsManagerAccess

# Check CloudWatch logs for errors
aws logs filter-log-events --log-group-name /aws/ec2/git-captain \
  --filter-pattern "ERROR"
```

### RDS Connection Issues
```bash
# Check RDS status
aws rds describe-db-instances --db-instance-identifier git-captain-prod-db

# Check security group rules
aws ec2 describe-security-groups --group-ids sg-rds-xxxxx

# Test connection from EC2
ssh -i ~/.ssh/git-captain-key.pem ec2-user@EC2_IP
nc -zv git-captain-prod-db.xxxxx.us-east-2.rds.amazonaws.com 5432
```

### Lambda Not Triggering
```bash
# Check S3 event notification
aws s3api get-bucket-notification-configuration --bucket git-captain-logs-bucket

# Check Lambda permissions
aws lambda get-policy --function-name git-captain-prod-s3-upload-logger

# Invoke Lambda manually
aws lambda invoke --function-name git-captain-prod-s3-upload-logger \
  --payload file://test-event.json response.json
```

---

## 📈 Monitoring Dashboard URLs

### AWS Console Quick Links
```
VPC Dashboard:
https://console.aws.amazon.com/vpc/home?region=us-east-2#vpcs:

EC2 Instances:
https://console.aws.amazon.com/ec2/v2/home?region=us-east-2#Instances:

Auto Scaling Groups:
https://console.aws.amazon.com/ec2autoscaling/home?region=us-east-2#/details

Load Balancers:
https://console.aws.amazon.com/ec2/v2/home?region=us-east-2#LoadBalancers:

RDS Databases:
https://console.aws.amazon.com/rds/home?region=us-east-2#databases:

Lambda Functions:
https://console.aws.amazon.com/lambda/home?region=us-east-2#/functions

CloudWatch Dashboard:
https://console.aws.amazon.com/cloudwatch/home?region=us-east-2#dashboards:name=git-captain-prod-dashboard

CloudWatch Alarms:
https://console.aws.amazon.com/cloudwatch/home?region=us-east-2#alarmsV2:

CloudWatch Logs:
https://console.aws.amazon.com/cloudwatch/home?region=us-east-2#logsV2:log-groups

S3 Buckets:
https://s3.console.aws.amazon.com/s3/buckets?region=us-east-2

Secrets Manager:
https://console.aws.amazon.com/secretsmanager/home?region=us-east-2#!/listSecrets/

WAF & Shield:
https://console.aws.amazon.com/wafv2/homev2/web-acls?region=us-east-2
```

---

## 📞 Emergency Contacts

**Critical Issues:**
1. Check CloudWatch alarms
2. Review application logs: `aws logs tail /aws/ec2/git-captain --follow`
3. Check EC2 instance status
4. Verify ALB target health
5. Test RDS connectivity

**Escalation:**
- GitHub Issues: https://github.com/YourUsername/Git-Captain/issues
- AWS Support: https://console.aws.amazon.com/support/

---

## 📚 Documentation Links

- **Architecture**: `docs/aws/ARCHITECTURE.md`
- **Deployment Guide**: `docs/aws/DEPLOYMENT_GUIDE.md`
- **Terraform Guide**: `terraform/README.md`
- **Boto3 Scripts**: `boto3-scripts/README.md`
- **Main README**: `README.md`

---

**Quick Reference Version**: 1.0  
**Last Updated**: November 15, 2025  
**Region**: us-east-2 (Ohio)
