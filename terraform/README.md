# Git-Captain Terraform Infrastructure

Terraform modules for deploying the network infrastructure layer of Git-Captain on AWS.

## 📋 Overview

This Terraform configuration creates a production-ready VPC with Multi-AZ architecture, security groups, and NAT gateway for Git-Captain application.

**What Terraform Deploys:**
- ✅ VPC with CIDR 10.0.0.0/16
- ✅ 2 Public Subnets (10.0.10.0/24, 10.0.11.0/24) in different AZs
- ✅ 2 Private Subnets (10.0.20.0/24, 10.0.21.0/24) in different AZs
- ✅ Internet Gateway for public internet access
- ✅ NAT Gateway with Elastic IP for private subnet internet access
- ✅ Route Tables (public and private)
- ✅ 4 Security Groups (ALB, EC2, RDS, Lambda)
- ✅ Outputs stored in AWS SSM Parameter Store for CloudFormation

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Region: us-east-2                     │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  VPC (10.0.0.0/16)                        │  │
│  │                                                            │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐        │  │
│  │  │  Public Subnet A    │  │  Public Subnet B    │        │  │
│  │  │  (10.0.10.0/24)     │  │  (10.0.11.0/24)     │        │  │
│  │  │  - Internet Gateway │  │  - ALB              │        │  │
│  │  │  - NAT Gateway      │  │                     │        │  │
│  │  └─────────────────────┘  └─────────────────────┘        │  │
│  │                                                            │  │
│  │  ┌─────────────────────┐  ┌─────────────────────┐        │  │
│  │  │  Private Subnet A   │  │  Private Subnet B   │        │  │
│  │  │  (10.0.20.0/24)     │  │  (10.0.21.0/24)     │        │  │
│  │  │  - EC2 Instances    │  │  - EC2 Instances    │        │  │
│  │  │  - RDS              │  │  - Lambda           │        │  │
│  │  └─────────────────────┘  └─────────────────────┘        │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

1. **Terraform 1.5.0+**
   ```bash
   # Check version
   terraform version
   
   # Install (Windows with Chocolatey)
   choco install terraform
   
   # Install (macOS with Homebrew)
   brew install terraform
   
   # Install (Linux)
   wget https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip
   unzip terraform_1.5.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

2. **AWS CLI Configured**
   ```bash
   aws configure
   # Enter: Access Key ID, Secret Access Key, Region (us-east-2), Output (json)
   ```

3. **IAM Permissions**
   - VPC Full Access
   - EC2 Full Access
   - Systems Manager (for Parameter Store)

---

## 📁 Project Structure

```
terraform/
├── main.tf                  # Main orchestration file
├── variables.tf             # Input variables
├── outputs.tf               # Output values (to SSM Parameter Store)
├── backend.tf               # Remote state configuration
├── terraform.tfvars         # Variable values (create this)
├── README.md               # This file
└── modules/
    ├── vpc/
    │   ├── main.tf         # VPC, subnets, IGW, route tables
    │   ├── variables.tf    # VPC module inputs
    │   └── outputs.tf      # VPC IDs, subnet IDs, CIDR blocks
    ├── security-groups/
    │   ├── main.tf         # Security groups for ALB, EC2, RDS, Lambda
    │   ├── variables.tf    # Security group module inputs
    │   └── outputs.tf      # Security group IDs
    └── nat-gateway/
        ├── main.tf         # NAT Gateway + Elastic IP
        ├── variables.tf    # NAT module inputs
        └── outputs.tf      # NAT Gateway ID, EIP
```

---

## ⚙️ Configuration

### 1. Create `terraform.tfvars`

Create a file named `terraform.tfvars` in the `terraform/` directory:

```hcl
# Project Configuration
project_name = "git-captain"
environment  = "prod"

# Network Configuration
vpc_cidr             = "10.0.0.0/16"
public_subnet_cidrs  = ["10.0.10.0/24", "10.0.11.0/24"]
private_subnet_cidrs = ["10.0.20.0/24", "10.0.21.0/24"]
availability_zones   = ["us-east-2a", "us-east-2b"]

# AWS Region
aws_region = "us-east-2"

# Tags
tags = {
  Project     = "git-captain"
  Environment = "prod"
  ManagedBy   = "terraform"
  Owner       = "your-name"
  CostCenter  = "engineering"
}
```

### 2. Configure Remote State (Optional but Recommended)

Create `backend.tf` for S3 remote state:

```hcl
terraform {
  backend "s3" {
    bucket         = "git-captain-terraform-state"
    key            = "prod/vpc/terraform.tfstate"
    region         = "us-east-2"
    encrypt        = true
    dynamodb_table = "git-captain-terraform-locks"
  }
}
```

**Create S3 backend resources first:**
```bash
# Create S3 bucket for state
aws s3api create-bucket \
  --bucket git-captain-terraform-state \
  --region us-east-2 \
  --create-bucket-configuration LocationConstraint=us-east-2

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket git-captain-terraform-state \
  --versioning-configuration Status=Enabled

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name git-captain-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
  --region us-east-2
```

---

## 🚀 Deployment

### Step 1: Initialize Terraform

```bash
cd terraform
terraform init
```

**Expected Output:**
```
Initializing modules...
- vpc in modules/vpc
- security-groups in modules/security-groups
- nat-gateway in modules/nat-gateway

Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.31.0...

Terraform has been successfully initialized!
```

### Step 2: Validate Configuration

```bash
terraform validate
```

**Expected Output:**
```
Success! The configuration is valid.
```

### Step 3: Preview Changes

```bash
terraform plan
```

**Expected Output Summary:**
```
Terraform will perform the following actions:

  # VPC Resources
  + aws_vpc.main
  + aws_subnet.public[0]
  + aws_subnet.public[1]
  + aws_subnet.private[0]
  + aws_subnet.private[1]
  + aws_internet_gateway.main
  + aws_route_table.public
  + aws_route_table.private
  + aws_route_table_association.public[0]
  + aws_route_table_association.public[1]
  + aws_route_table_association.private[0]
  + aws_route_table_association.private[1]

  # NAT Gateway Resources
  + aws_eip.nat
  + aws_nat_gateway.main

  # Security Group Resources
  + aws_security_group.alb
  + aws_security_group.ec2
  + aws_security_group.rds
  + aws_security_group.lambda

  # SSM Parameters (for CloudFormation)
  + aws_ssm_parameter.vpc_id
  + aws_ssm_parameter.public_subnet_ids
  + aws_ssm_parameter.private_subnet_ids
  + aws_ssm_parameter.alb_sg_id
  + aws_ssm_parameter.ec2_sg_id
  + aws_ssm_parameter.rds_sg_id
  + aws_ssm_parameter.lambda_sg_id

Plan: 26 to add, 0 to change, 0 to destroy.
```

### Step 4: Apply Configuration

```bash
terraform apply
```

**Type `yes` when prompted.**

**Expected Output:**
```
Apply complete! Resources: 26 added, 0 changed, 0 destroyed.

Outputs:

vpc_id = "vpc-0123456789abcdef0"
public_subnet_ids = [
  "subnet-0123456789abcdef1",
  "subnet-0123456789abcdef2",
]
private_subnet_ids = [
  "subnet-0123456789abcdef3",
  "subnet-0123456789abcdef4",
]
alb_security_group_id = "sg-0123456789abcdef5"
ec2_security_group_id = "sg-0123456789abcdef6"
rds_security_group_id = "sg-0123456789abcdef7"
lambda_security_group_id = "sg-0123456789abcdef8"
nat_gateway_id = "nat-0123456789abcdef9"
```

### Step 5: Verify Deployment

```bash
# Check VPC
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=git-captain-prod-vpc"

# Check Subnets
aws ec2 describe-subnets --filters "Name=tag:Project,Values=git-captain"

# Check Security Groups
aws ec2 describe-security-groups --filters "Name=tag:Project,Values=git-captain"

# Check SSM Parameters
aws ssm get-parameter --name "/git-captain/prod/vpc-id"
aws ssm get-parameter --name "/git-captain/prod/public-subnet-ids"
```

---

## 📊 Outputs

Terraform stores outputs in **AWS Systems Manager Parameter Store** for use by CloudFormation:

| Parameter Name | Value | Used By |
|----------------|-------|---------|
| `/git-captain/prod/vpc-id` | vpc-xxxxx | CloudFormation templates |
| `/git-captain/prod/public-subnet-ids` | subnet-xxx,subnet-yyy | ALB, NAT Gateway |
| `/git-captain/prod/private-subnet-ids` | subnet-zzz,subnet-aaa | EC2, RDS, Lambda |
| `/git-captain/prod/alb-sg-id` | sg-xxxxx | ALB CloudFormation |
| `/git-captain/prod/ec2-sg-id` | sg-yyyyy | EC2 CloudFormation |
| `/git-captain/prod/rds-sg-id` | sg-zzzzz | RDS CloudFormation |
| `/git-captain/prod/lambda-sg-id` | sg-aaaaa | Lambda CloudFormation |

---

## 🔄 Making Changes

### Update Variables

Edit `terraform.tfvars` and re-apply:

```bash
terraform plan
terraform apply
```

### Add New Resources

Edit `modules/*/main.tf` files and run:

```bash
terraform validate
terraform plan
terraform apply
```

---

## 🧹 Cleanup

### Destroy Infrastructure

```bash
# Preview what will be destroyed
terraform plan -destroy

# Destroy all resources
terraform destroy
```

**⚠️ WARNING**: This will **permanently delete** all networking resources. Make sure no EC2, RDS, or other resources are using the VPC first!

**Safe Cleanup Order:**
1. Delete CloudFormation stacks (EC2, RDS, Lambda, etc.)
2. Wait for all resources to be deleted
3. Run `terraform destroy`

---

## 🔍 Troubleshooting

### Error: "VPC has dependencies and cannot be deleted"

**Cause**: Resources (EC2, RDS, ALB) still exist in the VPC.

**Solution:**
```bash
# Check for remaining resources
aws ec2 describe-instances --filters "Name=vpc-id,Values=vpc-xxxxx"
aws rds describe-db-instances
aws elbv2 describe-load-balancers

# Delete CloudFormation stacks first
aws cloudformation delete-stack --stack-name git-captain-ec2-alb
aws cloudformation delete-stack --stack-name git-captain-rds

# Wait for deletion to complete, then retry
terraform destroy
```

### Error: "InvalidGroup.InUse"

**Cause**: Security groups are still attached to resources.

**Solution:**
```bash
# Find resources using the security group
aws ec2 describe-network-interfaces \
  --filters "Name=group-id,Values=sg-xxxxx"

# Delete the resource or detach the security group
# Then retry terraform destroy
```

### Error: "Error acquiring state lock"

**Cause**: Another Terraform process is running or previous run crashed.

**Solution:**
```bash
# List locks
aws dynamodb scan --table-name git-captain-terraform-locks

# Force unlock (use lock ID from error message)
terraform force-unlock <LOCK_ID>
```

### Error: "Provider configuration not present"

**Cause**: Terraform not initialized.

**Solution:**
```bash
terraform init
```

### Error: "Access Denied" when creating resources

**Cause**: IAM user lacks required permissions.

**Solution:**
```bash
# Attach required IAM policies
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess

aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
```

---

## 📚 Module Documentation

### VPC Module (`modules/vpc/`)

**Creates:**
- 1 VPC with specified CIDR
- 2 public subnets in different AZs
- 2 private subnets in different AZs
- 1 Internet Gateway
- Public route table (routes to IGW)
- Private route table (routes to NAT Gateway)

**Inputs:**
- `project_name`: Project name for tagging
- `environment`: Environment (prod, dev, staging)
- `vpc_cidr`: VPC CIDR block (e.g., 10.0.0.0/16)
- `public_subnet_cidrs`: List of public subnet CIDRs
- `private_subnet_cidrs`: List of private subnet CIDRs
- `availability_zones`: List of AZs to use

**Outputs:**
- `vpc_id`: VPC ID
- `public_subnet_ids`: List of public subnet IDs
- `private_subnet_ids`: List of private subnet IDs
- `public_route_table_id`: Public route table ID
- `private_route_table_id`: Private route table ID

### Security Groups Module (`modules/security-groups/`)

**Creates:**
- ALB Security Group (HTTP 80, HTTPS 443 from internet)
- EC2 Security Group (HTTP 3000 from ALB, SSH 22 from admin IP)
- RDS Security Group (PostgreSQL 5432 from EC2 and Lambda)
- Lambda Security Group (HTTPS 443 outbound)

**Inputs:**
- `project_name`: Project name for tagging
- `environment`: Environment
- `vpc_id`: VPC ID
- `admin_ip`: Your IP for SSH access (e.g., "1.2.3.4/32")

**Outputs:**
- `alb_security_group_id`: ALB SG ID
- `ec2_security_group_id`: EC2 SG ID
- `rds_security_group_id`: RDS SG ID
- `lambda_security_group_id`: Lambda SG ID

### NAT Gateway Module (`modules/nat-gateway/`)

**Creates:**
- 1 Elastic IP
- 1 NAT Gateway in first public subnet
- Route in private route table to NAT Gateway

**Inputs:**
- `project_name`: Project name for tagging
- `environment`: Environment
- `public_subnet_id`: Public subnet for NAT Gateway
- `private_route_table_id`: Private route table to update

**Outputs:**
- `nat_gateway_id`: NAT Gateway ID
- `nat_gateway_eip`: Elastic IP address

---

## 🔐 Security Best Practices

1. **Never commit terraform.tfvars**: It may contain sensitive values
2. **Use IAM roles in EC2**: Not access keys
3. **Enable S3 bucket encryption**: For Terraform state
4. **Enable DynamoDB encryption**: For state locking table
5. **Use MFA for AWS console**: Protect your account
6. **Review changes before apply**: Always run `terraform plan` first
7. **Use remote state**: S3 backend with versioning and encryption
8. **Restrict admin_ip**: Use your specific IP, not 0.0.0.0/0

---

## 💰 Cost Estimation

**Monthly Costs (Networking Only):**
- VPC: **Free**
- Subnets: **Free**
- Internet Gateway: **Free**
- Route Tables: **Free**
- NAT Gateway: **~$32.40/month** ($0.045/hour)
- Elastic IP (attached to NAT): **Free**
- Elastic IP (unattached): **$3.60/month** (if unused)
- Security Groups: **Free**

**Total Networking Cost**: ~$32.40/month

**Note**: This does not include compute (EC2), database (RDS), or other application resources deployed via CloudFormation.

---

## 📖 Additional Resources

- [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS VPC Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
- [Git-Captain AWS Architecture](../docs/aws/ARCHITECTURE.md)
- [Git-Captain AWS Deployment Guide](../docs/aws/DEPLOYMENT_GUIDE.md)

---

## 🤝 Contributing

When modifying Terraform modules:
1. Test in a separate AWS account first
2. Run `terraform fmt` to format code
3. Run `terraform validate` to check syntax
4. Document changes in module README
5. Update version numbers in `main.tf`

---

**Last Updated**: November 15, 2025  
**Terraform Version**: 1.5.0+  
**AWS Provider Version**: 5.0+
