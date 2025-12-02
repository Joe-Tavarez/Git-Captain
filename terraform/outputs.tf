/**
 * Terraform Outputs for Git-Captain Infrastructure
 * Export values for CloudFormation parameter imports and external reference
 */

output "vpc_id" {
  description = "VPC ID for CloudFormation import"
  value       = module.vpc.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs for ALB deployment"
  value       = module.vpc.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs for EC2 and RDS deployment"
  value       = module.vpc.private_subnet_ids
}

output "alb_security_group_id" {
  description = "Security Group ID for Application Load Balancer"
  value       = module.security_groups.alb_security_group_id
}

output "ec2_security_group_id" {
  description = "Security Group ID for EC2 instances"
  value       = module.security_groups.ec2_security_group_id
}

output "rds_security_group_id" {
  description = "Security Group ID for RDS database"
  value       = module.security_groups.rds_security_group_id
}

output "lambda_security_group_id" {
  description = "Security Group ID for Lambda functions"
  value       = module.security_groups.lambda_security_group_id
}

output "nat_gateway_id" {
  description = "NAT Gateway ID for private subnet internet access"
  value       = module.nat_gateway.nat_gateway_id
}

output "nat_gateway_eip" {
  description = "Elastic IP address of NAT Gateway"
  value       = module.nat_gateway.nat_gateway_eip
}

# Output in SSM Parameter Store for CloudFormation to consume
resource "aws_ssm_parameter" "vpc_id" {
  name  = "/git-captain/infrastructure/vpc-id"
  type  = "String"
  value = module.vpc.vpc_id
  
  tags = {
    Name = "git-captain-vpc-id"
  }
}

resource "aws_ssm_parameter" "public_subnets" {
  name  = "/git-captain/infrastructure/public-subnet-ids"
  type  = "StringList"
  value = join(",", module.vpc.public_subnet_ids)
  
  tags = {
    Name = "git-captain-public-subnets"
  }
}

resource "aws_ssm_parameter" "private_subnets" {
  name  = "/git-captain/infrastructure/private-subnet-ids"
  type  = "StringList"
  value = join(",", module.vpc.private_subnet_ids)
  
  tags = {
    Name = "git-captain-private-subnets"
  }
}

resource "aws_ssm_parameter" "alb_sg" {
  name  = "/git-captain/infrastructure/alb-security-group-id"
  type  = "String"
  value = module.security_groups.alb_security_group_id
  
  tags = {
    Name = "git-captain-alb-sg"
  }
}

resource "aws_ssm_parameter" "ec2_sg" {
  name  = "/git-captain/infrastructure/ec2-security-group-id"
  type  = "String"
  value = module.security_groups.ec2_security_group_id
  
  tags = {
    Name = "git-captain-ec2-sg"
  }
}

resource "aws_ssm_parameter" "rds_sg" {
  name  = "/git-captain/infrastructure/rds-security-group-id"
  type  = "String"
  value = module.security_groups.rds_security_group_id
  
  tags = {
    Name = "git-captain-rds-sg"
  }
}
