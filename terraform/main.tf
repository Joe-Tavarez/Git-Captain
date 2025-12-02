/**
 * Main Terraform Configuration for Git-Captain AWS Infrastructure
 * Orchestrates VPC, Security Groups, and NAT Gateway modules
 */

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Optional: Configure S3 backend for state management
  # backend "s3" {
  #   bucket         = "git-captain-terraform-state"
  #   key            = "infrastructure/terraform.tfstate"
  #   region         = "us-east-2"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

# VPC Module - Creates VPC with public and private subnets
module "vpc" {
  source = "./modules/vpc"

  project_name         = var.project_name
  environment          = var.environment
  vpc_cidr             = var.vpc_cidr
  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
}

# Security Groups Module - Creates security groups for ALB, EC2, RDS, Lambda
module "security_groups" {
  source = "./modules/security-groups"

  project_name    = var.project_name
  environment     = var.environment
  vpc_id          = module.vpc.vpc_id
  vpc_cidr        = var.vpc_cidr
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

# NAT Gateway Module - Creates NAT Gateway for private subnet internet access
module "nat_gateway" {
  source = "./modules/nat-gateway"

  project_name           = var.project_name
  environment            = var.environment
  public_subnet_id       = module.vpc.public_subnet_ids[0]
  private_route_table_id = module.vpc.private_route_table_id
}
