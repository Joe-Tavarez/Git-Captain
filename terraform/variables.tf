/**
 * Terraform Variables for Git-Captain AWS Infrastructure
 * Define all input variables for the infrastructure deployment
 */

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "git-captain"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones for high availability"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (ALB)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (EC2, RDS)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into EC2 instances (use your IP)"
  type        = string
  default     = "0.0.0.0/0" # WARNING: Restrict to your IP in production
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "Git-Captain"
    ManagedBy   = "Terraform"
    Environment = "Production"
    Owner       = "Joe-Tavarez"
  }
}
