variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet ID where NAT Gateway will be created"
  type        = string
}

variable "private_route_table_id" {
  description = "Private route table ID to add NAT Gateway route"
  type        = string
}
