/**
 * NAT Gateway Module - Creates NAT Gateway for private subnet internet access
 */

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-${var.environment}-nat-eip"
  }

  depends_on = [var.public_subnet_id]
}

# NAT Gateway in public subnet
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = var.public_subnet_id

  tags = {
    Name = "${var.project_name}-${var.environment}-nat-gateway"
  }
}

# Add route to private route table for internet access via NAT Gateway
resource "aws_route" "private_nat_gateway" {
  route_table_id         = var.private_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}
