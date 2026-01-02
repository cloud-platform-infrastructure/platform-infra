locals {
  enable_vpc = var.feature_flags.vpc
}

# VPC
resource "aws_vpc" "this" {
  count                = local.enable_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-vpc"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "this" {
  count  = local.enable_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-igw"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }
}

locals {
  public_subnets_map = {
    for idx, cidr in var.public_cidrs :
    idx => {
      cidr = cidr
      az   = var.azs[idx]
    }
  }

  private_subnets_map = {
    for idx, cidr in var.private_cidrs :
    idx => {
      cidr = cidr
      az   = var.azs[idx]
    }
  }
}

# Subnets públicas
resource "aws_subnet" "public" {
  for_each = local.enable_vpc ? local.public_subnets_map : {}

  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-public-${each.key}"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
    # Tag padrão para ELB público do EKS
    "kubernetes.io/role/elb" = "1"
  }
}

# Subnets privadas
resource "aws_subnet" "private" {
  for_each = local.enable_vpc ? local.private_subnets_map : {}

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-private-${each.key}"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
    # Tag padrão para ELB interno do EKS
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# NAT Gateway (Multi-AZ: 1 NAT por AZ / subnet pública)
resource "aws_eip" "nat" {
  for_each = local.enable_vpc ? aws_subnet.public : {}
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-nat-eip-${each.key}"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }
}

resource "aws_nat_gateway" "this" {
  for_each      = local.enable_vpc ? aws_subnet.public : {}
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-nat-${each.key}"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }

  depends_on = [aws_internet_gateway.this]
}

# Route tables
# Public route table: 0.0.0.0/0 → IGW
resource "aws_route_table" "public" {
  count  = local.enable_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-public-rt"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }
}

# Association public subnets → public RT
resource "aws_route_table_association" "public" {
  for_each       = local.enable_vpc ? aws_subnet.public : {}
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[0].id
}

# Private route tables
resource "aws_route_table" "private" {
  for_each = local.enable_vpc ? aws_subnet.private : {}
  vpc_id   = aws_vpc.this[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[each.key].id
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-private-rt-${each.key}"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "vpc"
  }
}

# Association private subnets → private RT
resource "aws_route_table_association" "private" {
  for_each       = local.enable_vpc ? aws_subnet.private : {}
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}