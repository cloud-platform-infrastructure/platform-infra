locals {
  enable_eks = var.feature_flags.eks && var.feature_flags.vpc
}

data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_cluster" {
  count = local.enable_eks ? 1 : 0

  name = "${var.project_name}-${var.environment}-${var.region_key}-eks-cluster-role"

  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks"
  }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
  count      = local.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSVPCResourceController" {
  count      = local.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

# Security Group do CLUSTER
resource "aws_security_group" "eks_cluster" {
  count       = local.enable_eks ? 1 : 0
  name        = "${var.project_name}-${var.environment}-${var.region_key}-eks-cluster-sg"
  description = "Cluster security group for EKS"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description = "Allow worker nodes to access cluster API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-eks-cluster-sg"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks"
  }
}

# CLUSTER EKS
resource "aws_eks_cluster" "this" {
  count    = local.enable_eks ? 1 : 0
  name     = "${var.project_name}-${var.environment}-${var.region_key}-eks"
  role_arn = aws_iam_role.eks_cluster[0].arn
  version  = "1.34"

  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"
  }
  
  vpc_config {
    subnet_ids              = [for s in aws_subnet.private : s.id]
    security_group_ids      = [aws_security_group.eks_cluster[0].id]

    # endpoint_private_access = true
    endpoint_public_access  = true
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks"
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSVPCResourceController
  ]
}

# Installs the EKS Pod Identity Agent (required for EKS Pod Identity).
resource "aws_eks_addon" "pod_identity_agent" {
  count = local.enable_eks ? 1 : 0

  cluster_name = aws_eks_cluster.this[0].name
  addon_name   = "eks-pod-identity-agent"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "EKS-Pod-Identity-Agent"
  }

  depends_on = [
    aws_eks_cluster.this
  ]
}

# IAM Role dos WORKER NODES
data "aws_iam_policy_document" "eks_nodes_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_nodes" {
  count = local.enable_eks ? 1 : 0

  name = "${var.project_name}-${var.environment}-${var.region_key}-eks-nodes-role"

  assume_role_policy = data.aws_iam_policy_document.eks_nodes_assume_role.json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks"
  }
}

resource "aws_iam_role_policy_attachment" "eks_nodes_AmazonEKSWorkerNodePolicy" {
  count      = local.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_AmazonEKS_CNI_Policy" {
  count      = local.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_AmazonEC2ContainerRegistryReadOnly" {
  count      = local.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Security Group dos WORKER NODES
resource "aws_security_group" "eks_nodes" {
  count       = local.enable_eks ? 1 : 0
  name        = "${var.project_name}-${var.environment}-${var.region_key}-eks-nodes-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.this[0].id

  # Receber tráfego do cluster e dos próprios nodes (pods, etc)
  ingress {
    description = "Allow node-to-node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description     = "Allow cluster to talk to nodes"
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-${var.region_key}-eks-nodes-sg"
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks"
  }
}

# NODE GROUP (workers)

resource "aws_eks_node_group" "this" {
  count           = local.enable_eks ? 1 : 0
  cluster_name    = aws_eks_cluster.this[0].name
  node_group_name = "${var.project_name}-${var.environment}-${var.region_key}-ng"

  node_role_arn = aws_iam_role.eks_nodes[0].arn

  subnet_ids = [for s in aws_subnet.private : s.id]

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 2
  }

  instance_types = ["t3.small"]

  tags = {
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "eks-nodegroup"
  }

  depends_on = [
    aws_eks_cluster.this,
    aws_iam_role_policy_attachment.eks_nodes_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eks_nodes_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eks_nodes_AmazonEC2ContainerRegistryReadOnly
  ]
}