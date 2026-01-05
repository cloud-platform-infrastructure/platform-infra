locals {
  pod_identity_namespace       = "backend-${var.environment}"
  pod_identity_service_account = "backend"

  enable_pod_identity = local.enable_eks && local.enable_dynamodb

  external_secrets_namespace       = "external-secrets"
  external_secrets_service_account = "external-secrets"

  # ESO only needs EKS + Pod Identity Agent; it reads from Secrets Manager
  enable_external_secrets_pod_identity = local.enable_eks
}

data "aws_iam_policy_document" "kubectl_admin_trust" {
  count = local.enable_eks ? 1 : 0

  # Local / human access (AWS principals)
  statement {
    sid    = "AllowLocalUserAssumeRole"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = distinct(concat(
        var.kubectl_trusted_principals,
      ))
    }

    actions = ["sts:AssumeRole"]
  }

  # GitHub Actions OIDC access (web identity)
  statement {
    sid    = "AllowGitHubActionsOIDC"
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::765949264044:oidc-provider/token.actions.githubusercontent.com"]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:cloud-platform-infrastructure/platform-infra:ref:refs/heads/main",
      "repo:cloud-platform-infrastructure/deploy-workflows:ref:refs/heads/main"]
    }
  }
}

# IAM Role used by humans to run kubectl
resource "aws_iam_role" "kubectl_admin" {
  count = local.enable_eks ? 1 : 0

  name               = "${var.project_name}-${var.environment}-kubectl-admin"
  assume_role_policy = data.aws_iam_policy_document.kubectl_admin_trust[0].json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "EKS-Human-kubectl-access"
  }
}

# Register the IAM principal in the EKS control plane
resource "aws_eks_access_entry" "kubectl_admin" {
  count = local.enable_eks ? 1 : 0

  cluster_name  = aws_eks_cluster.this[0].name
  principal_arn = aws_iam_role.kubectl_admin[0].arn

  depends_on = [aws_eks_cluster.this]
}

# Grant Kubernetes permissions (cluster-admin)
resource "aws_eks_access_policy_association" "kubectl_admin_cluster_admin" {
  count = local.enable_eks ? 1 : 0

  cluster_name  = aws_eks_cluster.this[0].name
  principal_arn = aws_iam_role.kubectl_admin[0].arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.kubectl_admin]
}

data "aws_iam_policy_document" "dynamodb_pod_identity_trust" {
  count = local.enable_pod_identity ? 1 : 0

  statement {
    sid    = "AllowEksAuthToAssumeRoleForPodIdentity"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [local.pod_identity_namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [local.pod_identity_service_account]
    }
  }
}

resource "aws_iam_role" "dynamodb_pod_identity" {
  count = local.enable_pod_identity ? 1 : 0

  name               = "${var.project_name}-${var.environment}-dynamodb-pod-identity"
  assume_role_policy = data.aws_iam_policy_document.dynamodb_pod_identity_trust[0].json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "EKS-Pod-Identity-DynamoDB"
  }
}

# DynamoDB permissions (scope to your logs table) and Secrets Manager access
data "aws_iam_policy_document" "pod_identity_app_access" {
  count = local.enable_pod_identity ? 1 : 0

  statement {
    sid    = "DynamoDBLogsAccess"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
    ]

    resources = [
      aws_dynamodb_table.logs[0].arn,
    ]
  }
}

# Inline policy attached directly to the role (enterprise pattern; avoids separate attachment resources)
resource "aws_iam_role_policy" "pod_identity_app_access" {
  count = local.enable_pod_identity ? 1 : 0

  name   = "${var.project_name}-${var.environment}-pod-identity-app-access"
  role   = aws_iam_role.dynamodb_pod_identity[0].name
  policy = data.aws_iam_policy_document.pod_identity_app_access[0].json
}

# Associate (cluster + namespace + serviceAccount) -> IAM role
resource "aws_eks_pod_identity_association" "dynamodb" {
  count = local.enable_pod_identity ? 1 : 0

  cluster_name    = aws_eks_cluster.this[0].name
  namespace       = local.pod_identity_namespace
  service_account = local.pod_identity_service_account
  role_arn        = aws_iam_role.dynamodb_pod_identity[0].arn

  depends_on = [
    aws_eks_addon.pod_identity_agent,
    aws_iam_role_policy.pod_identity_app_access,
  ]
}

data "aws_iam_policy_document" "external_secrets_pod_identity_trust" {
  count = local.enable_external_secrets_pod_identity ? 1 : 0

  statement {
    sid    = "AllowEksAuthToAssumeRoleForExternalSecrets"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [local.external_secrets_namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [local.external_secrets_service_account]
    }
  }
}

resource "aws_iam_role" "external_secrets_pod_identity" {
  count = local.enable_external_secrets_pod_identity ? 1 : 0

  name               = "${var.project_name}-${var.environment}-external-secrets-pod-identity"
  assume_role_policy = data.aws_iam_policy_document.external_secrets_pod_identity_trust[0].json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "EKS-Pod-Identity-External-Secrets-Operator"
  }
}

# ESO needs to read Secrets Manager values so it can materialize Kubernetes Secrets
data "aws_iam_policy_document" "external_secrets_access" {
  count = local.enable_external_secrets_pod_identity ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "external_secrets_access" {
  count = local.enable_external_secrets_pod_identity ? 1 : 0

  name   = "${var.project_name}-${var.environment}-external-secrets-access"
  role   = aws_iam_role.external_secrets_pod_identity[0].name
  policy = data.aws_iam_policy_document.external_secrets_access[0].json
}

resource "aws_eks_pod_identity_association" "external_secrets" {
  count = local.enable_external_secrets_pod_identity ? 1 : 0

  cluster_name    = aws_eks_cluster.this[0].name
  namespace       = local.external_secrets_namespace
  service_account = local.external_secrets_service_account
  role_arn        = aws_iam_role.external_secrets_pod_identity[0].arn

  depends_on = [
    aws_eks_addon.pod_identity_agent,
    aws_iam_role_policy.external_secrets_access,
  ]
}
