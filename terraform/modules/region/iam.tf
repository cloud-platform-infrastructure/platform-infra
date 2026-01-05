locals {
  pod_identity_namespace       = "backend-${var.environment}"
  pod_identity_service_account = "backend"

  enable_pod_identity = local.enable_eks && local.enable_dynamodb

  external_secrets_namespace       = "external-secrets"
  external_secrets_service_account = "external-secrets"

  aws_cli_namespace       = "aws-cli-${var.environment}"
  aws_cli_service_account = "aws-cli"

  enable_aws_cli_pod_identity = local.enable_eks

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
        "repo:cloud-platform-infrastructure/deploy-workflows:ref:refs/heads/main",
        "repo:cloud-platform-infrastructure/app-frontend:ref:refs/heads/main",
      "repo:cloud-platform-infrastructure/app-backend:ref:refs/heads/main", ]
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

data "aws_iam_policy_document" "aws_cli_pod_identity_trust" {
  count = local.enable_aws_cli_pod_identity ? 1 : 0

  statement {
    sid    = "AllowEksAuthToAssumeRoleForAwsCli"
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
      values   = [local.aws_cli_namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = [local.aws_cli_service_account]
    }
  }
}

resource "aws_iam_role" "aws_cli_pod_identity" {
  count = local.enable_aws_cli_pod_identity ? 1 : 0

  name               = "${var.project_name}-${var.environment}-aws-cli-pod-identity"
  assume_role_policy = data.aws_iam_policy_document.aws_cli_pod_identity_trust[0].json

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "EKS-Pod-Identity-AWS-CLI"
  }
}

data "aws_iam_policy_document" "aws_cli_access" {
  count = local.enable_aws_cli_pod_identity ? 1 : 0

  statement {
    sid    = "StsIdentity"
    effect = "Allow"

    actions = [
      "sts:GetCallerIdentity",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "SecretsManagerRead"
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "EcrReadAndAuth"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
      "ecr:ListImages",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "DynamoDbReadAndQuery"
    effect = "Allow"

    actions = [
      "dynamodb:ListTables",
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:ExecuteStatement",
      "dynamodb:PartiQLSelect",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "S3BucketFullManagement"
    effect = "Allow"

    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:GetBucketVersioning",
      "s3:PutBucketVersioning",
      "s3:GetBucketTagging",
      "s3:PutBucketTagging",

      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload"
    ]

    resources = [
      "arn:aws:s3:::*",
      "arn:aws:s3:::*/*"
    ]
  }
}

resource "aws_iam_role_policy" "aws_cli_access" {
  count = local.enable_aws_cli_pod_identity ? 1 : 0

  name   = "${var.project_name}-${var.environment}-aws-cli-access"
  role   = aws_iam_role.aws_cli_pod_identity[0].name
  policy = data.aws_iam_policy_document.aws_cli_access[0].json
}

# Associate (cluster + namespace + serviceAccount) -> IAM role
resource "aws_eks_pod_identity_association" "aws_cli" {
  count = local.enable_aws_cli_pod_identity ? 1 : 0

  cluster_name    = aws_eks_cluster.this[0].name
  namespace       = local.aws_cli_namespace
  service_account = local.aws_cli_service_account
  role_arn        = aws_iam_role.aws_cli_pod_identity[0].arn

  depends_on = [
    aws_eks_addon.pod_identity_agent,
    aws_iam_role_policy.aws_cli_access,
  ]
}
