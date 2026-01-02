output "region" {
  description = "Região AWS utilizada nesta instância regional."
  value       = var.aws_region
}

output "vpc_id" {
  description = "ID da VPC criada."
  value       = local.enable_vpc ? aws_vpc.this[0].id : null
}

output "eks_cluster_name" {
  description = "Nome do cluster EKS."
  value       = local.enable_eks ? aws_eks_cluster.this[0].name : null
}

output "eks_cluster_endpoint" {
  description = "Endpoint do cluster EKS."
  value       = local.enable_eks ? aws_eks_cluster.this[0].endpoint : null
}

output "nodegroup_name" {
  description = "Nome do node group padrão."
  value       = local.enable_eks ? aws_eks_node_group.this[0].node_group_name : null
}

output "dynamodb_table_name" {
  description = "Nome da tabela DynamoDB de itens."
  value       = local.enable_dynamodb ? aws_dynamodb_table.logs[0].name : null
}

output "ecr_repository_urls" {
  description = "ECR repository URLs for backend/frontend."
  value       = local.enable_ecr ? { for k, r in aws_ecr_repository.this : k => r.repository_url } : {}
}

output "slack_secret_name" {
  value = aws_secretsmanager_secret.backend_slack.name
}

output "slack_secret_arn" {
  value = aws_secretsmanager_secret.backend_slack.arn
}