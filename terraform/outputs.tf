output "eks_cluster_name" {
  description = "Nome do cluster EKS criado na região principal."
  value       = module.region.eks_cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint do cluster EKS."
  value       = module.region.eks_cluster_endpoint
}

output "eks_cluster_region" {
  description = "Região AWS do cluster EKS."
  value       = module.region.region
}

output "nodegroup_name" {
  description = "Nome do node group principal."
  value       = module.region.nodegroup_name
}

output "dynamodb_table_name" {
  description = "Nome da tabela DynamoDB de itens."
  value       = module.region.dynamodb_table_name
}

output "ecr_backend_repository" {
  description = "URL do repositório ECR para o backend."
  value       = module.region.ecr_repository_urls.backend
}

output "ecr_frontend_repository" {
  description = "URL do repositório ECR para o frontend."
  value       = module.region.ecr_repository_urls.frontend
}

output "slack_secret_arn" {
  value = module.region.slack_secret_arn
}