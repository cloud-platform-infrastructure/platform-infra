variable "region_key" {
  description = "Chave lógica da região (ex: use1, euw2)."
  type        = string
}

variable "aws_region" {
  description = "Região AWS (ex: us-east-1)."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR da VPC."
  type        = string
}

variable "azs" {
  description = "Lista de AZs usadas na região."
  type        = list(string)
}

variable "public_cidrs" {
  description = "Lista de CIDRs para as subnets públicas."
  type        = list(string)
}

variable "private_cidrs" {
  description = "Lista de CIDRs para as subnets privadas."
  type        = list(string)
}

variable "project_name" {
  description = "Nome base do projeto."
  type        = string
}

variable "environment" {
  description = "Ambiente (dev, staging, prod)."
  type        = string
}

variable "ecr_keep_last_images" {
  description = "How many images to keep per ECR repository via lifecycle policy."
  type        = number
}

variable "ecr_repositories" {
  description = "Logical ECR repositories to create. Names are built as <project_name>-<environment>-<value>."
  type        = map(string)
}

variable "kubectl_trusted_principals" {
  description = "Principals (IAM Users or Roles) allowed to assume the kubectl admin role."
  type        = list(string)
}

variable "slack_bot_token" {
  type      = string
  sensitive = true
}

variable "slack_channel_id" {
  type      = string
  sensitive = true
}

variable "feature_flags" {
  description = "Master flag map to enable/disable components for this region."
  type = object({
    vpc      = bool
    eks      = bool
    ecr      = bool
    dynamodb = bool
  })
}