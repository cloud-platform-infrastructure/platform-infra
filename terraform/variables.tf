variable "region" {
  description = "Região AWS onde o EKS será criado."
  type        = string
  default     = "us-east-1"
}

variable "region_key" {
  description = "Chave lógica da região (ex: use1, euw2)."
  type        = string
  default     = "use1"
}

variable "project_name" {
  description = "Nome base do projeto/sistema."
  type        = string
  default     = "slack-enterprise-study"
}

variable "environment" {
  description = "Ambiente (dev, staging, prod, etc)."
  type        = string
  default     = "dev"
}

# Configuração de rede agrupada por região
variable "network_by_region" {
  description = "CIDR, sub-redes públicas/privadas e AZs por região"
  type = map(object({
    cidr            = string
    public_subnets  = list(string)
    private_subnets = list(string)
    azs             = list(string)
  }))

  default = {
    "us-east-1" = {
      cidr            = "10.10.0.0/16"
      public_subnets  = ["10.10.1.0/24", "10.10.2.0/24"]
      private_subnets = ["10.10.101.0/24", "10.10.102.0/24"]
      azs             = ["us-east-1a", "us-east-1b"]
    }
  }
}

variable "ecr_keep_last_images" {
  description = "How many images to keep per ECR repository via lifecycle policy."
  type        = number
  default     = 30
}

variable "ecr_repositories" {
  description = "Logical ECR repositories to create (keys become Component tag values). Names are built as <project_name>-<environment>-<value>."
  type        = map(string)

  default = {
    backend  = "backend"
    frontend = "frontend"
  }
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

# Unified feature-flag map
variable "feature_flags" {
  description = "Master flag map to enable/disable infrastructure components."
  type = object({
    vpc      = bool
    eks      = bool
    ecr      = bool
    dynamodb = bool
  })

  default = {
    vpc      = true
    eks      = true
    ecr      = true
    dynamodb = true
  }
}
