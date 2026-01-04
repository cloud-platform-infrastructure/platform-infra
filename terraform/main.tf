locals {
  network = var.network_by_region[var.region]
}

module "region" {
  source = "./modules/region"

  region_key = var.region_key
  aws_region = var.region

  vpc_cidr      = local.network.cidr
  azs           = local.network.azs
  public_cidrs  = local.network.public_subnets
  private_cidrs = local.network.private_subnets

  project_name = var.project_name
  environment  = var.environment

  ecr_keep_last_images = var.ecr_keep_last_images
  ecr_repositories     = var.ecr_repositories

  feature_flags = var.feature_flags

  kubectl_trusted_principals = var.kubectl_trusted_principals

  slack_bot_token  = var.slack_bot_token
  slack_channel_id = var.slack_channel_id
}