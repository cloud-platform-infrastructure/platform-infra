terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  cloud {
    organization = "guilherme_cloud"

    workspaces {
      project = "aws-infrastructure"
      tags = ["repo:infrastructure"]
    }
  }
}

provider "aws" {
  region = var.region
}
