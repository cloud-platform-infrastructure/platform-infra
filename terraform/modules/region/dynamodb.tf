locals {
  enable_dynamodb = var.feature_flags.dynamodb
}

resource "aws_dynamodb_table" "logs" {
  count        = var.feature_flags.dynamodb ? 1 : 0
  name         = "${var.project_name}-${var.environment}-${var.region_key}-logs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    RegionKey   = var.region_key
    Module      = "logs-service"
  }
}
