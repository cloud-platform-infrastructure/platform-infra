resource "aws_secretsmanager_secret" "backend_slack" {
  name                    = "backend/${var.environment}/slack"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "backend_slack" {
  secret_id = aws_secretsmanager_secret.backend_slack.id

  secret_string = jsonencode({
    SLACK_BOT_TOKEN  = var.slack_bot_token
    SLACK_CHANNEL_ID = var.slack_channel_id
  })
}