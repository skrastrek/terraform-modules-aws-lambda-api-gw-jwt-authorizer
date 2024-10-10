data "aws_region" "current" {}

locals {
  resources_path = "${path.module}/resources"
}

data "external" "npm_build" {
  program = [
    "bash", "-c", <<EOT
(npm ci && npm run build) >&2 && echo "{\"filename\": \"index.js\"}"
EOT
  ]
  working_dir = local.resources_path
}

data "archive_file" "zip" {
  type        = "zip"
  source_file = "${local.resources_path}/dist/${data.external.npm_build.result.filename}"
  output_path = "${local.resources_path}/lambda.zip"
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  description   = var.description

  role = aws_iam_role.this.arn

  publish = true

  runtime       = "nodejs20.x"
  architectures = ["arm64"]

  memory_size = var.memory_size

  handler = var.payload_format_version == "1.0" ? "index.handlerV1" : "index.handlerV2"

  package_type     = title(data.archive_file.zip.type)
  filename         = data.archive_file.zip.output_path
  source_code_hash = data.archive_file.zip.output_base64sha256

  logging_config {
    log_format            = var.logging_config.log_format
    application_log_level = var.logging_config.application_log_level
    system_log_level      = var.logging_config.system_log_level
  }

  environment {
    variables = {
      JWT_AUDIENCE            = var.jwt_config.audience != null ? join(",", var.jwt_config.audience) : null
      JWT_COGNITO_CLIENT_ID   = var.jwt_config.cognito_client_id != null ? join(",", var.jwt_config.cognito_client_id) : null
      JWT_COGNITO_GROUP       = var.jwt_config.cognito_group != null ? join(",", var.jwt_config.cognito_group) : null
      JWT_COGNITO_TOKEN_USE   = var.jwt_config.cognito_token_use
      JWT_ISSUER              = var.jwt_config.issuer
      JWT_SCOPE               = var.jwt_config.scope != null ? join(",", var.jwt_config.scope) : null
      JWT_SOURCE_HEADER_NAME  = var.jwt_config.source_header_name
      JWT_SOURCE_COOKIE_REGEX = var.jwt_config.source_cookie_regex
    }
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id

  tags = var.tags
}
