variable "name" {
  type = string
}

variable "description" {
  type    = string
  default = null
}

variable "cloudwatch_log_group_retention_in_days" {
  type = number
}

variable "cloudwatch_log_group_kms_key_id" {
  type    = string
  default = null
}

variable "jwt_config" {
  type = object({
    audience            = list(string)
    issuer              = string
    scope               = optional(list(string), null)
    source_header_name  = optional(string, "Authorization")
    source_cookie_regex = optional(string, null)
    cognito_client_id   = optional(list(string), null)
    cognito_group       = optional(string, null)
    cognito_token_use   = optional(string, null)
  })

  validation {
    condition     = var.jwt_config.cognito_token_use == "access" || var.jwt_config.cognito_token_use == "id" || var.jwt_config.cognito_token_use == null
    error_message = "jwt_config.cognito_token_use value must be either 'access', 'id' or null"
  }
}

variable "logging_config" {
  type = object({
    log_format            = optional(string, "JSON")
    application_log_level = optional(string, "INFO")
    system_log_level      = optional(string, "WARN")
  })
  default = {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
  }
}

variable "memory_size" {
  type = number
}

variable "payload_format_version" {
  type = string

  validation {
    condition     = var.payload_format_version == "1.0" || var.payload_format_version == "2.0"
    error_message = "payload_format_version value must be either '1.0' or '2.0'."
  }
}

variable "tags" {
  type = map(string)
}
