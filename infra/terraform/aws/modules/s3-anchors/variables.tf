variable "bucket_name" {
  description = "Name of the audit-anchor S3 bucket."
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt anchor objects."
  type        = string
}

variable "retention_years" {
  description = "Default Object Lock COMPLIANCE retention (years). Once written it cannot be reduced — only extended."
  type        = number

  validation {
    condition     = var.retention_years >= 1 && var.retention_years <= 100
    error_message = "retention_years must be between 1 and 100."
  }
}
