variable "name_prefix" {
  description = "Prefix applied to IAM + Secrets Manager resource names."
  type        = string
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider (from eks module)."
  type        = string
}

variable "oidc_issuer_url" {
  description = "OIDC issuer URL without the https:// prefix (from eks module)."
  type        = string
}

variable "audit_anchor_bucket_arn" {
  description = "ARN of the audit-anchor S3 bucket."
  type        = string
}

variable "platform_kms_key_arn" {
  description = "ARN of the platform envelope KEK."
  type        = string
}

variable "s3_kms_key_arn" {
  description = "ARN of the KMS key used to encrypt audit anchor objects."
  type        = string
}

variable "rds_endpoint" {
  description = "RDS Postgres host."
  type        = string
}

variable "rds_port" {
  description = "RDS Postgres port."
  type        = number
}

variable "rds_database_name" {
  description = "RDS default database name."
  type        = string
}

variable "rds_username" {
  description = "RDS master username."
  type        = string
}

variable "rds_password" {
  description = "RDS master password."
  type        = string
  sensitive   = true
}

variable "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint."
  type        = string
}

variable "redis_auth_token" {
  description = "ElastiCache Redis AUTH token."
  type        = string
  sensitive   = true
}
