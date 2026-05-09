variable "name_prefix" {
  description = "Prefix applied to RDS resource names."
  type        = string
}

variable "environment" {
  description = "Environment tag (dev|staging|prod). Drives deletion protection + final snapshot."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID hosting the database."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the DB subnet group."
  type        = list(string)
}

variable "eks_node_security_group_id" {
  description = "Security group ID of EKS nodes (granted ingress on 5432)."
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt storage + Performance Insights."
  type        = string
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.m6g.large"
}

variable "engine_version" {
  description = "Postgres engine version."
  type        = string
  default     = "16.3"
}

variable "allocated_storage_gb" {
  description = "Allocated storage (GB)."
  type        = number
  default     = 100
}

variable "max_allocated_storage_gb" {
  description = "Storage autoscaling cap (GB)."
  type        = number
  default     = 500
}

variable "backup_retention_days" {
  description = "Automated backup retention (days). SOC 2 minimum is 7."
  type        = number
  default     = 30
}

variable "multi_az" {
  description = "Enable Multi-AZ."
  type        = bool
  default     = true
}
