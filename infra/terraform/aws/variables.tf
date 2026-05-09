variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag (dev|staging|prod). Drives naming + retention defaults."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "project" {
  description = "Project tag, used as a prefix on shared names."
  type        = string
  default     = "agcms"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "AZs to spread subnets across. Leave empty to auto-select first 3 in region."
  type        = list(string)
  default     = []
}

variable "eks_cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.29"
}

variable "eks_node_instance_types" {
  description = "Instance types for the managed EKS node group."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "eks_node_desired_size" {
  description = "Desired node count for the managed node group."
  type        = number
  default     = 3
}

variable "eks_node_min_size" {
  description = "Minimum node count."
  type        = number
  default     = 2
}

variable "eks_node_max_size" {
  description = "Maximum node count."
  type        = number
  default     = 8
}

variable "rds_instance_class" {
  description = "Instance class for the RDS Postgres database."
  type        = string
  default     = "db.m6g.large"
}

variable "rds_allocated_storage_gb" {
  description = "Allocated storage for RDS (GB)."
  type        = number
  default     = 100
}

variable "rds_max_allocated_storage_gb" {
  description = "Autoscaling storage cap for RDS (GB)."
  type        = number
  default     = 500
}

variable "rds_engine_version" {
  description = "Postgres engine version."
  type        = string
  default     = "16.3"
}

variable "rds_backup_retention_days" {
  description = "Automated backup retention (days). SOC 2 minimum is 7."
  type        = number
  default     = 30
}

variable "rds_multi_az" {
  description = "Enable Multi-AZ for RDS."
  type        = bool
  default     = true
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type."
  type        = string
  default     = "cache.m6g.large"
}

variable "redis_num_cache_clusters" {
  description = "Number of Redis replicas including primary."
  type        = number
  default     = 2
}

variable "audit_anchor_retention_years" {
  description = "Default S3 Object Lock retention (years) for audit anchor manifests. Can be overridden per object up to this ceiling. Minimum 7 for SOC 2."
  type        = number
  default     = 7

  validation {
    condition     = var.audit_anchor_retention_years >= 1 && var.audit_anchor_retention_years <= 100
    error_message = "audit_anchor_retention_years must be between 1 and 100."
  }
}

variable "audit_anchor_bucket_name" {
  description = "Explicit S3 bucket name for audit anchors. Leave empty to auto-generate."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags applied to every resource."
  type        = map(string)
  default     = {}
}
