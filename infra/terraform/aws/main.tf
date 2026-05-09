terraform {
  # Backend is intentionally left unconfigured here so callers can wire
  # remote state to their own S3+DynamoDB or Terraform Cloud workspace
  # via a backend.tf override or -backend-config at init time.
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix        = "${var.project}-${var.environment}"
  anchor_bucket_name = length(var.audit_anchor_bucket_name) > 0 ? var.audit_anchor_bucket_name : "${local.name_prefix}-audit-anchors-${data.aws_caller_identity.current.account_id}"
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

module "vpc" {
  source = "./modules/vpc"

  name_prefix        = local.name_prefix
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
}

# ---------------------------------------------------------------------------
# KMS — three customer-managed keys with rotation
# ---------------------------------------------------------------------------

module "kms" {
  source = "./modules/kms"

  name_prefix = local.name_prefix
}

# ---------------------------------------------------------------------------
# S3 audit-anchor bucket — Object Lock COMPLIANCE, SSE-KMS, lifecycle
# ---------------------------------------------------------------------------

module "s3_anchors" {
  source = "./modules/s3-anchors"

  bucket_name     = local.anchor_bucket_name
  kms_key_arn     = module.kms.s3_key_arn
  retention_years = var.audit_anchor_retention_years
}

# ---------------------------------------------------------------------------
# EKS — control plane + managed node group + OIDC for IRSA
# ---------------------------------------------------------------------------

module "eks" {
  source = "./modules/eks"

  name_prefix          = local.name_prefix
  vpc_id               = module.vpc.vpc_id
  private_subnet_ids   = module.vpc.private_subnet_ids
  public_subnet_ids    = module.vpc.public_subnet_ids
  platform_kms_key_arn = module.kms.platform_key_arn

  cluster_version     = var.eks_cluster_version
  node_instance_types = var.eks_node_instance_types
  node_desired_size   = var.eks_node_desired_size
  node_min_size       = var.eks_node_min_size
  node_max_size       = var.eks_node_max_size
}

# ---------------------------------------------------------------------------
# RDS Postgres — Multi-AZ, encrypted, only reachable from EKS nodes
# ---------------------------------------------------------------------------

module "rds" {
  source = "./modules/rds"

  name_prefix                = local.name_prefix
  environment                = var.environment
  vpc_id                     = module.vpc.vpc_id
  private_subnet_ids         = module.vpc.private_subnet_ids
  eks_node_security_group_id = module.eks.node_security_group_id
  kms_key_arn                = module.kms.rds_key_arn

  instance_class           = var.rds_instance_class
  engine_version           = var.rds_engine_version
  allocated_storage_gb     = var.rds_allocated_storage_gb
  max_allocated_storage_gb = var.rds_max_allocated_storage_gb
  backup_retention_days    = var.rds_backup_retention_days
  multi_az                 = var.rds_multi_az
}

# ---------------------------------------------------------------------------
# ElastiCache Redis — multi-AZ, encrypted in-transit + at-rest
# ---------------------------------------------------------------------------

module "redis" {
  source = "./modules/redis"

  name_prefix                = local.name_prefix
  vpc_id                     = module.vpc.vpc_id
  private_subnet_ids         = module.vpc.private_subnet_ids
  eks_node_security_group_id = module.eks.node_security_group_id

  node_type          = var.redis_node_type
  num_cache_clusters = var.redis_num_cache_clusters
}

# ---------------------------------------------------------------------------
# IAM — audit-service IRSA + Secrets Manager entries
# ---------------------------------------------------------------------------

module "iam" {
  source = "./modules/iam"

  name_prefix             = local.name_prefix
  oidc_provider_arn       = module.eks.oidc_provider_arn
  oidc_issuer_url         = module.eks.oidc_issuer_url
  audit_anchor_bucket_arn = module.s3_anchors.bucket_arn
  platform_kms_key_arn    = module.kms.platform_key_arn
  s3_kms_key_arn          = module.kms.s3_key_arn

  rds_endpoint           = module.rds.endpoint
  rds_port               = module.rds.port
  rds_database_name      = module.rds.database_name
  rds_username           = module.rds.username
  rds_password           = module.rds.password
  redis_primary_endpoint = module.redis.primary_endpoint
  redis_auth_token       = module.redis.auth_token
}
