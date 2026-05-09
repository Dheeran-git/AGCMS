output "vpc_id" {
  description = "ID of the VPC AGCMS is deployed into."
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (for EKS workers, RDS, ElastiCache)."
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs (for load balancers)."
  value       = module.vpc.public_subnet_ids
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster."
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Kubernetes API endpoint."
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_certificate_authority" {
  description = "Base64-encoded cluster CA certificate."
  value       = module.eks.cluster_certificate_authority
}

output "eks_oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider — required for additional IRSA roles."
  value       = module.eks.oidc_provider_arn
}

output "kubeconfig_command" {
  description = "Command to populate kubeconfig for this cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "rds_endpoint" {
  description = "RDS Postgres endpoint (host only)."
  value       = module.rds.endpoint
}

output "rds_port" {
  description = "RDS Postgres port."
  value       = module.rds.port
}

output "rds_database_name" {
  description = "Default database name."
  value       = module.rds.database_name
}

output "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint."
  value       = module.redis.primary_endpoint
}

output "redis_reader_endpoint" {
  description = "ElastiCache Redis reader endpoint."
  value       = module.redis.reader_endpoint
}

output "audit_anchor_bucket_name" {
  description = "S3 bucket holding signed audit-anchor manifests with Object Lock."
  value       = module.s3_anchors.bucket_name
}

output "audit_anchor_bucket_arn" {
  description = "ARN of the audit-anchor bucket."
  value       = module.s3_anchors.bucket_arn
}

output "kms_platform_key_arn" {
  description = "Platform envelope encryption KEK ARN — set as AGCMS_KMS_PLATFORM_KEY."
  value       = module.kms.platform_key_arn
}

output "kms_rds_key_arn" {
  description = "KMS key used to encrypt RDS storage."
  value       = module.kms.rds_key_arn
}

output "kms_s3_key_arn" {
  description = "KMS key used to encrypt the audit-anchor bucket."
  value       = module.kms.s3_key_arn
}

output "audit_service_role_arn" {
  description = "IRSA role ARN to annotate the audit service account with."
  value       = module.iam.audit_service_role_arn
}

output "secret_database_url_arn" {
  description = "ARN of the Secrets Manager entry holding DATABASE_URL."
  value       = module.iam.secret_database_url_arn
}

output "secret_redis_url_arn" {
  description = "ARN of the Secrets Manager entry holding REDIS_URL."
  value       = module.iam.secret_redis_url_arn
}
