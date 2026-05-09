output "vpc_id" {
  description = "ID of the VPC AGCMS is deployed into."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (for EKS workers, RDS, ElastiCache)."
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs (for load balancers)."
  value       = aws_subnet.public[*].id
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.this.name
}

output "eks_cluster_endpoint" {
  description = "Kubernetes API endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "eks_cluster_certificate_authority" {
  description = "Base64-encoded cluster CA certificate."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "eks_oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider — required for additional IRSA roles."
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "kubeconfig_command" {
  description = "Command to populate kubeconfig for this cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${aws_eks_cluster.this.name}"
}

output "rds_endpoint" {
  description = "RDS Postgres endpoint (host only)."
  value       = aws_db_instance.postgres.address
}

output "rds_port" {
  description = "RDS Postgres port."
  value       = aws_db_instance.postgres.port
}

output "rds_database_name" {
  description = "Default database name."
  value       = aws_db_instance.postgres.db_name
}

output "redis_primary_endpoint" {
  description = "ElastiCache Redis primary endpoint."
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "redis_reader_endpoint" {
  description = "ElastiCache Redis reader endpoint."
  value       = aws_elasticache_replication_group.redis.reader_endpoint_address
}

output "audit_anchor_bucket_name" {
  description = "S3 bucket holding signed audit-anchor manifests with Object Lock."
  value       = aws_s3_bucket.audit_anchors.bucket
}

output "audit_anchor_bucket_arn" {
  description = "ARN of the audit-anchor bucket."
  value       = aws_s3_bucket.audit_anchors.arn
}

output "kms_platform_key_arn" {
  description = "Platform envelope encryption KEK ARN — set as AGCMS_KMS_PLATFORM_KEY."
  value       = aws_kms_key.platform.arn
}

output "kms_rds_key_arn" {
  description = "KMS key used to encrypt RDS storage."
  value       = aws_kms_key.rds.arn
}

output "kms_s3_key_arn" {
  description = "KMS key used to encrypt the audit-anchor bucket."
  value       = aws_kms_key.s3.arn
}

output "audit_service_role_arn" {
  description = "IRSA role ARN to annotate the audit service account with."
  value       = aws_iam_role.audit_service.arn
}

output "secret_database_url_arn" {
  description = "ARN of the Secrets Manager entry holding DATABASE_URL."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "secret_redis_url_arn" {
  description = "ARN of the Secrets Manager entry holding REDIS_URL."
  value       = aws_secretsmanager_secret.redis_url.arn
}
