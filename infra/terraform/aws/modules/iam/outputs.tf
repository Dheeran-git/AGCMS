output "audit_service_role_arn" {
  description = "IRSA role ARN to annotate the audit ServiceAccount with."
  value       = aws_iam_role.audit_service.arn
}

output "audit_service_role_name" {
  description = "IRSA role name."
  value       = aws_iam_role.audit_service.name
}

output "secret_database_url_arn" {
  description = "ARN of the Secrets Manager entry holding DATABASE_URL."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "secret_redis_url_arn" {
  description = "ARN of the Secrets Manager entry holding REDIS_URL."
  value       = aws_secretsmanager_secret.redis_url.arn
}
