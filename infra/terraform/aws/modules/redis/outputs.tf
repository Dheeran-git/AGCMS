output "primary_endpoint" {
  description = "ElastiCache Redis primary endpoint."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint" {
  description = "ElastiCache Redis reader endpoint."
  value       = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "security_group_id" {
  description = "Security group ID attached to the cache."
  value       = aws_security_group.this.id
}

output "auth_token" {
  description = "Generated AUTH token (sensitive)."
  value       = random_password.auth.result
  sensitive   = true
}
