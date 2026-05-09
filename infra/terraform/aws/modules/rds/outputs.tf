output "endpoint" {
  description = "RDS Postgres endpoint (host only)."
  value       = aws_db_instance.this.address
}

output "port" {
  description = "RDS Postgres port."
  value       = aws_db_instance.this.port
}

output "database_name" {
  description = "Default database name."
  value       = aws_db_instance.this.db_name
}

output "security_group_id" {
  description = "Security group ID attached to the DB."
  value       = aws_security_group.this.id
}

output "password" {
  description = "Generated master password (sensitive)."
  value       = random_password.this.result
  sensitive   = true
}

output "username" {
  description = "Master username."
  value       = aws_db_instance.this.username
}
