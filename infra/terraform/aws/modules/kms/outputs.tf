output "platform_key_id" {
  description = "Key ID of the platform envelope KEK."
  value       = aws_kms_key.platform.key_id
}

output "platform_key_arn" {
  description = "ARN of the platform envelope KEK."
  value       = aws_kms_key.platform.arn
}

output "rds_key_id" {
  description = "Key ID of the RDS storage encryption key."
  value       = aws_kms_key.rds.key_id
}

output "rds_key_arn" {
  description = "ARN of the RDS storage encryption key."
  value       = aws_kms_key.rds.arn
}

output "s3_key_id" {
  description = "Key ID of the S3 audit-anchor encryption key."
  value       = aws_kms_key.s3.key_id
}

output "s3_key_arn" {
  description = "ARN of the S3 audit-anchor encryption key."
  value       = aws_kms_key.s3.arn
}
