output "bucket_id" {
  description = "ID (name) of the audit-anchor bucket."
  value       = aws_s3_bucket.this.id
}

output "bucket_name" {
  description = "Name of the audit-anchor bucket."
  value       = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  description = "ARN of the audit-anchor bucket."
  value       = aws_s3_bucket.this.arn
}
