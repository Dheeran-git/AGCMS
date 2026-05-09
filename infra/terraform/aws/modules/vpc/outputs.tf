output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs (for load balancers)."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (for EKS workers, RDS, ElastiCache)."
  value       = aws_subnet.private[*].id
}

output "azs" {
  description = "Availability zones the VPC spans."
  value       = local.azs
}
