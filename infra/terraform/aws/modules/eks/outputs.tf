output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority" {
  description = "Base64-encoded cluster CA certificate."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "node_security_group_id" {
  description = "Security group attached to worker nodes."
  value       = aws_security_group.nodes.id
}

output "cluster_security_group_id" {
  description = "Security group attached to the control plane."
  value       = aws_security_group.cluster.id
}

output "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider — required for additional IRSA roles."
  value       = aws_iam_openid_connect_provider.this.arn
}

output "oidc_issuer_url" {
  description = "OIDC issuer URL (without the https:// prefix)."
  value       = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
}
