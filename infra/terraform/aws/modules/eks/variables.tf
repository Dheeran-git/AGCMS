variable "name_prefix" {
  description = "Prefix applied to EKS resources. Used as the cluster name."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID hosting the cluster."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (workers run here)."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs (load balancers attach here)."
  type        = list(string)
}

variable "platform_kms_key_arn" {
  description = "KMS key ARN used for envelope encryption of cluster secrets."
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.29"
}

variable "node_instance_types" {
  description = "Instance types for the managed node group."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "node_desired_size" {
  description = "Desired node count."
  type        = number
  default     = 3
}

variable "node_min_size" {
  description = "Minimum node count."
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum node count."
  type        = number
  default     = 8
}
