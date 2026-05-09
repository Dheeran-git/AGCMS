variable "name_prefix" {
  description = "Prefix applied to Redis resource names."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID hosting the cache."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the cache subnet group."
  type        = list(string)
}

variable "eks_node_security_group_id" {
  description = "Security group ID of EKS nodes (granted ingress on 6379)."
  type        = string
}

variable "node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.m6g.large"
}

variable "num_cache_clusters" {
  description = "Number of Redis replicas including primary."
  type        = number
  default     = 2
}
