resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name_prefix}-redis"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-redis"
  description = "Allow Redis from EKS nodes only."
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-redis"
  }
}

resource "aws_security_group_rule" "ingress_from_eks" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = var.eks_node_security_group_id
  security_group_id        = aws_security_group.this.id
  description              = "Redis from EKS nodes"
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.this.id
}

resource "random_password" "auth" {
  length           = 48
  special          = false
  override_special = ""
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id       = "${var.name_prefix}-redis"
  description                = "AGCMS rate-limiter + cache"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.node_type
  port                       = 6379
  parameter_group_name       = "default.redis7"
  subnet_group_name          = aws_elasticache_subnet_group.this.name
  security_group_ids         = [aws_security_group.this.id]
  num_cache_clusters         = var.num_cache_clusters
  automatic_failover_enabled = var.num_cache_clusters > 1
  multi_az_enabled           = var.num_cache_clusters > 1
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.auth.result
  snapshot_retention_limit   = 7
  snapshot_window            = "02:00-03:00"
  maintenance_window         = "sun:05:00-sun:06:00"
  apply_immediately          = false

  tags = {
    Name = "${var.name_prefix}-redis"
  }
}
