resource "random_password" "this" {
  length           = 32
  special          = true
  override_special = "!#$%*()-_=+[]{}"
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-rds"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${var.name_prefix}-rds-subnets"
  }
}

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-rds"
  description = "Allow Postgres from EKS nodes only."
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-rds"
  }
}

resource "aws_security_group_rule" "ingress_from_eks" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_node_security_group_id
  security_group_id        = aws_security_group.this.id
  description              = "Postgres from EKS nodes"
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.this.id
}

resource "aws_db_parameter_group" "this" {
  name        = "${var.name_prefix}-pg16"
  family      = "postgres16"
  description = "AGCMS Postgres tuning."

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name_prefix}-postgres"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_name  = "agcms"
  username = "agcms"
  password = random_password.this.result
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false

  multi_az                              = var.multi_az
  backup_retention_period               = var.backup_retention_days
  backup_window                         = "03:00-04:00"
  maintenance_window                    = "Mon:04:30-Mon:05:30"
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  deletion_protection             = var.environment == "prod"
  skip_final_snapshot             = var.environment != "prod"
  final_snapshot_identifier       = var.environment == "prod" ? "${var.name_prefix}-postgres-final" : null
  copy_tags_to_snapshot           = true

  auto_minor_version_upgrade = true
  apply_immediately          = false

  tags = {
    Name = "${var.name_prefix}-postgres"
  }
}
