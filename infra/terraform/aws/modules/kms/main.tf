resource "aws_kms_key" "platform" {
  description             = "${var.name_prefix} platform envelope encryption key (KEK for per-tenant DEKs)."
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  tags = {
    Name    = "${var.name_prefix}-platform-kek"
    Purpose = "envelope-encryption"
  }
}

resource "aws_kms_alias" "platform" {
  name          = "alias/${var.name_prefix}-platform-kek"
  target_key_id = aws_kms_key.platform.key_id
}

resource "aws_kms_key" "rds" {
  description             = "${var.name_prefix} RDS Postgres storage encryption."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name    = "${var.name_prefix}-rds"
    Purpose = "rds-storage-encryption"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "s3" {
  description             = "${var.name_prefix} S3 audit-anchor bucket encryption."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name    = "${var.name_prefix}-s3"
    Purpose = "s3-audit-anchors"
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.name_prefix}-s3"
  target_key_id = aws_kms_key.s3.key_id
}
