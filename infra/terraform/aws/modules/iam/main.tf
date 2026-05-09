data "aws_iam_policy_document" "audit_irsa_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer_url}:sub"
      values   = ["system:serviceaccount:agcms:agcms-audit"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_service" {
  name               = "${var.name_prefix}-audit-service"
  assume_role_policy = data.aws_iam_policy_document.audit_irsa_assume.json
  description        = "IRSA role for audit service — writes anchor manifests to S3 with Object Lock retention."
}

data "aws_iam_policy_document" "audit_service" {
  statement {
    sid    = "WriteAnchors"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectRetention",
      "s3:PutObjectLegalHold",
    ]
    resources = ["${var.audit_anchor_bucket_arn}/*"]
  }

  statement {
    sid    = "ReadAnchors"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectRetention",
      "s3:ListBucket",
      "s3:GetBucketObjectLockConfiguration",
    ]
    resources = [
      var.audit_anchor_bucket_arn,
      "${var.audit_anchor_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "KmsForS3"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.s3_kms_key_arn]
  }

  statement {
    sid    = "KmsForPlatform"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.platform_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "audit_service" {
  name   = "${var.name_prefix}-audit-service"
  role   = aws_iam_role.audit_service.id
  policy = data.aws_iam_policy_document.audit_service.json
}

# ---------------------------------------------------------------------------
# Secrets Manager — DB + Redis URLs (consumed by ExternalSecrets in cluster)
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "database_url" {
  name        = "${var.name_prefix}/database-url"
  description = "Postgres connection string for AGCMS services."
  kms_key_id  = var.platform_kms_key_arn
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = jsonencode({
    DATABASE_URL = "postgresql+asyncpg://${var.rds_username}:${var.rds_password}@${var.rds_endpoint}:${var.rds_port}/${var.rds_database_name}?ssl=require"
  })
}

resource "aws_secretsmanager_secret" "redis_url" {
  name        = "${var.name_prefix}/redis-url"
  description = "Redis connection string for AGCMS services."
  kms_key_id  = var.platform_kms_key_arn
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id = aws_secretsmanager_secret.redis_url.id
  secret_string = jsonencode({
    REDIS_URL = "rediss://:${var.redis_auth_token}@${var.redis_primary_endpoint}:6379/0"
  })
}
