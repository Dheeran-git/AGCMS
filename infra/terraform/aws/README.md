# AGCMS — AWS Terraform Module

Provisions the foundational AWS infrastructure for an AGCMS deployment.

## Layout

The root composes seven self-contained modules under `modules/`:

| Module | What it provisions |
|---|---|
| `vpc` | VPC, 3 public + 3 private subnets across 3 AZs, NAT gateway per AZ, route tables. |
| `kms` | Three customer-managed KMS keys with rotation: platform KEK, RDS storage, S3 anchors. |
| `s3-anchors` | Audit-anchor bucket with Object Lock COMPLIANCE, 7-year retention, SSE-KMS, lifecycle to Glacier after 90d. |
| `eks` | EKS control plane (1.29), managed node group, control-plane + node security groups, OIDC provider for IRSA, secrets envelope encryption with the platform KEK. |
| `rds` | Postgres 16 — Multi-AZ, gp3, encrypted at rest, `rds.force_ssl=1`, Performance Insights, only reachable from EKS nodes. |
| `redis` | ElastiCache Redis 7.1 — multi-AZ, in-transit + at-rest encryption, AUTH token, only reachable from EKS nodes. |
| `iam` | Audit-service IRSA role (S3 PutObject + KMS) and Secrets Manager entries for `DATABASE_URL` + `REDIS_URL`. |

## Why this matters

- **VPC** with 3 public + 3 private subnets across 3 AZs, NAT per AZ.
- **EKS** cluster (Kubernetes 1.29 by default) with managed node group, OIDC provider for IRSA, and envelope encryption of cluster secrets via dedicated KMS key.
- **RDS** Postgres 16 — Multi-AZ, gp3, encrypted at rest with dedicated KMS key, 30-day backup retention, `rds.force_ssl = 1`, Performance Insights on.
- **ElastiCache** Redis 7.1 — multi-AZ, in-transit + at-rest encryption, AUTH token.
- **S3 audit-anchor bucket** with Object Lock in **Compliance mode** and a default 7-year retention. SSE-KMS, public access blocked, lifecycle to Glacier after 90 days. This bucket is what makes "tamper-evident audit chain" defensible — once written, no one (not even the AWS root account) can delete or alter an object before its retention expires.
- **KMS keys** — three customer-managed keys with rotation enabled (platform envelope KEK, RDS storage, S3 anchors).
- **IRSA role** for the audit service so it can write Object Lock'd manifests and use the platform KEK without static credentials.
- **Secrets Manager** entries for `DATABASE_URL` and `REDIS_URL`, suitable for consumption by `external-secrets-operator` in cluster.

## Apply

```bash
# 1. Configure remote state (recommended) — see backend-example.tf below.
# 2. Plan & apply
terraform init
terraform plan -out tfplan
terraform apply tfplan

# 3. Connect to the cluster
$(terraform output -raw kubeconfig_command)
kubectl get nodes
```

## Optional remote-state backend

Create `backend.tf` (gitignored) like:

```hcl
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "agcms/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
```

## Inputs you usually override

| Variable | Default | When to change |
|---|---|---|
| `region` | `us-east-1` | Customer data residency. |
| `environment` | `prod` | Per-environment naming + retention. |
| `vpc_cidr` | `10.42.0.0/16` | Avoid overlap with peered VPCs. |
| `eks_node_instance_types` | `["m6i.large"]` | Sizing. |
| `eks_node_desired_size` / `min_size` / `max_size` | 3 / 2 / 8 | Throughput. |
| `rds_instance_class` | `db.m6g.large` | Database load. |
| `rds_multi_az` | `true` | Always on for prod; off for dev to save cost. |
| `audit_anchor_retention_years` | `7` | SOC 2 / HIPAA / SEC 17a-4 minimums. **Once set on an object it cannot be reduced** — only extended. |

## Wiring outputs into the Helm chart

After apply:

```bash
terraform output -json > tf-out.json

# Helm values fragment:
helm install agcms ./infra/helm/agcms \
  --namespace agcms \
  --create-namespace \
  --set secrets.external=true \
  --set ingress.host=agcms.example.com
```

Then create `ExternalSecret` resources pointing at:

- `secret_database_url_arn`  → `DATABASE_URL`
- `secret_redis_url_arn`     → `REDIS_URL`

And annotate the audit ServiceAccount with `audit_service_role_arn` for IRSA.

## Destroying

The audit bucket has Object Lock in Compliance mode — `terraform destroy` **will not be able to delete it** until every object's retention has expired (default 7 years). This is intentional and required for compliance defensibility. To tear down a non-prod environment cleanly, set `audit_anchor_retention_years = 1` and `force_destroy = true` (manually, in `aws_s3_bucket.audit_anchors`) before applying — but never do this in production.

`deletion_protection = true` is set on RDS in `prod`. Disable manually before destroy.
