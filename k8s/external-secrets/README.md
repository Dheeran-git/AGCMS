# External Secrets Operator — AGCMS

Pull AGCMS runtime secrets from AWS Secrets Manager (prod) or a
vendor-equivalent secrets vault. Drop-in replacement for the manual
`kubectl create secret` flow described in `../secrets.yaml`.

## One-time install

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true \
  --wait
```

Confirm the CRDs + controller are up:

```bash
kubectl -n external-secrets rollout status deploy/external-secrets
kubectl get crd | grep external-secrets.io
```

## Authentication (AWS Secrets Manager)

We use IRSA (IAM Roles for Service Accounts). The controller's
`ServiceAccount` needs an IAM role with `secretsmanager:GetSecretValue`
on the keys AGCMS reads.

1. Create the IAM role with a trust policy for the EKS OIDC issuer.
2. Annotate the SA:

   ```bash
   kubectl -n external-secrets annotate sa external-secrets \
     eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/agcms-external-secrets
   ```

3. Apply the cluster-wide store:

   ```bash
   kubectl apply -f k8s/external-secrets/cluster-secret-store-aws.yaml
   ```

4. Apply the AGCMS secret pull:

   ```bash
   kubectl apply -f k8s/external-secrets/external-secret-agcms.yaml
   ```

The operator will create / update the `agcms-secrets` Kubernetes Secret
every 15 minutes from the AWS source. Pods reference that Secret
exactly as before; nothing in service manifests changes.

## Secrets to pre-populate in AWS Secrets Manager

Create these keys under `/agcms/prod/*`:

| AWS path                         | K8s Secret key        |
|----------------------------------|-----------------------|
| /agcms/prod/signing-key          | AGCMS_SIGNING_KEY     |
| /agcms/prod/anchor-key           | AGCMS_ANCHOR_KEY      |
| /agcms/prod/jwt-secret           | JWT_SECRET_KEY        |
| /agcms/prod/groq-api-key         | GROQ_API_KEY          |
| /agcms/prod/openai-api-key       | OPENAI_API_KEY        |
| /agcms/prod/anthropic-api-key    | ANTHROPIC_API_KEY     |
| /agcms/prod/mistral-api-key      | MISTRAL_API_KEY       |
| /agcms/prod/postgres-password    | POSTGRES_PASSWORD     |
| /agcms/prod/workos-api-key       | WORKOS_API_KEY        |
| /agcms/prod/workos-client-id     | WORKOS_CLIENT_ID      |
| /agcms/prod/kms-local-key        | AGCMS_KMS_LOCAL_KEY   |

## Verification

```bash
kubectl -n agcms get externalsecret
kubectl -n agcms describe externalsecret agcms-secrets
kubectl -n agcms get secret agcms-secrets -o yaml
```

`SyncedResourceRefresh` status should read `SecretSynced` within 30s.
If `SecretSyncFailed`, `kubectl describe` shows the exact AWS API error.
