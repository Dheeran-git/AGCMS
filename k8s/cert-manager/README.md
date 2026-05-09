# cert-manager bootstrap for AGCMS

This directory bootstraps cert-manager + two ClusterIssuers (Let's Encrypt
staging + prod) that the ingress in `../ingress.yaml` consumes via the
`cert-manager.io/cluster-issuer` annotation.

## One-time install

Apply cert-manager itself (v1.15+), then the issuers. The `--server-side`
flag is required because the cert-manager manifest is larger than the
default client-side patch limit.

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml --server-side
kubectl rollout status -n cert-manager deploy/cert-manager-webhook --timeout=120s
kubectl apply -f k8s/cert-manager/cluster-issuer-staging.yaml
kubectl apply -f k8s/cert-manager/cluster-issuer-prod.yaml
```

Set the owner email in both files before applying.

## Switching between staging + prod

The ingress annotation defaults to `letsencrypt-prod`. While testing, edit
the ingress to reference `letsencrypt-staging` to avoid hitting Let's
Encrypt rate limits (5 duplicate certificates per week).

## Verifying issuance

```bash
kubectl -n agcms get certificate agcms-tls -o wide
kubectl -n agcms describe certificate agcms-tls
```

A healthy certificate shows `Ready=True` within ~2 minutes. If stuck on
`Issuing`, check the associated `CertificateRequest` and `Order` objects
for events (usually a DNS or ACME-challenge failure).
