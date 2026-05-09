# Sealed Secrets — AGCMS GitOps flow

Use Bitnami Sealed Secrets when the deploy story is GitOps-first and
there is no cloud-native secrets vault to integrate with. The workflow:

1. Run `kubeseal` locally against a plain `Secret` manifest.
2. Commit the resulting `SealedSecret` (encrypted with the cluster's
   public key) to git.
3. The in-cluster controller decrypts and materialises the real
   `Secret` on the target cluster.

Sealed Secrets and the External Secrets Operator are alternatives —
pick one per environment. We use External Secrets for prod (AWS) and
this flow for on-prem / air-gapped demos where pulling from AWS is not
viable.

## One-time install

```bash
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system \
  --wait

# Install the `kubeseal` CLI locally (macOS shown; use the release
# binary on Linux/Windows):
brew install kubeseal
```

## Fetch the cluster public key once

```bash
kubeseal --fetch-cert > sealed-secrets-pub.pem
```

Commit the public cert next to this README so contributors can seal
without needing cluster access.

## Sealing a new secret

```bash
# 1. Write a plain Secret locally (do NOT commit).
cat > /tmp/agcms-raw.yaml <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: agcms-secrets
  namespace: agcms
type: Opaque
stringData:
  AGCMS_SIGNING_KEY: "<paste real value>"
  JWT_SECRET_KEY:    "<paste real value>"
  GROQ_API_KEY:      "<paste real value>"
  POSTGRES_PASSWORD: "<paste real value>"
EOF

# 2. Seal it against the cluster public key.
kubeseal \
  --cert sealed-secrets-pub.pem \
  --format yaml \
  < /tmp/agcms-raw.yaml \
  > k8s/sealed-secrets/agcms-secrets.sealed.yaml

# 3. Commit the sealed file, delete the raw one.
git add k8s/sealed-secrets/agcms-secrets.sealed.yaml
shred -u /tmp/agcms-raw.yaml
```

## Apply at deploy time

```bash
kubectl apply -f k8s/sealed-secrets/agcms-secrets.sealed.yaml
```

The controller reconciles the `SealedSecret` into the namespaced
`Secret` on the target cluster within a few seconds.

## Rotation

Re-run `kubeseal` against a new raw `Secret` and commit the updated
`SealedSecret`. The controller replaces the managed `Secret` in place;
pods reading the value via env or volume mounts pick it up after a
rollout restart.
