# cURL Quickstart

Five copy-paste commands to confirm an AGCMS gateway is reachable, governed,
and producing audit rows.

```bash
export AGCMS_BASE_URL="https://api.your-tenant.agcms.com"
export AGCMS_API_KEY="agc_live_..."
export AGCMS_JWT="$(...)"   # from /api/v1/auth/token
```

## 1 · Health

```bash
curl -s "$AGCMS_BASE_URL/health"
# {"status":"healthy","service":"gateway"}
```

## 2 · OpenAPI spec

```bash
curl -s "$AGCMS_BASE_URL/openapi.yaml" | head -20
```

## 3 · Auth — exchange email/password for a JWT

```bash
curl -s -X POST "$AGCMS_BASE_URL/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"change-me"}'
```

## 4 · Governed chat completion (PII-redacted, audited)

```bash
curl -s -X POST "$AGCMS_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $AGCMS_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-AGCMS-User-ID: alice@corp.example" \
  -H "X-AGCMS-Department: support" \
  -d '{
    "model": "groq:llama-3.3-70b-versatile",
    "messages": [{"role":"user","content":"Hello!"}]
  }'
```

The response includes an `X-AGCMS-Interaction-ID` header that links to the
audit row.

## 5 · Audit — verify chain integrity

```bash
curl -s "$AGCMS_BASE_URL/api/v1/audit/chain/verify" \
  -H "Authorization: Bearer $AGCMS_JWT"
# { "ok": true, "rows_checked": 12345, "merkle_roots_checked": 23, "errors": [] }
```

## 6 · Audit — export a portable bundle

```bash
curl -s -X POST "$AGCMS_BASE_URL/api/v1/audit/bundle" \
  -H "Authorization: Bearer $AGCMS_JWT" \
  -H "Content-Type: application/json" \
  -d '{"start":"2026-04-01T00:00:00Z","end":"2026-04-22T00:00:00Z"}' \
  -o agcms-bundle.zip

agcms verify agcms-bundle.zip
# [OK] chain intact for tenant ...
# [OK] Merkle root matches for tenant ...
# [OK] VERIFICATION PASSED — bundle is intact
```
