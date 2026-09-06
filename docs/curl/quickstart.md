# cURL Quickstart

A few copy-paste commands to confirm an AGCMS gateway is reachable, governed,
and producing audit rows.

```bash
export AGCMS_BASE_URL="http://localhost:8000"
export AGCMS_API_KEY="agcms_test_key_for_development"
export AGCMS_JWT="$(...)"   # from /api/v1/auth/token
```

## 1 · Health

```bash
curl -s "$AGCMS_BASE_URL/health"
# {"status":"healthy","service":"gateway"}
```

## 3 · Auth — exchange the API key for a JWT

```bash
curl -s -X POST "$AGCMS_BASE_URL/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"api_key":"'"$AGCMS_API_KEY"'"}'
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
# { "ok": true, "chain_rows_examined": 12345, "issues": [] }
```

