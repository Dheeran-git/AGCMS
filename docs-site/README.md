# AGCMS Docs

[Mintlify](https://mintlify.com)-powered docs site for `docs.agcms.com`.

## Local preview

```bash
cd docs-site
npx mintlify dev          # http://localhost:3000
```

## Structure

- `mint.json` — site config + navigation tree.
- `*.mdx` — content. Top-level pages are linked from `mint.json` directly.
- `api-reference/` — auto-generated from the gateway's `openapi.yaml`
  (URL pinned in `mint.json`).
