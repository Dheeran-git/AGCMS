# AGCMS Marketing Site

Next.js 14 (App Router, TypeScript, Tailwind) marketing site for
[agcms.com](https://agcms.com).

## Routes

| Path                | Purpose                                                |
|---------------------|--------------------------------------------------------|
| `/`                 | Hero, embedded paste-a-bundle verifier, value props.   |
| `/product`          | 13-step lifecycle, three-line integration snippet.     |
| `/compliance`       | Index of supported frameworks (HIPAA, GDPR, EU AI Act…) |
| `/pricing`          | Three tiers (Starter / Business / Enterprise).         |
| `/security`         | Public mirror of in-app Trust Center.                  |
| `/changelog`        | Live feed via gateway `/api/v1/changelog`.             |
| `/book-demo`        | Lead-capture form.                                     |
| `/blog`             | Long-form posts (MDX, future).                         |

## Local dev

```bash
cd marketing
npm install
npm run dev    # serves on http://localhost:3001
```

The changelog page reads from the gateway:

```bash
export AGCMS_API_URL=http://localhost:8000
```

## Deploy

Designed for Vercel / Cloudflare Pages. No backend required — all dynamic
content is sourced from the AGCMS gateway's public APIs.
