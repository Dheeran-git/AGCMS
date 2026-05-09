# @agcms/sdk

Official TypeScript / JavaScript client for **AGCMS** — AI Governance &
Compliance Monitoring. Works in Node 18+, Deno, and modern browsers (anything
with `fetch`).

- **Source:** https://github.com/Dheeran-git/AGCMS
- **Docs:** https://uip-f4b0bbe5.mintlify.app
- **Marketing:** https://agcms-six.vercel.app

## Install

```bash
npm install @agcms/sdk
```

## Quickstart

```ts
import { AGCMSClient } from "@agcms/sdk";

const client = new AGCMSClient({
  baseUrl: "http://localhost:8000",          // your AGCMS gateway
  apiKey: "agcms_test_key_for_development",  // or a real per-tenant key
});

const resp = await client.chat.completions.create({
  model: "groq:llama-3.3-70b-versatile",
  messages: [{ role: "user", content: "Hello!" }],
});

console.log(resp.choices[0].message.content);
console.log("audit interaction_id:", client.lastInteractionId);
```

## Wrap an existing OpenAI client (3-line integration)

```ts
import OpenAI from "openai";
import { openaiWrap } from "@agcms/sdk";

const client = openaiWrap(new OpenAI({ apiKey: "sk-..." }), {
  baseUrl: "http://localhost:8000",
  apiKey: "agcms_test_key_for_development",
});

await client.chat.completions.create({ model: "gpt-4o", messages: [...] });
```

## Errors

```ts
import { AGCMSError, BlockedError, RateLimitedError, AuthError } from "@agcms/sdk";

try {
  await client.chat.completions.create({ ... });
} catch (err) {
  if (err instanceof BlockedError) {
    console.log("AGCMS blocked the request:", err.message, err.interactionId);
  }
}
```

## Run AGCMS yourself

The repo ships an 11-service `docker-compose.yml`:

```bash
git clone https://github.com/Dheeran-git/AGCMS.git
cd AGCMS && cp .env.example .env
docker compose up --build --wait
# → gateway on :8000, dashboard on :3000
```

## License

Apache-2.0
