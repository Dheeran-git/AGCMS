# @agcms/sdk

Official TypeScript / JavaScript client for [AGCMS](https://agcms.com) — AI
Governance & Compliance Monitoring. Works in Node 18+, Deno, and modern
browsers (anything with `fetch`).

## Install

```bash
npm install @agcms/sdk
```

## Quickstart

```ts
import { AGCMSClient } from "@agcms/sdk";

const client = new AGCMSClient({
  baseUrl: "https://api.your-tenant.agcms.com",
  apiKey: "agc_live_...",
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
  baseUrl: "https://api.your-tenant.agcms.com",
  apiKey: "agc_live_...",
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

## License

Apache-2.0
