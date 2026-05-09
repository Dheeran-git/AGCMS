"use server";

/**
 * Server action that calls AGCMS from a Next.js 14 app.
 *
 * Place under app/actions.ts. The AGCMS API key MUST stay server-side —
 * never expose it to the browser bundle.
 */

import { AGCMSClient, BlockedError } from "@agcms/sdk";

const client = new AGCMSClient({
  baseUrl: process.env.AGCMS_BASE_URL!,
  apiKey: process.env.AGCMS_API_KEY!,
});

export async function summarise(text: string): Promise<{
  ok: boolean;
  summary?: string;
  reason?: string;
  interactionId?: string;
}> {
  try {
    const resp = await client.chat.completions.create({
      model: "groq:llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: "You are a concise summariser." },
        { role: "user", content: text },
      ],
    });
    return {
      ok: true,
      summary: resp.choices?.[0]?.message?.content,
      interactionId: client.lastInteractionId,
    };
  } catch (err) {
    if (err instanceof BlockedError) {
      return { ok: false, reason: err.message, interactionId: err.interactionId };
    }
    throw err;
  }
}
