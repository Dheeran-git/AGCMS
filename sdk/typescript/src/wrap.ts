/**
 * openaiWrap — drop AGCMS in front of an existing OpenAI client.
 *
 *   import OpenAI from "openai";
 *   import { openaiWrap } from "@agcms/sdk";
 *
 *   const client = openaiWrap(new OpenAI({ apiKey: "..." }), {
 *     baseUrl: "https://api.your-tenant.agcms.com",
 *     apiKey:  "agc_live_...",
 *   });
 *
 * The returned object proxies every property to the original OpenAI client,
 * except `chat.completions.create(...)` which is rerouted through AGCMS.
 */

import { AGCMSClient, type AGCMSClientOptions } from "./client.js";

export interface OpenAIWrapOptions extends Omit<AGCMSClientOptions, "fetch"> {
  /** Optional fetch override for the AGCMS leg only. */
  fetch?: AGCMSClientOptions["fetch"];
}

export function openaiWrap<T extends object>(
  openaiClient: T,
  options: OpenAIWrapOptions,
): T & { lastInteractionId: string | undefined } {
  const agcms = new AGCMSClient(options);

  const wrappedChat = {
    ...((openaiClient as any).chat ?? {}),
    completions: {
      ...(((openaiClient as any).chat?.completions) ?? {}),
      create: (body: any) => agcms.chat.completions.create(body),
    },
  };

  const proxy = new Proxy(openaiClient as any, {
    get(target, prop, receiver) {
      if (prop === "chat") return wrappedChat;
      if (prop === "lastInteractionId") return agcms.lastInteractionId;
      return Reflect.get(target, prop, receiver);
    },
  });

  return proxy as T & { lastInteractionId: string | undefined };
}
