/**
 * Vitest specs for the TypeScript SDK.
 *
 * We never hit the real network: a fake `fetch` is injected via
 * `AGCMSClientOptions.fetch` (kept dependency-free).
 */

import { describe, it, expect } from "vitest";
import {
  AGCMSClient,
  AuthError,
  BlockedError,
  RateLimitedError,
  UpstreamError,
  openaiWrap,
} from "../src/index.js";

type Handler = (req: { url: string; init?: RequestInit }) => Response;

function makeFetch(handler: Handler) {
  return ((input: string, init?: RequestInit) =>
    Promise.resolve(handler({ url: input, init }))) as any;
}

function jsonResp(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("AGCMSClient", () => {
  it("captures interaction id and returns parsed payload", async () => {
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch((req) => {
        expect(req.url).toBe("https://gw.test/v1/chat/completions");
        const headers = req.init?.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe("Bearer agc_test");
        return jsonResp(
          200,
          { choices: [{ message: { content: "hi" } }] },
          { "X-AGCMS-Interaction-ID": "iid-1" },
        );
      }),
    });
    const out = await client.chat.completions.create({
      model: "groq:llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "hello" }],
    });
    expect(out.choices[0].message.content).toBe("hi");
    expect(client.lastInteractionId).toBe("iid-1");
  });

  it("maps 403 request_blocked to BlockedError", async () => {
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch(() => jsonResp(403, {
        error: "request_blocked",
        reason: "PII detected",
        interaction_id: "iid-block",
      })),
    });
    await expect(
      client.chat.completions.create({ model: "x", messages: [] }),
    ).rejects.toBeInstanceOf(BlockedError);
  });

  it("maps 429 to RateLimitedError", async () => {
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch(() => jsonResp(429, { error: "rate_limited", reason: "too many" })),
    });
    await expect(
      client.chat.completions.create({ model: "x", messages: [] }),
    ).rejects.toBeInstanceOf(RateLimitedError);
  });

  it("maps 401 to AuthError", async () => {
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch(() => jsonResp(401, { error: "auth_failed", reason: "no key" })),
    });
    await expect(
      client.chat.completions.create({ model: "x", messages: [] }),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it("maps 502 to UpstreamError", async () => {
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch(() => jsonResp(502, { error: "llm_error", reason: "groq down" })),
    });
    await expect(
      client.chat.completions.create({ model: "x", messages: [] }),
    ).rejects.toBeInstanceOf(UpstreamError);
  });

  it("propagates user/department headers", async () => {
    let seen: Record<string, string> = {};
    const client = new AGCMSClient({
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      userId: "alice@corp",
      department: "sec-eng",
      fetch: makeFetch((req) => {
        seen = req.init?.headers as Record<string, string>;
        return jsonResp(200, {});
      }),
    });
    await client.chat.completions.create({ model: "x", messages: [] });
    expect(seen["X-AGCMS-User-ID"]).toBe("alice@corp");
    expect(seen["X-AGCMS-Department"]).toBe("sec-eng");
  });

  it("rejects when baseUrl missing", () => {
    expect(() => new AGCMSClient({ baseUrl: "", apiKey: "x" })).toThrow();
  });
});

describe("openaiWrap", () => {
  it("routes chat.completions through AGCMS but proxies other props", async () => {
    const fakeOpenAI = {
      embeddings: "embed-namespace",
      files: "files-namespace",
    };
    const client = openaiWrap(fakeOpenAI, {
      baseUrl: "https://gw.test",
      apiKey: "agc_test",
      fetch: makeFetch(() => jsonResp(200, { choices: [] }, { "X-AGCMS-Interaction-ID": "iid-w" })),
    });
    await (client as any).chat.completions.create({ model: "x", messages: [] });
    expect(client.lastInteractionId).toBe("iid-w");
    expect((client as any).embeddings).toBe("embed-namespace");
    expect((client as any).files).toBe("files-namespace");
  });
});
