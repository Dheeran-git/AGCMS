/**
 * AGCMSClient — drop-in OpenAI-compatible client for the AGCMS gateway.
 *
 * Uses global `fetch` (Node 18+, Deno, browsers). For environments without
 * a global fetch, pass one in via `options.fetch`.
 */

import { fromResponse, type AGCMSErrorPayload } from "./errors.js";

export type FetchLike = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

export interface AGCMSClientOptions {
  baseUrl: string;
  apiKey: string;
  /** End-user identifier propagated to AGCMS as `X-AGCMS-User-ID`. */
  userId?: string;
  /** Department name propagated as `X-AGCMS-Department`. */
  department?: string;
  /** Override `globalThis.fetch` (e.g. node-fetch in older runtimes). */
  fetch?: FetchLike;
  /** Extra headers added to every request. */
  defaultHeaders?: Record<string, string>;
}

/** OpenAI-compatible chat-completion request body (subset we type-check). */
export interface ChatCompletionsCreateBody {
  model: string;
  messages: { role: string; content: string }[];
  temperature?: number;
  max_tokens?: number;
  provider?: string;
  [k: string]: unknown;
}

const USER_AGENT = "agcms-typescript/0.1.0";

export class AGCMSClient {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly chat: { completions: { create: (body: ChatCompletionsCreateBody) => Promise<any> } };
  lastInteractionId: string | undefined;

  private readonly _fetch: FetchLike;
  private readonly _extraHeaders: Record<string, string>;

  constructor(options: AGCMSClientOptions) {
    if (!options.baseUrl) throw new Error("AGCMS baseUrl required");
    if (!options.apiKey) throw new Error("AGCMS apiKey required");
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this._fetch = options.fetch ?? (globalThis.fetch?.bind(globalThis) as FetchLike);
    if (!this._fetch) {
      throw new Error("global fetch not available — pass options.fetch");
    }
    this._extraHeaders = { ...(options.defaultHeaders ?? {}) };
    if (options.userId) this._extraHeaders["X-AGCMS-User-ID"] = options.userId;
    if (options.department) this._extraHeaders["X-AGCMS-Department"] = options.department;

    this.chat = {
      completions: {
        create: (body: ChatCompletionsCreateBody) => this._post("/v1/chat/completions", body),
      },
    };
  }

  async listModels(): Promise<unknown> {
    const resp = await this._fetch(this.baseUrl + "/v1/models", {
      method: "GET",
      headers: this._headers(),
    });
    return this._capture(resp);
  }

  private _headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": USER_AGENT,
      ...this._extraHeaders,
    };
  }

  private async _post(path: string, body: unknown): Promise<any> {
    const resp = await this._fetch(this.baseUrl + path, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    return this._capture(resp);
  }

  private async _capture(resp: Response): Promise<any> {
    this.lastInteractionId = resp.headers.get("X-AGCMS-Interaction-ID") ?? undefined;
    const text = await resp.text();
    let payload: any = {};
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { raw: text };
      }
    }
    if (!resp.ok) {
      throw fromResponse(payload as AGCMSErrorPayload, resp.status);
    }
    return payload;
  }
}
