/**
 * @agcms/sdk — public surface.
 */

export { AGCMSClient } from "./client.js";
export type {
  AGCMSClientOptions,
  ChatCompletionsCreateBody,
  FetchLike,
} from "./client.js";

export { openaiWrap } from "./wrap.js";
export type { OpenAIWrapOptions } from "./wrap.js";

export {
  AGCMSError,
  AuthError,
  RateLimitedError,
  BlockedError,
  UpstreamError,
  fromResponse,
} from "./errors.js";
export type { AGCMSErrorPayload } from "./errors.js";

export const VERSION = "0.1.0";
