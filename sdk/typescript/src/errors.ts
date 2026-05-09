/**
 * AGCMS error hierarchy.
 *
 * Every error thrown by the SDK is an instance of `AGCMSError`. Sub-classes
 * map to the gateway's `error` codes so callers can branch with `instanceof`
 * checks instead of string compares.
 */

export interface AGCMSErrorPayload {
  error?: string;
  reason?: string;
  interaction_id?: string;
  [k: string]: unknown;
}

export class AGCMSError extends Error {
  readonly statusCode?: number;
  readonly interactionId?: string;
  readonly payload: AGCMSErrorPayload;

  constructor(
    message: string,
    options: {
      statusCode?: number;
      interactionId?: string;
      payload?: AGCMSErrorPayload;
    } = {},
  ) {
    super(message);
    this.name = new.target.name;
    this.statusCode = options.statusCode;
    this.interactionId = options.interactionId;
    this.payload = options.payload ?? {};
  }
}

export class AuthError extends AGCMSError {}
export class RateLimitedError extends AGCMSError {}
export class BlockedError extends AGCMSError {}
export class UpstreamError extends AGCMSError {}

export function fromResponse(
  payload: AGCMSErrorPayload,
  status: number,
): AGCMSError {
  const code = payload?.error ?? "agcms_error";
  const reason = payload?.reason ?? code;
  const interactionId = payload?.interaction_id;
  const opts = { statusCode: status, interactionId, payload };

  if (status === 401) return new AuthError(reason, opts);
  if (status === 429 || code === "rate_limited") return new RateLimitedError(reason, opts);
  if (code === "request_blocked" || (status === 403 && code !== "forbidden")) {
    return new BlockedError(reason, opts);
  }
  if (status === 403) return new AuthError(reason, opts);
  if (status >= 500 || code === "llm_error" || code === "upstream_error") {
    return new UpstreamError(reason, opts);
  }
  return new AGCMSError(reason, opts);
}
