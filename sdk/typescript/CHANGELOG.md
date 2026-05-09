# Changelog

All notable changes to the `@agcms/sdk` TypeScript client will be documented here.

## [0.1.0] — Unreleased

Initial public beta.

### Added
- `AGCMSClient` with OpenAI-compatible `chat.completions.create(...)`
  passthrough. Works in Node 18+, Deno, modern browsers.
- `openaiWrap(...)` helper for 3-line drop-in integration.
- Typed exception hierarchy: `AGCMSError`, `AuthError`, `RateLimitedError`,
  `BlockedError`, `UpstreamError`.
- `lastInteractionId` capture for direct cross-reference into the AGCMS
  audit trail.
