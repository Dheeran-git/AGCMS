# Changelog

All notable changes to the `@agcms/sdk` TypeScript client will be documented here.

## [0.1.1] — 2026-05-09

### Changed
- Updated package metadata to point at the public repo and live docs:
  homepage → `agcms-six.vercel.app`, source → `github.com/Dheeran-git/AGCMS`.
- README rewritten with working install + run-it-yourself instructions.
- Apache 2.0 LICENSE now bundled with the package.

## [0.1.0] — 2026-05-09

Initial public beta on npm.

### Added
- `AGCMSClient` with OpenAI-compatible `chat.completions.create(...)`
  passthrough. Works in Node 18+, Deno, modern browsers.
- `openaiWrap(...)` helper for 3-line drop-in integration.
- Typed exception hierarchy: `AGCMSError`, `AuthError`, `RateLimitedError`,
  `BlockedError`, `UpstreamError`.
- `lastInteractionId` capture for direct cross-reference into the AGCMS
  audit trail.
