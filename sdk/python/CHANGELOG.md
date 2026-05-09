# Changelog

All notable changes to the AGCMS Python SDK will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-05-09

### Changed
- Updated package metadata to point at the public repo and live docs:
  homepage → `agcms-six.vercel.app`, docs → `uip-f4b0bbe5.mintlify.app`,
  source → `github.com/Dheeran-git/AGCMS`.
- Author switched from generic AGCMS contact to a real maintainer.
- README rewritten with working install + run-it-yourself instructions
  pointing at the open-source docker-compose stack.
- Apache 2.0 LICENSE now bundled inside the wheel + sdist.

## [0.1.0] — 2026-05-09

Initial public beta on PyPI.

### Added
- `AGCMSClient` and `AsyncAGCMSClient` with OpenAI-compatible
  `chat.completions.create(...)` passthrough.
- `openai_wrap(...)` helper for 3-line drop-in integration in front of an
  existing `openai.OpenAI` client.
- Typed exception hierarchy: `AuthError`, `RateLimitedError`, `BlockedError`,
  `UpstreamError`.
- `agcms verify <bundle.zip|dir>` CLI for offline validation of exported
  audit bundles (chain + Merkle root).
- `last_interaction_id` capture on every successful call for direct
  cross-reference into the AGCMS audit trail.
