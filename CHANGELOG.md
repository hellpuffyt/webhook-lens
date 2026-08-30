# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-30

### Added

- Local HTTP receiver (`webhook-lens listen`) that captures method, path, headers,
  and the raw request body byte-for-byte.
- Signature verification for GitHub, Stripe, Shopify, and Slack webhook schemes,
  plus a generic configurable HMAC scheme, all implemented from each provider's
  documented algorithm and compared with `crypto.timingSafeEqual`.
- Stripe (and optional Slack) replay-window checking against the signed timestamp.
- Filesystem-backed delivery storage with list/show/delete/clear operations.
- Replay support (`webhook-lens replay`) that re-sends a captured delivery to any
  target URL, preserving the raw body and headers, with optional re-signing.
- CLI commands: `listen`, `list`, `show`, `replay`, `verify`.
- Header redaction for sensitive values in CLI output.
