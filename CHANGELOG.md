# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `replay` now refuses non-loopback targets unless `--allow-remote`
  (library: `allowRemote: true`) is given, accepts only `http`/`https`, and
  refuses URLs with embedded credentials. Previously any URL was accepted and
  the captured `Authorization`/signature headers were forwarded to it.
- Delivery ids are validated (`[A-Za-z0-9_-]`): a crafted id such as
  `../x` could previously read, write, or delete `.json` files outside the
  deliveries directory.
- Capture files are written `0600` in a `0700` directory (were world-readable
  under a default umask) because they hold unredacted signature/auth headers.
- `verify --tolerance abc` (or a NaN tolerance through the library) silently
  disabled the Stripe/Slack replay window; malformed numeric flags are now an
  error and non-finite/negative tolerances fail verification.
- The receiver no longer echoes internal storage errors (which can contain
  local paths) back to the sender.
- Redaction now covers any header whose name contains `signature`, `secret`,
  `token`, `api-key`, `auth`, `cookie`, `password`, or `hmac` (including the
  generic scheme's default `x-signature` and GitLab's plaintext
  `x-gitlab-token`), and secret-looking query parameters in displayed paths.
- Replay responses are capped at 10 MB (`maxResponseBytes`).
- CI workflow runs with `permissions: contents: read`.

### Fixed

- Stripe and Slack signatures are now computed over the raw body bytes; a
  body containing non-UTF-8 bytes previously failed verification even with
  a correct signature.
- `show --raw <id>` no longer treats the id as the value of `--raw`.

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
