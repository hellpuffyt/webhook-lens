# Production readiness — webhook-lens

Audit of the `audit/production-readiness` branch. This document records evidence;
it does not award a production-ready label.

## Scope and architecture

`webhook-lens` is a local developer tool and small library:

- `src/server.ts` — `node:http` receiver that stores the raw request bytes (base64) per delivery.
- `src/storage.ts` — one JSON file per delivery under `.webhook-lens/deliveries` (or `--dir`).
- `src/signatures/*` — GitHub, Stripe, Shopify, Slack and generic HMAC verification with
  constant-time comparison.
- `src/replay.ts` — re-sends a stored delivery to a loopback URL (remote only with `--allow-remote`),
  optionally re-signed.
- `src/redact.ts` — masking of secret-looking headers and query parameters for display.
- `src/cli.ts`, `src/args.ts` — `listen` / `list` / `show` / `replay` / `verify`.

Zero runtime dependencies. Not published to npm; installed from a clone.

## Platforms and prerequisites

- Node.js >= 20 (`engines`; Node 18, end-of-life, was dropped with the vitest 4 upgrade). Verified locally on macOS (Apple Silicon) with Node 24.19.0 (full gate),
  and the test suite with Node 18.20.8, 20 and 22 (via `npx -p node@<v>`).
- CI matrix: ubuntu / windows / macOS x Node 20 / 22.
- Windows was not run locally. The file-permission test is skipped on Windows
  (`it.skipIf(process.platform === 'win32')`) because POSIX modes do not apply there.

## Clean-clone setup (as in the README)

```bash
git clone <this-repo>
cd webhook-lens
npm install
npm run build
npm test
```

Result on the audit branch (fresh clone into a temporary directory): `npm install` 0, `npm run build` 0,
`npm test` 110 passed / 0 failed / 0 skipped, `npx tsc --noEmit` 0, `npx eslint .` 0. Quick start:
`listen` on 8787, a GitHub-signed POST captured, `list`, `show`, `verify` (exit 0) and
`replay --to http://localhost:8787/... --resign-scheme github` (status 200) all worked.
`npm link` (optional, global) was not run.

## Commands executed (CI-equivalent, local)

| Command | Baseline (main @ 98028ca) | Audit branch |
|---|---|---|
| `npm ci` | 0 | 0 |
| `npm run lint` | 0 | 0 |
| `npm run typecheck` | 0 | 0 |
| `npm test` | 0 — 88 passed, 0 failed, 0 skipped | 0 — 110 passed, 0 failed, 0 skipped (Node 24); 1 test would be skipped on Windows |
| `npm run build` | 0 | 0 |
| CI smoke script (listen + signed POST + verify) | pass | pass, plus new refusal checks |
| `npm audit --omit=dev` | 0 vulnerabilities | 0 vulnerabilities |
| `npm audit` (incl. dev) | 16 (2 critical, 12 high, 2 moderate) | 14 (2 critical, 10 high, 2 moderate) |

Remaining dev-only advisories are in `vitest@1` (vite, vite-node, esbuild, tinypool) and
`@typescript-eslint@7` (braces/micromatch chain). Fixing them needs semver-major upgrades
(vitest 5, typescript-eslint 8 with ESLint flat config); they do not ship in the package
(`files: ["dist"]`, no runtime deps) and were left for a separate change.

## Security review

| Area | Finding | Severity | Status |
|---|---|---|---|
| SSRF / header exfiltration | `replay --to` accepted any URL (incl. `169.254.169.254`; non-http schemes were rejected only incidentally by Node) and forwarded captured `Authorization`/cookie/signature headers to it | High | Fixed: loopback-only by default, `--allow-remote` opt-in, http(s) only, no URL credentials |
| Path traversal | Delivery id was joined into a path unchecked: `save({id:'../x'})` wrote outside the store; `show ../x` / `delete` read/removed arbitrary `*.json` | Medium | Fixed: id allow-list `[A-Za-z0-9_-]{1,128}` |
| Sensitive data at rest | Capture files (unredacted auth/signature headers) were created 0644 | Medium | Fixed: 0600 files, 0700 directory |
| Replay-window bypass | `--tolerance abc` -> NaN -> `age > NaN` false -> stale Stripe/Slack deliveries accepted | Medium | Fixed: strict flag parsing + library rejects non-finite/negative tolerance |
| Correctness of "exact bytes" claim | Stripe/Slack HMAC decoded the body as UTF-8 first; non-UTF-8 bytes broke valid signatures | Low | Fixed |
| Information leak | Receiver returned raw storage error text (local paths) to the sender | Low | Fixed |
| Redaction gaps | `x-signature` (generic default), `x-gitlab-token` (plaintext secret), other `*-signature` headers and `?token=` query values printed in clear | Low | Fixed |
| Resource exhaustion | Request body capped at 10 MB (existing); replay response was unbounded | Low | Fixed: 10 MB cap |
| Workflow permissions | No `permissions:` block | Low | Fixed: `contents: read` |
| Secrets in tree/history | 1 commit scanned; only clearly synthetic `whsec_test_synthetic_*` / `whsec_ci_synthetic_*` test fixtures | Info | No rotation needed |

Not addressed (documented in README "Security"): no authentication, rate limiting or disk quota on the
receiver; secrets given as CLI flags are visible in the process list.

## Bugs fixed (each with a regression test in `test/security.test.ts`)

17 of the 22 new tests fail against the baseline source and pass on the audit branch; the other 5
(ordinary headers stay visible, loopback default bind, arg parsing helpers) pin existing or new-module behaviour.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Reference |
|---|---|---|---|---|
| Raw capture | Body stored byte-for-byte | `test/server.test.ts`, `test/storage.test.ts` (binary round trip) | pass | `src/server.ts` |
| Signature schemes | Valid sig accepted, tampered/wrong secret rejected for 5 schemes | `test/signatures.test.ts` (47) | pass | `src/signatures/*` |
| Raw bytes, not re-serialized | Non-UTF-8 and reformatted JSON verify over exact bytes | `test/raw-body.test.ts`, `security.test.ts` "HMAC is computed over raw bytes" | pass | `stripe.ts`, `slack.ts` |
| Replay window | Stale Stripe rejected; invalid tolerance never disables it | `signatures.test.ts`, `security.test.ts` tolerance tests, CI smoke | pass | `stripe.ts`, `args.ts` |
| Replay fidelity | Raw body + non hop-by-hop headers forwarded, optional re-sign | `test/replay.test.ts` | pass | `src/replay.ts` |
| Replay SSRF guard | Non-loopback / non-http / credentialed targets refused by default | `security.test.ts` "replay target restrictions", CI smoke | pass | `parseReplayTarget` |
| Store confinement | Crafted ids cannot read/write/delete outside the store | `security.test.ts` storage tests | pass | `isValidDeliveryId` |
| Secrets not shown | Sensitive headers and query values redacted in `list`/`show`/`listen` | `test/redact.test.ts`, `security.test.ts` redaction; manual `show` | pass | `src/redact.ts` |
| Loopback bind | Receiver binds 127.0.0.1 by default | `security.test.ts` "binds to loopback by default" | pass | `src/server.ts` |
| Clean clone | README steps build, test and run | see "Clean-clone setup" | pass | README |

## CI status

- Default branch (`main` @ 98028ca): last run `success`.
- Audit branch: pending until pushed.

## Limitations and unresolved risks

- Dev-toolchain advisories above (semver-major upgrades not done).
- Captured deliveries accumulate on disk without a quota or retention.
- `localhost` replay targets depend on how the OS resolves `localhost`.
- No Windows run locally (CI matrix covers it on the default branch).

## Tested commit

Code under test: `1c1b4832dcfd5a6fff0c8500249ec6c4bceb21f3` (this document is committed on top of it), 2026-10-22.

## Classification proposal

**Partially Verified** — all documented features are implemented and tested locally on macOS with
Node 18/20/22/24 and the clean clone passes; not yet verified: CI on the audit branch (including Windows)
and the dev-only dependency advisories, which need semver-major upgrades.
