# webhook-lens

Capture, inspect, and replay inbound webhooks locally, verifying provider
HMAC signatures before you trust a payload.

## What

`webhook-lens` runs a small HTTP server on your machine. Point a webhook
provider (or a `curl`/test client) at it, and it will:

- capture every request byte-for-byte (method, path, headers, raw body),
- persist it to disk as JSON so you can inspect it later,
- verify the provider's HMAC signature against a secret you supply, and
- replay any captured delivery against your real handler, as many times as
  you want, optionally re-signed with a different secret.

## Why

Debugging a webhook integration usually means one of two unpleasant options:
push to production and read logs, or route the payload through a hosted
tunnel that now sees every request you receive. `webhook-lens` runs entirely
on your machine: nothing leaves it. It also gets the fiddly part right --
verifying a provider's signature over the *exact bytes it sent*, not a
JSON-parsed-and-re-serialized approximation of them, which is where most
homegrown verification scripts quietly break.

## Features

- **Local receiver** -- an HTTP server (`node:http`) that captures method,
  path, headers, and the raw request body.
- **Signature verification** for five schemes, each implemented from its
  provider's documented algorithm and compared with `crypto.timingSafeEqual`:
  - GitHub (`X-Hub-Signature-256`)
  - Stripe (`Stripe-Signature`, with replay-window checking)
  - Shopify (`X-Shopify-Hmac-Sha256`)
  - Slack (`X-Slack-Signature`)
  - A generic, configurable HMAC scheme for anything else
- **Storage** -- every capture is written to disk as a standalone JSON file,
  listable and inspectable later.
- **Replay** -- re-send a captured delivery to any target URL, with the
  original raw body and headers preserved, optionally re-signed with your
  own secret.
- **Redaction** -- signatures, auth headers, and other sensitive values are
  masked in CLI output by default.

## Architecture

```
src/
  server.ts        HTTP receiver: reads raw request bytes, never parses them
  storage.ts        Filesystem-backed delivery store (one JSON file per capture)
  replay.ts          Re-sends a stored delivery, with optional re-signing
  redact.ts           Header/secret redaction for safe CLI output
  types.ts            Shared types (Delivery, VerifyOptions, ...)
  signatures/
    github.ts         X-Hub-Signature-256 (HMAC-SHA256, hex, "sha256=" prefix)
    stripe.ts          Stripe-Signature (HMAC-SHA256, hex, t=/v1= + replay window)
    shopify.ts        X-Shopify-Hmac-Sha256 (HMAC-SHA256, base64)
    slack.ts            X-Slack-Signature (HMAC-SHA256, hex, "v0:ts:body" basestring)
    generic.ts          Configurable HMAC (any header, algorithm, encoding, prefix)
    util.ts             Constant-time comparison helpers
    index.ts             verifyDelivery(): dispatches a Delivery to the right scheme
  cli.ts                listen / list / show / replay / verify commands
```

### Design point: the raw body is never re-serialized

Every provider signature here is computed over the *exact bytes* the
provider sent -- not over `JSON.stringify(JSON.parse(body))`. Those two are
not the same thing: key order, whitespace, numeric formatting, and unicode
escaping can all change silently when a body is parsed and re-serialized,
which changes the bytes and breaks any signature computed over them.

`webhook-lens` never parses the body before storing or verifying it. The
HTTP receiver (`src/server.ts`) accumulates the raw `Buffer` chunks straight
off the socket and stores that buffer, base64-encoded, in the `Delivery`
record's `bodyBase64` field. Replay (`src/replay.ts`) decodes that same
base64 field back into the original bytes and sends them unmodified.
`test/raw-body.test.ts` demonstrates this concretely: it signs a body with
unusual formatting, shows that `JSON.parse` + `JSON.stringify` produces
different bytes, and confirms verification against those re-serialized bytes
fails while verification against the stored raw bytes succeeds.

## Supported providers

| Provider | Header(s)                                          | Algorithm         | Encoding | Notes                          |
|----------|-----------------------------------------------------|--------------------|----------|----------------------------------|
| GitHub   | `X-Hub-Signature-256`                                | HMAC-SHA256        | hex      | `sha256=` prefix                |
| Stripe   | `Stripe-Signature`                                    | HMAC-SHA256        | hex      | `t=...,v1=...`; replay window   |
| Shopify  | `X-Shopify-Hmac-Sha256`                              | HMAC-SHA256        | base64   | no prefix                       |
| Slack    | `X-Slack-Signature`, `X-Slack-Request-Timestamp`      | HMAC-SHA256        | hex      | `v0:` prefix, `v0:ts:body` basestring; optional replay window |
| Generic  | any (configurable)                                   | any (configurable) | hex/base64 | optional configurable prefix  |

## Installation

```bash
git clone <this-repo>
cd webhook-lens
npm install
npm run build
npm link   # optional: makes `webhook-lens` available globally
```

Requires Node.js 18 or newer.

## Usage

```
webhook-lens listen [--port <n>] [--host <host>] [--dir <path>]
webhook-lens list [--dir <path>]
webhook-lens show <id> [--dir <path>] [--raw]
webhook-lens replay <id> --to <url> [--resign-scheme <scheme> --resign-secret <secret>] [--dir <path>]
webhook-lens verify <id> --scheme <scheme> --secret <secret> [--tolerance <seconds>] [--dir <path>]
                        [--header <name> --prefix <p> --encoding <hex|base64>]  (generic scheme only)
```

Schemes: `github`, `stripe`, `shopify`, `slack`, `generic`.

Deliveries are stored under `.webhook-lens/deliveries` in the current
working directory by default; pass `--dir` to use a different location.

## Examples

Start the receiver:

```bash
webhook-lens listen --port 8787
```

Point your provider's webhook URL (or a test client) at
`http://localhost:8787/<any-path>`. Each request is captured and printed as
it arrives.

List captured deliveries:

```bash
webhook-lens list
```

Inspect one:

```bash
webhook-lens show 8f9298fe-5a47-4b40-bb03-b0c8cf65bddb
```

Verify a GitHub delivery's signature:

```bash
webhook-lens verify 8f9298fe-5a47-4b40-bb03-b0c8cf65bddb \
  --scheme github --secret "$GITHUB_WEBHOOK_SECRET"
```

Verify a Stripe delivery, allowing a wider replay window (e.g. for an old
capture you're replaying much later):

```bash
webhook-lens verify 8f9298fe-5a47-4b40-bb03-b0c8cf65bddb \
  --scheme stripe --secret "$STRIPE_WEBHOOK_SECRET" --tolerance 999999999
```

Replay a captured delivery against your local dev server, re-signed with
your local secret:

```bash
webhook-lens replay 8f9298fe-5a47-4b40-bb03-b0c8cf65bddb \
  --to http://localhost:3000/webhooks/github \
  --resign-scheme github --resign-secret "$LOCAL_DEV_SECRET"
```

Verify against the generic scheme (e.g. a provider not listed above that
signs with `X-Signature: sha256=<hex hmac>`):

```bash
webhook-lens verify <id> --scheme generic --secret "$SECRET" \
  --header x-signature --prefix "sha256=" --encoding hex
```

### Using the library directly

```ts
import { verifyDelivery, DeliveryStore } from 'webhook-lens';

const store = new DeliveryStore();
const delivery = await store.get('some-id');

const result = verifyDelivery(delivery!, {
  scheme: 'github',
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

if (!result.valid) {
  throw new Error(`Invalid signature: ${result.reason}`);
}
```

## Testing

```bash
npm test          # vitest, 80+ tests
npx tsc --noEmit  # type-check
npx eslint .       # lint
```

The test suite covers, among other things: valid and invalid signatures for
every scheme, tampered-body detection, Stripe replay-window expiry, raw-body
preservation against JSON re-serialization, delivery storage round-trips,
and the HTTP receiver exercised against a real server on an ephemeral port.

## Security

- Signature comparisons always use `crypto.timingSafeEqual`, never `===` on
  strings or encoded values, to avoid timing side channels.
- Malformed signature encodings (non-hex, non-base64) are rejected rather
  than throwing or silently truncating.
- Stripe (and, optionally, Slack) verification enforces a replay-window
  check against the signed timestamp.
- Sensitive header values (`Authorization`, provider signature headers,
  cookies, etc.) are redacted in CLI output by default; pass `--raw` to
  `show` if you explicitly need to see them.
- The receiver binds to `127.0.0.1` by default -- it is meant for local use,
  not as an internet-facing endpoint.
- No captured secret or delivery ever leaves your machine; there is no
  telemetry and no external network calls other than the ones you
  explicitly trigger with `replay`.

If you find a security issue, please open an issue describing it (without
including real secrets or payloads).

## License

MIT © 2026 Prabesh Sharma
