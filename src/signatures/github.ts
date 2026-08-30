import { createHmac } from 'node:crypto';
import { timingSafeEqualHex } from './util.js';

/**
 * GitHub webhook signature verification.
 *
 * GitHub signs the raw request body with HMAC-SHA256 using the webhook
 * secret configured for the hook, and sends the hex digest in the
 * `X-Hub-Signature-256` header, prefixed with `sha256=`.
 *
 * Reference: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 */
export function verifyGitHubSignature(rawBody: Buffer, headerValue: string | undefined, secret: string): boolean {
  if (!headerValue) {
    return false;
  }
  const prefix = 'sha256=';
  if (!headerValue.startsWith(prefix)) {
    return false;
  }
  const providedHex = headerValue.slice(prefix.length);
  const expectedHex = createHmac('sha256', secret).update(rawBody).digest('hex');
  return timingSafeEqualHex(expectedHex, providedHex);
}

/** Compute the `X-Hub-Signature-256` header value for a payload, e.g. for replay re-signing. */
export function signGitHub(rawBody: Buffer, secret: string): string {
  return `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}
