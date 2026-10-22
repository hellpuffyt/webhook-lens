import { createHmac } from 'node:crypto';
import { timingSafeEqualHex } from './util.js';

export interface StripeVerifyOptions {
  toleranceSeconds?: number;
  /** Reference "now" instant in milliseconds since epoch. Defaults to Date.now(). */
  now?: number;
}

export interface StripeVerifyResult {
  valid: boolean;
  reason?: string;
}

const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Stripe webhook signature verification.
 *
 * The `Stripe-Signature` header looks like:
 *   t=1614556800,v1=5257a869e7...,v0=...
 *
 * The signed payload is the ASCII string `${timestamp}.${rawBody}`, HMAC-SHA256'd
 * with the webhook signing secret, hex-encoded. Stripe may include multiple
 * `v1` values (e.g. during secret rotation) -- a match against any is accepted.
 * A `v0` scheme also appears for older/deprecated signing; we only verify `v1`.
 *
 * Stripe also recommends rejecting deliveries whose timestamp is too far from
 * "now" as a defense against replay attacks.
 *
 * Reference: https://docs.stripe.com/webhooks/signatures
 */
export function verifyStripeSignature(
  rawBody: Buffer,
  headerValue: string | undefined,
  secret: string,
  options: StripeVerifyOptions = {},
): StripeVerifyResult {
  if (!headerValue) {
    return { valid: false, reason: 'missing Stripe-Signature header' };
  }

  const parts = parseStripeHeader(headerValue);
  if (parts.timestamp === undefined) {
    return { valid: false, reason: 'missing timestamp (t=) in signature header' };
  }
  if (parts.v1Signatures.length === 0) {
    return { valid: false, reason: 'missing v1 signature in signature header' };
  }

  // Sign `${t}.` followed by the raw body BYTES. Decoding the body to a UTF-8
  // string first would corrupt any non-UTF-8 byte and break verification.
  const expectedHex = createHmac('sha256', secret).update(`${parts.timestamp}.`, 'utf8').update(rawBody).digest('hex');

  const matched = parts.v1Signatures.some((sig) => timingSafeEqualHex(expectedHex, sig));
  if (!matched) {
    return { valid: false, reason: 'signature mismatch' };
  }

  const toleranceSeconds = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  // A NaN tolerance would make `age > tolerance` always false and silently
  // disable the replay-window check, so reject anything that is not a
  // non-negative finite number.
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0) {
    return { valid: false, reason: 'invalid tolerance (must be a non-negative number of seconds)' };
  }
  const nowMs = options.now ?? Date.now();
  const nowSeconds = Math.floor(nowMs / 1000);
  const age = Math.abs(nowSeconds - parts.timestamp);
  if (age > toleranceSeconds) {
    return { valid: false, reason: `timestamp outside tolerance window (age=${age}s, tolerance=${toleranceSeconds}s)` };
  }

  return { valid: true };
}

function parseStripeHeader(headerValue: string): { timestamp?: number; v1Signatures: string[] } {
  let timestamp: number | undefined;
  const v1Signatures: string[] = [];

  for (const rawPart of headerValue.split(',')) {
    const eq = rawPart.indexOf('=');
    if (eq === -1) continue;
    const key = rawPart.slice(0, eq).trim();
    const value = rawPart.slice(eq + 1).trim();
    if (key === 't') {
      const parsed = Number.parseInt(value, 10);
      if (!Number.isNaN(parsed)) {
        timestamp = parsed;
      }
    } else if (key === 'v1') {
      v1Signatures.push(value);
    }
  }

  return { timestamp, v1Signatures };
}

/** Build a `Stripe-Signature` header value for a payload, e.g. for replay re-signing. */
export function signStripe(rawBody: Buffer, secret: string, timestampSeconds: number = Math.floor(Date.now() / 1000)): string {
  const v1 = createHmac('sha256', secret).update(`${timestampSeconds}.`, 'utf8').update(rawBody).digest('hex');
  return `t=${timestampSeconds},v1=${v1}`;
}
