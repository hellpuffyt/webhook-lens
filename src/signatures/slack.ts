import { createHmac } from 'node:crypto';
import { timingSafeEqualHex } from './util.js';

export interface SlackVerifyResult {
  valid: boolean;
  reason?: string;
}

export interface SlackVerifyOptions {
  /**
   * Optional replay-window check (seconds). Slack's docs recommend rejecting
   * requests whose timestamp is more than five minutes old. Left undefined
   * by default so basic signature-only verification (matching the documented
   * algorithm exactly) still works without a clock-dependent check.
   */
  toleranceSeconds?: number;
  now?: number;
}

/**
 * Slack webhook (Events API / interactivity) signature verification.
 *
 * Slack signs a basestring of `v0:{timestamp}:{raw body}` with HMAC-SHA256
 * using the app's signing secret, hex-encodes the digest, and sends it in
 * `X-Slack-Signature` prefixed with `v0=`. The timestamp is sent separately
 * in `X-Slack-Request-Timestamp` and must be included verbatim (as a string)
 * in the basestring.
 *
 * Reference: https://api.slack.com/authentication/verifying-requests-from-slack
 */
export function verifySlackSignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  timestampHeader: string | undefined,
  secret: string,
  options: SlackVerifyOptions = {},
): SlackVerifyResult {
  if (!signatureHeader) {
    return { valid: false, reason: 'missing X-Slack-Signature header' };
  }
  if (!timestampHeader) {
    return { valid: false, reason: 'missing X-Slack-Request-Timestamp header' };
  }
  const prefix = 'v0=';
  if (!signatureHeader.startsWith(prefix)) {
    return { valid: false, reason: 'signature header missing v0= prefix' };
  }

  if (options.toleranceSeconds !== undefined) {
    if (!Number.isFinite(options.toleranceSeconds) || options.toleranceSeconds < 0) {
      return { valid: false, reason: 'invalid tolerance (must be a non-negative number of seconds)' };
    }
    const ts = Number.parseInt(timestampHeader, 10);
    if (Number.isNaN(ts)) {
      return { valid: false, reason: 'malformed timestamp header' };
    }
    const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
    const age = Math.abs(nowSeconds - ts);
    if (age > options.toleranceSeconds) {
      return { valid: false, reason: `timestamp outside tolerance window (age=${age}s, tolerance=${options.toleranceSeconds}s)` };
    }
  }

  // HMAC over `v0:{ts}:` followed by the raw body bytes (never a decoded string).
  const expectedHex = createHmac('sha256', secret).update(`v0:${timestampHeader}:`, 'utf8').update(rawBody).digest('hex');
  const providedHex = signatureHeader.slice(prefix.length);

  if (!timingSafeEqualHex(expectedHex, providedHex)) {
    return { valid: false, reason: 'signature mismatch' };
  }
  return { valid: true };
}

/** Compute the `X-Slack-Signature` header value for a payload, e.g. for replay re-signing. */
export function signSlack(rawBody: Buffer, secret: string, timestampSeconds: number = Math.floor(Date.now() / 1000)): string {
  return `v0=${createHmac('sha256', secret).update(`v0:${timestampSeconds}:`, 'utf8').update(rawBody).digest('hex')}`;
}
