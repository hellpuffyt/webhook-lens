import type { Delivery, VerificationResult, VerifyOptions } from '../types.js';
import { verifyGitHubSignature } from './github.js';
import { verifyStripeSignature } from './stripe.js';
import { verifyShopifySignature } from './shopify.js';
import { verifySlackSignature } from './slack.js';
import { verifyGenericHmac } from './generic.js';

export * from './github.js';
export * from './stripe.js';
export * from './shopify.js';
export * from './slack.js';
export * from './generic.js';
export * from './util.js';

/** Decode a stored delivery's body back into raw bytes. */
export function deliveryRawBody(delivery: Delivery): Buffer {
  return Buffer.from(delivery.bodyBase64, 'base64');
}

/** Case-insensitive header lookup (delivery headers are stored lower-cased, but be defensive). */
function header(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      return value;
    }
  }
  return undefined;
}

/**
 * Verify a captured delivery's signature against the given scheme.
 * This is the single entry point the CLI and tests use so that scheme
 * dispatch lives in one place.
 */
export function verifyDelivery(delivery: Delivery, options: VerifyOptions): VerificationResult {
  const rawBody = deliveryRawBody(delivery);

  switch (options.scheme) {
    case 'github': {
      const valid = verifyGitHubSignature(rawBody, header(delivery.headers, 'x-hub-signature-256'), options.secret);
      return { scheme: 'github', valid, reason: valid ? undefined : 'signature mismatch or missing header' };
    }
    case 'stripe': {
      const result = verifyStripeSignature(rawBody, header(delivery.headers, 'stripe-signature'), options.secret, {
        toleranceSeconds: options.toleranceSeconds,
        now: options.now,
      });
      return { scheme: 'stripe', valid: result.valid, reason: result.reason };
    }
    case 'shopify': {
      const valid = verifyShopifySignature(rawBody, header(delivery.headers, 'x-shopify-hmac-sha256'), options.secret);
      return { scheme: 'shopify', valid, reason: valid ? undefined : 'signature mismatch or missing header' };
    }
    case 'slack': {
      const result = verifySlackSignature(
        rawBody,
        header(delivery.headers, 'x-slack-signature'),
        header(delivery.headers, 'x-slack-request-timestamp'),
        options.secret,
        { toleranceSeconds: options.toleranceSeconds, now: options.now },
      );
      return { scheme: 'slack', valid: result.valid, reason: result.reason };
    }
    case 'generic': {
      if (!options.generic) {
        return { scheme: 'generic', valid: false, reason: 'generic scheme requires headerName/encoding options' };
      }
      const valid = verifyGenericHmac(rawBody, header(delivery.headers, options.generic.headerName), {
        ...options.generic,
        secret: options.secret,
      });
      return { scheme: 'generic', valid, reason: valid ? undefined : 'signature mismatch or missing header' };
    }
    default: {
      const exhaustiveCheck: never = options.scheme;
      throw new Error(`Unknown signature scheme: ${String(exhaustiveCheck)}`);
    }
  }
}
