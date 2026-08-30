import { createHmac } from 'node:crypto';
import { timingSafeEqualBase64 } from './util.js';

/**
 * Shopify webhook signature verification.
 *
 * Shopify signs the raw request body with HMAC-SHA256 using the app's shared
 * secret, and sends the *base64-encoded* digest (not hex, unlike GitHub/Stripe)
 * in the `X-Shopify-Hmac-Sha256` header, with no scheme prefix.
 *
 * Reference: https://shopify.dev/docs/apps/build/webhooks/subscribe/https#step-5-verify-the-webhook
 */
export function verifyShopifySignature(rawBody: Buffer, headerValue: string | undefined, secret: string): boolean {
  if (!headerValue) {
    return false;
  }
  const expectedB64 = createHmac('sha256', secret).update(rawBody).digest('base64');
  return timingSafeEqualBase64(expectedB64, headerValue.trim());
}

/** Compute the `X-Shopify-Hmac-Sha256` header value for a payload, e.g. for replay re-signing. */
export function signShopify(rawBody: Buffer, secret: string): string {
  return createHmac('sha256', secret).update(rawBody).digest('base64');
}
