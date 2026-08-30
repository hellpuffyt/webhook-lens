/**
 * Redaction helpers so secrets never leak into logs, stored files, or CLI
 * output.
 */

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-hub-signature',
  'x-hub-signature-256',
  'stripe-signature',
  'x-shopify-hmac-sha256',
  'x-slack-signature',
  'x-webhook-secret',
  'proxy-authorization',
]);

/** Replace a secret value with a short, non-reversible preview. */
export function redactSecret(secret: string): string {
  if (secret.length <= 4) {
    return '****';
  }
  return `${secret.slice(0, 2)}${'*'.repeat(Math.max(4, secret.length - 4))}${secret.slice(-2)}`;
}

/** Returns true if a header name is considered sensitive and should be redacted in display output. */
export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER_NAMES.has(name.toLowerCase());
}

/** Produce a copy of headers with sensitive values redacted, for safe display/logging. */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = isSensitiveHeader(key) ? redactSecret(value) : value;
  }
  return out;
}
