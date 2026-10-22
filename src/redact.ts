/**
 * Redaction helpers so secrets do not leak into console logs or CLI output.
 *
 * Stored capture files are deliberately NOT redacted: verification and
 * replay need the exact original headers. They are written owner-only
 * (0600) instead; see storage.ts.
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
  'x-signature',
  'x-gitlab-token',
]);

/**
 * Header-name fragments that indicate a secret-bearing header even when the
 * exact name is not in the list above (e.g. `X-Twilio-Signature`,
 * `Webhook-Signature`, `X-Custom-Token`, the generic scheme's configurable
 * header). Erring towards redaction is the safe default for display output.
 */
const SENSITIVE_HEADER_FRAGMENT_RE = /(signature|secret|token|api[-_]?key|auth|cookie|password|hmac)/i;

/** Query-string parameter names whose values are redacted in displayed paths. */
const SENSITIVE_QUERY_PARAM_RE = /(sig|signature|secret|token|key|auth|password|passwd|code|hmac)/i;

/** Replace a secret value with a short, non-reversible preview. */
export function redactSecret(secret: string): string {
  if (secret.length <= 4) {
    return '****';
  }
  return `${secret.slice(0, 2)}${'*'.repeat(Math.max(4, secret.length - 4))}${secret.slice(-2)}`;
}

/** Returns true if a header name is considered sensitive and should be redacted in display output. */
export function isSensitiveHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return SENSITIVE_HEADER_NAMES.has(lower) || SENSITIVE_HEADER_FRAGMENT_RE.test(lower);
}

/**
 * Redact the values of secret-looking query parameters in a request path
 * (e.g. `/hook?token=abc` -> `/hook?token=****`), for safe display/logging.
 * The path itself and non-sensitive parameters are left untouched.
 */
export function redactPath(requestPath: string): string {
  const q = requestPath.indexOf('?');
  if (q === -1) {
    return requestPath;
  }
  const base = requestPath.slice(0, q);
  const query = requestPath.slice(q + 1);
  const parts = query.split('&').map((part) => {
    const eq = part.indexOf('=');
    if (eq === -1) return part;
    let name = part.slice(0, eq);
    try {
      name = decodeURIComponent(name.replace(/\+/g, ' '));
    } catch {
      // keep the raw name if it is not valid percent-encoding
    }
    return SENSITIVE_QUERY_PARAM_RE.test(name) ? `${part.slice(0, eq)}=****` : part;
  });
  return `${base}?${parts.join('&')}`;
}

/** Produce a copy of headers with sensitive values redacted, for safe display/logging. */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = isSensitiveHeader(key) ? redactSecret(value) : value;
  }
  return out;
}
