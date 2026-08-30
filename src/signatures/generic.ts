import { createHmac } from 'node:crypto';
import { timingSafeEqualBase64, timingSafeEqualHex } from './util.js';
import type { GenericHmacOptions } from '../types.js';

/**
 * Generic, configurable HMAC verification for providers without a
 * dedicated scheme. The caller supplies the header name to read the
 * signature from, the algorithm (anything OpenSSL/Node supports, default
 * sha256), the digest encoding (hex or base64), and an optional prefix to
 * strip from the header value (e.g. "sha256=").
 */
export function verifyGenericHmac(rawBody: Buffer, headerValue: string | undefined, options: GenericHmacOptions): boolean {
  if (!headerValue) {
    return false;
  }
  const algorithm = options.algorithm ?? 'sha256';
  const encoding = options.encoding ?? 'hex';
  let value = headerValue.trim();
  if (options.prefix) {
    if (!value.startsWith(options.prefix)) {
      return false;
    }
    value = value.slice(options.prefix.length);
  }

  const expected = createHmac(algorithm, options.secret).update(rawBody).digest(encoding);
  return encoding === 'hex' ? timingSafeEqualHex(expected, value) : timingSafeEqualBase64(expected, value);
}

/** Compute a generic HMAC signature header value for a payload, e.g. for replay re-signing. */
export function signGeneric(rawBody: Buffer, options: GenericHmacOptions): string {
  const algorithm = options.algorithm ?? 'sha256';
  const encoding = options.encoding ?? 'hex';
  const digest = createHmac(algorithm, options.secret).update(rawBody).digest(encoding);
  return options.prefix ? `${options.prefix}${digest}` : digest;
}
