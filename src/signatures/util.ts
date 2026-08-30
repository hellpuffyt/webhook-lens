import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time comparison of two buffers of possibly-different length.
 *
 * `crypto.timingSafeEqual` throws if the buffers differ in length, which
 * itself leaks a bit of timing information (and is inconvenient). We first
 * compare lengths (cheap, and length is not the secret we are protecting),
 * and only fall through to timingSafeEqual when lengths match.
 */
export function timingSafeEqualBuffers(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/** Compare two hex strings in constant time. Returns false on malformed hex. */
export function timingSafeEqualHex(expectedHex: string, actualHex: string): boolean {
  if (!/^[0-9a-f]+$/i.test(expectedHex) || !/^[0-9a-f]+$/i.test(actualHex)) {
    return false;
  }
  if (expectedHex.length % 2 !== 0 || actualHex.length % 2 !== 0) {
    return false;
  }
  return timingSafeEqualBuffers(Buffer.from(expectedHex, 'hex'), Buffer.from(actualHex, 'hex'));
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Compare two base64 strings in constant time. Returns false on malformed base64. */
export function timingSafeEqualBase64(expectedB64: string, actualB64: string): boolean {
  if (!BASE64_RE.test(expectedB64) || !BASE64_RE.test(actualB64)) {
    return false;
  }
  const a = Buffer.from(expectedB64, 'base64');
  const b = Buffer.from(actualB64, 'base64');
  return timingSafeEqualBuffers(a, b);
}
