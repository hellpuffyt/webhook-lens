/**
 * Core shared types for webhook-lens.
 */

/** A single captured HTTP delivery, stored exactly as received. */
export interface Delivery {
  /** Unique identifier assigned at capture time. */
  id: string;
  /** ISO-8601 timestamp of when the delivery was received. */
  receivedAt: string;
  /** HTTP method (GET, POST, ...). */
  method: string;
  /** Request path including query string, as received. */
  path: string;
  /** All request headers, lower-cased keys, as received. */
  headers: Record<string, string>;
  /**
   * The raw request body, base64-encoded.
   *
   * The body is stored as base64 (not UTF-8 text) so that byte-for-byte
   * fidelity is preserved regardless of encoding. Signature verification is
   * always computed over these exact bytes -- never over a re-serialized
   * JSON representation, which is not guaranteed to produce the same bytes
   * (key order, whitespace, numeric formatting, and unicode escaping can
   * all change silently).
   */
  bodyBase64: string;
  /** Remote address of the sender, if known. */
  remoteAddress?: string;
}

/** Supported signature verification schemes. */
export type SignatureScheme = 'github' | 'stripe' | 'shopify' | 'slack' | 'generic';

/** Result of a signature verification attempt. */
export interface VerificationResult {
  scheme: SignatureScheme;
  valid: boolean;
  reason?: string;
}

/** Options accepted by the generic HMAC scheme. */
export interface GenericHmacOptions {
  headerName: string;
  secret: string;
  /** Optional prefix stripped from the header value before decoding, e.g. "sha256=". */
  prefix?: string;
  encoding?: 'hex' | 'base64';
  algorithm?: string;
}

/** Options for verifying a single delivery against a given scheme. */
export interface VerifyOptions {
  scheme: SignatureScheme;
  secret: string;
  /** For Stripe: max allowed age (seconds) between timestamp and "now". Default 300. */
  toleranceSeconds?: number;
  /** For Stripe replay-window checks: the reference "now" instant (ms epoch). Defaults to Date.now(). */
  now?: number;
  /** For the generic scheme. */
  generic?: Omit<GenericHmacOptions, 'secret'>;
}
