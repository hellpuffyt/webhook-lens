import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { Delivery, GenericHmacOptions } from './types.js';
import { deliveryRawBody } from './signatures/index.js';
import { signGitHub } from './signatures/github.js';
import { signStripe } from './signatures/stripe.js';
import { signShopify } from './signatures/shopify.js';
import { signSlack } from './signatures/slack.js';
import { signGeneric } from './signatures/generic.js';

/** Headers that describe the original connection/host and should not be forwarded verbatim on replay. */
const HOP_BY_HOP_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'expect',
]);

export interface ResignOptions {
  scheme: 'github' | 'stripe' | 'shopify' | 'slack' | 'generic';
  secret: string;
  generic?: Omit<GenericHmacOptions, 'secret'>;
}

export interface ReplayOptions {
  /** Target URL to send the delivery to. */
  to: string;
  /** Optionally recompute and overwrite the provider signature header using a (possibly different) secret. */
  resign?: ResignOptions;
  /** Request timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  /**
   * Allow replaying to a non-loopback host. Default false: replay forwards
   * the captured headers (including Authorization, cookies and signatures),
   * so by default it only targets `localhost`, `127.0.0.0/8` or `[::1]`.
   * Set this only for a target you explicitly trust.
   */
  allowRemote?: boolean;
  /** Maximum response body size buffered from the target, in bytes. Default 10MB. */
  maxResponseBytes?: number;
}

const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

/** Raised when a replay target is refused (bad URL, scheme, credentials, or non-loopback host). */
export class ReplayTargetError extends Error {
  override name = 'ReplayTargetError';
}

/** True if a URL hostname (as normalised by WHATWG `URL`) is a loopback address. */
export function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '[::1]') {
    return true;
  }
  // WHATWG URL already normalises IPv4 forms like 0x7f.1 or 2130706433 to dotted quads.
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return m !== null && m.slice(1).every((octet) => Number(octet) <= 255);
}

/**
 * Validate a replay target and return the parsed URL. Only http(s) is
 * accepted, credentials embedded in the URL are refused, and non-loopback
 * hosts are refused unless `allowRemote` is set.
 */
export function parseReplayTarget(to: string, allowRemote = false): URL {
  let url: URL;
  try {
    url = new URL(to);
  } catch {
    throw new ReplayTargetError(`Invalid replay target URL: ${to}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ReplayTargetError(`Replay target must be http(s), got ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new ReplayTargetError('Replay target URL must not embed credentials');
  }
  if (!allowRemote && !isLoopbackHostname(url.hostname)) {
    throw new ReplayTargetError(
      `Refusing to replay to non-loopback host ${url.hostname}: captured headers (auth, signatures) would be sent there. ` +
        'Pass --allow-remote (library: allowRemote: true) if you explicitly trust this target.',
    );
  }
  return url;
}

export interface ReplayResult {
  statusCode: number | undefined;
  headers: Record<string, string | string[] | undefined>;
  bodyBase64: string;
}

/**
 * Re-send a captured delivery to a target URL.
 *
 * The raw body bytes are forwarded exactly as captured (never re-serialized),
 * and all original headers are forwarded except hop-by-hop / connection
 * headers that must be recomputed for the new connection. When `resign` is
 * given, the relevant signature header is recomputed with the provided
 * secret/scheme so a delivery can be replayed against a handler configured
 * with a different (e.g. local/dev) signing secret.
 */
export function replayDelivery(delivery: Delivery, options: ReplayOptions): Promise<ReplayResult> {
  let url: URL;
  try {
    url = parseReplayTarget(options.to, options.allowRemote ?? false);
  } catch (err) {
    return Promise.reject(err);
  }
  const rawBody = deliveryRawBody(delivery);
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const isHttps = url.protocol === 'https:';
  const requestFn = isHttps ? httpsRequest : httpRequest;

  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(delivery.headers)) {
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase())) continue;
    headers[key] = value;
  }
  headers['content-length'] = String(rawBody.length);

  if (options.resign) {
    applyResign(headers, rawBody, options.resign);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const req = requestFn(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: delivery.method,
        headers,
        timeout: options.timeoutMs ?? 10_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxResponseBytes) {
            fail(new Error(`replay response exceeded ${maxResponseBytes} bytes`));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', fail);
        res.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            bodyBase64: Buffer.concat(chunks).toString('base64'),
          });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('replay request timed out')));
    req.on('error', fail);
    req.end(rawBody);
  });
}

function applyResign(headers: Record<string, string>, rawBody: Buffer, resign: ResignOptions): void {
  switch (resign.scheme) {
    case 'github':
      headers['x-hub-signature-256'] = signGitHub(rawBody, resign.secret);
      return;
    case 'stripe':
      headers['stripe-signature'] = signStripe(rawBody, resign.secret);
      return;
    case 'shopify':
      headers['x-shopify-hmac-sha256'] = signShopify(rawBody, resign.secret);
      return;
    case 'slack': {
      const timestamp = Math.floor(Date.now() / 1000);
      headers['x-slack-request-timestamp'] = String(timestamp);
      headers['x-slack-signature'] = signSlack(rawBody, resign.secret, timestamp);
      return;
    }
    case 'generic': {
      if (!resign.generic) {
        throw new Error('generic re-sign requires generic options (headerName, encoding, prefix)');
      }
      headers[resign.generic.headerName] = signGeneric(rawBody, { ...resign.generic, secret: resign.secret });
      return;
    }
    default: {
      const exhaustiveCheck: never = resign.scheme;
      throw new Error(`Unknown resign scheme: ${String(exhaustiveCheck)}`);
    }
  }
}
