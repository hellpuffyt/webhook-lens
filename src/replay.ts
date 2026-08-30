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
  const rawBody = deliveryRawBody(delivery);
  const url = new URL(options.to);
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
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            bodyBase64: Buffer.concat(chunks).toString('base64'),
          });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('replay request timed out')));
    req.on('error', reject);
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
