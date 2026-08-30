import { describe, expect, it } from 'vitest';
import { verifyDelivery } from '../src/signatures/index.js';
import { signGitHub } from '../src/signatures/github.js';
import { signStripe } from '../src/signatures/stripe.js';
import { signShopify } from '../src/signatures/shopify.js';
import { signSlack } from '../src/signatures/slack.js';
import { signGeneric } from '../src/signatures/generic.js';
import type { Delivery } from '../src/types.js';

const SECRET = 'whsec_test_synthetic_dispatch_secret';

function makeDelivery(headers: Record<string, string>, body: Buffer): Delivery {
  return {
    id: 'test-id',
    receivedAt: new Date().toISOString(),
    method: 'POST',
    path: '/hook',
    headers,
    bodyBase64: body.toString('base64'),
  };
}

describe('verifyDelivery dispatch', () => {
  it('verifies a github-scheme delivery end to end from stored headers', () => {
    const body = Buffer.from(JSON.stringify({ a: 1 }));
    const delivery = makeDelivery({ 'x-hub-signature-256': signGitHub(body, SECRET) }, body);
    const result = verifyDelivery(delivery, { scheme: 'github', secret: SECRET });
    expect(result.valid).toBe(true);
    expect(result.scheme).toBe('github');
  });

  it('verifies a stripe-scheme delivery end to end from stored headers', () => {
    const body = Buffer.from(JSON.stringify({ a: 1 }));
    const now = Date.now();
    const delivery = makeDelivery({ 'stripe-signature': signStripe(body, SECRET, Math.floor(now / 1000)) }, body);
    const result = verifyDelivery(delivery, { scheme: 'stripe', secret: SECRET, now });
    expect(result.valid).toBe(true);
  });

  it('verifies a shopify-scheme delivery end to end from stored headers', () => {
    const body = Buffer.from(JSON.stringify({ a: 1 }));
    const delivery = makeDelivery({ 'x-shopify-hmac-sha256': signShopify(body, SECRET) }, body);
    const result = verifyDelivery(delivery, { scheme: 'shopify', secret: SECRET });
    expect(result.valid).toBe(true);
  });

  it('verifies a slack-scheme delivery end to end from stored headers', () => {
    const body = Buffer.from('a=1');
    const ts = Math.floor(Date.now() / 1000);
    const delivery = makeDelivery(
      { 'x-slack-signature': signSlack(body, SECRET, ts), 'x-slack-request-timestamp': String(ts) },
      body,
    );
    const result = verifyDelivery(delivery, { scheme: 'slack', secret: SECRET });
    expect(result.valid).toBe(true);
  });

  it('verifies a generic-scheme delivery end to end from stored headers', () => {
    const body = Buffer.from('a=1');
    const genericOpts = { headerName: 'x-signature', prefix: 'sha256=', encoding: 'hex' as const };
    const delivery = makeDelivery({ 'x-signature': signGeneric(body, { ...genericOpts, secret: SECRET }) }, body);
    const result = verifyDelivery(delivery, { scheme: 'generic', secret: SECRET, generic: genericOpts });
    expect(result.valid).toBe(true);
  });

  it('does header lookup case-insensitively', () => {
    const body = Buffer.from(JSON.stringify({ a: 1 }));
    const delivery = makeDelivery({ 'X-Hub-Signature-256': signGitHub(body, SECRET) }, body);
    const result = verifyDelivery(delivery, { scheme: 'github', secret: SECRET });
    expect(result.valid).toBe(true);
  });

  it('returns invalid with a reason when the required header is absent', () => {
    const body = Buffer.from('{}');
    const delivery = makeDelivery({}, body);
    const result = verifyDelivery(delivery, { scheme: 'github', secret: SECRET });
    expect(result.valid).toBe(false);
    expect(result.reason).toBeTruthy();
  });

  it('returns invalid for generic scheme when no generic options are supplied', () => {
    const body = Buffer.from('{}');
    const delivery = makeDelivery({ 'x-signature': 'sha256=abc' }, body);
    const result = verifyDelivery(delivery, { scheme: 'generic', secret: SECRET });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/generic scheme requires/i);
  });
});
