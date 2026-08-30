import { describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import { verifyGitHubSignature, signGitHub } from '../src/signatures/github.js';
import { verifyStripeSignature, signStripe } from '../src/signatures/stripe.js';
import { verifyShopifySignature, signShopify } from '../src/signatures/shopify.js';
import { verifySlackSignature, signSlack } from '../src/signatures/slack.js';
import { verifyGenericHmac, signGeneric } from '../src/signatures/generic.js';
import { timingSafeEqualBuffers, timingSafeEqualHex, timingSafeEqualBase64 } from '../src/signatures/util.js';

const SECRET = 'whsec_test_synthetic_0123456789abcdef';
const OTHER_SECRET = 'whsec_test_synthetic_other_secret_zz';

describe('GitHub signature (X-Hub-Signature-256)', () => {
  it('accepts a validly signed body', () => {
    const body = Buffer.from(JSON.stringify({ action: 'opened', number: 42 }));
    const header = signGitHub(body, SECRET);
    expect(header.startsWith('sha256=')).toBe(true);
    expect(verifyGitHubSignature(body, header, SECRET)).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const body = Buffer.from(JSON.stringify({ action: 'opened' }));
    const header = signGitHub(body, OTHER_SECRET);
    expect(verifyGitHubSignature(body, header, SECRET)).toBe(false);
  });

  it('rejects when the body is tampered with after signing', () => {
    const body = Buffer.from(JSON.stringify({ amount: 100 }));
    const header = signGitHub(body, SECRET);
    const tampered = Buffer.from(JSON.stringify({ amount: 999 }));
    expect(verifyGitHubSignature(tampered, header, SECRET)).toBe(false);
  });

  it('rejects a missing header', () => {
    const body = Buffer.from('{}');
    expect(verifyGitHubSignature(body, undefined, SECRET)).toBe(false);
  });

  it('rejects a header missing the sha256= prefix', () => {
    const body = Buffer.from('{}');
    const raw = createHmac('sha256', SECRET).update(body).digest('hex');
    expect(verifyGitHubSignature(body, raw, SECRET)).toBe(false);
  });

  it('rejects a malformed (non-hex) signature value', () => {
    const body = Buffer.from('{}');
    expect(verifyGitHubSignature(body, 'sha256=not-hex-zzz', SECRET)).toBe(false);
  });

  it('rejects an empty string signature', () => {
    const body = Buffer.from('{}');
    expect(verifyGitHubSignature(body, 'sha256=', SECRET)).toBe(false);
  });
});

describe('Stripe signature (Stripe-Signature)', () => {
  it('accepts a validly signed body within the tolerance window', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_1', type: 'charge.succeeded' }));
    const nowMs = Date.parse('2026-01-01T00:00:00Z');
    const header = signStripe(body, SECRET, Math.floor(nowMs / 1000));
    const result = verifyStripeSignature(body, header, SECRET, { now: nowMs });
    expect(result.valid).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_1' }));
    const nowMs = Date.parse('2026-01-01T00:00:00Z');
    const header = signStripe(body, OTHER_SECRET, Math.floor(nowMs / 1000));
    const result = verifyStripeSignature(body, header, SECRET, { now: nowMs });
    expect(result.valid).toBe(false);
  });

  it('rejects when the body is tampered with after signing', () => {
    const body = Buffer.from(JSON.stringify({ amount: 100 }));
    const nowMs = Date.parse('2026-01-01T00:00:00Z');
    const header = signStripe(body, SECRET, Math.floor(nowMs / 1000));
    const tampered = Buffer.from(JSON.stringify({ amount: 999 }));
    const result = verifyStripeSignature(tampered, header, SECRET, { now: nowMs });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/mismatch/);
  });

  it('rejects a missing header', () => {
    const body = Buffer.from('{}');
    const result = verifyStripeSignature(body, undefined, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/missing/i);
  });

  it('rejects a header with no timestamp', () => {
    const body = Buffer.from('{}');
    const sig = createHmac('sha256', SECRET).update(`.${body.toString('utf8')}`).digest('hex');
    const result = verifyStripeSignature(body, `v1=${sig}`, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/timestamp/i);
  });

  it('rejects a header with no v1 signature', () => {
    const body = Buffer.from('{}');
    const result = verifyStripeSignature(body, 't=1700000000', SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/v1/);
  });

  it('rejects a delivery outside the default 300s replay window', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_old' }));
    const tenMinutesAgo = Math.floor(Date.now() / 1000) - 600;
    const header = signStripe(body, SECRET, tenMinutesAgo);
    const result = verifyStripeSignature(body, header, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/tolerance/i);
  });

  it('accepts a delivery within a custom, wider tolerance window', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_old' }));
    const tenMinutesAgo = Math.floor(Date.now() / 1000) - 600;
    const header = signStripe(body, SECRET, tenMinutesAgo);
    const result = verifyStripeSignature(body, header, SECRET, { toleranceSeconds: 3600 });
    expect(result.valid).toBe(true);
  });

  it('accepts a signature matching any v1 value when multiple are present (secret rotation)', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_rot' }));
    const nowMs = Date.parse('2026-01-01T00:00:00Z');
    const ts = Math.floor(nowMs / 1000);
    const wrongV1 = createHmac('sha256', OTHER_SECRET).update(`${ts}.${body.toString('utf8')}`).digest('hex');
    const rightV1 = createHmac('sha256', SECRET).update(`${ts}.${body.toString('utf8')}`).digest('hex');
    const header = `t=${ts},v1=${wrongV1},v1=${rightV1}`;
    const result = verifyStripeSignature(body, header, SECRET, { now: nowMs });
    expect(result.valid).toBe(true);
  });

  it('rejects a future-dated timestamp beyond tolerance', () => {
    const body = Buffer.from(JSON.stringify({ id: 'evt_future' }));
    const tenMinutesFromNow = Math.floor(Date.now() / 1000) + 600;
    const header = signStripe(body, SECRET, tenMinutesFromNow);
    const result = verifyStripeSignature(body, header, SECRET);
    expect(result.valid).toBe(false);
  });
});

describe('Shopify signature (X-Shopify-Hmac-Sha256)', () => {
  it('accepts a validly signed body', () => {
    const body = Buffer.from(JSON.stringify({ id: 12345, order_number: 1001 }));
    const header = signShopify(body, SECRET);
    expect(verifyShopifySignature(body, header, SECRET)).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const body = Buffer.from(JSON.stringify({ id: 12345 }));
    const header = signShopify(body, OTHER_SECRET);
    expect(verifyShopifySignature(body, header, SECRET)).toBe(false);
  });

  it('rejects when the body is tampered with after signing', () => {
    const body = Buffer.from(JSON.stringify({ total: '10.00' }));
    const header = signShopify(body, SECRET);
    const tampered = Buffer.from(JSON.stringify({ total: '10000.00' }));
    expect(verifyShopifySignature(tampered, header, SECRET)).toBe(false);
  });

  it('rejects a missing header', () => {
    const body = Buffer.from('{}');
    expect(verifyShopifySignature(body, undefined, SECRET)).toBe(false);
  });

  it('rejects a malformed base64 signature', () => {
    const body = Buffer.from('{}');
    expect(verifyShopifySignature(body, '***not-base64***', SECRET)).toBe(false);
  });

  it('produces a base64-encoded signature, not hex', () => {
    const body = Buffer.from('{}');
    const header = signShopify(body, SECRET);
    expect(/^[A-Za-z0-9+/]+=*$/.test(header)).toBe(true);
    expect(/^[0-9a-f]+$/i.test(header)).toBe(false);
  });
});

describe('Slack signature (X-Slack-Signature)', () => {
  it('accepts a validly signed body', () => {
    const body = Buffer.from('token=xyz&team_id=T1&command=%2Fecho');
    const ts = String(Math.floor(Date.now() / 1000));
    const header = signSlack(body, SECRET, Number(ts));
    const result = verifySlackSignature(body, header, ts, SECRET);
    expect(result.valid).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const body = Buffer.from('token=xyz');
    const ts = String(Math.floor(Date.now() / 1000));
    const header = signSlack(body, OTHER_SECRET, Number(ts));
    const result = verifySlackSignature(body, header, ts, SECRET);
    expect(result.valid).toBe(false);
  });

  it('rejects when the body is tampered with after signing', () => {
    const body = Buffer.from('amount=100');
    const ts = String(Math.floor(Date.now() / 1000));
    const header = signSlack(body, SECRET, Number(ts));
    const tampered = Buffer.from('amount=999999');
    const result = verifySlackSignature(tampered, header, ts, SECRET);
    expect(result.valid).toBe(false);
  });

  it('rejects a missing signature header', () => {
    const body = Buffer.from('x=1');
    const result = verifySlackSignature(body, undefined, '1700000000', SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/X-Slack-Signature/);
  });

  it('rejects a missing timestamp header', () => {
    const body = Buffer.from('x=1');
    const result = verifySlackSignature(body, 'v0=abc', undefined, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Timestamp/i);
  });

  it('rejects a signature header missing the v0= prefix', () => {
    const body = Buffer.from('x=1');
    const ts = '1700000000';
    const raw = createHmac('sha256', SECRET).update(`v0:${ts}:${body.toString('utf8')}`).digest('hex');
    const result = verifySlackSignature(body, raw, ts, SECRET);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/v0=/);
  });

  it('enforces an optional replay-window tolerance', () => {
    const body = Buffer.from('x=1');
    const oldTs = Math.floor(Date.now() / 1000) - 600;
    const header = signSlack(body, SECRET, oldTs);
    const result = verifySlackSignature(body, header, String(oldTs), SECRET, { toleranceSeconds: 300 });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/tolerance/i);
  });

  it('accepts an old timestamp when no tolerance is configured', () => {
    const body = Buffer.from('x=1');
    const oldTs = Math.floor(Date.now() / 1000) - 600;
    const header = signSlack(body, SECRET, oldTs);
    const result = verifySlackSignature(body, header, String(oldTs), SECRET);
    expect(result.valid).toBe(true);
  });

  it('rejects a malformed timestamp header when tolerance is configured', () => {
    const body = Buffer.from('x=1');
    const header = signSlack(body, SECRET, 1700000000);
    const result = verifySlackSignature(body, header, 'not-a-number', SECRET, { toleranceSeconds: 300 });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });
});

describe('Generic configurable HMAC scheme', () => {
  it('accepts a validly signed body (hex, with prefix)', () => {
    const body = Buffer.from(JSON.stringify({ event: 'ping' }));
    const opts = { headerName: 'x-signature', secret: SECRET, prefix: 'sha256=', encoding: 'hex' as const };
    const header = signGeneric(body, opts);
    expect(verifyGenericHmac(body, header, opts)).toBe(true);
  });

  it('accepts a validly signed body (base64, no prefix)', () => {
    const body = Buffer.from(JSON.stringify({ event: 'ping' }));
    const opts = { headerName: 'x-signature', secret: SECRET, encoding: 'base64' as const };
    const header = signGeneric(body, opts);
    expect(verifyGenericHmac(body, header, opts)).toBe(true);
  });

  it('accepts a validly signed body using sha1 algorithm', () => {
    const body = Buffer.from('payload');
    const opts = { headerName: 'x-signature', secret: SECRET, algorithm: 'sha1', encoding: 'hex' as const };
    const header = signGeneric(body, opts);
    expect(verifyGenericHmac(body, header, opts)).toBe(true);
  });

  it('rejects a signature computed with the wrong secret', () => {
    const body = Buffer.from('payload');
    const opts = { headerName: 'x-signature', secret: SECRET, encoding: 'hex' as const };
    const header = signGeneric(body, { ...opts, secret: OTHER_SECRET });
    expect(verifyGenericHmac(body, header, opts)).toBe(false);
  });

  it('rejects when the body is tampered with after signing', () => {
    const opts = { headerName: 'x-signature', secret: SECRET, encoding: 'hex' as const };
    const header = signGeneric(Buffer.from('a=1'), opts);
    expect(verifyGenericHmac(Buffer.from('a=2'), header, opts)).toBe(false);
  });

  it('rejects a header missing the configured prefix', () => {
    const body = Buffer.from('payload');
    const opts = { headerName: 'x-signature', secret: SECRET, prefix: 'sha256=', encoding: 'hex' as const };
    const rawHex = createHmac('sha256', SECRET).update(body).digest('hex');
    expect(verifyGenericHmac(body, rawHex, opts)).toBe(false);
  });

  it('rejects a missing header', () => {
    const opts = { headerName: 'x-signature', secret: SECRET, encoding: 'hex' as const };
    expect(verifyGenericHmac(Buffer.from('x'), undefined, opts)).toBe(false);
  });
});

describe('timing-safe comparison helpers', () => {
  it('timingSafeEqualBuffers returns true for identical buffers', () => {
    expect(timingSafeEqualBuffers(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
  });

  it('timingSafeEqualBuffers returns false for different-length buffers', () => {
    expect(timingSafeEqualBuffers(Buffer.from('abc'), Buffer.from('abcd'))).toBe(false);
  });

  it('timingSafeEqualBuffers returns false for same-length, different content', () => {
    expect(timingSafeEqualBuffers(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
  });

  it('timingSafeEqualHex rejects non-hex input rather than throwing', () => {
    expect(timingSafeEqualHex('zz', 'zz')).toBe(false);
  });

  it('timingSafeEqualHex rejects odd-length hex input rather than throwing', () => {
    expect(timingSafeEqualHex('abc', 'abcd')).toBe(false);
  });

  it('timingSafeEqualHex matches equal hex case-insensitively at the encoding level', () => {
    expect(timingSafeEqualHex('AABB', 'aabb')).toBe(true);
  });

  it('timingSafeEqualBase64 rejects malformed base64 input rather than throwing', () => {
    expect(timingSafeEqualBase64('***', '***')).toBe(false);
  });

  it('timingSafeEqualBase64 matches equal base64 values', () => {
    const b64 = Buffer.from('hello world').toString('base64');
    expect(timingSafeEqualBase64(b64, b64)).toBe(true);
  });
});
