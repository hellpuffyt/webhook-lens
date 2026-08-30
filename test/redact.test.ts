import { describe, expect, it } from 'vitest';
import { redactSecret, redactHeaders, isSensitiveHeader } from '../src/redact.js';

describe('redactSecret', () => {
  it('keeps only a short preview of a long secret', () => {
    const redacted = redactSecret('whsec_test_synthetic_0123456789abcdef');
    expect(redacted.startsWith('wh')).toBe(true);
    expect(redacted.endsWith('ef')).toBe(true);
    expect(redacted).not.toContain('synthetic');
  });

  it('fully masks very short secrets', () => {
    expect(redactSecret('ab')).toBe('****');
  });
});

describe('isSensitiveHeader', () => {
  it('flags known sensitive header names case-insensitively', () => {
    expect(isSensitiveHeader('Authorization')).toBe(true);
    expect(isSensitiveHeader('X-Hub-Signature-256')).toBe(true);
    expect(isSensitiveHeader('stripe-signature')).toBe(true);
  });

  it('does not flag ordinary headers', () => {
    expect(isSensitiveHeader('content-type')).toBe(false);
    expect(isSensitiveHeader('user-agent')).toBe(false);
  });
});

describe('redactHeaders', () => {
  it('redacts sensitive header values and leaves others untouched', () => {
    const out = redactHeaders({
      'content-type': 'application/json',
      authorization: 'Bearer verysecrettoken1234',
    });
    expect(out['content-type']).toBe('application/json');
    expect(out.authorization).not.toBe('Bearer verysecrettoken1234');
    expect(out.authorization).toContain('*');
  });
});
