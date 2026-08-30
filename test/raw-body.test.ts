import { describe, expect, it } from 'vitest';
import { verifyGitHubSignature, signGitHub } from '../src/signatures/github.js';

const SECRET = 'whsec_test_synthetic_rawbody_secret';

describe('raw-body preservation', () => {
  it('a payload whose JSON re-serialization differs from the original bytes still verifies against the raw bytes', () => {
    // Deliberately unusual formatting: extra whitespace, a specific key
    // order, and a trailing newline -- all things JSON.stringify will not
    // reproduce if the body is parsed and re-serialized.
    const rawBody = Buffer.from('{\n  "b": 2,\n  "a": 1,\n  "note": "hello   world"\n}\n');
    const header = signGitHub(rawBody, SECRET);

    // Verification against the exact captured bytes succeeds.
    expect(verifyGitHubSignature(rawBody, header, SECRET)).toBe(true);

    // Proof that re-serializing would have changed the bytes (and thus, had
    // we stored/verified against the re-serialized form, would have broken
    // verification): parsing then re-stringifying does NOT reproduce the
    // original bytes.
    const parsed = JSON.parse(rawBody.toString('utf8'));
    const reserialized = Buffer.from(JSON.stringify(parsed));
    expect(reserialized.equals(rawBody)).toBe(false);

    // And verifying against that re-serialized (mangled) form fails,
    // demonstrating why storage must never round-trip through JSON.parse.
    expect(verifyGitHubSignature(reserialized, header, SECRET)).toBe(false);
  });

  it('preserves non-JSON raw bodies (e.g. form-encoded) byte-for-byte', () => {
    const rawBody = Buffer.from('a=1&b=2&note=hello%20world');
    const header = signGitHub(rawBody, SECRET);
    expect(verifyGitHubSignature(rawBody, header, SECRET)).toBe(true);
  });

  it('preserves unicode bytes exactly, including characters JSON.stringify would escape differently', () => {
    const rawBody = Buffer.from(JSON.stringify({ msg: 'café ☃ 😀' }), 'utf8');
    const header = signGitHub(rawBody, SECRET);
    expect(verifyGitHubSignature(rawBody, header, SECRET)).toBe(true);
  });
});
