import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import { createServer, request, type Server } from 'node:http';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DeliveryStore, isValidDeliveryId } from '../src/storage.js';
import { replayDelivery, parseReplayTarget, isLoopbackHostname, ReplayTargetError } from '../src/replay.js';
import { verifyStripeSignature, signStripe } from '../src/signatures/stripe.js';
import { verifySlackSignature, signSlack } from '../src/signatures/slack.js';
import { isSensitiveHeader, redactHeaders, redactPath } from '../src/redact.js';
import { startReceiver } from '../src/server.js';
import { parseArgs, flagInt, UsageError } from '../src/args.js';
import type { Delivery } from '../src/types.js';

// Built at runtime so no token-shaped literal lives in the repository.
const SECRET = ['test', 'only', 'security', 'secret'].join('-');

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'webhook-lens-security-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('storage: delivery ids cannot escape the store directory', () => {
  it('rejects path separators and dot-dot in ids', () => {
    expect(isValidDeliveryId('8f9298fe-5a47-4b40-bb03-b0c8cf65bddb')).toBe(true);
    expect(isValidDeliveryId('../secret')).toBe(false);
    expect(isValidDeliveryId('a/b')).toBe(false);
    expect(isValidDeliveryId('a\\b')).toBe(false);
    expect(isValidDeliveryId('..')).toBe(false);
    expect(isValidDeliveryId('')).toBe(false);
  });

  it('get() does not read a JSON file outside the store via a crafted id', async () => {
    const store = new DeliveryStore(path.join(dir, 'store'));
    await store.ensureDir();
    await writeFile(path.join(dir, 'outside.json'), JSON.stringify({ leaked: true }));
    expect(await store.get('../outside')).toBeNull();
  });

  it('save() refuses a crafted id instead of writing outside the store', async () => {
    const store = new DeliveryStore(path.join(dir, 'store'));
    await expect(
      store.save({ id: '../escaped', method: 'POST', path: '/', headers: {}, bodyBase64: '' }),
    ).rejects.toThrow(/Invalid delivery id/);
  });

  it('delete() with a crafted id is a no-op', async () => {
    const store = new DeliveryStore(path.join(dir, 'store'));
    await writeFile(path.join(dir, 'victim.json'), '{}');
    expect(await store.delete('../victim')).toBe(false);
    await expect(stat(path.join(dir, 'victim.json'))).resolves.toBeTruthy();
  });

  it.skipIf(process.platform === 'win32')('writes capture files owner-only (0600) in an owner-only dir (0700)', async () => {
    const store = new DeliveryStore(path.join(dir, 'store'));
    const saved = await store.save({ method: 'POST', path: '/', headers: { authorization: 'x' }, bodyBase64: '' });
    const fileMode = (await stat(path.join(store.dir, `${saved.id}.json`))).mode & 0o777;
    const dirMode = (await stat(store.dir)).mode & 0o777;
    expect(fileMode).toBe(0o600);
    expect(dirMode).toBe(0o700);
  });
});

describe('signatures: HMAC is computed over raw bytes, not a decoded string', () => {
  // 0xff / 0xfe are not valid UTF-8; decoding them would replace them with U+FFFD.
  const nonUtf8Body = Buffer.concat([Buffer.from('{"k":"'), Buffer.from([0xff, 0xfe, 0x80]), Buffer.from('"}')]);

  it('Stripe verifies a correctly signed non-UTF-8 body', () => {
    const t = 1_700_000_000;
    const v1 = createHmac('sha256', SECRET).update(`${t}.`).update(nonUtf8Body).digest('hex');
    const result = verifyStripeSignature(nonUtf8Body, `t=${t},v1=${v1}`, SECRET, { now: t * 1000 });
    expect(result).toEqual({ valid: true });
    expect(signStripe(nonUtf8Body, SECRET, t)).toBe(`t=${t},v1=${v1}`);
  });

  it('Slack verifies a correctly signed non-UTF-8 body', () => {
    const ts = '1700000000';
    const sig = `v0=${createHmac('sha256', SECRET).update(`v0:${ts}:`).update(nonUtf8Body).digest('hex')}`;
    expect(verifySlackSignature(nonUtf8Body, sig, ts, SECRET)).toEqual({ valid: true });
    expect(signSlack(nonUtf8Body, SECRET, Number(ts))).toBe(sig);
  });
});

describe('signatures: an invalid tolerance never disables the replay window', () => {
  const body = Buffer.from('{"id":"evt"}');
  const t = 1_000_000_000; // far in the past relative to `now` below
  const now = 2_000_000_000 * 1000;

  it('Stripe rejects NaN tolerance instead of accepting a stale delivery', () => {
    const header = signStripe(body, SECRET, t);
    const result = verifyStripeSignature(body, header, SECRET, { toleranceSeconds: Number.NaN, now });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/invalid tolerance/);
  });

  it('Stripe rejects a negative tolerance', () => {
    const header = signStripe(body, SECRET, t);
    expect(verifyStripeSignature(body, header, SECRET, { toleranceSeconds: -1, now: t * 1000 }).valid).toBe(false);
  });

  it('Slack rejects NaN tolerance instead of skipping the window check', () => {
    const sig = signSlack(body, SECRET, t);
    const result = verifySlackSignature(body, sig, String(t), SECRET, { toleranceSeconds: Number.NaN, now });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/invalid tolerance/);
  });
});

describe('CLI argument parsing', () => {
  it('rejects non-integer numeric flags (e.g. --tolerance abc) instead of producing NaN', () => {
    const { flags } = parseArgs(['--tolerance', 'abc']);
    expect(() => flagInt(flags, 'tolerance')).toThrow(UsageError);
    expect(() => flagInt(parseArgs(['--port', '80x']).flags, 'port')).toThrow(UsageError);
    expect(() => flagInt(parseArgs(['--tolerance', '-5']).flags, 'tolerance')).toThrow(UsageError);
    expect(flagInt(parseArgs(['--tolerance', '300']).flags, 'tolerance')).toBe(300);
    expect(flagInt(parseArgs([]).flags, 'tolerance')).toBeUndefined();
  });

  it('boolean flags do not swallow the following positional', () => {
    expect(parseArgs(['--raw', 'abc']).positionals).toEqual(['abc']);
    expect(parseArgs(['--allow-remote', 'abc', '--to', 'http://localhost']).positionals).toEqual(['abc']);
  });
});

describe('redaction', () => {
  it('redacts the generic scheme default header and other secret-bearing headers', () => {
    for (const name of ['x-signature', 'X-Gitlab-Token', 'X-Twilio-Signature', 'webhook-signature', 'x-custom-api-key']) {
      expect(isSensitiveHeader(name)).toBe(true);
    }
    const out = redactHeaders({ 'x-signature': `sha256=${'ab'.repeat(32)}` });
    expect(out['x-signature']).not.toContain('ab'.repeat(8));
  });

  it('keeps ordinary headers visible', () => {
    for (const name of ['content-type', 'user-agent', 'x-github-event', 'x-github-delivery', 'accept']) {
      expect(isSensitiveHeader(name)).toBe(false);
    }
  });

  it('redacts secret-looking query parameters in paths', () => {
    const leaked = ['abc', 'def', '123'].join('');
    expect(redactPath(`/hook?token=${leaked}&event=push`)).toBe('/hook?token=****&event=push');
    expect(redactPath(`/hook?sig=${leaked}`)).toBe('/hook?sig=****');
    expect(redactPath('/hook')).toBe('/hook');
    expect(redactPath('/hook?event=push')).toBe('/hook?event=push');
  });
});

describe('replay target restrictions (SSRF / header exfiltration)', () => {
  const delivery: Delivery = {
    id: 'sec-test',
    receivedAt: new Date(0).toISOString(),
    method: 'POST',
    path: '/',
    headers: { authorization: 'Bearer x' },
    bodyBase64: Buffer.from('{}').toString('base64'),
  };

  it('classifies loopback hostnames', () => {
    expect(isLoopbackHostname('localhost')).toBe(true);
    expect(isLoopbackHostname('127.0.0.1')).toBe(true);
    expect(isLoopbackHostname('127.10.20.30')).toBe(true);
    expect(isLoopbackHostname('[::1]')).toBe(true);
    expect(isLoopbackHostname(new URL('http://0x7f.1/').hostname)).toBe(true);
    expect(isLoopbackHostname('example.com')).toBe(false);
    expect(isLoopbackHostname('169.254.169.254')).toBe(false);
    expect(isLoopbackHostname('0.0.0.0')).toBe(false);
    expect(isLoopbackHostname('127.0.0.1.example.com')).toBe(false);
  });

  it('refuses a non-loopback target by default, before any connection is made', async () => {
    const attempt = replayDelivery(delivery, { to: 'http://169.254.169.254/latest/meta-data' });
    await expect(attempt).rejects.toThrow(/non-loopback/);
    await expect(attempt).rejects.toBeInstanceOf(ReplayTargetError);
  });

  it('refuses non-http(s) schemes and URLs with embedded credentials', () => {
    expect(() => parseReplayTarget('file:///etc/passwd')).toThrow(/http\(s\)/);
    expect(() => parseReplayTarget('ftp://localhost/x')).toThrow(/http\(s\)/);
    expect(() => parseReplayTarget('http://user:pw@localhost/x')).toThrow(/credentials/);
    expect(() => parseReplayTarget('not a url')).toThrow(/Invalid replay target/);
  });

  it('allows a remote target only when explicitly opted in', () => {
    expect(parseReplayTarget('https://hooks.example.com/x', true).hostname).toBe('hooks.example.com');
  });

  it('bounds the buffered response size from the target', async () => {
    const big = createServer((_req, res) => {
      res.writeHead(200);
      res.end(Buffer.alloc(64 * 1024, 0x61));
    });
    await new Promise<void>((resolve) => big.listen(0, '127.0.0.1', resolve));
    const addr = big.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    try {
      await expect(
        replayDelivery(delivery, { to: `http://127.0.0.1:${port}/`, maxResponseBytes: 1024 }),
      ).rejects.toThrow(/exceeded 1024 bytes/);
    } finally {
      await new Promise<void>((resolve) => big.close(() => resolve()));
    }
  });
});

describe('receiver', () => {
  let receiverServer: Server | undefined;

  afterEach(async () => {
    if (receiverServer) await new Promise<void>((resolve) => receiverServer!.close(() => resolve()));
    receiverServer = undefined;
  });

  it('does not echo internal storage errors (e.g. local paths) to the sender', async () => {
    const secretPath = path.join(dir, 'private', 'location');
    const failingStore = {
      save: () => Promise.reject(new Error(`EACCES: permission denied, open '${secretPath}'`)),
    } as unknown as DeliveryStore;
    const errors: unknown[] = [];
    const receiver = await startReceiver(failingStore, { port: 0, onError: (e) => errors.push(e) });
    receiverServer = receiver.server;

    const body = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: receiver.port, method: 'POST', path: '/x' }, (res) => {
        let text = '';
        res.on('data', (c: Buffer) => (text += c.toString()));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
      });
      req.on('error', reject);
      req.end('{}');
    });
    expect(body.status).toBe(500);
    expect(body.text).not.toContain(secretPath);
    expect(errors).toHaveLength(1);
  });

  it('binds to loopback by default', async () => {
    const receiver = await startReceiver(new DeliveryStore(path.join(dir, 'store')), { port: 0 });
    receiverServer = receiver.server;
    const addr = receiver.server.address();
    expect(typeof addr === 'object' && addr !== null ? addr.address : '').toBe('127.0.0.1');
  });
});
