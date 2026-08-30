import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DeliveryStore } from '../src/storage.js';
import { replayDelivery } from '../src/replay.js';
import { verifyGitHubSignature } from '../src/signatures/github.js';
import type { Delivery } from '../src/types.js';

let dir: string;
let store: DeliveryStore;
let targetServer: Server;
let targetPort: number;
let received: { headers: Record<string, string | string[] | undefined>; body: Buffer }[] = [];

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'webhook-lens-replay-test-'));
  store = new DeliveryStore(dir);
  received = [];

  targetServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => targetServer.listen(0, '127.0.0.1', resolve));
  const addr = targetServer.address();
  targetPort = typeof addr === 'object' && addr !== null ? addr.port : 0;
});

afterEach(async () => {
  await new Promise<void>((resolve) => targetServer.close(() => resolve()));
  await rm(dir, { recursive: true, force: true });
});

async function makeDelivery(headers: Record<string, string>, bodyText: string): Promise<Delivery> {
  return store.save({
    method: 'POST',
    path: '/hook',
    headers,
    bodyBase64: Buffer.from(bodyText).toString('base64'),
  });
}

describe('replayDelivery', () => {
  it('forwards the exact raw body bytes to the target URL', async () => {
    const delivery = await makeDelivery({ 'content-type': 'application/json' }, '{"a":1}');
    const result = await replayDelivery(delivery, { to: `http://127.0.0.1:${targetPort}/hook` });
    expect(result.statusCode).toBe(200);
    expect(received.length).toBe(1);
    expect(received[0]!.body.toString('utf8')).toBe('{"a":1}');
  });

  it('forwards original (non hop-by-hop) headers', async () => {
    const delivery = await makeDelivery({ 'content-type': 'application/json', 'x-original': 'yes' }, 'body');
    await replayDelivery(delivery, { to: `http://127.0.0.1:${targetPort}/hook` });
    expect(received[0]!.headers['x-original']).toBe('yes');
    expect(received[0]!.headers['content-type']).toBe('application/json');
  });

  it('does not forward the original host/connection headers verbatim', async () => {
    const delivery = await makeDelivery({ host: 'original.example.com', connection: 'keep-alive' }, 'body');
    await replayDelivery(delivery, { to: `http://127.0.0.1:${targetPort}/hook` });
    expect(received[0]!.headers.host).not.toBe('original.example.com');
  });

  it('recomputes the GitHub signature header when resign options are given', async () => {
    const originalSecret = 'whsec_test_synthetic_original';
    const newSecret = 'whsec_test_synthetic_replay_new';
    const delivery = await makeDelivery({ 'x-hub-signature-256': 'sha256=stale-or-unknown' }, '{"a":1}');

    await replayDelivery(delivery, {
      to: `http://127.0.0.1:${targetPort}/hook`,
      resign: { scheme: 'github', secret: newSecret },
    });

    const forwardedSig = received[0]!.headers['x-hub-signature-256'] as string;
    expect(verifyGitHubSignature(received[0]!.body, forwardedSig, newSecret)).toBe(true);
    expect(verifyGitHubSignature(received[0]!.body, forwardedSig, originalSecret)).toBe(false);
  });

  it('recomputes a generic HMAC signature header when resign options are given', async () => {
    const delivery = await makeDelivery({ 'x-signature': 'stale' }, 'payload-body');
    await replayDelivery(delivery, {
      to: `http://127.0.0.1:${targetPort}/hook`,
      resign: {
        scheme: 'generic',
        secret: 'whsec_test_synthetic_generic_replay',
        generic: { headerName: 'x-signature', prefix: 'sha256=', encoding: 'hex' },
      },
    });
    const forwarded = received[0]!.headers['x-signature'] as string;
    expect(forwarded.startsWith('sha256=')).toBe(true);
    expect(forwarded).not.toBe('stale');
  });

  it('returns the target response status and body', async () => {
    const delivery = await makeDelivery({}, 'x');
    const result = await replayDelivery(delivery, { to: `http://127.0.0.1:${targetPort}/hook` });
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(Buffer.from(result.bodyBase64, 'base64').toString('utf8'))).toEqual({ ok: true });
  });

  it('rejects (via a thrown error) when the target is unreachable', async () => {
    const delivery = await makeDelivery({}, 'x');
    await expect(replayDelivery(delivery, { to: 'http://127.0.0.1:1' })).rejects.toBeTruthy();
  });
});
