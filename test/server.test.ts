import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { request as httpRequest } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DeliveryStore } from '../src/storage.js';
import { startReceiver, type Receiver } from '../src/server.js';
import { verifyGitHubSignature, signGitHub } from '../src/signatures/github.js';

let dir: string;
let store: DeliveryStore;
let receiver: Receiver;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'webhook-lens-server-test-'));
  store = new DeliveryStore(dir);
  receiver = await startReceiver(store, { port: 0 });
});

afterEach(async () => {
  await receiver.close();
  await rm(dir, { recursive: true, force: true });
});

function post(port: number, urlPath: string, headers: Record<string, string>, body: Buffer): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, path: urlPath, method: 'POST', headers: { ...headers, 'content-length': String(body.length) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

describe('HTTP receiver (real listening server on an ephemeral port)', () => {
  it('binds to an OS-assigned ephemeral port when port 0 is requested', () => {
    expect(receiver.port).toBeGreaterThan(0);
  });

  it('captures method, path, headers, and body of a real POST request', async () => {
    const body = Buffer.from(JSON.stringify({ hello: 'world' }));
    const res = await post(receiver.port, '/hooks/test?x=1', { 'content-type': 'application/json', 'x-custom': 'abc' }, body);
    expect(res.status).toBe(200);

    const deliveries = await store.list();
    expect(deliveries.length).toBe(1);
    const delivery = deliveries[0]!;
    expect(delivery.method).toBe('POST');
    expect(delivery.path).toBe('/hooks/test?x=1');
    expect(delivery.headers['content-type']).toBe('application/json');
    expect(delivery.headers['x-custom']).toBe('abc');
    expect(Buffer.from(delivery.bodyBase64, 'base64').equals(body)).toBe(true);
  });

  it('responds with a JSON status and the delivery id', async () => {
    const res = await post(receiver.port, '/hook', {}, Buffer.from('{}'));
    const parsed = JSON.parse(res.body) as { status: string; id: string };
    expect(parsed.status).toBe('captured');
    expect(parsed.id).toBeTruthy();
  });

  it('preserves a real signed GitHub delivery raw body such that signature verification passes after capture', async () => {
    const secret = 'whsec_test_synthetic_server_secret';
    const body = Buffer.from(JSON.stringify({ zen: 'Responsive is better than fast.' }));
    const signature = signGitHub(body, secret);

    await post(receiver.port, '/hooks/github', { 'x-hub-signature-256': signature, 'content-type': 'application/json' }, body);

    const [delivery] = await store.list();
    const storedBody = Buffer.from(delivery!.bodyBase64, 'base64');
    expect(verifyGitHubSignature(storedBody, delivery!.headers['x-hub-signature-256'], secret)).toBe(true);
  });

  it('invokes the onDelivery callback synchronously with the captured delivery', async () => {
    const captured: string[] = [];
    const cbReceiver = await startReceiver(store, {
      port: 0,
      onDelivery: (d) => captured.push(d.id),
    });
    try {
      await post(cbReceiver.port, '/x', {}, Buffer.from('body'));
      expect(captured.length).toBe(1);
    } finally {
      await cbReceiver.close();
    }
  });

  it('captures multiple sequential deliveries independently', async () => {
    await post(receiver.port, '/a', {}, Buffer.from('one'));
    await post(receiver.port, '/b', {}, Buffer.from('two'));
    const deliveries = await store.list();
    expect(deliveries.length).toBe(2);
    expect(new Set(deliveries.map((d) => d.path))).toEqual(new Set(['/a', '/b']));
  });

  it('rejects a body larger than the configured maximum with 413', async () => {
    const smallLimitReceiver = await startReceiver(store, { port: 0, maxBodyBytes: 10 });
    try {
      const res = await post(smallLimitReceiver.port, '/big', {}, Buffer.alloc(1000, 'x'));
      expect(res.status).toBe(413);
    } finally {
      await smallLimitReceiver.close();
    }
  });

  it('captures an empty body correctly', async () => {
    const res = await post(receiver.port, '/empty', {}, Buffer.alloc(0));
    expect(res.status).toBe(200);
    const [delivery] = await store.list();
    expect(Buffer.from(delivery!.bodyBase64, 'base64').length).toBe(0);
  });

  it('captures binary (non-UTF8) bodies without corruption', async () => {
    const bytes = Buffer.from([0, 1, 2, 3, 255, 254, 253, 128, 127]);
    await post(receiver.port, '/bin', { 'content-type': 'application/octet-stream' }, bytes);
    const [delivery] = await store.list();
    expect(Buffer.from(delivery!.bodyBase64, 'base64').equals(bytes)).toBe(true);
  });
});
