import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DeliveryStore } from '../src/storage.js';

let dir: string;
let store: DeliveryStore;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'webhook-lens-test-'));
  store = new DeliveryStore(dir);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('DeliveryStore', () => {
  it('round-trips a saved delivery through get()', async () => {
    const saved = await store.save({
      method: 'POST',
      path: '/hooks/github',
      headers: { 'content-type': 'application/json' },
      bodyBase64: Buffer.from('{"ok":true}').toString('base64'),
    });
    expect(saved.id).toBeTruthy();
    expect(saved.receivedAt).toBeTruthy();

    const loaded = await store.get(saved.id);
    expect(loaded).toEqual(saved);
  });

  it('preserves arbitrary binary body bytes exactly through save/get', async () => {
    const bytes = Buffer.from([0, 1, 2, 255, 254, 10, 13, 0]);
    const saved = await store.save({
      method: 'POST',
      path: '/bin',
      headers: {},
      bodyBase64: bytes.toString('base64'),
    });
    const loaded = await store.get(saved.id);
    expect(Buffer.from(loaded!.bodyBase64, 'base64').equals(bytes)).toBe(true);
  });

  it('get() returns null for an unknown id', async () => {
    const result = await store.get('does-not-exist');
    expect(result).toBeNull();
  });

  it('list() returns an empty array when nothing has been saved', async () => {
    const result = await store.list();
    expect(result).toEqual([]);
  });

  it('list() returns all saved deliveries, most recent first', async () => {
    const first = await store.save({
      method: 'POST',
      path: '/a',
      headers: {},
      bodyBase64: '',
      receivedAt: '2026-01-01T00:00:00.000Z',
    });
    const second = await store.save({
      method: 'POST',
      path: '/b',
      headers: {},
      bodyBase64: '',
      receivedAt: '2026-01-01T00:05:00.000Z',
    });
    const listed = await store.list();
    expect(listed.map((d) => d.id)).toEqual([second.id, first.id]);
    void first;
  });

  it('delete() removes a delivery and reports success', async () => {
    const saved = await store.save({ method: 'GET', path: '/x', headers: {}, bodyBase64: '' });
    expect(await store.delete(saved.id)).toBe(true);
    expect(await store.get(saved.id)).toBeNull();
  });

  it('delete() returns false for an unknown id', async () => {
    expect(await store.delete('nope')).toBe(false);
  });

  it('clear() removes every delivery', async () => {
    await store.save({ method: 'GET', path: '/1', headers: {}, bodyBase64: '' });
    await store.save({ method: 'GET', path: '/2', headers: {}, bodyBase64: '' });
    await store.clear();
    expect(await store.list()).toEqual([]);
  });

  it('creates the storage directory lazily on first save', async () => {
    const freshDir = path.join(dir, 'nested', 'deliveries');
    const freshStore = new DeliveryStore(freshDir);
    await freshStore.save({ method: 'GET', path: '/', headers: {}, bodyBase64: '' });
    expect((await freshStore.list()).length).toBe(1);
  });
});
