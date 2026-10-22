import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import type { Delivery } from './types.js';

/** Default on-disk location for captured deliveries. */
export const DEFAULT_STORE_DIR = path.join(process.cwd(), '.webhook-lens', 'deliveries');

const DELIVERY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/**
 * True if `id` is safe to use as a delivery file name: letters, digits, `-`
 * and `_` only. This rejects path separators and `..`, so a crafted id can
 * never read, write, or delete a file outside the store directory.
 */
export function isValidDeliveryId(id: string): boolean {
  return DELIVERY_ID_RE.test(id);
}

/**
 * Filesystem-backed store for captured deliveries. Each delivery is written
 * as its own JSON file named `<id>.json` so that captures are durable,
 * human-inspectable, and safe to concurrently append to (each write targets
 * a distinct file).
 */
export class DeliveryStore {
  readonly dir: string;

  constructor(dir: string = DEFAULT_STORE_DIR) {
    this.dir = dir;
  }

  private fileFor(id: string): string {
    if (!isValidDeliveryId(id)) {
      throw new Error(`Invalid delivery id: ${JSON.stringify(id.slice(0, 80))}`);
    }
    return path.join(this.dir, `${id}.json`);
  }

  async ensureDir(): Promise<void> {
    // Captures contain signature/auth headers: keep the directory owner-only.
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
  }

  /** Persist a new delivery, generating an id and timestamp, and return the stored record. */
  async save(input: Omit<Delivery, 'id' | 'receivedAt'> & Partial<Pick<Delivery, 'id' | 'receivedAt'>>): Promise<Delivery> {
    await this.ensureDir();
    const delivery: Delivery = {
      id: input.id ?? randomUUID(),
      receivedAt: input.receivedAt ?? new Date().toISOString(),
      method: input.method,
      path: input.path,
      headers: input.headers,
      bodyBase64: input.bodyBase64,
      ...(input.remoteAddress !== undefined ? { remoteAddress: input.remoteAddress } : {}),
    };
    // Mode 0600 keeps captured secrets (Authorization, signature headers)
    // readable by the owner only.
    await writeFile(this.fileFor(delivery.id), JSON.stringify(delivery, null, 2), { encoding: 'utf8', mode: 0o600 });
    return delivery;
  }

  /** Load a single delivery by id, or null if it does not exist (or the id is not a valid delivery id). */
  async get(id: string): Promise<Delivery | null> {
    if (!isValidDeliveryId(id)) {
      return null;
    }
    const file = this.fileFor(id);
    if (!existsSync(file)) {
      return null;
    }
    const raw = await readFile(file, 'utf8');
    return JSON.parse(raw) as Delivery;
  }

  /** List all captured deliveries, most recent first. */
  async list(): Promise<Delivery[]> {
    if (!existsSync(this.dir)) {
      return [];
    }
    const files = (await readdir(this.dir)).filter((f) => f.endsWith('.json'));
    const deliveries = await Promise.all(
      files.map(async (f) => JSON.parse(await readFile(path.join(this.dir, f), 'utf8')) as Delivery),
    );
    return deliveries.sort((a, b) => b.receivedAt.localeCompare(a.receivedAt));
  }

  /** Delete a delivery by id. Returns true if it existed and was removed. */
  async delete(id: string): Promise<boolean> {
    if (!isValidDeliveryId(id)) {
      return false;
    }
    const file = this.fileFor(id);
    if (!existsSync(file)) {
      return false;
    }
    await rm(file);
    return true;
  }

  /** Remove all captured deliveries. Primarily for tests / `--clear` style tooling. */
  async clear(): Promise<void> {
    if (!existsSync(this.dir)) {
      return;
    }
    const files = (await readdir(this.dir)).filter((f) => f.endsWith('.json'));
    await Promise.all(files.map((f) => rm(path.join(this.dir, f))));
  }
}
