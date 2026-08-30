import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import type { Delivery } from './types.js';

/** Default on-disk location for captured deliveries. */
export const DEFAULT_STORE_DIR = path.join(process.cwd(), '.webhook-lens', 'deliveries');

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
    return path.join(this.dir, `${id}.json`);
  }

  async ensureDir(): Promise<void> {
    await mkdir(this.dir, { recursive: true });
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
    await writeFile(this.fileFor(delivery.id), JSON.stringify(delivery, null, 2), 'utf8');
    return delivery;
  }

  /** Load a single delivery by id, or null if it does not exist. */
  async get(id: string): Promise<Delivery | null> {
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
