import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import type { Delivery } from './types.js';
import type { DeliveryStore } from './storage.js';

export interface ReceiverOptions {
  /** Port to listen on. 0 lets the OS assign an ephemeral free port. */
  port?: number;
  /** Host to bind to. Defaults to 127.0.0.1 (local-only, by design). */
  host?: string;
  /** Maximum accepted body size in bytes, to avoid unbounded memory use. Default 10MB. */
  maxBodyBytes?: number;
  /** Called after each delivery is captured and persisted. */
  onDelivery?: (delivery: Delivery) => void;
}

export interface Receiver {
  server: Server;
  /** The actual port bound (useful when `port: 0` was requested). */
  port: number;
  close: () => Promise<void>;
}

const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

/**
 * Start a local HTTP receiver that captures every inbound request byte-for-
 * byte and persists it to the given store.
 *
 * Raw-body preservation is the whole point: this handler never calls
 * `JSON.parse`/re-`JSON.stringify` on the body before storing it. It
 * concatenates the raw Buffer chunks exactly as received and stores that
 * buffer (base64-encoded) verbatim. Any provider signature is computed over
 * these exact bytes, and JSON re-serialization is not guaranteed to
 * reproduce them (key order, spacing, numeric formatting, unicode escapes),
 * so touching the body as parsed JSON before storage would silently break
 * verification for a real proportion of deliveries.
 */
export function startReceiver(store: DeliveryStore, options: ReceiverOptions = {}): Promise<Receiver> {
  const host = options.host ?? '127.0.0.1';
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let aborted = false;

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBodyBytes) {
        aborted = true;
        res.writeHead(413, { 'content-type': 'text/plain' });
        res.end('Payload too large');
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;
      const rawBody = Buffer.concat(chunks);
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
      }

      void store
        .save({
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          headers,
          bodyBase64: rawBody.toString('base64'),
          remoteAddress: req.socket.remoteAddress ?? undefined,
        })
        .then((delivery) => {
          options.onDelivery?.(delivery);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'captured', id: delivery.id }));
        })
        .catch((err: unknown) => {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'error', message: err instanceof Error ? err.message : String(err) }));
        });
    });

    req.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end('Bad request');
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, host, () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : (options.port ?? 0);
      resolve({
        server,
        port,
        close: () =>
          new Promise<void>((res2, rej2) => {
            server.close((err) => (err ? rej2(err) : res2()));
          }),
      });
    });
  });
}
