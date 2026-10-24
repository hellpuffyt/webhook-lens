#!/usr/bin/env node
import { DeliveryStore, DEFAULT_STORE_DIR } from './storage.js';
import { startReceiver } from './server.js';
import { replayDelivery } from './replay.js';
import { verifyDelivery, deliveryRawBody } from './signatures/index.js';
import { redactHeaders, redactPath } from './redact.js';
import { isLoopbackHostname, ReplayTargetError } from './replay.js';
import type { SignatureScheme } from './types.js';
import { parseArgs, flagString, flagInt, UsageError } from './args.js';

function storeFor(flags: Record<string, string | boolean>): DeliveryStore {
  const dir = flagString(flags, 'dir') ?? DEFAULT_STORE_DIR;
  return new DeliveryStore(dir);
}

function printUsage(): void {
  console.log(`webhook-lens - capture, inspect, and replay inbound webhooks locally

Usage:
  webhook-lens listen [--port <n>] [--host <host>] [--dir <path>]
  webhook-lens list [--dir <path>]
  webhook-lens show <id> [--dir <path>] [--raw]
  webhook-lens replay <id> --to <url> [--resign-scheme <scheme> --resign-secret <secret>] [--allow-remote] [--dir <path>]
  webhook-lens verify <id> --scheme <scheme> --secret <secret> [--tolerance <seconds>] [--dir <path>]
                          [--header <name> --prefix <p> --encoding <hex|base64>]  (generic scheme only)

Schemes: github, stripe, shopify, slack, generic
Replay targets must be loopback (localhost, 127.0.0.0/8, [::1]) unless --allow-remote is given.
`);
}

async function cmdListen(flags: Record<string, string | boolean>): Promise<void> {
  const store = storeFor(flags);
  const host = flagString(flags, 'host') ?? '127.0.0.1';
  const port = flagInt(flags, 'port') ?? 8787;
  if (port > 65535) {
    throw new UsageError(`--port must be between 0 and 65535, got ${port}`);
  }
  if (!isLoopbackHostname(host.includes(':') && !host.startsWith('[') ? `[${host}]` : host)) {
    console.error(
      `warning: binding to ${host} exposes the receiver beyond this machine; captured requests may contain secrets.`,
    );
  }

  const receiver = await startReceiver(store, {
    port,
    host,
    onDelivery: (delivery) => {
      console.log(`[captured] ${delivery.id}  ${delivery.method} ${redactPath(delivery.path)}  (${delivery.receivedAt})`);
    },
    onError: (err) => {
      console.error(`[error] failed to store delivery: ${err instanceof Error ? err.message : String(err)}`);
    },
  });

  console.log(`webhook-lens listening on http://${host}:${receiver.port}`);
  console.log(`Storing deliveries in ${store.dir}`);
  console.log('Press Ctrl+C to stop.');

  const shutdown = (): void => {
    void receiver.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function cmdList(flags: Record<string, string | boolean>): Promise<void> {
  const store = storeFor(flags);
  const deliveries = await store.list();
  if (deliveries.length === 0) {
    console.log('No captured deliveries yet.');
    return;
  }
  for (const d of deliveries) {
    console.log(`${d.id}  ${d.receivedAt}  ${d.method} ${redactPath(d.path)}  (${Buffer.from(d.bodyBase64, 'base64').length} bytes)`);
  }
}

async function cmdShow(id: string | undefined, flags: Record<string, string | boolean>): Promise<void> {
  if (!id) {
    console.error('Usage: webhook-lens show <id>');
    process.exitCode = 1;
    return;
  }
  const store = storeFor(flags);
  const delivery = await store.get(id);
  if (!delivery) {
    console.error(`No delivery found with id ${id}`);
    process.exitCode = 1;
    return;
  }
  console.log(`id:          ${delivery.id}`);
  console.log(`receivedAt:  ${delivery.receivedAt}`);
  console.log(`method:      ${delivery.method}`);
  console.log(`path:        ${flags.raw ? delivery.path : redactPath(delivery.path)}`);
  console.log(`remoteAddr:  ${delivery.remoteAddress ?? '(unknown)'}`);
  console.log('headers:');
  const headers = flags.raw ? delivery.headers : redactHeaders(delivery.headers);
  for (const [k, v] of Object.entries(headers)) {
    console.log(`  ${k}: ${v}`);
  }
  console.log('body:');
  console.log(deliveryRawBody(delivery).toString('utf8'));
}

async function cmdReplay(id: string | undefined, flags: Record<string, string | boolean>): Promise<void> {
  const to = flagString(flags, 'to');
  if (!id || !to) {
    console.error('Usage: webhook-lens replay <id> --to <url> [--resign-scheme <scheme> --resign-secret <secret>]');
    process.exitCode = 1;
    return;
  }
  const store = storeFor(flags);
  const delivery = await store.get(id);
  if (!delivery) {
    console.error(`No delivery found with id ${id}`);
    process.exitCode = 1;
    return;
  }

  const resignScheme = flagString(flags, 'resign-scheme') as SignatureScheme | undefined;
  const resignSecret = flagString(flags, 'resign-secret');

  const result = await replayDelivery(delivery, {
    to,
    allowRemote: flags['allow-remote'] === true,
    resign:
      resignScheme && resignSecret
        ? {
            scheme: resignScheme,
            secret: resignSecret,
            generic:
              resignScheme === 'generic'
                ? {
                    headerName: flagString(flags, 'header') ?? 'x-signature',
                    prefix: flagString(flags, 'prefix'),
                    encoding: (flagString(flags, 'encoding') as 'hex' | 'base64' | undefined) ?? 'hex',
                  }
                : undefined,
          }
        : undefined,
  });

  console.log(`Replayed ${id} to ${to}`);
  console.log(`Response status: ${result.statusCode}`);
  console.log(`Response body: ${Buffer.from(result.bodyBase64, 'base64').toString('utf8')}`);
}

async function cmdVerify(id: string | undefined, flags: Record<string, string | boolean>): Promise<void> {
  const scheme = flagString(flags, 'scheme') as SignatureScheme | undefined;
  const secret = flagString(flags, 'secret');
  if (!id || !scheme || !secret) {
    console.error('Usage: webhook-lens verify <id> --scheme <scheme> --secret <secret>');
    process.exitCode = 1;
    return;
  }
  const store = storeFor(flags);
  const delivery = await store.get(id);
  if (!delivery) {
    console.error(`No delivery found with id ${id}`);
    process.exitCode = 1;
    return;
  }

  const result = verifyDelivery(delivery, {
    scheme,
    secret,
    toleranceSeconds: flagInt(flags, 'tolerance'),
    generic:
      scheme === 'generic'
        ? {
            headerName: flagString(flags, 'header') ?? 'x-signature',
            prefix: flagString(flags, 'prefix'),
            encoding: (flagString(flags, 'encoding') as 'hex' | 'base64' | undefined) ?? 'hex',
          }
        : undefined,
  });

  console.log(`scheme: ${result.scheme}`);
  console.log(`valid:  ${result.valid}`);
  if (result.reason) {
    console.log(`reason: ${result.reason}`);
  }
  if (!result.valid) {
    process.exitCode = 1;
  }
}

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  const { positionals, flags } = parseArgs(rest);

  switch (command) {
    case 'listen':
      await cmdListen(flags);
      return;
    case 'list':
      await cmdList(flags);
      return;
    case 'show':
      await cmdShow(positionals[0], flags);
      return;
    case 'replay':
      await cmdReplay(positionals[0], flags);
      return;
    case 'verify':
      await cmdVerify(positionals[0], flags);
      return;
    case '--help':
    case '-h':
    case 'help':
    case undefined:
      printUsage();
      return;
    default:
      console.error(`Unknown command: ${command}\n`);
      printUsage();
      process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  if (err instanceof UsageError || err instanceof ReplayTargetError) {
    console.error(`error: ${err.message}`);
  } else {
    console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  }
  process.exitCode = 1;
});
