/** Minimal, dependency-free argument parsing for the CLI. */

export class UsageError extends Error {}

/** Flags that never take a value, so `show --raw <id>` does not swallow the id. */
const BOOLEAN_FLAGS = new Set(['raw', 'allow-remote']);

export interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg.startsWith('--')) {
      const name = arg.slice(2);
      const next = argv[i + 1];
      if (!BOOLEAN_FLAGS.has(name) && next !== undefined && !next.startsWith('--')) {
        flags[name] = next;
        i++;
      } else {
        flags[name] = true;
      }
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

export function flagString(flags: Record<string, string | boolean>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

/** Parse a non-negative integer flag strictly; throws on anything else (e.g. "abc", "10s", "-5"). */
export function flagInt(flags: Record<string, string | boolean>, name: string): number | undefined {
  const raw = flags[name];
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    throw new UsageError(`--${name} expects a non-negative integer, got ${JSON.stringify(raw)}`);
  }
  return Number.parseInt(raw, 10);
}
