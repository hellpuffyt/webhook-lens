# Contributing

Contributions are welcome. This is a small, focused tool, so please keep
changes scoped and well-tested.

## Getting started

```bash
npm install
npm run build
npm test
```

## Development workflow

1. Fork and clone the repository.
2. Create a branch for your change.
3. Make your change, with tests. Signature-verification code in particular
   needs both a valid-signature test and an invalid/tampered-signature test.
4. Run the full gate before opening a pull request:

   ```bash
   npm test
   npx tsc --noEmit
   npx eslint .
   ```

5. Open a pull request describing the change and why it's needed.

## Guidelines

- Keep runtime dependencies minimal. Prefer Node's standard library
  (`node:http`, `node:crypto`, `node:fs`) over adding a new package.
- Never weaken or delete a test to make it pass. If a test is wrong, explain
  why in the pull request.
- Signature verification must always use `crypto.timingSafeEqual` (or the
  project's `timingSafeEqual*` helpers) rather than `===` string comparison.
- Never log or persist a webhook signing secret. Use the redaction helpers in
  `src/redact.ts` for anything that reaches stdout.
- New provider schemes should follow the existing pattern in
  `src/signatures/`: a `verify*` function, a `sign*` helper for tests and
  replay re-signing, and a doc comment linking to the provider's official
  signature-verification documentation.

## Reporting issues

Please include the provider/scheme involved (if applicable), the Node.js
version, and, if possible, a minimal reproduction with a synthetic (never
real) secret and payload.
