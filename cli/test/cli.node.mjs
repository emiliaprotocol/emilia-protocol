import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { EPClient, normalizeSecureBaseUrl } from '../lib/client.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const cliRoot = resolve(here, '..');
const bin = join(cliRoot, 'bin', 'ep.mjs');
const sampleReceipt = resolve(cliRoot, '..', 'examples', 'sample-receipt.json');

function run(args, options = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    cwd: cliRoot,
    encoding: 'utf8',
    ...options,
  });
}

test('help describes offline verification and exits successfully', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /ep verify <file\.json>/);
  assert.match(result.stdout, /No EMILIA server or network connection is required/);
});

test('unknown commands fail closed', () => {
  const result = run(['definitely-not-a-command']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown command/);
});

test('offline verifier accepts a valid receipt and rejects a visible mutation', () => {
  const accepted = run(['verify', sampleReceipt]);
  assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout);
  assert.match(accepted.stdout, /VERIFIED/);

  const directory = mkdtempSync(join(tmpdir(), 'emilia-cli-'));
  const tamperedPath = join(directory, 'tampered.json');
  const tampered = JSON.parse(readFileSync(sampleReceipt, 'utf8'));
  tampered.payload.claim.amount_usd += 1;
  writeFileSync(tamperedPath, `${JSON.stringify(tampered, null, 2)}\n`);

  const rejected = run(['verify', tamperedPath]);
  assert.equal(rejected.status, 1);
  assert.match(rejected.stdout, /NOT VERIFIED/);
});

test('API client pins auth headers and encodes object identifiers', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const client = new EPClient('https://example.test/root/', 'secret', fetchImpl);
  await client.profile('merchant/a b');
  await client.submit('merchant/a b', 'order-1');

  assert.equal(calls[0].url, 'https://example.test/api/trust/profile/merchant%2Fa%20b');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer secret');
  assert.equal(calls[1].options.method, 'POST');
  assert.equal(JSON.parse(calls[1].options.body).transaction_ref, 'order-1');
});

test('API client turns non-JSON failures into bounded errors', async () => {
  const client = new EPClient('https://example.test', '', async () => new Response(
    '<html>upstream unavailable</html>',
    { status: 502 },
  ));
  await assert.rejects(() => client.health(), /HTTP 502: <html>upstream unavailable<\/html>/);
});

test('API client refuses credential transport over non-loopback HTTP', () => {
  assert.throws(() => new EPClient('http://api.example.test', 'secret', async () => {}), /must use HTTPS/);
  assert.equal(normalizeSecureBaseUrl('http://127.0.0.1:8787/'), 'http://127.0.0.1:8787');
  assert.throws(() => normalizeSecureBaseUrl('https://user:pass@example.test'), /must not contain credentials/);
});

test('API client refuses ambiguous duplicate-member responses and disables redirects', async () => {
  let observed;
  const client = new EPClient('https://example.test', '', async (_url, options) => {
    observed = options;
    return new Response('{"decision":"allow","decision":"deny"}', { status: 200 });
  });
  await assert.rejects(() => client.health(), /duplicate object member/);
  assert.equal(observed.redirect, 'error');
  assert.ok(observed.signal instanceof AbortSignal);
});

test('write commands refuse locally when the API key is absent', () => {
  const result = run(['submit', 'merchant-1', '--ref', 'order-1'], {
    env: { ...process.env, EP_API_KEY: '' },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /EP_API_KEY is required/);
});
