// SPDX-License-Identifier: Apache-2.0
//
// CLI regression test for EP-QUORUM-v1 dispatch. The library's verifyQuorum is
// covered by quorum.test.js; this proves the CLI wiring is fail-closed end to
// end: it auto-detects an `ep.quorum` document, runs the quorum predicate, and
// reflects the verdict in its exit code (0 = verified, 1 = not verified) for
// every adversarial vector. Spawns the real CLI as a subprocess. Pure Node test.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('./cli.js', import.meta.url));
const vectors = JSON.parse(readFileSync(new URL('../../conformance/vectors/quorum.v1.json', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'ep-verify-cli-'));
const QUORUM_TRUST = [
  '--rp-id', 'emiliaprotocol.ai',
  '--allowed-origin', 'https://www.emiliaprotocol.ai',
  '--allowed-origin', 'https://emiliaprotocol.ai',
];

function runCli(doc, extraArgs = []) {
  const f = join(dir, 'doc.json');
  writeFileSync(f, JSON.stringify(doc));
  try {
    return { code: 0, out: execFileSync('node', [cli, f, ...extraArgs], { encoding: 'utf8' }) };
  } catch (e) {
    return { code: e.status ?? 1, out: `${e.stdout || ''}${e.stderr || ''}` };
  }
}

function runCliRaw(raw, extraArgs = []) {
  const f = join(dir, 'raw-doc.json');
  writeFileSync(f, raw);
  try {
    return { code: 0, out: execFileSync('node', [cli, f, ...extraArgs], { encoding: 'utf8' }) };
  } catch (e) {
    return { code: e.status ?? 1, out: `${e.stdout || ''}${e.stderr || ''}` };
  }
}

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

test('CLI verifies a valid quorum (exit 0, VERIFIED, per-signer lines)', () => {
  const ok = vectors.vectors.find((v) => v.id === 'accept_ordered_3of3');
  const r = runCli(ok.quorum, QUORUM_TRUST);
  assert.strictEqual(r.code, 0);
  assert.match(r.out, /VERIFIED/);
  assert.match(r.out, /multi-party quorum \(EP-QUORUM-v1\)/);
  assert.match(r.out, /signer \[program_officer\]/);
});

test('CLI rejects an invalid quorum (exit 1, NOT VERIFIED)', () => {
  const bad = vectors.vectors.find((v) => v.id === 'reject_duplicate_human');
  const r = runCli(bad.quorum, QUORUM_TRUST);
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /NOT VERIFIED/);
});

test('CLI is fail-closed across every EP-QUORUM-v1 vector', () => {
  for (const v of vectors.vectors) {
    const r = runCli(v.quorum, QUORUM_TRUST);
    const expected = v.expect.valid ? 0 : 1;
    assert.strictEqual(r.code, expected, `${v.id}: expected exit ${expected}, got ${r.code}`);
  }
});

test('CLI refuses a WebAuthn quorum when relying-party pins are omitted', () => {
  const ok = vectors.vectors.find((v) => v.id === 'accept_ordered_3of3');
  const r = runCli(ok.quorum);
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /needs relying-party pins/);
});

test('CLI explicit --key cannot be overridden by an artifact-embedded key', () => {
  const attacker = crypto.generateKeyPairSync('ed25519');
  const trusted = crypto.generateKeyPairSync('ed25519');
  const payload = { receipt_id: 'cli-pin-inversion', claim: { action_type: 'payment.release' } };
  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    issuer_public_key: attacker.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(null, Buffer.from(canonicalize(payload)), attacker.privateKey).toString('base64url'),
    },
  };
  const trustedKey = trusted.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const r = runCli(doc, ['--key', trustedKey]);
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /NOT VERIFIED/);
});

test('CLI rejects duplicate-member JSON before document dispatch', () => {
  const r = runCliRaw('{"@version":"EP-RECEIPT-v1","payload":{},"payload":{"forged":true}}');
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /strict JSON required.*duplicate object member/i);
});
