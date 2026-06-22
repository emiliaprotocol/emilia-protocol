// SPDX-License-Identifier: Apache-2.0
//
// EP-REVOCATION-v1 offline verifier test. Builds a REAL Ed25519-signed
// revocation statement over an exact target, then asserts the fail-closed
// predicate: accept the authentic, pinned, exactly-bound statement; reject an
// unpinned revoker, a key substitution, a target mismatch (revoke-A-for-B), a
// tampered field, and a stale statement under a freshness window.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { verifyRevocation, isRevoked, REVOCATION_VERSION } from './revocation.js';

const TARGET = { target_type: 'receipt', target_id: 'rcpt_abc123', action_hash: 'sha256:' + 'a'.repeat(64) };

function sign(payloadObj, privateKey) {
  const bytes = Buffer.from(canonicalize(payloadObj), 'utf8');
  return crypto.sign(null, bytes, privateKey).toString('base64url');
}

function buildStatement({ revokerId = 'ep:revoker:ig_okafor', revokedAt = '2026-06-20T12:00:00.000Z',
  reason = 'authority withdrawn', actionHash = TARGET.action_hash, signer }) {
  const signedFields = {
    '@version': REVOCATION_VERSION,
    action_hash: actionHash,
    reason,
    revoked_at: revokedAt,
    revoker_id: revokerId,
    target_id: TARGET.target_id,
    target_type: TARGET.target_type,
  };
  return {
    '@version': REVOCATION_VERSION,
    target_type: TARGET.target_type,
    target_id: TARGET.target_id,
    action_hash: actionHash,
    revoker_id: revokerId,
    revoked_at: revokedAt,
    reason,
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: 'rk1',
      public_key: signer.publicKeyB64u,
      signature_b64u: sign(signedFields, signer.privateKey),
    },
  };
}

function newSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}

test('accepts an authentic, pinned, exactly-bound revocation', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  const r = verifyRevocation(TARGET, stmt, { revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } } });
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
  assert.ok(isRevoked(TARGET, [stmt], { revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } } }));
});

test('rejects an unpinned revoker (identified but not trusted)', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  const r = verifyRevocation(TARGET, stmt, { revokerKeys: {} });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.revoker_key_pinned, false);
});

test('rejects key substitution (pinned key != presented key)', () => {
  const s = newSigner(); const other = newSigner();
  const stmt = buildStatement({ signer: s });
  const r = verifyRevocation(TARGET, stmt, { revokerKeys: { 'ep:revoker:ig_okafor': { public_key: other.publicKeyB64u } } });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.revoker_key_pinned, false);
});

test('rejects revoke-A-presented-for-B (action_hash mismatch)', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s, actionHash: 'sha256:' + 'b'.repeat(64) });
  const r = verifyRevocation(TARGET, stmt, { revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } } });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.target_bound, false);
});

test('rejects a tampered field (signature no longer binds the statement)', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  stmt.reason = 'totally different reason'; // post-signing tamper
  const r = verifyRevocation(TARGET, stmt, { revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } } });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.signature_binds_statement, false);
});

test('rejects a stale statement under a freshness window', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s, revokedAt: '2020-01-01T00:00:00.000Z' });
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
    maxAgeSeconds: 3600, now: '2026-06-20T12:00:00.000Z',
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.freshness, false);
});
