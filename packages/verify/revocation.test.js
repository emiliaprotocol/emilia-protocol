// SPDX-License-Identifier: Apache-2.0
//
// EP-REVOCATION-v1 offline verifier test. Builds a REAL Ed25519-signed
// revocation statement over an exact target, then asserts the fail-closed
// predicate: accept the authentic, pinned, exactly-bound statement; reject an
// unpinned revoker, a key substitution, a target mismatch (revoke-A-for-B), a
// tampered field, and a revocation that has not taken effect yet. It also
// proves that an old terminal revocation never ages out.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from './index.js';
import { verifyRevocation, isRevoked, REVOCATION_VERSION } from './revocation.js';

const TARGET = { target_type: 'receipt', target_id: 'rcpt_abc123', action_hash: 'sha256:' + 'a'.repeat(64) };
const keyIdFor = (publicKeyB64u) => `ep:revoker-key:sha256:${crypto
  .createHash('sha256').update(Buffer.from(publicKeyB64u, 'base64url')).digest('hex')}`;

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
      revoker_key_id: keyIdFor(signer.publicKeyB64u),
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

test('accepts the historical v1 local key label only with the exact pinned SPKI', () => {
  const historical = JSON.parse(readFileSync(
    new URL('../../conformance/vectors/revocation.exec.v1.json', import.meta.url),
    'utf8',
  )).vectors.find((vector) => vector.id === 'accept_pinned_exact_binding');
  const result = verifyRevocation(historical.target, historical.revocation, {
    revokerKeys: historical.revoker_keys,
  });
  assert.strictEqual(result.valid, true, JSON.stringify(result.errors));

  const mismatchedPin = {
    ...historical.revoker_keys,
    'ep:revoker:ig_okafor': {
      ...historical.revoker_keys['ep:revoker:ig_okafor'],
      key_id: 'different-local-label',
    },
  };
  assert.strictEqual(verifyRevocation(historical.target, historical.revocation, {
    revokerKeys: mismatchedPin,
  }).valid, false);
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

test('an old terminal revocation remains valid despite a legacy max-age option', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s, revokedAt: '2020-01-01T00:00:00.000Z' });
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
    maxAgeSeconds: 3600, now: '2026-06-20T12:00:00.000Z',
  });
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
});

test('rejects a revocation whose effective instant is still in the future', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s, revokedAt: '2026-06-21T12:00:00.000Z' });
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
    now: '2026-06-20T12:00:00.000Z',
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.effective_at_or_before_T, false);
});

test('rejects a nonexistent calendar instant', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s, revokedAt: '2026-02-30T12:00:00.000Z' });
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
    now: '2026-06-20T12:00:00.000Z',
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.revoked_at_present, false);
});

test('rejects malformed targets even when both sides normalize to emptiness', () => {
  const s = newSigner();
  const malformed = { target_type: 'receipt', target_id: '', action_hash: 'not-a-digest' };
  const stmt = buildStatement({ signer: s });
  stmt.target_id = '';
  stmt.action_hash = 'not-a-digest';
  const signedFields = {
    '@version': REVOCATION_VERSION,
    action_hash: stmt.action_hash,
    reason: stmt.reason,
    revoked_at: stmt.revoked_at,
    revoker_id: stmt.revoker_id,
    target_id: stmt.target_id,
    target_type: stmt.target_type,
  };
  stmt.proof.signature_b64u = sign(signedFields, s.privateKey);
  const r = verifyRevocation(malformed, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.target_bound, false);
});

test('rejects a mismatched signature algorithm label', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  stmt.proof.algorithm = 'ES256';
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.revoker_signature_valid, false);
});

test('rejects a substituted revoker key id', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  stmt.proof.revoker_key_id = 'ep:revoker-key:sha256:' + 'ff'.repeat(32);
  const r = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.revoker_key_bound, false);
});

test('rejects an empty presented key even when the signature verifies under the pin', () => {
  const s = newSigner();
  const stmt = buildStatement({ signer: s });
  stmt.proof.public_key = '';
  stmt.proof.revoker_key_id = `ep:revoker-key:sha256:${crypto
    .createHash('sha256').digest('hex')}`;
  const result = verifyRevocation(TARGET, stmt, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.checks.revoker_key_pinned, false);
});

test('rejects a non-string revoker id and over-precise timestamp without throwing', () => {
  const s = newSigner();
  const badId = buildStatement({ signer: s });
  badId.revoker_id = { tenant: 'ep:revoker:ig_okafor' };
  assert.doesNotThrow(() => verifyRevocation(TARGET, badId, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  }));
  assert.strictEqual(verifyRevocation(TARGET, badId, { revokerKeys: {} }).valid, false);

  const overPrecise = buildStatement({
    signer: s,
    revokedAt: '2026-06-20T12:00:00.1234567890Z',
  });
  const result = verifyRevocation(TARGET, overPrecise, {
    revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
  });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.checks.revoked_at_present, false);
});

test('accepts one through nine fractional-second digits and schema enforces the same bounds', () => {
  const s = newSigner();
  const pin = { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } };
  for (const revokedAt of [
    '2026-06-20T12:00:00.1Z',
    '2026-06-20T12:00:00.123456789Z',
  ]) {
    const result = verifyRevocation(TARGET, buildStatement({ signer: s, revokedAt }), {
      revokerKeys: pin,
      now: '2026-06-20T12:00:01Z',
    });
    assert.strictEqual(result.valid, true, `${revokedAt}: ${JSON.stringify(result.errors)}`);
  }

  const schema = JSON.parse(readFileSync(
    new URL('../../public/schemas/ep-revocation.schema.json', import.meta.url),
    'utf8',
  ));
  const revokedAtPattern = new RegExp(schema.properties.revoked_at.pattern);
  assert.match('2026-06-20T12:00:00.1Z', revokedAtPattern);
  assert.match('2026-06-20T12:00:00.123456789Z', revokedAtPattern);
  assert.doesNotMatch('2026-06-20T12:00:00.1234567890Z', revokedAtPattern);
  assert.doesNotMatch('', new RegExp(schema.properties.proof.properties.public_key.pattern));
});

test('fails closed when malformed revoker_id cannot be converted to a string', () => {
  const s = newSigner();
  const malformed = buildStatement({ signer: s });
  malformed.revoker_id = Object.create(null);
  assert.doesNotThrow(() => {
    const result = verifyRevocation(TARGET, malformed, {
      revokerKeys: { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } },
    });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.revoker_key_pinned, false);
  });
});

test('rejects unsigned fields at the statement or proof level', () => {
  const s = newSigner();
  const pin = { 'ep:revoker:ig_okafor': { public_key: s.publicKeyB64u } };
  const top = { ...buildStatement({ signer: s }), scope_note: 'unsigned' };
  assert.strictEqual(verifyRevocation(TARGET, top, { revokerKeys: pin }).checks.structure, false);
  const proof = buildStatement({ signer: s });
  proof.proof.signed_payload_b64u = Buffer.from('unsigned').toString('base64url');
  assert.strictEqual(verifyRevocation(TARGET, proof, { revokerKeys: pin }).checks.structure, false);
});
