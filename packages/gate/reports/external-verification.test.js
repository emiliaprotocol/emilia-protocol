// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  EXTERNAL_VERIFICATION_STATEMENT_VERSION,
  externalVerificationDigest,
  signExternalVerificationStatement,
  verifyExternalVerificationStatement,
} from './external-verification.js';

function verifierKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function statementFixture(k, overrides = {}) {
  return signExternalVerificationStatement({
    generated_at: '2026-07-06T12:00:00.000Z',
    verifier: { id: 'ext:auditor:alpha', name: 'Alpha External Verification' },
    subject: { kind: 'gate_evidence_log', evidence_head: 'sha256:' + 'a'.repeat(64) },
    procedure: {
      id: 'ep-gate-reperformance',
      version: 'EP-GATE-REPERFORMANCE-v1',
      tool: '@emilia-protocol/gate/reports/reperform',
    },
    inputs: {
      entries_digest: 'sha256:' + 'b'.repeat(64),
      issuer_keys_pinned: 1,
      admissibility_profile_hash: 'sha256:' + 'c'.repeat(64),
    },
    result: {
      status: 'verified',
      artifact_digest: 'sha256:' + 'd'.repeat(64),
      checks: [
        { id: 'chain_reperformed', ok: true },
        { id: 'receipts_reverified', ok: true, detail: { count: 3 } },
      ],
    },
    ...overrides,
  }, k.privateKey);
}

test('signs an external verification statement and verifies only under a pinned verifier key', () => {
  const k = verifierKey();
  const s = statementFixture(k);
  const r = verifyExternalVerificationStatement(s, {
    pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:alpha', public_key: k.public_key }],
  });

  assert.equal(s['@version'], EXTERNAL_VERIFICATION_STATEMENT_VERSION);
  assert.equal(r.verified, true);
  assert.equal(r.accepted, true);
  assert.equal(r.statement_digest, s.signature.statement_digest);
  assert.equal(externalVerificationDigest(s), s.signature.statement_digest);
  assert.match(s.limitations.join(' '), /does not authorize/);
});

test('a valid signature from an unpinned verifier key is not accepted', () => {
  const k = verifierKey();
  const s = statementFixture(k);
  const other = verifierKey();
  const r = verifyExternalVerificationStatement(s, {
    pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:alpha', public_key: other.public_key }],
  });

  assert.equal(r.verified, false);
  assert.equal(r.accepted, false);
  assert.equal(r.reason, 'verifier_key_not_pinned');
  assert.equal(r.checks.statement_digest, true);
});

test('tampering with the signed result fails before signature acceptance', () => {
  const k = verifierKey();
  const s = statementFixture(k);
  const tampered = {
    ...s,
    result: { ...s.result, status: 'verified_and_certified' },
  };
  const r = verifyExternalVerificationStatement(tampered, {
    pinnedVerifierKeys: [{ verifier_id: 'ext:auditor:alpha', public_key: k.public_key }],
  });

  assert.equal(r.verified, false);
  assert.equal(r.accepted, false);
  assert.equal(r.reason, 'statement_digest_mismatch');
  assert.notEqual(externalVerificationDigest(tampered), s.signature.statement_digest);
});

test('re-signing a changed result gets a different statement digest', () => {
  const k = verifierKey();
  const a = statementFixture(k, { result: { status: 'verified', checks: [{ id: 'x', ok: true }] } });
  const b = statementFixture(k, { result: { status: 'refused', checks: [{ id: 'x', ok: false }] } });

  assert.notEqual(a.signature.statement_digest, b.signature.statement_digest);
  assert.equal(verifyExternalVerificationStatement(a, { pinnedVerifierKeys: [{ public_key: k.public_key }] }).verified, true);
  assert.equal(verifyExternalVerificationStatement(b, { pinnedVerifierKeys: [{ public_key: k.public_key }] }).verified, true);
});

test('malformed version and signature fail closed', () => {
  const k = verifierKey();
  const s = statementFixture(k);

  assert.equal(
    verifyExternalVerificationStatement({ ...s, '@version': 'NOPE' }, { pinnedVerifierKeys: [{ public_key: k.public_key }] }).reason,
    'unsupported_version',
  );
  const noSig = { ...s };
  delete noSig.signature;
  assert.equal(
    verifyExternalVerificationStatement(noSig, { pinnedVerifierKeys: [{ public_key: k.public_key }] }).reason,
    'signature_missing_or_malformed',
  );
});
