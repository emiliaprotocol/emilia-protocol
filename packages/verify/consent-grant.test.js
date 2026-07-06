// SPDX-License-Identifier: Apache-2.0
//
// EP-CONSENT-GRANT-v1 offline verifier test. Builds a REAL Ed25519-signed
// standing consent grant over an exact {asset, control_verb, expiry}, and a
// per-action receipt bound to it by grant_hash, then asserts the fail-closed
// predicate: accept the authentic, pinned, in-window, covered, bound pair;
// reject an expired grant, a wrong asset, a wrong verb, a receipt bound to a
// DIFFERENT grant_hash, a tampered grant (hash mismatch), a bad principal
// signature, and a revoked grant.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { REVOCATION_VERSION } from './revocation.js';
import {
  buildConsentGrant,
  computeGrantHash,
  verifyGrantHash,
  verifyConsentGrant,
  verifyReceiptUnderGrant,
  CONSENT_GRANT_VERSION,
} from './consent-grant.js';

function newSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const PRINCIPAL = newSigner();
const NOW = '2026-07-06T12:00:00.000Z';

function makeGrant(overrides = {}, signer = PRINCIPAL) {
  return buildConsentGrant(
    {
      grant_id: 'grant_ot_pump_7',
      principal: 'ep:approver:diane_staheli',
      asset: 'ot:site-3/pump-array/valve-7',
      control_verb: 'setpoint.write',
      constraints: { amount_ceiling: '500000' }, // non-integer quantities as STRINGS
      issued_at: '2026-07-01T00:00:00.000Z',
      expires_at: '2026-08-01T00:00:00.000Z',
      ...overrides,
    },
    signer,
  );
}

// A per-action receipt that acts under the grant by carrying grant_hash in its
// signed Action Object (receipt SHOULD carry grant_hash; here inside action).
function makeReceipt(grant, actionOverrides = {}) {
  return {
    '@version': 'EP-RECEIPT-v1',
    action: {
      asset: grant.asset,
      control_verb: grant.control_verb,
      grant_hash: grant.grant_hash,
      ...actionOverrides,
    },
  };
}

const revokerSigner = newSigner();
function makeRevocation(grant, { revokerId = 'ep:revoker:site3_ciso', revokedAt = NOW } = {}) {
  const signedFields = {
    '@version': REVOCATION_VERSION,
    action_hash: grant.grant_hash,
    reason: 'authority withdrawn',
    revoked_at: revokedAt,
    revoker_id: revokerId,
    target_id: grant.grant_id,
    target_type: 'commit',
  };
  const signature = crypto
    .sign(null, Buffer.from(canonicalize(signedFields), 'utf8'), revokerSigner.privateKey)
    .toString('base64url');
  return {
    '@version': REVOCATION_VERSION,
    target_type: 'commit',
    target_id: grant.grant_id,
    action_hash: grant.grant_hash,
    revoker_id: revokerId,
    revoked_at: revokedAt,
    reason: 'authority withdrawn',
    proof: {
      algorithm: 'Ed25519',
      revoker_key_id: 'rk1',
      public_key: revokerSigner.publicKeyB64u,
      signature_b64u: signature,
    },
  };
}

// ── happy path ───────────────────────────────────────────────────────────────

test('grant_hash binds the canonical body and recomputes', () => {
  const grant = makeGrant();
  assert.strictEqual(grant.profile, CONSENT_GRANT_VERSION);
  assert.ok(/^sha256:[0-9a-f]{64}$/.test(grant.grant_hash));
  assert.strictEqual(computeGrantHash(grant), grant.grant_hash);
  assert.strictEqual(verifyGrantHash(grant), true);
});

test('accepts an authentic, pinned, in-window grant', () => {
  const grant = makeGrant();
  const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, { now: NOW });
  assert.strictEqual(r.valid, true, r.reason);
  assert.deepStrictEqual(r.checks, { hash: true, signature: true, within_window: true });
});

test('accepts a per-action receipt acting under the grant (composition)', () => {
  const grant = makeGrant();
  const receipt = makeReceipt(grant);
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, true, r.reason);
  assert.deepStrictEqual(r.checks, {
    grant: true, asset_covered: true, verb_covered: true, grant_binding: true,
  });
});

// ── reject vectors ─────────────────────────────────────────────────────────────

test('rejects an expired grant (window)', () => {
  const grant = makeGrant({
    issued_at: '2026-01-01T00:00:00.000Z',
    expires_at: '2026-02-01T00:00:00.000Z',
  });
  const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, { now: NOW });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.within_window, false);
  assert.match(r.reason, /expired/);
  // and it surfaces as grant_expired through the composition
  const c = verifyReceiptUnderGrant(makeReceipt(grant), grant, {
    now: NOW, pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(c.ok, false);
  assert.strictEqual(c.reason, 'grant_expired');
});

test('rejects a wrong asset (asset_mismatch)', () => {
  const grant = makeGrant();
  const receipt = makeReceipt(grant, { asset: 'ot:site-3/pump-array/valve-9' });
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW, pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'asset_mismatch');
  assert.strictEqual(r.checks.asset_covered, false);
});

test('rejects a wrong control verb (verb_mismatch)', () => {
  const grant = makeGrant();
  const receipt = makeReceipt(grant, { control_verb: 'setpoint.delete' });
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW, pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'verb_mismatch');
  assert.strictEqual(r.checks.verb_covered, false);
});

test('rejects a receipt bound to a DIFFERENT grant_hash (grant_binding_mismatch)', () => {
  const grant = makeGrant();
  const otherGrant = makeGrant({ grant_id: 'grant_other' });
  const receipt = makeReceipt(grant, { grant_hash: otherGrant.grant_hash });
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW, pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'grant_binding_mismatch');
  assert.strictEqual(r.checks.grant_binding, false);
});

test('rejects a tampered grant (hash mismatch)', () => {
  const grant = makeGrant();
  const tampered = { ...grant, control_verb: 'setpoint.delete' }; // hash no longer binds
  assert.strictEqual(verifyGrantHash(tampered), false);
  const r = verifyConsentGrant(tampered, PRINCIPAL.publicKeyB64u, { now: NOW });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.hash, false);
  assert.match(r.reason, /grant_hash does not bind/);
});

test('rejects a bad principal signature (wrong pinned key => grant_signature_invalid)', () => {
  const grant = makeGrant();
  const wrongKey = newSigner().publicKeyB64u;
  const r = verifyConsentGrant(grant, wrongKey, { now: NOW });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.signature, false);
  // composition maps a bad signature to grant_signature_invalid
  const c = verifyReceiptUnderGrant(makeReceipt(grant), grant, {
    now: NOW, pinnedPrincipalKey: wrongKey,
  });
  assert.strictEqual(c.ok, false);
  assert.strictEqual(c.reason, 'grant_signature_invalid');
});

test('rejects an unpinned principal (no key => refuse)', () => {
  const grant = makeGrant();
  const r = verifyConsentGrant(grant, undefined, { now: NOW });
  assert.strictEqual(r.valid, false);
  assert.match(r.reason, /not trusted/);
});

test('rejects a revoked grant (grant_revoked)', () => {
  const grant = makeGrant();
  const revocation = makeRevocation(grant);
  const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, {
    now: NOW,
    revocation,
    revokerKeys: { 'ep:revoker:site3_ciso': { public_key: revokerSigner.publicKeyB64u } },
  });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.reason, 'grant_revoked');
  // and through the composition
  const c = verifyReceiptUnderGrant(makeReceipt(grant), grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
    revocation,
    revokerKeys: { 'ep:revoker:site3_ciso': { public_key: revokerSigner.publicKeyB64u } },
  });
  assert.strictEqual(c.ok, false);
  assert.strictEqual(c.reason, 'grant_revoked');
});

test('an unpinned revoker cannot revoke (fail-closed on the revoker, grant stays valid)', () => {
  const grant = makeGrant();
  const revocation = makeRevocation(grant);
  const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, {
    now: NOW,
    revocation,
    revokerKeys: {}, // revoker not pinned => revocation does not bind => grant valid
  });
  assert.strictEqual(r.valid, true, r.reason);
});

test('a revocation bound to a DIFFERENT grant does not revoke (revoke-A-for-B)', () => {
  const grant = makeGrant();
  const otherGrant = makeGrant({ grant_id: 'grant_other' });
  const revocationForOther = makeRevocation(otherGrant);
  const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, {
    now: NOW,
    revocation: revocationForOther,
    revokerKeys: { 'ep:revoker:site3_ciso': { public_key: revokerSigner.publicKeyB64u } },
  });
  assert.strictEqual(r.valid, true, r.reason);
});
