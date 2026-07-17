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
  receiptReferencedGrantHash,
  receiptGrantBindingStrength,
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
    grant: true,
    asset_covered: true,
    verb_covered: true,
    grant_binding: true,
    constraints_covered: true,
  });
  // grant_hash is inside the signed Action Object here => STRONG binding.
  assert.strictEqual(r.binding_strength, 'signed_action');
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

test('rejects impossible calendar dates and invalid UTC offsets', () => {
  for (const [issued_at, expires_at] of [
    ['2026-02-30T00:00:00Z', '2026-03-03T00:00:00Z'],
    ['2026-07-01T00:00:00+24:00', '2026-08-01T00:00:00Z'],
  ]) {
    const grant = makeGrant({ issued_at, expires_at });
    const r = verifyConsentGrant(grant, PRINCIPAL.publicKeyB64u, { now: NOW });
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.checks.within_window, false);
    assert.match(r.reason, /RFC-3339 instant/);
  }
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

test('throwing custom asset or verb predicates refuse instead of escaping', () => {
  const grant = makeGrant();
  const receipt = makeReceipt(grant);
  const cases = [
    { assetCovers: () => { throw new Error('asset parser failed'); }, reason: 'asset_mismatch' },
    { verbCovers: () => { throw new Error('verb parser failed'); }, reason: 'verb_mismatch' },
  ];
  for (const options of cases) {
    const r = verifyReceiptUnderGrant(receipt, grant, {
      now: NOW,
      pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
      ...options,
    });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, options.reason);
  }
});

test('a constrained grant refuses when no profile evaluator is supplied', () => {
  const grant = makeGrant({ constraints: { amount_ceiling: '500000' } });
  const receipt = makeReceipt(grant, { amount: '250000' });
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'constraint_evaluator_missing');
  assert.strictEqual(r.checks.grant_binding, true);
  assert.strictEqual(r.checks.constraints_covered, false);
});

test('a constrained grant composes only when the profile evaluator returns exactly true', () => {
  const grant = makeGrant({ constraints: { amount_ceiling: '500000' } });
  const constraintsCover = (action, constraints) => (
    /^\d+$/.test(action.amount)
    && /^\d+$/.test(constraints.amount_ceiling)
    && BigInt(action.amount) <= BigInt(constraints.amount_ceiling)
  );
  const r = verifyReceiptUnderGrant(
    makeReceipt(grant, { amount: '250000' }),
    grant,
    {
      now: NOW,
      pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
      constraintsCover,
    },
  );
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(r.checks.constraints_covered, true);

  const overLimit = verifyReceiptUnderGrant(
    makeReceipt(grant, { amount: '500001' }),
    grant,
    {
      now: NOW,
      pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
      constraintsCover,
    },
  );
  assert.strictEqual(overLimit.ok, false);
  assert.strictEqual(overLimit.reason, 'constraints_mismatch');
});

test('a throwing or truthy non-boolean constraint evaluator refuses', () => {
  const grant = makeGrant({ constraints: { amount_ceiling: '500000' } });
  const receipt = makeReceipt(grant, { amount: '250000' });
  for (const constraintsCover of [
    () => { throw new Error('profile parser failed'); },
    () => 'yes',
  ]) {
    const r = verifyReceiptUnderGrant(receipt, grant, {
      now: NOW,
      pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
      constraintsCover,
    });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, 'constraints_mismatch');
  }
});

test('malformed grant constraints fail closed before composition', () => {
  const grant = buildConsentGrant(
    {
      grant_id: 'grant_bad_constraints',
      principal: 'ep:approver:diane_staheli',
      asset: 'ot:site-3/pump-array/valve-7',
      control_verb: 'setpoint.write',
      constraints: ['not', 'an', 'object'],
      issued_at: '2026-07-01T00:00:00.000Z',
      expires_at: '2026-08-01T00:00:00.000Z',
    },
    PRINCIPAL,
  );
  const r = verifyReceiptUnderGrant(makeReceipt(grant), grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
    constraintsCover: () => true,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'grant_constraints_invalid');
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

// ── native grant_hash in the SIGNED Action Object ────────────────────────────
//
// The mint path (lib/guard-adapter.js) puts grant_hash INSIDE the canonical
// Action Object, so it is covered by the action hash AND by the human signature
// over the action. These tests model a real signed receipt (action_hash =
// sha256(canonicalize(action)), plus an Ed25519 signature over the SAME canonical
// action bytes, exactly as the receipt signs its action) and prove that tampering
// the native grant_hash breaks BOTH the action hash and the signature.

const ACTOR = newSigner();

// sha256 over the canonical action, matching hashCanonicalAction / verifyTrustReceipt step 1.
function actionHashOf(action) {
  return 'sha256:' + crypto.createHash('sha256').update(canonicalize(action), 'utf8').digest('hex');
}

// A REAL signed receipt whose Action Object carries grant_hash natively. The
// signature is Ed25519 over the canonical action bytes (the same bytes the action
// hash is computed over), so tampering any action field — including grant_hash —
// breaks both.
function makeSignedReceipt(grant, actionOverrides = {}) {
  const action = {
    organization_id: 'org_ot',
    actor_id: 'ep:approver:diane_staheli',
    action_type: 'ot.setpoint_write',
    target_resource_id: grant.asset,
    asset: grant.asset,
    control_verb: grant.control_verb,
    grant_hash: grant.grant_hash, // native, inside the signed Action Object
    nonce: 'nonce_abc',
    ...actionOverrides,
  };
  const canonical = canonicalize(action);
  const signature = crypto
    .sign(null, Buffer.from(canonical, 'utf8'), ACTOR.privateKey)
    .toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    action,
    action_hash: actionHashOf(action),
    signature: { algorithm: 'Ed25519', value: signature },
  };
}

// Independent re-check of the receipt's action self-consistency: action_hash must
// recompute from the canonical action, and the signature must verify over the same
// canonical bytes. This is what a full receipt verifier (verifyReceipt /
// verifyTrustReceipt) enforces; here it lets us assert the tamper breaks it.
function actionSelfConsistent(receipt) {
  const recomputed = actionHashOf(receipt.action);
  const hashOk = recomputed.replace(/^sha256:/, '') === String(receipt.action_hash).replace(/^sha256:/, '');
  let sigOk = false;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(ACTOR.publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    sigOk = crypto.verify(
      null,
      Buffer.from(canonicalize(receipt.action), 'utf8'),
      key,
      Buffer.from(receipt.signature.value, 'base64url'),
    );
  } catch {
    sigOk = false;
  }
  return { hashOk, sigOk };
}

test('receiptReferencedGrantHash prefers the signed action.grant_hash over the caller override', () => {
  const grant = makeGrant();
  const other = makeGrant({ grant_id: 'grant_other' });
  const receipt = makeReceipt(grant); // action.grant_hash = grant.grant_hash
  // Even when the caller supplies a DIFFERENT override, the signed reference wins.
  assert.strictEqual(receiptReferencedGrantHash(receipt, other.grant_hash), grant.grant_hash);
  assert.strictEqual(receiptGrantBindingStrength(receipt, other.grant_hash), 'signed_action');
});

test('a receipt whose SIGNED action carries grant_hash composes under the grant (strong binding)', () => {
  const grant = makeGrant();
  const receipt = makeSignedReceipt(grant);
  // The signed receipt is self-consistent to begin with.
  assert.deepStrictEqual(actionSelfConsistent(receipt), { hashOk: true, sigOk: true });
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(r.checks.grant_binding, true);
  assert.strictEqual(r.binding_strength, 'signed_action');
});

test('tampering the native grant_hash breaks the action hash AND the signature', () => {
  const grant = makeGrant();
  const other = makeGrant({ grant_id: 'grant_other' });
  const receipt = makeSignedReceipt(grant);
  // Repoint the grant reference to a DIFFERENT grant WITHOUT re-signing.
  const tampered = {
    ...receipt,
    action: { ...receipt.action, grant_hash: other.grant_hash },
  };
  // Because grant_hash is inside the signed Action Object, the tamper breaks BOTH
  // the recomputed action hash and the Ed25519 signature over the action.
  const consistency = actionSelfConsistent(tampered);
  assert.strictEqual(consistency.hashOk, false, 'action_hash must no longer bind the tampered action');
  assert.strictEqual(consistency.sigOk, false, 'signature must no longer verify over the tampered action');

  // The composition also refuses: the (now-signed) reference points at other's
  // grant, which does not equal THIS grant's grant_hash.
  const r = verifyReceiptUnderGrant(tampered, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'grant_binding_mismatch');
  assert.strictEqual(r.binding_strength, 'signed_action');
});

test('a receipt with NO native grant_hash still composes via caller override (advisory binding)', () => {
  const grant = makeGrant();
  // Receipt whose action does NOT carry grant_hash (pre-native / transitional).
  const receipt = {
    '@version': 'EP-RECEIPT-v1',
    action: { asset: grant.asset, control_verb: grant.control_verb },
  };
  assert.strictEqual(receiptReferencedGrantHash(receipt), null);
  assert.strictEqual(receiptGrantBindingStrength(receipt), 'none');

  // Without an override the binding is missing (fail-closed).
  const missing = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
  });
  assert.strictEqual(missing.ok, false);
  assert.strictEqual(missing.reason, 'missing_grant_reference');
  assert.strictEqual(missing.binding_strength, 'none');

  // A caller-supplied grant_hash lets it compose, flagged as ADVISORY.
  const r = verifyReceiptUnderGrant(receipt, grant, {
    now: NOW,
    pinnedPrincipalKey: PRINCIPAL.publicKeyB64u,
    grantHash: grant.grant_hash,
  });
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(r.checks.grant_binding, true);
  assert.strictEqual(r.binding_strength, 'caller_override');
});
