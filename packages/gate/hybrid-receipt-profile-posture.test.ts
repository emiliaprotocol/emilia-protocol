// SPDX-License-Identifier: Apache-2.0
/**
 * The CUSTODY-RESOLVED DEFAULT for src/hybrid-receipt-profile.ts.
 *
 * Three jobs:
 *
 *  1. THE POSTURE MATRIX. With no explicit operator setting, the default is
 *     resolved from custody: a dual signer whose PQ leg custody is permitted
 *     resolves `dual`; a refusing custody policy resolves classical-only with
 *     the NAMED reason (pq_custody_not_permitted / custody_policy_not_satisfied);
 *     no dual signer resolves classical-only (hybrid_signer_absent). An explicit
 *     setting wins in both directions, and `required` is untouched by any of it.
 *
 *  2. THE BYTE-IDENTITY REGRESSION. The EP-RECEIPT-v1 twin a `dual` issuance
 *     returns is byte-identical to what the same issuer produces under
 *     `disabled`. Proved WITHOUT trusting either path's helpers: the test
 *     independently recomputes canonicalize(payload) and verifies the flat
 *     signature with raw node crypto. The RNG is controlled (fixed ML-DSA seed,
 *     FIPS 204 deterministic signing, fixed Ed25519 key), so the whole dual
 *     result is reproducible and a one-byte shift fails this.
 *
 *  3. THE TWIN LINK AND THE v1 VERIFIER. Both artifacts recompute the same
 *     action digest from their own payloads, and a v1-ONLY verifier (one that
 *     refuses any @version it does not know, before looking at a signature)
 *     accepts the classical twin unchanged and refuses the hybrid twin on the
 *     version marker.
 *
 * BOUNDARY, REPEATED HERE BECAUSE THE TESTS DO NOT PROVE OTHERWISE: two
 * receipts over one payload is a COMPATIBILITY arrangement, not a security
 * upgrade to the classical artifact. The EP-RECEIPT-v1 twin is exactly as
 * forgeable as it was alone; what dual buys is that the hybrid twin EXISTS for
 * the same action. Nothing here is deployed, default-in-production, or
 * certified: no call site in this repository issues receipts through this
 * module, and the ML-DSA implementation is not a FIPS validated module.
 *
 * Real ML-DSA-65 runs here; a green run means the PQ leg actually signed.
 *
 * Run: node --test packages/gate/hybrid-receipt-profile-posture.test.js
 *  or: npx tsx --test packages/gate/hybrid-receipt-profile-posture.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  CLASSICAL_RECEIPT_PROFILE_ID,
  DUAL_ISSUANCE_RESULT_ID,
  HYBRID_PROFILE_REASONS,
  HYBRID_RECEIPT_PROFILE_ID,
  acceptUnderHybridProfile,
  issueUnderHybridProfile,
  loadHybridIssuanceModule,
  resolveHybridIssuancePosture,
  resolveHybridReceiptProfile,
} from './dist/hybrid-receipt-profile.js';
import {
  generateHybridIssuerKeyBundle,
  signingKeysFromHybridBundle,
  verificationKeysFromHybridBundle,
} from '../issue/dist/hybrid-issuance.js';
import { canonicalize } from '../verify/index.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

// --- fixtures ---------------------------------------------------------------

const issuance = await loadHybridIssuanceModule();
assert.ok(issuance, 'the hybrid issuance module must resolve; a skipped posture suite proves nothing');

// RNG CONTROL. A fixed ML-DSA seed plus FIPS 204 deterministic signing plus a
// fixed Ed25519 key means every artifact below is a pure function of the
// payload, so byte identity is an assertion rather than a coincidence.
const MLDSA_SEED = new Uint8Array(32).fill(7);
const bundle = await generateHybridIssuerKeyBundle({ seed: MLDSA_SEED });
const hybridSigningKeys = signingKeysFromHybridBundle(bundle);
const hybridVerificationKeys = verificationKeysFromHybridBundle(bundle);
const DETERMINISTIC = Object.freeze({ deterministic: true });

const PAYLOAD = Object.freeze({
  action: { parameters: { amount: '25.00' }, type: 'payment.capture.1' },
  issued_at: '2026-08-18T00:00:00Z',
  issuer: 'ep:issuer:gate-posture-test',
});

const ED_SEED_KEY = crypto.generateKeyPairSync('ed25519');
const CLASSICAL_PUBLIC_SPKI_B64U = ED_SEED_KEY.publicKey
  .export({ format: 'der', type: 'spki' })
  .toString('base64url');

/** A stand-in for whatever EP-RECEIPT-v1 issuance a deployment already runs. */
function issueClassical({ payload, metadata }: { payload: Record<string, any>; metadata?: Record<string, any> }) {
  return {
    '@version': CLASSICAL_RECEIPT_PROFILE_ID,
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), ED_SEED_KEY.privateKey).toString('base64url'),
    },
    ...(metadata ? { metadata } : {}),
  };
}

/**
 * A v1-ONLY verifier: it knows exactly one @version and refuses anything else
 * on the marker, BEFORE looking at a signature. This is the deployed verifier
 * the dual posture must not disturb.
 */
function verifyV1Only(receipt: any) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { valid: false, error: 'malformed_receipt' };
  }
  if (receipt['@version'] !== CLASSICAL_RECEIPT_PROFILE_ID) {
    return { valid: false, error: `unsupported version: ${String(receipt['@version'])}` };
  }
  try {
    const ok = crypto.verify(
      null,
      Buffer.from(canonicalize(receipt.payload), 'utf8'),
      crypto.createPublicKey({ key: Buffer.from(CLASSICAL_PUBLIC_SPKI_B64U, 'base64url'), format: 'der', type: 'spki' }),
      Buffer.from(receipt.signature.value, 'base64url'),
    );
    return ok ? { valid: true } : { valid: false, error: 'signature_invalid' };
  } catch {
    return { valid: false, error: 'signature_invalid' };
  }
}

/** `sha256:<hex>` over the canonical payload bytes, recomputed independently. */
function actionDigestOf(payload: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(Buffer.from(canonicalize(payload), 'utf8')).digest('hex')}`;
}

const CUSTODY_PERMITS = Object.freeze({
  hybrid_signer_present: true,
  pq_leg_permitted: true,
  pq_custody: 'software',
  reason: null,
});
const CUSTODY_REFUSES_PQ = Object.freeze({
  hybrid_signer_present: true,
  pq_leg_permitted: false,
  pq_custody: 'software',
  reason: 'pq_custody_not_permitted',
  detail: 'pq_leg_custody:software',
});
const CUSTODY_POLICY_UNSATISFIED = Object.freeze({
  hybrid_signer_present: true,
  pq_leg_permitted: false,
  pq_custody: 'software',
  reason: 'custody_policy_not_satisfied',
  detail: 'local_key_custody_forbidden',
});
const CUSTODY_NO_SIGNER = Object.freeze({
  hybrid_signer_present: false,
  pq_leg_permitted: false,
  pq_custody: null,
  reason: 'hybrid_signer_absent',
});

// ===========================================================================
// 1. THE POSTURE MATRIX
// ===========================================================================

test('a hybrid signer whose PQ custody is permitted resolves the DEFAULT to dual', () => {
  const posture = resolveHybridIssuancePosture({ custody: CUSTODY_PERMITS });
  assert.equal(posture.source, 'custody_default');
  assert.equal(posture.profile.mode, 'dual');
  assert.equal(posture.profile.issues_dual, true);
  assert.equal(posture.profile.issues_hybrid, true);
  // dual is a migration posture, not the strict end-state.
  assert.equal(posture.profile.requires_hybrid, false);
  assert.equal(posture.reason, null);
  assert.equal(posture.custody.pq_leg_permitted, true);
  assert.equal(resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS).mode, 'dual');
});

test('custody REFUSING the software PQ leg keeps the default classical-only, with the named reason', () => {
  const posture = resolveHybridIssuancePosture({ custody: CUSTODY_REFUSES_PQ });
  assert.equal(posture.source, 'custody_default');
  assert.equal(posture.profile.mode, 'disabled');
  assert.equal(posture.profile.issues_hybrid, false);
  // The whole point: NAMED and observable, never a silent downgrade.
  assert.equal(posture.reason, HYBRID_PROFILE_REASONS.PQ_CUSTODY_NOT_PERMITTED);
  assert.equal(posture.reason, 'pq_custody_not_permitted');
  assert.equal(posture.custody.hybrid_signer_present, true);
  assert.equal(posture.custody.pq_custody, 'software');
  assert.equal(posture.custody.reason, 'pq_custody_not_permitted');
});

test('an unsatisfied deployment custody policy is its own named reason', () => {
  const posture = resolveHybridIssuancePosture({ custody: CUSTODY_POLICY_UNSATISFIED });
  assert.equal(posture.profile.mode, 'disabled');
  assert.equal(posture.reason, HYBRID_PROFILE_REASONS.CUSTODY_POLICY_NOT_SATISFIED);
});

test('no hybrid signer resolves classical-only (hybrid_signer_absent), including with no custody at all', () => {
  for (const custody of [CUSTODY_NO_SIGNER, undefined, null]) {
    const posture = resolveHybridIssuancePosture({ custody });
    assert.equal(posture.profile.mode, 'disabled');
    assert.equal(posture.reason, HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ABSENT);
    assert.equal(posture.custody.pq_leg_permitted, false);
  }
  // The pre-existing call shape keeps its pre-existing answer.
  assert.equal(resolveHybridReceiptProfile(undefined).mode, 'disabled');
  assert.equal(resolveHybridReceiptProfile({}).mode, 'disabled');
});

test('an explicit operator setting wins over the resolved default, in BOTH directions', () => {
  // Down: custody would have said dual; the operator pins classical-only.
  for (const off of ['disabled', false, { hybrid_issuance: 'disabled' }, { hybrid_issuance: false }]) {
    const pinned = resolveHybridIssuancePosture({ config: off, custody: CUSTODY_PERMITS });
    assert.equal(pinned.source, 'operator');
    assert.equal(pinned.profile.mode, 'disabled');
    assert.equal(pinned.reason, HYBRID_PROFILE_REASONS.OPERATOR_PINNED_CLASSICAL);
    // The custody assessment is still recorded, so the override is auditable.
    assert.equal(pinned.custody.pq_leg_permitted, true);
  }

  // Up: custody refused the PQ leg; the operator turns hybrid on anyway. That
  // is an operator attestation about custody they operate, and the refusing
  // custody verdict stays visible on the result rather than being erased.
  for (const [setting, mode] of [['enabled', 'enabled'], ['dual', 'dual'], ['required', 'required'], [true, 'enabled']] as const) {
    const forced = resolveHybridIssuancePosture({ config: setting, custody: CUSTODY_REFUSES_PQ });
    assert.equal(forced.source, 'operator');
    assert.equal(forced.profile.mode, mode);
    assert.equal(forced.reason, null);
    assert.equal(forced.custody.pq_leg_permitted, false);
    assert.equal(forced.custody.reason, HYBRID_PROFILE_REASONS.PQ_CUSTODY_NOT_PERMITTED);
  }
});

test('a contradictory custody verdict fails CLOSED, never up to dual', () => {
  // "permitted" while naming a refusal is treated as the refusal it names.
  const contradictory = resolveHybridIssuancePosture({
    custody: { hybrid_signer_present: true, pq_leg_permitted: true, reason: 'pq_custody_not_permitted' },
  });
  assert.equal(contradictory.profile.mode, 'disabled');
  assert.equal(contradictory.reason, HYBRID_PROFILE_REASONS.PQ_CUSTODY_NOT_PERMITTED);

  // A permission flag with no signer behind it is not permission either.
  const noSigner = resolveHybridIssuancePosture({
    custody: { hybrid_signer_present: false, pq_leg_permitted: true },
  });
  assert.equal(noSigner.profile.mode, 'disabled');
  assert.equal(noSigner.reason, HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ABSENT);

  // An unrecognized custody reason is passed through, not swallowed.
  const unknown = resolveHybridIssuancePosture({
    custody: { hybrid_signer_present: true, pq_leg_permitted: false, reason: 'some_future_custody_reason' },
  });
  assert.equal(unknown.profile.mode, 'disabled');
  assert.equal(unknown.reason, 'some_future_custody_reason');
});

test('a misconfigured flag still THROWS; custody never rounds it down to a default', () => {
  for (const bad of ['on', 'REQUIRED', 'yes', 1, { hybrid_issuance: 'optional' }]) {
    assert.throws(() => resolveHybridIssuancePosture({ config: bad, custody: CUSTODY_PERMITS }), /hybrid_issuance must be one of/);
    assert.throws(() => resolveHybridReceiptProfile(bad, CUSTODY_PERMITS), /hybrid_issuance must be one of/);
  }
});

test('required semantics are UNCHANGED by custody resolution', async () => {
  // `required` is only ever reached through an explicit setting...
  assert.notEqual(resolveHybridIssuancePosture({ custody: CUSTODY_PERMITS }).profile.mode, 'required');
  const profile = resolveHybridReceiptProfile('required', CUSTODY_PERMITS);
  assert.equal(profile.mode, 'required');
  assert.equal(profile.requires_hybrid, true);
  assert.equal(profile.issues_dual, false);

  // ...it still refuses an explicit classical ask...
  const refusedIssue = await issueUnderHybridProfile({
    profile,
    payload: PAYLOAD,
    requestHybrid: false,
    hybridKeys: hybridSigningKeys,
    issueClassical,
  });
  assert.equal(refusedIssue.ok, false);
  assert.equal(!refusedIssue.ok && refusedIssue.reason, HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);

  // ...and it still refuses a classical receipt on acceptance.
  const refusedAccept = await acceptUnderHybridProfile({
    profile,
    receipt: issueClassical({ payload: PAYLOAD as Record<string, any> }),
    hybridKeys: hybridVerificationKeys,
    verifyClassical: verifyV1Only,
  });
  assert.equal(refusedAccept.ok, false);
  assert.equal(!refusedAccept.ok && refusedAccept.reason, HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
});

// ===========================================================================
// 2. THE BYTE-IDENTITY REGRESSION
// ===========================================================================

test('the dual classical twin is BYTE-IDENTICAL to what a non-hybrid deployment produces', async () => {
  // What a deployment that never heard of this module produces today.
  const off = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_NO_SIGNER),
    payload: PAYLOAD as Record<string, any>,
    issueClassical,
  });
  assert.equal(off.ok, true);
  assert.equal(off.ok && off.profile, CLASSICAL_RECEIPT_PROFILE_ID);
  const classicalOnly = off.ok ? (off as any).receipt : null;

  // What the custody-resolved default produces for the same action.
  const dual = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridKeys: hybridSigningKeys,
    agilityOptions: DETERMINISTIC,
    issueClassical,
  });
  assert.equal(dual.ok, true);
  assert.equal(dual.ok && (dual as any).profile, DUAL_ISSUANCE_RESULT_ID);
  const twin = (dual as any).classical_receipt;

  // Byte identity of the whole artifact, not just a field-by-field compare.
  assert.equal(canonicalize(twin), canonicalize(classicalOnly));
  assert.equal(JSON.stringify(twin), JSON.stringify(classicalOnly));

  // And the signature is real, checked by an INDEPENDENT recomputation of the
  // canonical bytes plus raw node crypto. A one-byte shift anywhere fails here.
  const recomputed = Buffer.from(canonicalize(twin.payload), 'utf8');
  assert.equal(
    crypto.verify(
      null,
      recomputed,
      crypto.createPublicKey({ key: Buffer.from(CLASSICAL_PUBLIC_SPKI_B64U, 'base64url'), format: 'der', type: 'spki' }),
      Buffer.from(twin.signature.value, 'base64url'),
    ),
    true,
  );

  // The twin carries exactly the v1 shape: dual adds a second ARTIFACT, never a
  // second signature or an extra member on the v1 one.
  assert.deepEqual(Object.keys(twin).sort(), ['@version', 'payload', 'signature']);
  assert.equal(twin.signature.algorithm, 'Ed25519');

  // With the RNG controlled the whole dual result is reproducible, hybrid twin
  // included, so this regression pins the PQ leg's bytes as well.
  const again = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridKeys: hybridSigningKeys,
    agilityOptions: DETERMINISTIC,
    issueClassical,
  });
  assert.equal(canonicalize((again as any).hybrid_receipt), canonicalize((dual as any).hybrid_receipt));
});

// ===========================================================================
// 3. THE TWIN LINK AND THE v1 VERIFIER
// ===========================================================================

test('both artifacts of a dual pair recompute the SAME action digest', async () => {
  const dual: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridKeys: hybridSigningKeys,
    agilityOptions: DETERMINISTIC,
    issueClassical,
  });
  assert.equal(dual.ok, true);
  assert.equal(dual.profile, DUAL_ISSUANCE_RESULT_ID);

  // Recomputed here from each artifact's OWN payload, not read from the result.
  const fromClassical = actionDigestOf(dual.classical_receipt.payload);
  const fromHybrid = actionDigestOf(dual.hybrid_receipt.payload);
  assert.equal(fromClassical, fromHybrid);
  assert.equal(dual.action_digest, fromClassical);
  assert.equal(dual.action_digest, actionDigestOf(PAYLOAD));
  assert.match(dual.action_digest, /^sha256:[0-9a-f]{64}$/);

  // A relying party handed ONE artifact reaches the same value, which is the
  // whole content of the link. It says the two commit to identical action
  // bytes; it says nothing about the other artifact's signatures.
  assert.equal(actionDigestOf(dual.hybrid_receipt.payload), dual.action_digest);
});

test('a v1-ONLY verifier accepts the classical twin unchanged and refuses the hybrid twin by version', async () => {
  const dual: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridKeys: hybridSigningKeys,
    agilityOptions: DETERMINISTIC,
    issueClassical,
  });

  // The deployed verifier keeps working, with no knowledge of this module.
  assert.deepEqual(verifyV1Only(dual.classical_receipt), { valid: true });

  // And it does not accept the hybrid twin on the strength of a leg it could
  // read: it refuses on the version marker, before any signature is inspected.
  const refused = verifyV1Only(dual.hybrid_receipt);
  assert.equal(refused.valid, false);
  assert.equal(refused.error, `unsupported version: ${HYBRID_RECEIPT_PROFILE_ID}`);

  // The hybrid twin is real: both legs verify over the same canonical bytes,
  // through the profile's own acceptance path.
  const accepted = await acceptUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    receipt: dual.hybrid_receipt,
    hybridKeys: hybridVerificationKeys,
    verifyClassical: verifyV1Only,
  });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.ok && accepted.profile, HYBRID_RECEIPT_PROFILE_ID);
  assert.deepEqual(dual.hybrid_receipt.signatures.map((s: any) => s.alg), ['Ed25519', 'ML-DSA-65']);
});

// ===========================================================================
// 4. THE CUSTODY-SIGNER ISSUANCE PATH
// ===========================================================================
//
// A deployment whose classical leg is behind a KMS/HSM boundary has no secret
// bytes to hand over, only a registered dual signer. Without this path a
// custody-resolved `dual` would resolve to a posture that deployment could not
// execute. The signer below is the structural shape of
// HybridCustodySigner#signSet in lib/key-custody.ts.

const PQ_PAIR = ml_dsa65.keygen(new Uint8Array(32).fill(11));
const SIGNER_ED = crypto.generateKeyPairSync('ed25519');

function makeSignSetSigner(overrides: { pqSign?: (bytes: Buffer) => string } = {}) {
  return {
    async signSet(bytes: Uint8Array | Buffer) {
      const buf = Buffer.from(bytes);
      return [
        { alg: 'Ed25519', sig: crypto.sign(null, buf, SIGNER_ED.privateKey).toString('base64url'), key_id: 'pkcs11:ep-issuer#1' },
        {
          alg: 'ML-DSA-65',
          sig: overrides.pqSign
            ? overrides.pqSign(buf)
            : Buffer.from(ml_dsa65.sign(new Uint8Array(buf), PQ_PAIR.secretKey, { extraEntropy: false })).toString('base64url'),
          key_id: 'ep:key:pq#1',
        },
      ];
    },
  };
}

test('dual mints through a custody signer, and both legs are real signatures over identical bytes', async () => {
  const dual: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridSigner: makeSignSetSigner(),
    issueClassical,
  });
  assert.equal(dual.ok, true);
  assert.equal(dual.profile, DUAL_ISSUANCE_RESULT_ID);

  const doc = dual.hybrid_receipt;
  assert.equal(doc['@version'], HYBRID_RECEIPT_PROFILE_ID);
  assert.deepEqual(doc.profile.required_algorithms, ['Ed25519', 'ML-DSA-65']);
  assert.deepEqual(doc.signatures.map((s: any) => s.alg), ['Ed25519', 'ML-DSA-65']);

  // The anti-stripping commitment is built by the issuance module from the
  // REGISTERED set, not by the signer: rebuild those bytes here and check both
  // legs against them independently.
  const signedBytes = Buffer.from(canonicalize({
    '@version': HYBRID_RECEIPT_PROFILE_ID,
    payload: doc.payload,
    required_algorithms: ['Ed25519', 'ML-DSA-65'],
  }), 'utf8');
  assert.equal(
    crypto.verify(null, signedBytes, SIGNER_ED.publicKey, Buffer.from(doc.signatures[0].sig, 'base64url')),
    true,
  );
  assert.equal(
    ml_dsa65.verify(
      new Uint8Array(Buffer.from(doc.signatures[1].sig, 'base64url')),
      new Uint8Array(signedBytes),
      PQ_PAIR.publicKey,
    ),
    true,
  );

  // And the classical twin is untouched by the signer path.
  assert.deepEqual(verifyV1Only(dual.classical_receipt), { valid: true });
  assert.equal(dual.action_digest, actionDigestOf(PAYLOAD));
});

test('a signer that cannot produce the PQ leg is a REFUSAL, never a classical-only answer', async () => {
  const broken = {
    async signSet() {
      throw new Error('softwareMldsaSigner: refusing to sign: pq_backend_unavailable (@noble/post-quantum ml_dsa65 not resolvable)');
    },
  };
  const outcome: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridSigner: broken,
    issueClassical,
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);
  assert.match(String(outcome.detail?.error), /pq_backend_unavailable/);
  assert.equal(outcome.classical_receipt, undefined);
});

test('a signer returning only the classical leg is a refusal, not a narrowed set', async () => {
  const halfHybrid = {
    async signSet(bytes: Uint8Array | Buffer) {
      return [{ alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(bytes), SIGNER_ED.privateKey).toString('base64url') }];
    },
  };
  const outcome: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridSigner: halfHybrid,
    issueClassical,
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);
  assert.match(String(outcome.detail?.error), /no ML-DSA-65 leg/);
});

test('an issuance module without the custody-signer entry point refuses by name', async () => {
  const outcome: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    hybridSigner: makeSignSetSigner(),
    issueClassical,
    issuance: {
      createHybridReceipt: issuance!.createHybridReceipt,
      verifyHybridReceipt: issuance!.verifyHybridReceipt,
    },
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, HYBRID_PROFILE_REASONS.HYBRID_SIGNER_ISSUANCE_UNSUPPORTED);
});

test('dual with neither keys nor signer refuses before the classical side effect', async () => {
  let classicalCalls = 0;
  const outcome: any = await issueUnderHybridProfile({
    profile: resolveHybridReceiptProfile(undefined, CUSTODY_PERMITS),
    payload: PAYLOAD as Record<string, any>,
    issueClassical: (args) => { classicalCalls += 1; return issueClassical(args); },
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);
  assert.equal(classicalCalls, 0, 'a refused dual issuance must leave no orphan classical receipt behind');
});
