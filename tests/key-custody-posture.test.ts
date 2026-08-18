// SPDX-License-Identifier: Apache-2.0
//
// describeHybridCustodyPosture() -- the CUSTODY half of the custody-resolved
// issuance default (lib/key-custody.ts).
//
// The property under test is a refusal, not a feature. There is no KMS or HSM
// ML-DSA-65 signing path available to EP today, so a dual signer's PQ leg is
// software-held. assertProductionKeyCustody() does not bless that, and neither
// does this: a gov-strict (or production) deployment that requires kms/hsm
// custody must NOT be handed a software PQ key because a default changed. It
// stays classical-only under the named reason `pq_custody_not_permitted`.
//
// The last block joins the two halves end to end: a real HybridCustodySigner,
// through this posture, through packages/gate's mode resolution, into a real
// dual issuance whose ML-DSA-65 leg is verified here with @noble/post-quantum.
//
// Two receipts over one payload is a COMPATIBILITY arrangement, not a security
// upgrade to the classical artifact; nothing below is deployed or certified.
import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'node:crypto';

import {
  CUSTODY_BOUNDARY_LABELS,
  HYBRID_CUSTODY_POSTURE_REASONS,
  createExternalCustodySigner,
  createLocalDevSigner,
  clearCustodySigner,
  describeHybridCustodyPosture,
  registerCustodySigner,
} from '../lib/key-custody.js';
import { hybridSigner, softwareMldsaSigner } from '../lib/custody-signers.js';
import {
  issueUnderHybridProfile,
  resolveHybridIssuancePosture,
} from '../packages/gate/dist/hybrid-receipt-profile.js';
import { canonicalize } from '../packages/issue/dist/index.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

afterEach(() => clearCustodySigner());

const DEV_CONFIG = Object.freeze({ mode: 'local-dev', keyId: null, govStrict: false, isProduction: false });
const GOV_HSM_CONFIG = Object.freeze({ mode: 'hsm', keyId: 'pkcs11:ep-issuer#1', govStrict: true, isProduction: false });
const GOV_LOCAL_CONFIG = Object.freeze({ mode: 'local-dev', keyId: null, govStrict: true, isProduction: false });

/** A dual signer whose classical leg really is behind an external boundary. */
function makeHybridSigner({ classicalMode = 'hsm' as 'kms' | 'hsm' } = {}) {
  const ed = crypto.generateKeyPairSync('ed25519');
  const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(3));
  const classical = createExternalCustodySigner({
    mode: classicalMode,
    keyId: 'pkcs11:ep-issuer#1',
    sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'),
    getPublicKey: () => ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  });
  const pq = softwareMldsaSigner({
    keyId: 'ep:key:pq#1',
    secretKey: pqPair.secretKey,
    publicKeyRawB64u: pqPair.publicKey,
    deterministic: true,
  });
  return { signer: hybridSigner({ classical, pq }), ed, pqPair };
}

describe('describeHybridCustodyPosture', () => {
  it('permits the PQ leg for a dual signer below gov-strict', () => {
    const { signer } = makeHybridSigner();
    const posture = describeHybridCustodyPosture({ signer, config: DEV_CONFIG });
    expect(posture.hybrid_signer_present).toBe(true);
    expect(posture.pq_leg_permitted).toBe(true);
    expect(posture.reason).toBeNull();
    expect(posture.detail).toBeNull();
    // The label is reported, never smoothed over.
    expect(posture.pq_custody).toBe('software');
    expect(posture.classical_custody).toBe('hsm');
    expect(posture.gov_strict).toBe(false);
  });

  it('REFUSES the software PQ leg under gov-strict, by name', () => {
    const { signer } = makeHybridSigner();
    const posture = describeHybridCustodyPosture({ signer, config: GOV_HSM_CONFIG });
    expect(posture.hybrid_signer_present).toBe(true);
    expect(posture.pq_leg_permitted).toBe(false);
    expect(posture.reason).toBe(HYBRID_CUSTODY_POSTURE_REASONS.PQ_CUSTODY_NOT_PERMITTED);
    expect(posture.reason).toBe('pq_custody_not_permitted');
    expect(posture.detail).toBe('pq_leg_custody:software');
    // No KMS/HSM ML-DSA path exists today, so 'software' is the only value a
    // real PQ leg carries and this refusal is the state of the art, not a bug.
    expect(posture.pq_custody).toBe('software');
    expect(CUSTODY_BOUNDARY_LABELS).not.toContain(posture.pq_custody as any);
  });

  it('refuses the same way when production is on rather than EP_GOV_STRICT', () => {
    const { signer } = makeHybridSigner();
    const posture = describeHybridCustodyPosture({
      signer,
      config: { mode: 'hsm', keyId: 'pkcs11:ep-issuer#1', govStrict: false, isProduction: true },
    });
    expect(posture.gov_strict).toBe(true);
    expect(posture.pq_leg_permitted).toBe(false);
    expect(posture.reason).toBe('pq_custody_not_permitted');
  });

  it('refuses a gov-strict deployment whose own custody policy is unsatisfied, before reaching the PQ leg', () => {
    const { signer } = makeHybridSigner();
    const posture = describeHybridCustodyPosture({ signer, config: GOV_LOCAL_CONFIG });
    expect(posture.pq_leg_permitted).toBe(false);
    expect(posture.reason).toBe(HYBRID_CUSTODY_POSTURE_REASONS.CUSTODY_POLICY_NOT_SATISFIED);
    expect(posture.detail).toBe('local_key_custody_forbidden');
  });

  it('refuses when the registered classical leg is not the boundary the config claims', () => {
    const ed = crypto.generateKeyPairSync('ed25519');
    const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(4));
    const signer = hybridSigner({
      classical: createLocalDevSigner({ privateKey: ed.privateKey }),
      pq: softwareMldsaSigner({ keyId: 'ep:key:pq#2', secretKey: pqPair.secretKey }),
    });
    const posture = describeHybridCustodyPosture({ signer, config: GOV_HSM_CONFIG });
    expect(posture.pq_leg_permitted).toBe(false);
    expect(posture.reason).toBe(HYBRID_CUSTODY_POSTURE_REASONS.CUSTODY_POLICY_NOT_SATISFIED);
    expect(posture.detail).toBe('classical_leg_custody:local-dev');
  });

  it('names an absent or non-hybrid signer rather than throwing', () => {
    const absent = describeHybridCustodyPosture({ signer: null, config: DEV_CONFIG });
    expect(absent.hybrid_signer_present).toBe(false);
    expect(absent.pq_leg_permitted).toBe(false);
    expect(absent.reason).toBe(HYBRID_CUSTODY_POSTURE_REASONS.HYBRID_SIGNER_ABSENT);
    expect(absent.pq_custody).toBeNull();

    const classicalOnly = describeHybridCustodyPosture({
      signer: createLocalDevSigner({ seedB64: Buffer.alloc(32, 9).toString('base64') }),
      config: DEV_CONFIG,
    });
    expect(classicalOnly.hybrid_signer_present).toBe(false);
    expect(classicalOnly.reason).toBe('hybrid_signer_absent');
    expect(classicalOnly.classical_custody).toBe('local-dev');
  });

  it('reads the process-wide registered signer when none is passed', () => {
    expect(describeHybridCustodyPosture({ config: DEV_CONFIG }).hybrid_signer_present).toBe(false);
    const { signer } = makeHybridSigner();
    registerCustodySigner(signer);
    const posture = describeHybridCustodyPosture({ config: DEV_CONFIG });
    expect(posture.hybrid_signer_present).toBe(true);
    expect(posture.pq_leg_permitted).toBe(true);
  });

  it('returns a frozen verdict', () => {
    const { signer } = makeHybridSigner();
    expect(Object.isFrozen(describeHybridCustodyPosture({ signer, config: DEV_CONFIG }))).toBe(true);
  });
});

// ===========================================================================
// End to end: custody -> posture -> mode -> a real dual issuance
// ===========================================================================

describe('custody-resolved default, end to end', () => {
  const PAYLOAD = Object.freeze({
    action: { parameters: { amount: '10.00' }, type: 'payment.capture.1' },
    issued_at: '2026-08-18T00:00:00Z',
    issuer: 'ep:issuer:custody-posture-test',
  });

  function classicalIssuer(key: crypto.KeyObject) {
    return ({ payload }: { payload: Record<string, any> }) => ({
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: {
        algorithm: 'Ed25519',
        value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), key).toString('base64url'),
      },
    });
  }

  it('a registered dual signer below gov-strict resolves dual and mints BOTH artifacts', async () => {
    const { signer, ed, pqPair } = makeHybridSigner();
    registerCustodySigner(signer);
    const custody = describeHybridCustodyPosture({ config: DEV_CONFIG });
    const posture = resolveHybridIssuancePosture({ custody });
    expect(posture.source).toBe('custody_default');
    expect(posture.profile.mode).toBe('dual');
    expect(posture.reason).toBeNull();

    const classicalKey = crypto.generateKeyPairSync('ed25519');
    const outcome: any = await issueUnderHybridProfile({
      profile: posture.profile,
      payload: PAYLOAD as Record<string, any>,
      hybridSigner: signer,
      issueClassical: classicalIssuer(classicalKey.privateKey),
    });
    expect(outcome.ok).toBe(true);
    expect(outcome.profile).toBe('EP-RECEIPT-DUAL-ISSUANCE-v1');
    expect(outcome.classical_receipt['@version']).toBe('EP-RECEIPT-v1');
    expect(outcome.hybrid_receipt['@version']).toBe('EP-RECEIPT-HYBRID-v1');

    // The PQ leg is a REAL ML-DSA-65 signature over the set-committed bytes.
    const signedBytes = Buffer.from(canonicalize({
      '@version': 'EP-RECEIPT-HYBRID-v1',
      payload: outcome.hybrid_receipt.payload,
      required_algorithms: ['Ed25519', 'ML-DSA-65'],
    }), 'utf8');
    const [edLeg, pqLeg] = outcome.hybrid_receipt.signatures;
    expect(crypto.verify(null, signedBytes, ed.publicKey, Buffer.from(edLeg.sig, 'base64url'))).toBe(true);
    expect(ml_dsa65.verify(
      new Uint8Array(Buffer.from(pqLeg.sig, 'base64url')),
      new Uint8Array(signedBytes),
      pqPair.publicKey,
    )).toBe(true);

    // The classical twin is unchanged v1: same canonical bytes, same flat
    // signature field, verified independently with raw node crypto.
    expect(crypto.verify(
      null,
      Buffer.from(canonicalize(outcome.classical_receipt.payload), 'utf8'),
      classicalKey.publicKey,
      Buffer.from(outcome.classical_receipt.signature.value, 'base64url'),
    )).toBe(true);
  });

  it('the SAME signer under gov-strict resolves classical-only, with the reason on the record', async () => {
    const { signer } = makeHybridSigner();
    registerCustodySigner(signer);
    const custody = describeHybridCustodyPosture({ config: GOV_HSM_CONFIG });
    const posture = resolveHybridIssuancePosture({ custody });
    expect(posture.source).toBe('custody_default');
    expect(posture.profile.mode).toBe('disabled');
    expect(posture.profile.issues_hybrid).toBe(false);
    expect(posture.reason).toBe('pq_custody_not_permitted');
    expect(posture.custody.pq_custody).toBe('software');

    const classicalKey = crypto.generateKeyPairSync('ed25519');
    const outcome: any = await issueUnderHybridProfile({
      profile: posture.profile,
      payload: PAYLOAD as Record<string, any>,
      hybridSigner: signer,
      issueClassical: classicalIssuer(classicalKey.privateKey),
    });
    // Classical-only issuance, and no hybrid twin anywhere in the result.
    expect(outcome.ok).toBe(true);
    expect(outcome.profile).toBe('EP-RECEIPT-v1');
    expect(outcome.hybrid_receipt).toBeUndefined();
  });

  it('an explicit operator setting overrides the gov-strict refusal, and the refusal stays visible', () => {
    const { signer } = makeHybridSigner();
    const custody = describeHybridCustodyPosture({ signer, config: GOV_HSM_CONFIG });
    const forced = resolveHybridIssuancePosture({ config: { hybrid_issuance: 'dual' }, custody });
    expect(forced.source).toBe('operator');
    expect(forced.profile.mode).toBe('dual');
    // The operator attested; the custody verdict is recorded, not erased.
    expect(forced.custody.pq_leg_permitted).toBe(false);
    expect(forced.custody.reason).toBe('pq_custody_not_permitted');
    expect(forced.custody.pq_custody).toBe('software');
  });
});
