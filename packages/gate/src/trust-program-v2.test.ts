// SPDX-License-Identifier: Apache-2.0
//
// EP-GATE-TRUST-PROGRAM-PROFILE-v2 / EP-GATE-TRUST-STAGE-RECEIPT-v2 --
// hostile matrix for the hybrid trust-program surfaces. New file, co-located
// under src/ so vitest exercises this package's TS source directly (no build
// step needed); the dist-backed node --test suites keep covering v1 and are
// untouched.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  TRUST_PROGRAM_VERSION,
  TRUST_PROGRAM_V2_VERSION,
  TRUST_STAGE_RECEIPT_VERSION,
  TRUST_STAGE_RECEIPT_V2_VERSION,
  TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS,
  validateTrustProgram,
  validateTrustProgramV2,
  validateTrustProgramStatement,
  trustProgramDigest,
  trustProgramV2Digest,
  verifyTrustStageReceipt,
  signTrustStageReceiptV2,
  verifyTrustStageReceiptV2,
  verifyTrustStageReceiptStatement,
} from './trust-program.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => `caid:1:health.prior-authorization-determination.1:jcs-sha256:${character.repeat(43)}`;
const KEY_ID = 'stage-key-1';

const CONTEXT = Object.freeze({
  issuer: 'ep:gate:example',
  tenant: 'acme',
  environment: 'production',
  audience: 'relying-party:example',
  key_id: KEY_ID,
});

function program(version: string = TRUST_PROGRAM_V2_VERSION) {
  return {
    '@version': version,
    program_id: 'tp.payer.pas-adverse-determination.1',
    version: 1,
    root_caid: C('A'),
    action_digest: D('1'),
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    stages: [
      {
        stage_id: 'licensed-review',
        depends_on: [],
        rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
        requirements: [{
          requirement_id: 'admissibility-01',
          evidence_type: 'ep-admissibility-evaluation',
          verifier_profile: 'ep-admissibility-profile:v1',
          policy_digest: D('b'),
          max_age_sec: 300,
          revocation_required: true,
        }],
      },
    ],
    execution: {
      depends_on: ['licensed-review'],
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: D('e'),
    },
  };
}

function payload(over: Record<string, unknown> = {}) {
  return {
    instance_id: 'instance-1',
    program_id: 'tp.payer.pas-adverse-determination.1',
    program_version: 1,
    program_digest: trustProgramV2Digest(program()),
    root_caid: C('A'),
    action_digest: D('1'),
    stage_id: 'licensed-review',
    stage_policy_digest: D('c'),
    predecessor_receipt_digests: [],
    evidence_digests: [D('a')],
    subjects: ['subject:clinician-one'],
    key_fingerprints: ['kf:clinician-one'],
    satisfied_at: '2026-07-28T13:00:00Z',
    ...over,
  };
}

function issuerFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
  return {
    ed,
    keys: {
      ed: { privateKey: ed.privateKey, publicKey: edPubB64u },
      pq: { secretKey: pq.secretKey, publicKey: pqPubB64u },
    },
    hybridPin: { [KEY_ID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } },
    classicalPin: { [KEY_ID]: edPubB64u },
  };
}

/** Mint a v1 stage receipt by hand: the v1 signer is module-internal. */
function mintV1Receipt(privateKey: crypto.KeyObject) {
  const body = {
    version: TRUST_STAGE_RECEIPT_VERSION,
    issuer: { ...CONTEXT },
    payload: payload(),
  };
  const bytes = Buffer.from(`${TRUST_STAGE_RECEIPT_VERSION}\0${canonicalize(body)}`, 'utf8');
  return {
    ...body,
    receipt_digest: `sha256:${hashCanonical(body)}`,
    signature: { algorithm: 'Ed25519', value: crypto.sign(null, bytes, privateKey).toString('base64url') },
  };
}

describe('EP-GATE-TRUST-PROGRAM-PROFILE-v2 program profile', () => {
  it('validates a v2 program under the same DAG body as v1', () => {
    const result = validateTrustProgramV2(program());
    expect(result.valid).toBe(true);
    expect(result.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('v1-refuses-v2: the untouched v1 validator refuses on the version marker, never a crash', () => {
    const result = validateTrustProgram(program());
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('program_version_unsupported');
  });

  it('v2-refuses-v1 symmetrically, and the router accepts both', () => {
    expect(validateTrustProgramV2(program(TRUST_PROGRAM_VERSION)).reason).toBe('program_version_unsupported');
    expect(validateTrustProgramStatement(program()).valid).toBe(true);
    expect(validateTrustProgramStatement(program(TRUST_PROGRAM_VERSION)).valid).toBe(true);
    expect(trustProgramDigest(program(TRUST_PROGRAM_VERSION)))
      .not.toBe(trustProgramV2Digest(program()));
  });

  it('a structurally broken v2 program refuses by the shared rules, not by the marker', () => {
    const broken = program() as Record<string, any>;
    broken.stages[0].depends_on = ['licensed-review'];
    expect(validateTrustProgramV2(broken).reason).toBe('stage_dependency_invalid');
  });
});

describe('EP-GATE-TRUST-STAGE-RECEIPT-v2 hybrid stage receipt', () => {
  it('valid v2 roundtrip: both legs verify under the pinned key pair', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    expect(receipt.version).toBe(TRUST_STAGE_RECEIPT_V2_VERSION);
    expect(receipt.signature.required_algorithms).toEqual([...TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS]);
    expect(receipt.signature.signatures.map((s) => s.alg)).toEqual([...TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS]);

    const verified = await verifyTrustStageReceiptV2(receipt, {
      trustedKeys: issuer.hybridPin,
      expectedIssuer: CONTEXT,
      expected: { stage_id: 'licensed-review', action_digest: D('1') },
    });
    expect(verified.valid).toBe(true);
    expect(verified.reason).toBeNull();
    expect(verified.receipt_digest).toBe(receipt.receipt_digest);
  });

  it('v1-refuses-v2: the SYNC v1 verifier refuses a v2 receipt on the version marker, never a crash', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    // No await: verifyTrustStageReceipt remains synchronous and untouched.
    const result = verifyTrustStageReceipt(receipt as unknown, { trustedKeys: issuer.classicalPin });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_structure_invalid');
    expect(result.checks.structure).toBe(false);
  });

  it('the router keeps the exact v1 verdict for a v1 receipt and hybrid-checks a v2 one', async () => {
    const issuer = issuerFixture();
    const v1 = mintV1Receipt(issuer.ed.privateKey);
    const routedV1 = await verifyTrustStageReceiptStatement(v1, { trustedKeys: issuer.classicalPin });
    expect(routedV1.valid).toBe(true);

    const v2 = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const routedV2 = await verifyTrustStageReceiptStatement(v2, { trustedKeys: issuer.hybridPin });
    expect(routedV2.valid).toBe(true);
  });

  it('a key id pinned WITHOUT the ML-DSA half never satisfies a v2 pin', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const result = await verifyTrustStageReceiptV2(receipt, { trustedKeys: issuer.classicalPin as any });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_key_untrusted');
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const stripped = {
      ...receipt,
      signature: {
        ...receipt.signature,
        signatures: receipt.signature.signatures.filter((s) => s.alg !== 'ML-DSA-65'),
      },
    };
    const result = await verifyTrustStageReceiptV2(stripped, { trustedKeys: issuer.hybridPin });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_signature_leg_missing');
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] is refused structurally AND cryptographically', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const narrowed = {
      ...receipt,
      signature: {
        ...receipt.signature,
        required_algorithms: ['Ed25519'],
        signatures: receipt.signature.signatures.filter((s) => s.alg === 'Ed25519'),
      },
    };
    const result = await verifyTrustStageReceiptV2(narrowed, { trustedKeys: issuer.hybridPin });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_algorithm_set_unsupported');

    // Independently: the surviving Ed25519 signature does not verify over the
    // bytes rebuilt from the REGISTERED set, because the set is inside them.
    const setIntact = { ...narrowed, signature: { ...narrowed.signature, required_algorithms: [...TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS] } };
    const second = await verifyTrustStageReceiptV2(setIntact, { trustedKeys: issuer.hybridPin });
    expect(second.valid).toBe(false);
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const tampered = {
      ...receipt,
      signature: {
        ...receipt.signature,
        signatures: receipt.signature.signatures.map((s) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: crypto.randomBytes(16).toString('base64url') } : s
        )),
      },
    };
    const result = await verifyTrustStageReceiptV2(tampered, { trustedKeys: issuer.hybridPin });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('receipt_signature_invalid');
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI pinned as the classical half is refused, never verified', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueraded = {
      ...receipt,
      signature: { ...receipt.signature, public_key: ed448PubB64u },
    };
    const pin = { [KEY_ID]: { public_key: ed448PubB64u, pq_public_key: issuer.hybridPin[KEY_ID].pq_public_key } };
    const result = await verifyTrustStageReceiptV2(masqueraded, { trustedKeys: pin });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_key_untrusted');
  });

  it('an absent ML-DSA backend is pq_backend_unavailable, never a pass on the Ed25519 leg', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const result = await verifyTrustStageReceiptV2(receipt, {
      trustedKeys: issuer.hybridPin,
      mldsaBackend: {},
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('pq_backend_unavailable');
  });

  it('a tampered payload breaks the recomputed digest before any signature is checked', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const tampered = { ...receipt, payload: { ...receipt.payload, stage_id: 'other-stage' } };
    const result = await verifyTrustStageReceiptV2(tampered, { trustedKeys: issuer.hybridPin });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_digest_mismatch');
  });

  it('expected-binding and expected-issuer pins still gate a cryptographically valid receipt', async () => {
    const issuer = issuerFixture();
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, keys: issuer.keys });
    const wrongBinding = await verifyTrustStageReceiptV2(receipt, {
      trustedKeys: issuer.hybridPin,
      expected: { stage_id: 'some-other-stage' },
    });
    expect(wrongBinding.reason).toBe('receipt_expected_binding_mismatch');
    const wrongIssuer = await verifyTrustStageReceiptV2(receipt, {
      trustedKeys: issuer.hybridPin,
      expectedIssuer: { ...CONTEXT, tenant: 'someone-else' },
    });
    expect(wrongIssuer.reason).toBe('receipt_expected_issuer_mismatch');
  });

  it('never throws on hostile input', async () => {
    for (const bad of [null, undefined, '', 42, [], { version: TRUST_STAGE_RECEIPT_V2_VERSION }]) {
      await expect(verifyTrustStageReceiptV2(bad as unknown, { trustedKeys: {} }))
        .resolves.toMatchObject({ valid: false });
    }
  });

  it('refuses to issue a receipt whose signSet signer returns an incomplete set', async () => {
    const issuer = issuerFixture();
    const signer = {
      publicKeys: issuer.hybridPin[KEY_ID],
      async signSet(bytes: Uint8Array | Buffer) {
        return [{ alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(bytes), issuer.ed.privateKey).toString('base64url') }];
      },
    };
    await expect(signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, signer }))
      .rejects.toThrow(/malformed signature set/);
  });

  it('accepts an injected signSet signer that supplies both legs', async () => {
    const issuer = issuerFixture();
    const pqSecret = issuer.keys.pq.secretKey as Uint8Array;
    const signer = {
      publicKeys: issuer.hybridPin[KEY_ID],
      async signSet(bytes: Uint8Array | Buffer) {
        const message = new Uint8Array(Buffer.from(bytes));
        return [
          { alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(message), issuer.ed.privateKey).toString('base64url') },
          { alg: 'ML-DSA-65', sig: Buffer.from(ml_dsa65.sign(message, pqSecret)).toString('base64url') },
        ];
      },
    };
    const receipt = await signTrustStageReceiptV2({ payload: payload(), context: CONTEXT, signer });
    const verified = await verifyTrustStageReceiptV2(receipt, { trustedKeys: issuer.hybridPin });
    expect(verified.valid).toBe(true);
  });
});
