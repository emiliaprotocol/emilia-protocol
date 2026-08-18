// SPDX-License-Identifier: Apache-2.0
//
// EP-ACTION-REMEDY-RECEIPT-v2 -- hostile matrix for the hybrid remedy receipt,
// plus the EP-GATE-REMEDY-PROGRAM-PROFILE-v2 state marker it can describe. New
// file, co-located under src/ so vitest exercises this package's TS source
// directly (no build step needed); the dist-backed
// packages/gate/remedy-program-receipt.test.js keeps covering v1 and is
// untouched.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import {
  ACTION_REMEDY_RECEIPT_VERSION,
  ACTION_REMEDY_RECEIPT_V2_VERSION,
  ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS,
  REMEDY_PROGRAM_PROFILE_V2_VERSION,
  expectedRemedyProgramReceiptBindings,
  expectedRemedyProgramReceiptV2Bindings,
  issueRemedyProgramReceipt,
  issueRemedyProgramReceiptV2,
  verifyRemedyProgramReceipt,
  verifyRemedyProgramReceiptV2,
  verifyRemedyProgramReceiptStatement,
} from './remedy-program-receipt.js';
import type { FipsPosture } from '@emilia-protocol/verify/fips-mode';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const HASH = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = (operation: string, character: string) => `caid:1:${operation}.1:jcs-sha256:${character.repeat(43)}`;

const CONTEXT = {
  issuer: 'emilia-gate-operator',
  tenant: 'tenant-a',
  environment: 'production',
  audience: 'remedy-auditor',
  key_id: 'remedy-key-1',
};

function outcomeEvidence() {
  return {
    evidence_id: 'remedy-outcome-evidence-1',
    evidence_digest: HASH('8'),
    remedy_operation_id: 'refund-op-1',
    remedy_action_digest: HASH('5'),
    destination_binding_digest: HASH('3'),
    units: 4_000,
    unit: 'USD-cent',
    outcome: 'executed',
    observed_at: '2026-07-21T18:28:00.000Z',
  };
}

function remedyAttempt(overrides: Record<string, unknown> = {}) {
  return {
    evidence_id: 'remedy-authorization-evidence-1',
    evidence_digest: HASH('7'),
    dispute_id: 'dispute-1',
    original_operation_id: 'payment-op-1',
    remedy_operation_id: 'refund-op-1',
    remedy_caid: CAID('payments.refund', 'B'),
    remedy_action_digest: HASH('5'),
    consequence_mode: 'receipt-program',
    capability_template_digest: HASH('2'),
    escrow_profile_digest: null,
    destination_binding_digest: HASH('3'),
    units: 4_000,
    unit: 'USD-cent',
    authorized_at: '2026-07-21T18:25:00.000Z',
    request_digest: HASH('6'),
    status: 'executed',
    claim_token_digest: HASH('9'),
    claimed_at: '2026-07-21T18:26:00.000Z',
    claim_request_digest: HASH('a'),
    outcome: 'executed',
    outcome_evidence: outcomeEvidence(),
    finalize_request_digest: HASH('b'),
    reconciliation: null,
    reconcile_request_digest: null,
    ...overrides,
  };
}

function remedyState(overrides: Record<string, unknown> = {}) {
  return {
    version: 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1',
    instance_id: 'remedy-case-v2-1',
    tenant_id: 'tenant-a',
    environment: 'production',
    audience: 'remedy-auditor',
    status: 'partially_remedied',
    revision: 5,
    created_at: '2026-07-21T18:00:00.000Z',
    updated_at: '2026-07-21T18:30:00.000Z',
    original: {
      caid: CAID('payments.capture', 'A'),
      action_digest: HASH('0'),
      operation_id: 'payment-op-1',
      consequence_mode: 'receipt-program',
      consequence_digest: HASH('1'),
      terminal_evidence_digest: HASH('4'),
      outcome: 'executed',
      occurred_at: '2026-07-21T18:10:00.000Z',
      evidence_digest: HASH('4'),
    },
    remedy_profile_digest: HASH('c'),
    destination_binding_digest: HASH('3'),
    max_remedy_units: 10_000,
    unit: 'USD-cent',
    remedied_units: 4_000,
    remaining_units: 6_000,
    used_evidence_ids: ['dispute-evidence-1', 'remedy-authorization-evidence-1', 'remedy-outcome-evidence-1'],
    used_evidence_digests: [HASH('d'), HASH('7'), HASH('8')],
    original_reconciliation: null,
    revocation: null,
    dispute: {
      dispute_id: 'dispute-1',
      evidence_id: 'dispute-evidence-1',
      evidence_digest: HASH('d'),
      challenger_id: 'buyer-1',
      requested_units: 10_000,
      opened_at: '2026-07-21T18:20:00.000Z',
      original_operation_id: 'payment-op-1',
      original_action_digest: HASH('0'),
      request_digest: HASH('e'),
    },
    active_remedy: null,
    remedies: [remedyAttempt()],
    resolution: null,
    create_request_digest: HASH('f'),
    ...overrides,
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
    hybridPin: { [CONTEXT.key_id]: { public_key: edPubB64u, pq_public_key: pqPubB64u } },
    classicalPin: { [CONTEXT.key_id]: edPubB64u },
  };
}

async function issued(state = remedyState()) {
  const issuer = issuerFixture();
  const receipt = await issueRemedyProgramReceiptV2(
    { state, remedyOperationId: 'refund-op-1' },
    { context: CONTEXT, keys: issuer.keys, allowEphemeralState: true },
  ) as any;
  const expected = expectedRemedyProgramReceiptV2Bindings(state, 'refund-op-1');
  return { issuer, receipt, state, expected };
}

function verifyOptions(fixture: Awaited<ReturnType<typeof issued>>, over: Record<string, unknown> = {}) {
  return {
    trustedKeys: fixture.issuer.hybridPin,
    expectedIssuer: CONTEXT,
    state: fixture.state,
    expected: fixture.expected,
    ...over,
  };
}

/** An ACTIVE posture with an undeclared Ed25519 boundary: a deterministic deny. */
const DENYING_POSTURE: FipsPosture = {
  version: 'EP-FIPS-MODE-v1',
  fips_status: 'active',
  fips_mode_active: true,
  openssl_version: '3.9.9',
  node_version: process.version,
  openssl_operational: true,
  ed25519_operational: true,
  ed25519_in_validated_boundary: null,
  mldsa_backend: '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)',
  mldsa_validated_module: false,
};

describe('EP-ACTION-REMEDY-RECEIPT-v2 hybrid remedy receipt', () => {
  it('valid v2 roundtrip: both legs verify under the pinned key pair', async () => {
    const fixture = await issued();
    expect(fixture.receipt.version).toBe(ACTION_REMEDY_RECEIPT_V2_VERSION);
    expect(fixture.receipt.signature.required_algorithms)
      .toEqual([...ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS]);
    expect(fixture.receipt.signature.signatures.map((s: any) => s.alg))
      .toEqual([...ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS]);

    const verified = await verifyRemedyProgramReceiptV2(fixture.receipt, verifyOptions(fixture));
    expect(verified.valid).toBe(true);
    expect(verified.reason).toBe('verified');
    expect(verified.payload!.semantics).toEqual({
      original_effect: 'immutable_fact',
      remedy_effect: 'compensating_action',
      rollback: false,
    });
  });

  it('a v2 receipt over an EP-GATE-REMEDY-PROGRAM-PROFILE-v2 state verifies, and the marker is committed', async () => {
    const state = remedyState({ version: REMEDY_PROGRAM_PROFILE_V2_VERSION });
    const fixture = await issued(state);
    expect((await verifyRemedyProgramReceiptV2(fixture.receipt, verifyOptions(fixture))).valid).toBe(true);
    // Swapping the marker on the presented state breaks the recomputed
    // state-snapshot digest, which is inside content_digest and the signature.
    const swapped = { ...state, version: 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1' };
    const result = await verifyRemedyProgramReceiptV2(fixture.receipt, verifyOptions(fixture, { state: swapped }));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_state_snapshot_mismatch');
  });

  it('the v1 receipt still refuses a v2-profile state snapshot', async () => {
    const keys = crypto.generateKeyPairSync('ed25519');
    await expect(issueRemedyProgramReceipt(
      { state: remedyState({ version: REMEDY_PROGRAM_PROFILE_V2_VERSION }), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, privateKey: keys.privateKey, allowEphemeralState: true },
    )).rejects.toThrow(/state snapshot is invalid/);
  });

  it('v1-refuses-v2: the SYNC v1 verifier refuses a v2 receipt structurally, never a crash', async () => {
    const fixture = await issued();
    // No await: verifyRemedyProgramReceipt remains synchronous and untouched.
    const result = verifyRemedyProgramReceipt(fixture.receipt, {
      trustedKeys: fixture.issuer.classicalPin,
      expectedIssuer: CONTEXT,
      state: fixture.state,
      expected: fixture.expected,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_structure_invalid');
  });

  it('the router keeps the exact v1 verdict for a v1 receipt and hybrid-checks a v2 one', async () => {
    const keys = crypto.generateKeyPairSync('ed25519');
    const state = remedyState();
    const v1 = await issueRemedyProgramReceipt(
      { state, remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, privateKey: keys.privateKey, allowEphemeralState: true },
    );
    expect(v1.version).toBe(ACTION_REMEDY_RECEIPT_VERSION);
    const routedV1 = await verifyRemedyProgramReceiptStatement(v1, {
      trustedKeys: { [CONTEXT.key_id]: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') },
      expectedIssuer: CONTEXT,
      state,
      expected: expectedRemedyProgramReceiptBindings(state, 'refund-op-1'),
    });
    expect(routedV1.valid).toBe(true);

    const fixture = await issued();
    expect((await verifyRemedyProgramReceiptStatement(fixture.receipt, verifyOptions(fixture))).valid).toBe(true);
  });

  it('a key id pinned WITHOUT the ML-DSA half never satisfies a v2 pin', async () => {
    const fixture = await issued();
    const result = await verifyRemedyProgramReceiptV2(
      fixture.receipt, verifyOptions(fixture, { trustedKeys: fixture.issuer.classicalPin }),
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_key_untrusted');
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const fixture = await issued();
    const stripped = {
      ...fixture.receipt,
      signature: {
        ...fixture.receipt.signature,
        signatures: fixture.receipt.signature.signatures.filter((s: any) => s.alg !== 'ML-DSA-65'),
      },
    };
    const result = await verifyRemedyProgramReceiptV2(stripped, verifyOptions(fixture));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_signature_leg_missing');
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] is refused structurally AND cryptographically', async () => {
    const fixture = await issued();
    const narrowed = {
      ...fixture.receipt,
      signature: {
        ...fixture.receipt.signature,
        required_algorithms: ['Ed25519'],
        signatures: fixture.receipt.signature.signatures.filter((s: any) => s.alg === 'Ed25519'),
      },
    };
    expect((await verifyRemedyProgramReceiptV2(narrowed, verifyOptions(fixture))).reason)
      .toBe('receipt_algorithm_set_unsupported');
    const setIntact = {
      ...narrowed,
      signature: {
        ...narrowed.signature,
        required_algorithms: [...ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS],
      },
    };
    expect((await verifyRemedyProgramReceiptV2(setIntact, verifyOptions(fixture))).reason)
      .toBe('receipt_signature_leg_missing');
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const fixture = await issued();
    const tampered = {
      ...fixture.receipt,
      signature: {
        ...fixture.receipt.signature,
        signatures: fixture.receipt.signature.signatures.map((s: any) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: crypto.randomBytes(16).toString('base64url') } : s
        )),
      },
    };
    const result = await verifyRemedyProgramReceiptV2(tampered, verifyOptions(fixture));
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('receipt_signature_invalid');
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI pinned as the classical half is refused, never verified', async () => {
    const fixture = await issued();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueraded = {
      ...fixture.receipt,
      signature: { ...fixture.receipt.signature, public_key: ed448PubB64u },
    };
    const pin = {
      [CONTEXT.key_id]: {
        public_key: ed448PubB64u,
        pq_public_key: fixture.issuer.hybridPin[CONTEXT.key_id].pq_public_key,
      },
    };
    const result = await verifyRemedyProgramReceiptV2(masqueraded, verifyOptions(fixture, { trustedKeys: pin }));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_key_untrusted');
  });

  it('an absent ML-DSA backend is pq_backend_unavailable, never a pass on the Ed25519 leg', async () => {
    const fixture = await issued();
    const result = await verifyRemedyProgramReceiptV2(
      fixture.receipt, verifyOptions(fixture, { mldsaBackend: {} }),
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('pq_backend_unavailable');
  });

  it('a tampered payload breaks the recomputed content digest before any signature is checked', async () => {
    const fixture = await issued();
    const tampered = {
      ...fixture.receipt,
      payload: {
        ...fixture.receipt.payload,
        remedy: { ...fixture.receipt.payload.remedy, units: 9_999 },
      },
    };
    const result = await verifyRemedyProgramReceiptV2(tampered, verifyOptions(fixture));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('receipt_content_digest_mismatch');
  });

  it('never throws on hostile input', async () => {
    for (const bad of [null, undefined, '', 42, [], { version: ACTION_REMEDY_RECEIPT_V2_VERSION }]) {
      await expect(verifyRemedyProgramReceiptV2(bad, { trustedKeys: {} }))
        .resolves.toMatchObject({ valid: false });
      await expect(verifyRemedyProgramReceiptStatement(bad, { trustedKeys: {} }))
        .resolves.toMatchObject({ valid: false });
    }
  });
});

describe('EP-ACTION-REMEDY-RECEIPT-v2 FIPS consult and custody gates', () => {
  it('with no fipsPosture configured, issuance runs exactly as before the option existed', async () => {
    const fixture = await issued();
    expect(fixture.receipt.signature.profile).toBe(ACTION_REMEDY_RECEIPT_V2_VERSION);
  });

  it('a denied FIPS policy refuses issuance BEFORE the signer runs, named reason, never a silent sign', async () => {
    const issuer = issuerFixture();
    let signCalls = 0;
    const signer = {
      keyId: CONTEXT.key_id,
      custody: 'software',
      publicKeys: issuer.hybridPin[CONTEXT.key_id],
      async signSet() {
        signCalls += 1;
        return [];
      },
    };
    await expect(issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, signer, allowEphemeralState: true, fipsPosture: DENYING_POSTURE },
    )).rejects.toThrow(/fips_policy_denied:Ed25519:ed25519_boundary_undeclared/);
    expect(signCalls).toBe(0);
  });

  it('an inactive posture (the normal case) permits BOTH legs with no acknowledgment required', async () => {
    const issuer = issuerFixture();
    const inactive: FipsPosture = { ...DENYING_POSTURE, fips_status: 'inactive', fips_mode_active: false };
    const receipt = await issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, keys: issuer.keys, allowEphemeralState: true, fipsPosture: inactive },
    );
    expect(receipt.version).toBe(ACTION_REMEDY_RECEIPT_V2_VERSION);
  });

  it('an ACTIVE posture refuses the ML-DSA leg until the unvalidated implementation is acknowledged', async () => {
    const issuer = issuerFixture();
    const active: FipsPosture = { ...DENYING_POSTURE, ed25519_in_validated_boundary: true };
    await expect(issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, keys: issuer.keys, allowEphemeralState: true, fipsPosture: active },
    )).rejects.toThrow(/fips_policy_denied:ML-DSA-65:mldsa_implementation_unvalidated/);

    const receipt = await issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      {
        context: CONTEXT,
        keys: issuer.keys,
        allowEphemeralState: true,
        fipsPosture: active,
        allowUnvalidatedMldsa: true,
      },
    );
    expect(receipt.version).toBe(ACTION_REMEDY_RECEIPT_V2_VERSION);
  });

  it('local keys without the ephemeral opt-in are refused, and a software signSet signer is refused in production mode', async () => {
    const issuer = issuerFixture();
    await expect(issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, keys: issuer.keys },
    )).rejects.toThrow(/requires an external signSet signer/);

    const signer = {
      keyId: CONTEXT.key_id,
      custody: 'software',
      publicKeys: issuer.hybridPin[CONTEXT.key_id],
      async signSet() { return []; },
    };
    await expect(issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, signer },
    )).rejects.toThrow(/custody must be kms or hsm/);
  });

  it('an injected signSet signer that supplies both legs issues a verifiable receipt', async () => {
    const issuer = issuerFixture();
    const pqSecret = issuer.keys.pq.secretKey as Uint8Array;
    const signer = {
      keyId: CONTEXT.key_id,
      custody: 'hsm',
      publicKeys: issuer.hybridPin[CONTEXT.key_id],
      async signSet(bytes: Uint8Array | Buffer) {
        const message = new Uint8Array(Buffer.from(bytes));
        return [
          { alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(message), issuer.ed.privateKey).toString('base64url') },
          { alg: 'ML-DSA-65', sig: Buffer.from(ml_dsa65.sign(message, pqSecret)).toString('base64url') },
        ];
      },
    };
    const state = remedyState();
    const receipt = await issueRemedyProgramReceiptV2(
      { state, remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, signer },
    );
    const verified = await verifyRemedyProgramReceiptV2(receipt, {
      trustedKeys: issuer.hybridPin,
      expectedIssuer: CONTEXT,
      state,
      expected: expectedRemedyProgramReceiptBindings(state, 'refund-op-1'),
    });
    expect(verified.valid).toBe(true);
  });

  it('an injected signer returning an incomplete set refuses issuance, never emits a one-leg receipt', async () => {
    const issuer = issuerFixture();
    const signer = {
      keyId: CONTEXT.key_id,
      custody: 'hsm',
      publicKeys: issuer.hybridPin[CONTEXT.key_id],
      async signSet(bytes: Uint8Array | Buffer) {
        return [{
          alg: 'Ed25519',
          sig: crypto.sign(null, Buffer.from(bytes), issuer.ed.privateKey).toString('base64url'),
        }];
      },
    };
    await expect(issueRemedyProgramReceiptV2(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, signer },
    )).rejects.toThrow(/malformed signature set/);
  });
});
