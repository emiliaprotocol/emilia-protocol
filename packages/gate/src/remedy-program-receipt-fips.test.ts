// SPDX-License-Identifier: Apache-2.0
//
// EP-ACTION-REMEDY-RECEIPT-v1 -- opt-in FIPS operation-policy consult at the
// receipt signer call site (issueRemedyProgramReceipt,
// remedy-program-receipt.ts ~:735). New file under src/ so vitest exercises
// this package's TS source directly; the dist-backed
// packages/gate/remedy-program-receipt.test.js keeps covering the receipt
// artifact itself and is untouched.
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import { issueRemedyProgramReceipt } from './remedy-program-receipt.js';
import type { FipsPosture } from '@emilia-protocol/verify/fips-mode';

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
    instance_id: 'remedy-case-fips-1',
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

/** Same deterministic denial as the receipt-program FIPS test: an ACTIVE
 * posture with an undeclared Ed25519 boundary. */
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

describe('EP-ACTION-REMEDY-RECEIPT-v1 opt-in FIPS consult', () => {
  it('with no fipsPosture configured, issuance succeeds exactly as before (byte-identical default)', async () => {
    const keys = generateKeyPairSync('ed25519');
    const receipt = await issueRemedyProgramReceipt(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, privateKey: keys.privateKey, allowEphemeralState: true },
    );
    expect(receipt.version).toBe('EP-ACTION-REMEDY-RECEIPT-v1');
    expect(receipt.signature.algorithm).toBe('Ed25519');
  });

  it('a denied FIPS policy refuses issuance BEFORE the signer runs, named reason, never a silent sign', async () => {
    const keys = generateKeyPairSync('ed25519');
    let signCalls = 0;
    const signer = {
      keyId: CONTEXT.key_id,
      publicKey: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      custody: 'software',
      async sign(bytes: Buffer) {
        signCalls += 1;
        const crypto = await import('node:crypto');
        return crypto.sign(null, bytes, keys.privateKey);
      },
    };
    await expect(issueRemedyProgramReceipt(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, signer, allowEphemeralState: true, fipsPosture: DENYING_POSTURE },
    )).rejects.toThrow(/fips_policy_denied:ed25519_boundary_undeclared/);
    expect(signCalls).toBe(0);
  });

  it('an inactive FIPS posture (the normal case) permits issuance even when fipsPosture is supplied', async () => {
    const keys = generateKeyPairSync('ed25519');
    const inactive: FipsPosture = { ...DENYING_POSTURE, fips_status: 'inactive', fips_mode_active: false };
    const receipt = await issueRemedyProgramReceipt(
      { state: remedyState(), remedyOperationId: 'refund-op-1' },
      { context: CONTEXT, privateKey: keys.privateKey, allowEphemeralState: true, fipsPosture: inactive },
    );
    expect(receipt.signature.algorithm).toBe('Ed25519');
  });
});
