// SPDX-License-Identifier: Apache-2.0
//
// EP-RECEIPT-PROGRAM-CERTIFICATE-v1 -- opt-in FIPS operation-policy consult
// at the certificate signer call site (createReceiptProgramKernel's
// issueCertificate, receipt-program.ts ~:400). New file under src/ so vitest
// exercises this package's TS source directly; the dist-backed
// packages/gate/receipt-program.test.js keeps covering the certificate
// artifact itself and is untouched.
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import { computeCaid } from '../../../caid/impl/js/caid.mjs';
import {
  createEg1Harness,
  createGate,
  createMemoryCapabilityStore,
  createRuntimeMonitor,
  mintCapabilityReceipt,
  CAPABILITY_CAID_SCOPE_PROFILE,
  createDefaultActionRiskManifest,
} from './index.js';
import { createReceiptProgramKernel } from './receipt-program.js';
import type { FipsPosture } from '@emilia-protocol/verify/fips-mode';

const NOW = Date.parse('2026-08-17T22:00:00.000Z');
const CERTIFICATE_CONTEXT = Object.freeze({
  issuer: 'emilia-reference-operator',
  tenant: 'tenant_receipt_program_fips_test',
  environment: 'test',
  audience: 'receipt-program-verifier',
  key_id: 'local-dev',
});
const SELECTOR = Object.freeze({ protocol: 'mcp', tool: 'release_payment' });
const BENEFICIARY = `sha256:${'a'.repeat(64)}`;
const OBSERVED_ACTION = Object.freeze({
  action_type: 'payment.release',
  amount: '40.00',
  amount_usd: 40,
  currency: 'USD',
  beneficiary_account: BENEFICIARY,
  beneficiary_account_hash: BENEFICIARY,
  payment_instruction_id: 'pi_receipt_program_fips_1',
});
const CAID_DEFINITIONS = Object.freeze([{
  action_type: 'payment.release.1',
  required_fields: [
    { name: 'amount', type: 'amount-string' },
    { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
    { name: 'beneficiary_account', type: 'digest' },
    { name: 'payment_instruction_id', type: 'string' },
  ],
  optional_fields: [],
}]);

function caidAction(action: any) {
  return {
    action_type: 'payment.release.1',
    amount: action.amount,
    currency: action.currency,
    beneficiary_account: action.beneficiary_account,
    payment_instruction_id: action.payment_instruction_id,
  };
}
function resolveCaid(action: any) {
  const result = computeCaid(caidAction(action), { suite: 'jcs-sha256', definitions: CAID_DEFINITIONS });
  if (!result.caid) throw new Error(result.refusals.join(','));
  return result.caid;
}

/** Same shape as receipt-program.test.js's fixture(), trimmed to what this suite needs. */
function fixture({ fipsPosture }: { fipsPosture?: FipsPosture } = {}) {
  const action = OBSERVED_ACTION;
  const harness = createEg1Harness({ action, now: () => NOW, idPrefix: 'receipt-program-fips' });
  const capabilityIssuer = generateKeyPairSync('ed25519');
  const capabilityIssuerPublicKey = capabilityIssuer.publicKey
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  const certificateSigner = generateKeyPairSync('ed25519');
  const caid = resolveCaid(action);
  const baseReceipt = harness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });
  const capability = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: capabilityIssuer.privateKey,
    budget: { amount: 100, currency: 'USD' },
    expiry: NOW + 60_000,
    revocationMode: 'direct',
    secret: Buffer.alloc(32, 9),
    capabilityId: 'cap_receipt_program_fips_1',
    scope: { profile: CAPABILITY_CAID_SCOPE_PROFILE, operation_id_field: 'payment_instruction_id', caids: [caid] },
  });
  const capabilityStore = createMemoryCapabilityStore();
  capabilityStore.registerCapability(capability.capabilityReceipt);
  const runtimeMonitor = createRuntimeMonitor({ now: () => NOW });
  const gate = createGate({
    manifest: createDefaultActionRiskManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    capabilityStore,
    capabilityTrustedIssuerKeys: [capabilityIssuerPublicKey],
    capabilityCaidResolver: resolveCaid,
    runtimeMonitor,
    allowEphemeralStore: true,
    now: () => NOW,
  });
  const kernel = createReceiptProgramKernel({
    gate,
    resolveCaid,
    operationIdField: 'payment_instruction_id',
    certificatePrivateKey: certificateSigner.privateKey,
    certificateContext: CERTIFICATE_CONTEXT,
    effectTimeoutMs: 1000,
    allowEphemeralState: true,
    now: () => NOW,
    ...(fipsPosture !== undefined ? { fipsPosture } : {}),
  });
  return {
    kernel,
    caid,
    capability,
    action,
  };
}

function request(f: ReturnType<typeof fixture>, overrides: Record<string, unknown> = {}) {
  return {
    programId: 'delegated-payment-reference',
    instructionId: 'release-milestone-fips-1',
    caid: f.caid,
    selector: SELECTOR,
    observedAction: f.action,
    capability: {
      capabilityReceipt: f.capability.capabilityReceipt,
      secret: f.capability.secret,
      action: { amount: (f.action as any).amount_usd, currency: (f.action as any).currency },
      operationId: (f.action as any).payment_instruction_id,
    },
    ...overrides,
  };
}

/** A synthetic ACTIVE FIPS posture with an undeclared Ed25519 boundary --
 * checkOperationPolicy refuses this deterministically (`ed25519_boundary_undeclared`)
 * without depending on the real process's OpenSSL FIPS state. */
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

describe('EP-RECEIPT-PROGRAM-CERTIFICATE-v1 opt-in FIPS consult', () => {
  it('with no fipsPosture configured, issuance succeeds exactly as before (byte-identical default)', async () => {
    const f = fixture();
    let effects = 0;
    const out = await f.kernel.run(request(f), async (_authorization: any, operation: any) => {
      effects += 1;
      return {
        provider: 'simulated-custodian',
        provider_operation_id: operation.providerIdempotencyKey,
        status: 'settled',
      };
    });
    expect(out.ok).toBe(true);
    expect(effects).toBe(1);
    expect(out.certificate.signature.algorithm).toBe('Ed25519');
  });

  it('a denied FIPS policy refuses issuance BEFORE the signer runs, named reason, never a silent sign', async () => {
    const f = fixture({ fipsPosture: DENYING_POSTURE });
    let effects = 0;
    const out = await f.kernel.run(request(f), async (_authorization: any, operation: any) => {
      effects += 1;
      return {
        provider: 'simulated-custodian',
        provider_operation_id: operation.providerIdempotencyKey,
        status: 'settled',
      };
    });
    expect(out.ok).toBe(false);
    expect(out.reason).toBe('fips_policy_denied:ed25519_boundary_undeclared');
    expect(out.certificate).toBeNull();
    // The provider effect itself may or may not have run depending on Gate's
    // own ordering, but no certificate was ever produced under the denied
    // posture -- that is the property this test protects.
    expect(out.certificate).toBe(null);
  });

  it('passing fipsPosture as a per-request field is refused as a runtime trust-field override attempt', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f, { fipsPosture: DENYING_POSTURE } as any), async () => ({
      provider: 'simulated-custodian', status: 'settled',
    }));
    expect(out.ok).toBe(false);
  });
});
