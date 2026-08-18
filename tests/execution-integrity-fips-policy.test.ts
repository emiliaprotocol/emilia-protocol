/**
 * EP-EXECUTION-INTEGRITY-v1 -- FIPS operation-policy consult wired into
 * bindExecution()'s executor signing call (lib/execution/integrity.ts).
 *
 * checkOperationPolicy() (packages/verify/src/fips-mode.ts, EP-FIPS-MODE-v1)
 * previously had zero production call sites. This file pins the two jobs:
 *
 *  1. THE REGRESSION. With no FIPS posture configured (EP_FIPS_REQUIRED unset
 *     or false), the consult is a complete no-op -- even a posture object
 *     that would otherwise DENY has no effect -- and bindExecution() produces
 *     the same, independently VERIFIABLE attestation as before this consult
 *     existed (checked with verifyExecutionIntegrity(), never the module's
 *     own signing helper).
 *
 *  2. THE CONSULT. With EP_FIPS_REQUIRED=true, an injected posture that the
 *     real (unmocked) checkOperationPolicy() denies causes bindExecution() to
 *     refuse with a named reason BEFORE the executor's signer.sign() is ever
 *     invoked.
 *
 * The FIPS postures below are plain data objects fed through the REAL
 * checkOperationPolicy()/getFipsPosture() -- nothing about fips-mode.ts
 * itself is mocked.
 */

import { describe, it, expect, afterEach } from 'vitest';
import crypto from 'node:crypto';

import {
  bindExecution,
  verifyExecutionIntegrity,
  consultFipsIssuancePolicy,
} from '../lib/execution/integrity.js';
import { actionHash, generateEd25519KeyPair } from '../packages/issue/index.js';
import { checkOperationPolicy } from '../packages/verify/fips-mode.js';

const APPROVED_ACTION = {
  action_type: 'payment.release',
  policy_id: 'policy.wires',
  initiator: 'ep:agent:worker',
  target_resource_id: 'wire/fips-1',
  amount: 100,
  currency: 'USD',
};
const APPROVED_HASH = actionHash(APPROVED_ACTION);
const RECEIPT = { action_hash: APPROVED_HASH, receipt_id: 'ep:receipt:fips-policy-test#1' };

const EXECUTOR_ID = 'ep:executor:fips-policy-test';
const executorKp = generateEd25519KeyPair();
const pinnedKeys = { [EXECUTOR_ID]: { public_key: executorKp.publicKeyB64u } };

function executorSigner(kp = executorKp) {
  return {
    executorId: EXECUTOR_ID,
    publicKeyB64u: kp.publicKeyB64u,
    sign: (bytes) => crypto.sign(null, bytes, kp.privateKey).toString('base64url'),
  };
}

// ---------------------------------------------------------------------------
// Posture fixtures -- same shape/semantics as the commit-side consult tests.
// ---------------------------------------------------------------------------

const INACTIVE_POSTURE = Object.freeze({
  version: 'EP-FIPS-MODE-v1',
  fips_status: 'inactive',
  fips_mode_active: false,
  openssl_version: null,
  node_version: null,
  openssl_operational: null,
  ed25519_operational: null,
  ed25519_in_validated_boundary: null,
  mldsa_backend: '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)',
  mldsa_validated_module: false,
});

/** Active FIPS mode, live OpenSSL, Ed25519 works but the boundary is declared OUTSIDE the certificate. */
const DENY_ED25519_POSTURE = Object.freeze({
  ...INACTIVE_POSTURE,
  fips_status: 'active',
  fips_mode_active: true,
  openssl_operational: true,
  ed25519_operational: true,
  ed25519_in_validated_boundary: false,
});

const PERMIT_ED25519_POSTURE = Object.freeze({
  ...DENY_ED25519_POSTURE,
  ed25519_in_validated_boundary: true,
});

describe('sanity: posture fixtures drive the real checkOperationPolicy()', () => {
  it('DENY_ED25519_POSTURE is refused with the boundary reason', () => {
    const r = checkOperationPolicy('Ed25519', DENY_ED25519_POSTURE as any);
    expect(r.permitted).toBe(false);
    expect(r.reason).toBe('ed25519_outside_validated_boundary');
  });
  it('PERMIT_ED25519_POSTURE is permitted', () => {
    expect(checkOperationPolicy('Ed25519', PERMIT_ED25519_POSTURE as any).permitted).toBe(true);
  });
});

function enableFipsRequired() {
  process.env.EP_FIPS_REQUIRED = 'true';
}

afterEach(() => {
  delete process.env.EP_FIPS_REQUIRED;
});

// ===========================================================================
// 1. consultFipsIssuancePolicy unit behavior
// ===========================================================================

describe('lib/execution/integrity.ts consultFipsIssuancePolicy (unit)', () => {
  it('is a no-op with no posture configured, even given a posture that would deny', () => {
    delete process.env.EP_FIPS_REQUIRED;
    expect(() => consultFipsIssuancePolicy('Ed25519', DENY_ED25519_POSTURE as any)).not.toThrow();
  });

  it('permits silently when configured and the policy allows', () => {
    enableFipsRequired();
    expect(() => consultFipsIssuancePolicy('Ed25519', PERMIT_ED25519_POSTURE as any)).not.toThrow();
  });

  it('refuses with a named reason when configured and the policy denies', () => {
    enableFipsRequired();
    try {
      consultFipsIssuancePolicy('Ed25519', DENY_ED25519_POSTURE as any);
      throw new Error('expected consultFipsIssuancePolicy to throw');
    } catch (e: any) {
      expect(e.message).toContain('fips_policy_denied');
      expect(e.message).toContain('Ed25519');
      expect(e.message).toContain('ed25519_outside_validated_boundary');
    }
  });
});

// ===========================================================================
// 2. bindExecution() end-to-end
// ===========================================================================

describe('bindExecution(): byte-identical when no FIPS posture is configured', () => {
  it('produces a normally-verifiable attestation even given an unevaluated denying posture', () => {
    delete process.env.EP_FIPS_REQUIRED;
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer: executorSigner(),
      // Even though this posture would deny Ed25519, the consult never runs
      // because EP_FIPS_REQUIRED is unset -- proving the no-op gate end to end.
      fipsPosture: DENY_ED25519_POSTURE as any,
    });
    const result = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys });
    expect(result.valid).toBe(true);
    expect(result.binding_status).toBe('match');
  });

  it('EP_FIPS_REQUIRED=true alone (no active FIPS runtime) does not change issuance', () => {
    // The consult runs (fipsRequired is true), but with no injected posture it
    // reads the live process posture, which is 'inactive' on this test host --
    // permitted unconditionally for Ed25519 -- proving the flag alone is inert
    // on an ordinary, non-FIPS Node process.
    enableFipsRequired();
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer: executorSigner(),
    });
    const result = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys });
    expect(result.valid).toBe(true);
  });
});

describe('bindExecution(): FIPS consult runs BEFORE signer.sign()', () => {
  it('a denied policy refuses BEFORE signer.sign() is ever called, naming the reason', () => {
    enableFipsRequired();
    let signCalled = false;
    const signer = {
      executorId: EXECUTOR_ID,
      publicKeyB64u: executorKp.publicKeyB64u,
      sign: (bytes) => { signCalled = true; return crypto.sign(null, bytes, executorKp.privateKey).toString('base64url'); },
    };
    expect(() => bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer,
      fipsPosture: DENY_ED25519_POSTURE as any,
    })).toThrow(/fips_policy_denied/);
    expect(signCalled).toBe(false);
  });

  it('an allowed policy proceeds to sign normally, and the attestation verifies', () => {
    enableFipsRequired();
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: false,
      signer: executorSigner(),
      fipsPosture: PERMIT_ED25519_POSTURE as any,
    });
    const result = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys });
    expect(result.valid).toBe(true);
  });
});
