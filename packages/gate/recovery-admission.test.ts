// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
  RECOVERY_CAPABILITY_STATUS_VERSION,
  RECOVERY_CAPABILITY_VERSION,
  RECOVERY_RESERVATION_STATUS_VERSION,
  evaluateRecoveryAdmission,
  recoveryCapabilityDigest,
  signRecoveryCapability,
  verifyRecoveryCapability,
} from './recovery-admission.js';
import { signRiskBody } from './dist/reliance-risk-crypto.js';

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => (
  `caid:1:operations.recovery.1:jcs-sha256:${character.repeat(43)}`
);
const NOW = '2026-08-03T20:00:00.000Z';
const ACTION_EXPIRES = '2026-08-03T20:30:00.000Z';
const CAPABILITY_EXPIRES = '2026-08-03T21:00:00.000Z';

function keyMaterial() {
  const pair = generateKeyPairSync('ed25519');
  return {
    signer: {
      issuer_id: 'rp:example-operations',
      key_id: 'key:rp:recovery-capability:v1',
      private_key: pair.privateKey,
    },
    trusted_keys: {
      'key:rp:recovery-capability:v1': {
        issuer_id: 'rp:example-operations',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
  };
}

function baseInput() {
  return {
    capability_id: 'recovery-capability:operation:01',
    admission_id: 'admission:operation:01',
    admission_snapshot_digest: D('0'),
    tenant_id: 'tenant:example',
    audience: 'gate:production:01',
    action_caid: C('A'),
    action_digest: D('a'),
    action_capability_expires_at: ACTION_EXPIRES,
    provider_id: 'provider:payments:01',
    account_digest: D('2'),
    environment_digest: D('3'),
    operation_id: 'operation:payment:01',
    issuer_digest: D('4'),
    trust_epoch_digest: D('5'),
    config_epoch_digest: D('6'),
    adapter_id: 'adapter:payments:primary',
    adapter_digest: D('7'),
    resource_set_digest: D('8'),
    issued_at: '2026-08-03T19:55:00.000Z',
    valid_from: NOW,
    expires_at: CAPABILITY_EXPIRES,
  };
}

function localInput() {
  return {
    ...baseInput(),
    mode: 'LOCAL_ATOMIC' as const,
    recovery: {
      scope: 'INTRA_TRANSACTION_ONLY' as const,
      state_domain_digest: D('b'),
      adapter_id: 'adapter:payments:primary',
      adapter_digest: baseInput().adapter_digest,
      max_transaction_ms: 5_000,
    },
  };
}

function reservedInput() {
  return {
    ...baseInput(),
    mode: 'RESERVED_COMPENSATION' as const,
    recovery: {
      scope: 'RESERVED_CAPACITY_ONLY' as const,
      compensation_admission: 'FRESH_SEPARATE_ACTION_REQUIRED' as const,
      remedy_caid: C('R'),
      remedy_action_digest: D('d'),
      destination_digest: D('e'),
      authority_digest: D('f'),
      reservation_digest: D('1'),
      units: 25,
      unit: 'minor-currency-unit',
      available_until: ACTION_EXPIRES,
    },
  };
}

function irreversibleInput() {
  return {
    ...baseInput(),
    mode: 'IRREVERSIBLE' as const,
    recovery: null,
  };
}

function verificationContext(
  material: ReturnType<typeof keyMaterial>,
  input: ReturnType<typeof localInput>
    | ReturnType<typeof reservedInput>
    | ReturnType<typeof irreversibleInput> = localInput(),
) {
  return {
    trusted_keys: material.trusted_keys,
    expected_policy: {
      capability_id: input.capability_id,
      admission_id: input.admission_id,
      admission_snapshot_digest: input.admission_snapshot_digest,
      mode: input.mode,
      recovery: structuredClone(input.recovery),
      tenant_id: input.tenant_id,
      audience: input.audience,
      action_caid: input.action_caid,
      action_digest: input.action_digest,
      action_capability_expires_at: input.action_capability_expires_at,
      provider_id: input.provider_id,
      account_digest: input.account_digest,
      environment_digest: input.environment_digest,
      operation_id: input.operation_id,
      issuer_id: material.signer.issuer_id,
      issuer_digest: input.issuer_digest,
      trust_epoch_digest: input.trust_epoch_digest,
      config_epoch_digest: input.config_epoch_digest,
      adapter_id: input.adapter_id,
      adapter_digest: input.adapter_digest,
      resource_set_digest: input.resource_set_digest,
    },
    now: NOW,
  };
}

type ResolverInput = Readonly<{
  capability: Readonly<Record<string, any>>;
  capability_digest: string;
  issuer_id: string;
  admission_at: string;
  action_capability_expires_at: string;
}>;

function currentStatus(input: ResolverInput, overrides: Record<string, unknown> = {}) {
  return {
    '@version': RECOVERY_CAPABILITY_STATUS_VERSION,
    capability_id: input.capability.capability_id,
    capability_digest: input.capability_digest,
    tenant_id: input.capability.tenant_id,
    audience: input.capability.audience,
    action_caid: input.capability.action_caid,
    action_digest: input.capability.action_digest,
    provider_id: input.capability.provider_id,
    adapter_id: input.capability.adapter_id,
    issuer_id: input.issuer_id,
    status: 'CURRENT',
    observed_at: NOW,
    valid_from: NOW,
    valid_until: ACTION_EXPIRES,
    ...overrides,
  };
}

function reservationStatus(input: ResolverInput, overrides: Record<string, unknown> = {}) {
  const recovery = input.capability.recovery;
  return {
    '@version': RECOVERY_RESERVATION_STATUS_VERSION,
    capability_id: input.capability.capability_id,
    capability_digest: input.capability_digest,
    tenant_id: input.capability.tenant_id,
    audience: input.capability.audience,
    action_caid: input.capability.action_caid,
    action_digest: input.capability.action_digest,
    provider_id: input.capability.provider_id,
    adapter_id: input.capability.adapter_id,
    reservation_digest: recovery.reservation_digest,
    remedy_caid: recovery.remedy_caid,
    remedy_action_digest: recovery.remedy_action_digest,
    destination_digest: recovery.destination_digest,
    authority_digest: recovery.authority_digest,
    units: recovery.units,
    unit: recovery.unit,
    status: 'RESERVED',
    observed_at: NOW,
    valid_from: NOW,
    available_until: recovery.available_until,
    ...overrides,
  };
}

test('LOCAL_ATOMIC is signed, pinned, current, and limited to the same transaction', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);

  assert.equal(artifact['@version'], RECOVERY_CAPABILITY_VERSION);
  assert.equal(artifact.claim_boundary, RECOVERY_CAPABILITY_CLAIM_BOUNDARY);
  assert.equal(artifact.admission_id, localInput().admission_id);
  assert.equal(
    artifact.admission_snapshot_digest,
    localInput().admission_snapshot_digest,
  );
  assert.equal(artifact.recovery.adapter_id, artifact.adapter_id);
  assert.equal(artifact.proof.algorithm, 'Ed25519');

  const verified = verifyRecoveryCapability(artifact, verificationContext(material));
  assert.equal(verified.accepted, true);
  assert.equal(verified.verified, true);
  assert.equal(verified.capability_digest, recoveryCapabilityDigest(artifact));
  assert.equal(verified.capability?.mode, 'LOCAL_ATOMIC');
  assert.equal(Object.isFrozen(verified.capability), true);
  assert.equal(Object.isFrozen(verified.capability?.recovery), true);

  let resolved = 0;
  const decision = await evaluateRecoveryAdmission(
    artifact,
    verificationContext(material),
    {
      current_status_resolver(input: ResolverInput) {
        resolved += 1;
        assert.equal(Object.isFrozen(input), true);
        assert.equal(Object.isFrozen(input.capability), true);
        return currentStatus(input);
      },
    },
  );
  assert.equal(resolved, 1);
  assert.equal(decision.recovery_route_accepted, true);
  assert.equal(decision.route, 'LOCAL_ATOMIC');
  assert.equal(decision.reason, null);
  assert.equal(decision.scope, 'INTRA_TRANSACTION_ONLY');
  assert.equal(decision.retry_permitted, false);
  assert.equal(decision.fresh_action_admission_required, false);
  assert.equal(decision.reservation, null);
});

test('RESERVED_COMPENSATION routes only with exact capacity and requires fresh action admission', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(reservedInput(), material.signer);
  const decision = await evaluateRecoveryAdmission(
    artifact,
    verificationContext(material, reservedInput()),
    {
      current_status_resolver: (input: ResolverInput) => currentStatus(input),
      reservation_verifier: (input: ResolverInput) => reservationStatus(input),
    },
  );

  assert.equal(decision.recovery_route_accepted, true);
  assert.equal(decision.route, 'RESERVED_COMPENSATION');
  assert.equal(decision.scope, 'RESERVED_CAPACITY_ONLY');
  assert.equal(decision.retry_permitted, false);
  assert.equal(decision.fresh_action_admission_required, true);
  assert.equal(decision.reservation?.reservation_digest, reservedInput().recovery.reservation_digest);
  assert.equal(decision.reservation?.available_until, ACTION_EXPIRES);
});

test('IRREVERSIBLE has null recovery and always routes to fresh authority', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(irreversibleInput(), material.signer);
  let statusCalls = 0;
  let reservationCalls = 0;
  const decision = await evaluateRecoveryAdmission(
    artifact,
    verificationContext(material, irreversibleInput()),
    {
      current_status_resolver(input: ResolverInput) {
        statusCalls += 1;
        return currentStatus(input);
      },
      // Unknown or presenter-selected callbacks are not accepted for this mode.
    },
  );

  assert.equal(artifact.recovery, null);
  assert.equal(statusCalls, 1);
  assert.equal(reservationCalls, 0);
  assert.equal(decision.recovery_route_accepted, false);
  assert.equal(decision.route, 'AUTHORITY_REQUIRED');
  assert.equal(decision.reason, 'irreversible_authority_required');
  assert.equal(decision.scope, 'FRESH_AUTHORITY_REQUIRED');
  assert.equal(decision.retry_permitted, false);
  assert.equal(decision.fresh_action_admission_required, true);

  assert.throws(
    () => signRecoveryCapability({ ...irreversibleInput(), recovery: {} }, material.signer),
    /irreversible recovery must be null/,
  );
});

test('tampering and validly signed unknown presenter status both refuse', () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  const tampered = structuredClone(artifact);
  tampered.recovery.state_domain_digest = D('9');
  const tamperResult = verifyRecoveryCapability(tampered, verificationContext(material));
  assert.equal(tamperResult.accepted, false);
  assert.equal(tamperResult.reason, 'signature_invalid');

  const withPresenterStatus = signRiskBody(
    RECOVERY_CAPABILITY_VERSION,
    {
      '@version': RECOVERY_CAPABILITY_VERSION,
      ...localInput(),
      claim_boundary: RECOVERY_CAPABILITY_CLAIM_BOUNDARY,
      status: { status: 'CURRENT', valid_until: CAPABILITY_EXPIRES },
    },
    material.signer,
  );
  const statusResult = verifyRecoveryCapability(withPresenterStatus, verificationContext(material));
  assert.equal(statusResult.accepted, false);
  assert.equal(statusResult.verified, true);
  assert.equal(statusResult.reason, 'capability_schema_invalid');
});

test('verification requires the complete RP-pinned expected policy snapshot', () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  const context = verificationContext(material);
  const substitutions: Array<[keyof typeof context.expected_policy, unknown, string]> = [
    ['capability_id', 'recovery-capability:attacker', 'capability_id_mismatch'],
    ['admission_id', 'admission:attacker', 'admission_id_mismatch'],
    ['admission_snapshot_digest', D('9'), 'admission_snapshot_digest_mismatch'],
    ['tenant_id', 'tenant:attacker', 'tenant_mismatch'],
    ['audience', 'gate:attacker', 'audience_mismatch'],
    ['action_caid', C('Z'), 'action_caid_mismatch'],
    ['action_digest', D('9'), 'action_digest_mismatch'],
    ['action_capability_expires_at', CAPABILITY_EXPIRES, 'action_capability_expiry_mismatch'],
    ['provider_id', 'provider:attacker', 'provider_mismatch'],
    ['account_digest', D('9'), 'account_mismatch'],
    ['environment_digest', D('9'), 'environment_mismatch'],
    ['operation_id', 'operation:attacker', 'operation_mismatch'],
    ['issuer_id', 'issuer:attacker', 'issuer_mismatch'],
    ['issuer_digest', D('9'), 'issuer_digest_mismatch'],
    ['trust_epoch_digest', D('9'), 'trust_epoch_mismatch'],
    ['config_epoch_digest', D('9'), 'config_epoch_mismatch'],
    ['resource_set_digest', D('9'), 'resource_set_mismatch'],
  ];
  for (const [key, value, reason] of substitutions) {
    const result = verifyRecoveryCapability(artifact, {
      ...context,
      expected_policy: { ...context.expected_policy, [key]: value },
    });
    assert.equal(result.accepted, false, key);
    assert.equal(result.reason, reason, key);
  }
  const modeResult = verifyRecoveryCapability(artifact, {
    ...context,
    expected_policy: {
      ...context.expected_policy,
      mode: 'IRREVERSIBLE' as const,
      recovery: null,
    },
  });
  assert.equal(modeResult.accepted, false);
  assert.equal(modeResult.reason, 'mode_mismatch');
  const adapterSubstitutions: Array<[string, string, string]> = [
    ['adapter_id', 'adapter:attacker', 'adapter_mismatch'],
    ['adapter_digest', D('9'), 'adapter_digest_mismatch'],
  ];
  for (const [field, value, reason] of adapterSubstitutions) {
    const candidate = structuredClone(context) as any;
    candidate.expected_policy[field] = value;
    candidate.expected_policy.recovery[field] = value;
    const result = verifyRecoveryCapability(artifact, candidate);
    assert.equal(result.accepted, false, field);
    assert.equal(result.reason, reason, field);
  }

  const incomplete = structuredClone(context) as any;
  delete incomplete.expected_policy.action_digest;
  assert.equal(
    verifyRecoveryCapability(artifact, incomplete as any).reason,
    'verification_context_required',
  );
  const missingRecovery = structuredClone(context) as any;
  delete missingRecovery.expected_policy.recovery;
  assert.equal(
    verifyRecoveryCapability(artifact, missingRecovery).reason,
    'verification_context_required',
  );
  const openRecovery = structuredClone(context) as any;
  openRecovery.expected_policy.recovery.surprise = true;
  assert.equal(
    verifyRecoveryCapability(artifact, openRecovery).reason,
    'verification_context_required',
  );
  assert.equal(
    verifyRecoveryCapability(artifact, { ...context, trusted_keys: {} }).reason,
    'verification_context_required',
  );
  assert.equal(
    verifyRecoveryCapability(artifact, { ...context, surprise: true } as any).reason,
    'verification_context_required',
  );
});

test('validly signed recovery capabilities cannot be substituted across admissions', () => {
  const material = keyMaterial();
  const expected = localInput();
  const context = verificationContext(material, expected);

  const otherAdmission = signRecoveryCapability({
    ...expected,
    admission_id: 'admission:operation:02',
  }, material.signer);
  const admissionResult = verifyRecoveryCapability(otherAdmission, context);
  assert.equal(admissionResult.verified, true);
  assert.equal(admissionResult.accepted, false);
  assert.equal(admissionResult.reason, 'admission_id_mismatch');

  const otherSnapshot = signRecoveryCapability({
    ...expected,
    admission_snapshot_digest: D('9'),
  }, material.signer);
  const snapshotResult = verifyRecoveryCapability(otherSnapshot, context);
  assert.equal(snapshotResult.verified, true);
  assert.equal(snapshotResult.accepted, false);
  assert.equal(snapshotResult.reason, 'admission_snapshot_digest_mismatch');
});

test('LOCAL_ATOMIC expected policy pins every class-specific recovery field', () => {
  const material = keyMaterial();
  const input = localInput();
  const artifact = signRecoveryCapability(input, material.signer);
  const context = verificationContext(material, input);
  const substitutions: Array<[
    string,
    (candidate: any) => void,
    'recovery_mismatch' | 'verification_context_required'
      | 'adapter_mismatch' | 'adapter_digest_mismatch',
  ]> = [
    ['scope', (candidate) => {
      candidate.expected_policy.recovery.scope = 'CROSS_TRANSACTION';
    }, 'verification_context_required'],
    ['state_domain_digest', (candidate) => {
      candidate.expected_policy.recovery.state_domain_digest = D('9');
    }, 'recovery_mismatch'],
    ['adapter_id', (candidate) => {
      candidate.expected_policy.adapter_id = 'adapter:payments:substituted';
      candidate.expected_policy.recovery.adapter_id = 'adapter:payments:substituted';
    }, 'adapter_mismatch'],
    ['adapter_digest', (candidate) => {
      candidate.expected_policy.adapter_digest = D('9');
      candidate.expected_policy.recovery.adapter_digest = D('9');
    }, 'adapter_digest_mismatch'],
    ['max_transaction_ms', (candidate) => {
      candidate.expected_policy.recovery.max_transaction_ms = 5_001;
    }, 'recovery_mismatch'],
  ];

  for (const [field, substitute, reason] of substitutions) {
    const candidate = structuredClone(context);
    substitute(candidate);
    const result = verifyRecoveryCapability(artifact, candidate);
    assert.equal(result.accepted, false, field);
    assert.equal(result.reason, reason, field);
  }
});

test('RESERVED_COMPENSATION expected policy pins every class-specific recovery field', () => {
  const material = keyMaterial();
  const input = reservedInput();
  const artifact = signRecoveryCapability(input, material.signer);
  const context = verificationContext(material, input);
  const substitutions: Array<[
    string,
    unknown,
    'recovery_mismatch' | 'verification_context_required',
  ]> = [
    ['scope', 'UNRESERVED_CAPACITY', 'verification_context_required'],
    ['compensation_admission', 'REUSE_ACTION', 'verification_context_required'],
    ['remedy_caid', C('Z'), 'recovery_mismatch'],
    ['remedy_action_digest', D('9'), 'recovery_mismatch'],
    ['destination_digest', D('9'), 'recovery_mismatch'],
    ['authority_digest', D('9'), 'recovery_mismatch'],
    ['reservation_digest', D('9'), 'recovery_mismatch'],
    ['units', 26, 'recovery_mismatch'],
    ['unit', 'other-unit', 'recovery_mismatch'],
    ['available_until', CAPABILITY_EXPIRES, 'recovery_mismatch'],
  ];

  for (const [field, value, reason] of substitutions) {
    const candidate = structuredClone(context) as any;
    candidate.expected_policy.recovery[field] = value;
    const result = verifyRecoveryCapability(artifact, candidate);
    assert.equal(result.accepted, false, field);
    assert.equal(result.reason, reason, field);
  }
});

test('IRREVERSIBLE expected policy requires the exact null recovery class', () => {
  const material = keyMaterial();
  const input = irreversibleInput();
  const artifact = signRecoveryCapability(input, material.signer);
  const context = verificationContext(material, input);
  const substituted = structuredClone(context) as any;
  substituted.expected_policy.recovery = {};

  const result = verifyRecoveryCapability(artifact, substituted);
  assert.equal(result.accepted, false);
  assert.equal(result.reason, 'verification_context_required');
});

test('signed mode downgrade is refused before any mutable-status callback', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  const context = verificationContext(material);
  let callbackCalls = 0;
  const result = await evaluateRecoveryAdmission(artifact, {
    ...context,
    expected_policy: {
      ...context.expected_policy,
      mode: 'IRREVERSIBLE' as const,
      recovery: null,
    },
  }, {
    current_status_resolver() {
      callbackCalls += 1;
      throw new Error('must not run');
    },
  });
  assert.equal(callbackCalls, 0);
  assert.equal(result.route, 'REFUSED');
  assert.equal(result.reason, 'mode_mismatch');
  assert.equal(result.retry_permitted, false);
});

test('cross-tenant/account/environment replay and policy epoch drift are refused', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  const context = verificationContext(material);
  const substitutions: Array<[keyof typeof context.expected_policy, string, string]> = [
    ['tenant_id', 'tenant:other', 'tenant_mismatch'],
    ['account_digest', D('9'), 'account_mismatch'],
    ['environment_digest', D('9'), 'environment_mismatch'],
    ['trust_epoch_digest', D('9'), 'trust_epoch_mismatch'],
    ['config_epoch_digest', D('9'), 'config_epoch_mismatch'],
  ];
  for (const [field, value, reason] of substitutions) {
    const result = await evaluateRecoveryAdmission(artifact, {
      ...context,
      expected_policy: { ...context.expected_policy, [field]: value },
    }, {
      current_status_resolver() { throw new Error('must not run'); },
    });
    assert.equal(result.route, 'REFUSED', field);
    assert.equal(result.reason, reason, field);
  }
});

test('validity, action-capability expiry, and local adapter equality fail closed', () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  assert.equal(verifyRecoveryCapability(artifact, {
    ...verificationContext(material),
    now: '2026-08-03T19:59:59.999Z',
  }).reason, 'capability_not_yet_valid');
  assert.equal(verifyRecoveryCapability(artifact, {
    ...verificationContext(material),
    now: CAPABILITY_EXPIRES,
  }).reason, 'capability_expired');
  assert.equal(verifyRecoveryCapability(artifact, {
    ...verificationContext(material),
    now: ACTION_EXPIRES,
  }).reason, 'action_capability_expired');

  const adapterMismatch = localInput();
  adapterMismatch.recovery.adapter_id = 'adapter:payments:substituted';
  assert.throws(
    () => signRecoveryCapability(adapterMismatch, material.signer),
    /local recovery adapter must match the provider adapter binding/,
  );
});

test('construction rejects unknown keys, symbols, accessors, cycles, and bad mode shapes', () => {
  const material = keyMaterial();
  const missingAdmission: any = localInput();
  delete missingAdmission.admission_id;
  assert.throws(
    () => signRecoveryCapability(missingAdmission, material.signer),
    /capability input must be a closed JSON object/,
  );
  assert.throws(
    () => signRecoveryCapability({
      ...localInput(),
      admission_id: '',
    }, material.signer),
    /admission_id is invalid/,
  );
  assert.throws(
    () => signRecoveryCapability({
      ...localInput(),
      admission_snapshot_digest: 'sha256:not-a-digest',
    }, material.signer),
    /admission_snapshot_digest is invalid/,
  );
  assert.throws(
    () => signRecoveryCapability({ ...localInput(), surprise: true } as any, material.signer),
    /capability input must be a closed JSON object/,
  );
  assert.throws(
    () => signRecoveryCapability({
      ...localInput(),
      recovery: { ...localInput().recovery, surprise: true },
    } as any, material.signer),
    /local recovery shape is invalid/,
  );

  const symbolInput: any = localInput();
  symbolInput[Symbol('hidden')] = true;
  assert.throws(
    () => signRecoveryCapability(symbolInput, material.signer),
    /outside strict JSON|closed JSON object/,
  );

  let getterCalls = 0;
  const accessorInput: any = localInput();
  Object.defineProperty(accessorInput, 'tenant_id', {
    enumerable: true,
    get() { getterCalls += 1; return 'tenant:attacker'; },
  });
  assert.throws(
    () => signRecoveryCapability(accessorInput, material.signer),
    /outside strict JSON|closed JSON object/,
  );
  assert.equal(getterCalls, 0);

  const cyclicInput: any = localInput();
  cyclicInput.recovery.cycle = cyclicInput.recovery;
  assert.throws(
    () => signRecoveryCapability(cyclicInput, material.signer),
    /outside strict JSON|local recovery shape is invalid/,
  );

  assert.throws(
    () => signRecoveryCapability({ ...localInput(), mode: 'OTHER' } as any, material.signer),
    /recovery mode is invalid/,
  );
  assert.throws(
    () => signRecoveryCapability({
      ...reservedInput(),
      recovery: { ...reservedInput().recovery, units: 0 },
    }, material.signer),
    /reservation units are invalid/,
  );
});

test('hostile artifact JSON and unknown nested members are refused without execution', () => {
  const material = keyMaterial();
  const context = verificationContext(material);
  const artifact: any = structuredClone(signRecoveryCapability(localInput(), material.signer));
  let getterCalls = 0;
  Object.defineProperty(artifact.recovery, 'adapter_digest', {
    enumerable: true,
    get() { getterCalls += 1; return D('9'); },
  });
  assert.equal(verifyRecoveryCapability(artifact, context).accepted, false);
  assert.equal(getterCalls, 0);

  const symbolArtifact: any = structuredClone(signRecoveryCapability(localInput(), material.signer));
  symbolArtifact.recovery[Symbol('hidden')] = true;
  assert.equal(verifyRecoveryCapability(symbolArtifact, context).accepted, false);

  const cyclicArtifact: any = structuredClone(signRecoveryCapability(localInput(), material.signer));
  cyclicArtifact.recovery.cycle = cyclicArtifact.recovery;
  assert.equal(verifyRecoveryCapability(cyclicArtifact, context).accepted, false);
});

test('stale, revoked, future, mismatched, malformed, and throwing status refuse', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(localInput(), material.signer);
  const evaluateWith = (resolver: (input: ResolverInput) => unknown) => evaluateRecoveryAdmission(
    artifact,
    verificationContext(material),
    { current_status_resolver: resolver },
  );

  const stale = await evaluateWith((input) => currentStatus(input, {
      valid_until: '2026-08-03T20:20:00.000Z',
    }));
  assert.equal(stale.recovery_route_accepted, false);
  assert.equal(stale.route, 'REFUSED');
  assert.equal(stale.reason, 'current_status_insufficient_coverage');
  assert.equal(stale.capability_digest, recoveryCapabilityDigest(artifact));
  assert.equal(stale.retry_permitted, false);
  assert.equal((await evaluateWith((input) => currentStatus(input, {
    status: 'REVOKED',
  }))).reason, 'current_status_revoked');
  assert.equal((await evaluateWith((input) => currentStatus(input, {
    valid_from: '2026-08-03T20:01:00.000Z',
  }))).reason, 'current_status_not_yet_valid');
  assert.equal((await evaluateWith((input) => currentStatus(input, {
    action_digest: D('9'),
  }))).reason, 'current_status_binding_mismatch');
  assert.equal((await evaluateWith((input) => ({
    ...currentStatus(input),
    surprise: true,
  }))).reason, 'current_status_invalid');
  assert.equal((await evaluateWith(() => null)).reason, 'current_status_invalid');
  assert.equal((await evaluateWith(() => {
    throw new Error('status backend unavailable');
  })).reason, 'current_status_resolver_exception');
  assert.equal((await evaluateRecoveryAdmission(
    artifact,
    verificationContext(material),
    {} as any,
  )).reason, 'current_status_resolver_required');
});

test('reservation absence, mismatches, expiry, malformed output, and exceptions refuse', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(reservedInput(), material.signer);
  const context = verificationContext(material, reservedInput());
  const goodStatus = (input: ResolverInput) => currentStatus(input);

  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
  } as any)).reason, 'reservation_verifier_required');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: () => null,
  })).reason, 'reservation_invalid');

  const mismatches: Array<[string, unknown]> = [
    ['reservation_digest', D('9')],
    ['remedy_caid', C('Z')],
    ['remedy_action_digest', D('8')],
    ['destination_digest', D('7')],
    ['authority_digest', D('6')],
    ['units', 24],
    ['unit', 'other-unit'],
    ['action_digest', D('5')],
  ];
  for (const [field, value] of mismatches) {
    const decision = await evaluateRecoveryAdmission(artifact, context, {
      current_status_resolver: goodStatus,
      reservation_verifier: (input: ResolverInput) => reservationStatus(input, { [field]: value }),
    });
    assert.equal(decision.route, 'REFUSED', field);
    assert.equal(decision.reason, 'reservation_binding_mismatch', field);
  }

  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: (input: ResolverInput) => reservationStatus(input, {
      available_until: '2026-08-03T19:59:59.999Z',
    }),
  })).reason, 'reservation_expired');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: (input: ResolverInput) => reservationStatus(input, {
      available_until: '2026-08-03T20:20:00.000Z',
    }),
  })).reason, 'reservation_insufficient_coverage');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: (input: ResolverInput) => reservationStatus(input, {
      valid_from: '2026-08-03T20:01:00.000Z',
    }),
  })).reason, 'reservation_not_yet_valid');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: (input: ResolverInput) => reservationStatus(input, {
      status: 'RELEASED',
    }),
  })).reason, 'reservation_not_current');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: (input: ResolverInput) => ({
      ...reservationStatus(input),
      surprise: true,
    }),
  })).reason, 'reservation_invalid');
  assert.equal((await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: goodStatus,
    reservation_verifier: () => {
      throw new Error('reservation backend unavailable');
    },
  })).reason, 'reservation_verifier_exception');
});

test('status and reservation must both cover admission and the action capability expiry', async () => {
  const material = keyMaterial();
  const artifact = signRecoveryCapability(reservedInput(), material.signer);
  const context = verificationContext(material, reservedInput());

  const statusShort = await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: (input: ResolverInput) => currentStatus(input, {
      valid_until: '2026-08-03T20:29:59.999Z',
    }),
    reservation_verifier: (input: ResolverInput) => reservationStatus(input),
  });
  assert.equal(statusShort.reason, 'current_status_insufficient_coverage');

  const reservationShort = await evaluateRecoveryAdmission(artifact, context, {
    current_status_resolver: (input: ResolverInput) => currentStatus(input),
    reservation_verifier: (input: ResolverInput) => reservationStatus(input, {
      available_until: '2026-08-03T20:29:59.999Z',
    }),
  });
  assert.equal(reservationShort.reason, 'reservation_insufficient_coverage');
});
