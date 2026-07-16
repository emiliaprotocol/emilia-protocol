// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  buildMobileAuthorizationContext,
  hashCanonical,
} from '../packages/mobile/index.js';
import {
  ACTION_STATE_SPEC_VERSION,
  GRACE_METER_VERSION,
  actionStateCapsuleId,
  buildActionStateCapsule,
  buildCurtailmentPresentation,
  createCurtailmentAction,
  executeGraceCurtailment,
  graceDigest,
  signGraceArtifact,
  validateCurtailmentAction,
  verifyActionStateSignedStatement,
  verifyGraceMobileAuthorization,
} from '../lib/grace/mobile-grid.js';
import {
  createCosaReferenceActuator,
  createFencedMemoryStore,
  createReferenceMeter,
  verifyReferenceMeterStatement,
} from '../lib/grace/reference-adapters.js';
import { FLEX_ENVELOPE_VERSION } from '../lib/grace/curtailment.js';

const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';
const MOBILE_PROFILE_HASH = `sha256:${'9'.repeat(64)}`;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function p256() {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    ...pair,
    spki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function ed25519(keyId) {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey: pair.privateKey,
    keyId,
    trust: {
      key_id: keyId,
      public_key_spki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
  };
}

const envelope = {
  '@version': FLEX_ENVELOPE_VERSION,
  envelope_id: 'grace:envelope:summer-2026',
  bounds: {
    max_event_mw: 30,
    max_period_mwh: 250,
    max_events: 12,
    max_event_hours: 48,
    min_notice_minutes: 10,
    window: { start: '2026-06-01T00:00:00.000Z', end: '2026-09-30T23:59:59.000Z' },
  },
};

const action = createCurtailmentAction({
  actionId: 'grace:event:caiso-2026-07-15-0042',
  facility: 'facility:us-west-dc-17',
  targetDeltaKw: '18000',
  notBefore: '2026-07-15T20:15:00.000Z',
  notAfter: '2026-07-15T21:45:00.000Z',
  issuedAt: '2026-07-15T20:00:00.000Z',
  baselineMethodHash: `sha256:${'b'.repeat(64)}`,
  envelopeId: envelope.envelope_id,
  requestedBy: 'ep:agent:grid-coordinator',
});
const presentation = buildCurtailmentPresentation(action);
const policy = {
  policy_id: 'ep:grace:mobile-curtailment:v1',
  human_approval: 'class_a',
  required_approvals: 2,
  approvers: ['ep:approver:grid-operator', 'ep:approver:facility-operator'],
};

function mobileApprover({
  approver,
  role,
  index,
  key = p256(),
  deviceKeyId = `ep:key:${approver.split(':').at(-1)}-iphone`,
  decision = 'approved',
  initiator = action.requested_by,
  signedAction = action,
  signedPresentation = presentation,
  signedPolicy = policy,
} = {}) {
  const credentialId = crypto.randomBytes(32).toString('base64url');
  const appId = 'ai.emiliaprotocol.approver';
  const context = buildMobileAuthorizationContext({
    actionHash: graceDigest(signedAction),
    policyId: signedPolicy.policy_id,
    policyHash: graceDigest(signedPolicy),
    initiatorId: initiator,
    approverId: approver,
    approverIndex: index,
    requiredApprovals: 2,
    nonce: `sig_${crypto.randomBytes(16).toString('hex')}`,
    issuedAt: `2026-07-15T20:0${index}:00.000Z`,
    expiresAt: '2026-07-15T20:10:00.000Z',
    decision,
    displayHash: graceDigest(signedPresentation),
    profileHash: MOBILE_PROFILE_HASH,
    platform: 'ios',
    appId,
    deviceKeyId,
    credentialId,
    attestationKeyId: `appattest_${index}_reference`,
  });
  const canonicalChallenge = Buffer.from(graceDigest(context).slice(7), 'hex').toString('base64url');
  const correctedClientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge: canonicalChallenge, origin: ORIGIN, crossOrigin: false,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(index);
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    counter,
  ]);
  const signed = Buffer.concat([
    authenticatorData,
    crypto.createHash('sha256').update(correctedClientData).digest(),
  ]);
  const signature = crypto.sign('sha256', signed, key.privateKey);
  return {
    evidence: {
      context,
      signoff: {
        context_hash: hashCanonical(context),
        key_class: 'A',
        approver_key_id: deviceKeyId,
        signed_at: context.issued_at,
        webauthn: {
          authenticator_data: authenticatorData.toString('base64url'),
          client_data_json: correctedClientData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
      },
    },
    roster: {
      role,
      approver,
      device_key_id: deviceKeyId,
      public_key_spki: key.spki,
      platform: 'ios',
      app_id: appId,
      credential_id: credentialId,
    },
    key,
  };
}

function authorizationFixture(options = {}) {
  const first = mobileApprover({
    approver: 'ep:approver:grid-operator', role: 'grid_operator', index: 1,
    ...options.first,
  });
  const second = mobileApprover({
    approver: 'ep:approver:facility-operator', role: 'facility_operator', index: 2,
    ...options.second,
  });
  return {
    evidence: [first.evidence, second.evidence],
    profile: {
      required: 2,
      rp_id: RP_ID,
      allowed_origins: [ORIGIN],
      mobile_profile_hash: MOBILE_PROFILE_HASH,
      window_sec: 900,
      max_challenge_age_ms: 600000,
      approvers: [first.roster, second.roster],
    },
    first,
    second,
  };
}

function runtime() {
  const actuatorKey = ed25519('ep:key:cosa-reference-1');
  const meterKey = ed25519('ep:key:meter-reference-1');
  const capsuleKey = ed25519('ep:key:action-state-gate-1');
  return {
    actuatorKey,
    meterKey,
    capsuleKey,
    actuator: createCosaReferenceActuator({
      ...actuatorKey,
      clock: () => '2026-07-15T20:15:00.000Z',
    }),
    meter: createReferenceMeter({
      ...meterKey,
      clock: () => '2026-07-15T21:45:01.000Z',
    }),
    executionStore: createFencedMemoryStore(),
    settlementStore: createFencedMemoryStore(),
  };
}

async function run(overrides = {}) {
  const auth = overrides.auth || authorizationFixture();
  const state = overrides.state || runtime();
  let settlements = 0;
  const result = await executeGraceCurtailment({
    action: overrides.action || action,
    envelope: overrides.envelope || envelope,
    spent: overrides.spent || {},
    presentation: overrides.presentation || presentation,
    policy: overrides.policy || policy,
    authorizationEvidence: auth.evidence,
    authorizationProfile: auth.profile,
    executionStore: state.executionStore,
    actuator: overrides.actuator || state.actuator,
    actuatorTrust: state.actuatorKey.trust,
    meter: overrides.meter || state.meter,
    meterTrust: state.meterKey.trust,
    settlementStore: state.settlementStore,
    settle: async ({ key }) => {
      settlements += 1;
      return { settlement_id: 'settlement:reference:1', entitlement_key: key };
    },
    operator: 'operator:us-west-dc-17',
    developer: 'cosa-reference-adapter/1.0',
    capsuleSigner: state.capsuleKey,
    clock: () => '2026-07-15T20:15:00.000Z',
  });
  return { result, state, settlements };
}

describe('GRACE mobile action contract', () => {
  it('uses one canonical grid.curtailment action and server-derived presentation', () => {
    expect(validateCurtailmentAction(action)).toEqual({ valid: true, errors: [] });
    expect(action.action_type).toBe('grid.curtailment');
    expect(action.target_delta_kw).toBe('18000');
    expect(presentation.material_fields.reduction).toBe('18 MW');
    expect(() => createCurtailmentAction({ ...action, actionId: undefined })).toThrow();
  });

  it('refuses unknown fields, floats, invalid windows, and action-type drift', () => {
    for (const candidate of [
      { ...action, unexpected: true },
      { ...action, target_delta_kw: 18000.5 },
      { ...action, action_type: 'grid.datacenter.curtailment' },
      { ...action, window: { not_before: action.window.not_after, not_after: action.window.not_before } },
    ]) expect(validateCurtailmentAction(candidate).valid).toBe(false);
  });
});

describe('GRACE mobile authorization is pinned, action-bound, and quorum-enforced', () => {
  it('accepts two distinct Class-A handshakes under the relying-party roster', () => {
    const auth = authorizationFixture();
    const result = verifyGraceMobileAuthorization({ action, presentation, policy, ...auth });
    expect(result.valid).toBe(true);
    expect(result.quorum.valid).toBe(true);
    expect(result.authorization_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it.each([
    ['denial presented as approval', { second: { decision: 'denied' } }],
    ['initiator self-approval', { second: { initiator: 'ep:approver:facility-operator' } }],
    ['different action', { second: { signedAction: { ...action, target_delta_kw: '29000' } } }],
    ['different display', { second: { signedPresentation: { ...presentation, title: 'Reduce load by 29 MW' } } }],
  ])('refuses %s', (_name, options) => {
    const auth = authorizationFixture(options);
    expect(verifyGraceMobileAuthorization({ action, presentation, policy, ...auth }).valid).toBe(false);
  });

  it('refuses initiator self-approval under the pinned mobile roster', () => {
    const auth = authorizationFixture({
      second: { initiator: 'ep:approver:facility-operator' },
    });
    const result = verifyGraceMobileAuthorization({ action, presentation, policy, ...auth });
    expect(result.valid).toBe(false);
    expect(result.quorum?.checks?.initiator_excluded ?? false).toBe(false);
  });

  it('refuses one device key occupying both human seats', () => {
    const shared = p256();
    const auth = authorizationFixture({ first: { key: shared }, second: { key: shared } });
    const result = verifyGraceMobileAuthorization({ action, presentation, policy, ...auth });
    expect(result.valid).toBe(false);
    expect(result.quorum.checks.distinct_keys).toBe(false);
  });

  it('refuses a partial quorum even when its one signature is valid', () => {
    const auth = authorizationFixture();
    auth.evidence.pop();
    const result = verifyGraceMobileAuthorization({ action, presentation, policy, ...auth });
    expect(result.valid).toBe(false);
    expect(result.quorum.checks.threshold_met).toBe(false);
  });

  it('binds each signed approval index to the relying-party roster order', () => {
    const auth = authorizationFixture({ first: { index: 2 }, second: { index: 1 } });
    const result = verifyGraceMobileAuthorization({ action, presentation, policy, ...auth });
    expect(result.valid).toBe(false);
    expect(result.checks.signed_semantics).toBe(false);
  });

  it('fails closed on malformed freshness and origin policy inputs', () => {
    const auth = authorizationFixture();
    for (const profile of [
      { ...auth.profile, allowed_origins: [ORIGIN, 7] },
      { ...auth.profile, max_challenge_age_ms: null },
      { ...auth.profile, window_sec: 0 },
    ]) {
      expect(verifyGraceMobileAuthorization({
        action, presentation, policy, evidence: auth.evidence, profile,
      }).valid).toBe(false);
    }
  });
});

describe('phone to COSA to meter to Action State to settlement', () => {
  it('executes, measures, emits a valid -02 Signed Statement, and settles once', async () => {
    const state = runtime();
    const { result, settlements } = await run({ state });
    expect(result.ok).toBe(true);
    expect(result.verdict).toBe('executed_measured_settled');
    expect(result.compliance.compliant).toBe(true);
    expect(result.acknowledgment.simulation).toBe(true);
    expect(result.meter_statement.measurement_class).toBe('reference_simulation');
    expect(result.action_state.capsule.spec_version).toBe(ACTION_STATE_SPEC_VERSION);
    expect(result.action_state.anchoring).toBe('unregistered_signed_statement');
    expect(verifyActionStateSignedStatement(result.action_state, {
      publicKeySpkiB64u: state.capsuleKey.trust.public_key_spki,
      keyId: state.capsuleKey.keyId,
    }).valid).toBe(true);
    expect(settlements).toBe(1);
  });

  it('verifies the exact Action State statement with the pinned capsule key', async () => {
    const state = runtime();
    const { result } = await run({ state });
    const verified = verifyActionStateSignedStatement(result.action_state, {
      publicKeySpkiB64u: state.capsuleKey.trust.public_key_spki,
      keyId: state.capsuleKey.keyId,
    });
    expect(verified.valid).toBe(true);
    expect(verified.capsule.effect.status).toBe('confirmed');
    expect(verified.capsule.effect.effect_attestation).toBe('gate_executed');
    expect(verified.capsule.disposition.human_disposed).toBe(true);
  });

  it('refuses an order outside the seasonal envelope before touching COSA', async () => {
    const state = runtime();
    const oversized = { ...action, target_delta_kw: '40000' };
    const auth = authorizationFixture({
      first: { signedAction: oversized }, second: { signedAction: oversized },
    });
    const result = await run({ action: oversized, auth, state });
    expect(result.result.verdict).toBe('refuse_outside_envelope');
    expect(state.actuator.invocationCount()).toBe(0);
  });

  it('refuses an inactive or expired action before touching COSA', async () => {
    const state = runtime();
    const auth = authorizationFixture();
    const base = {
      action,
      envelope,
      presentation,
      policy,
      authorizationEvidence: auth.evidence,
      authorizationProfile: auth.profile,
      executionStore: state.executionStore,
      actuator: state.actuator,
      actuatorTrust: state.actuatorKey.trust,
      meter: state.meter,
      meterTrust: state.meterKey.trust,
      settlementStore: state.settlementStore,
      settle: async () => ({ settlement_id: 'must-not-run' }),
      operator: 'operator:us-west-dc-17',
      capsuleSigner: state.capsuleKey,
    };
    for (const clock of [
      () => '2026-07-15T20:14:59.999Z',
      () => '2026-07-15T21:45:00.001Z',
      () => { throw new Error('clock unavailable'); },
    ]) {
      const result = await executeGraceCurtailment({ ...base, clock });
      expect(result.verdict).toBe('refuse_action_not_active');
    }
    expect(state.actuator.invocationCount()).toBe(0);
  });

  it('burns an indeterminate dispatch and never retries the physical effect', async () => {
    const state = runtime();
    let calls = 0;
    const actuator = {
      verify: state.actuator.verify,
      async dispatch() { calls += 1; throw new Error('COSA response lost after dispatch'); },
    };
    const first = await run({ state, actuator });
    expect(first.result).toMatchObject({ verdict: 'execution_indeterminate', retry_safe: false });
    const second = await run({ state, actuator });
    expect(second.result.verdict).toBe('refuse_replay');
    expect(calls).toBe(1);
  });

  it('refuses a tampered actuator acknowledgment after consuming execution', async () => {
    const state = runtime();
    const actuator = {
      verify: state.actuator.verify,
      async dispatch(request) {
        const ack = await state.actuator.dispatch(request);
        return { ...ack, action_hash: `sha256:${'0'.repeat(64)}` };
      },
    };
    const { result } = await run({ state, actuator });
    expect(result).toMatchObject({ verdict: 'refuse_actuator_ack', retry_safe: false });
  });

  it('refuses meter signature substitution and market-rule smuggling', async () => {
    const state = runtime();
    const meter = {
      verify: verifyReferenceMeterStatement,
      async observe(input) {
        const statement = await state.meter.observe(input);
        return { ...statement, baseline_method_hash: action.baseline_method_hash };
      },
    };
    const { result } = await run({ state, meter });
    expect(result).toMatchObject({ verdict: 'effect_unconfirmed', retry_safe: false });
  });

  it('consumes one execution and one settlement under concurrent duplicate delivery', async () => {
    const state = runtime();
    const [first, second] = await Promise.all([run({ state }), run({ state })]);
    const verdicts = [first.result.verdict, second.result.verdict].sort();
    expect(verdicts).toEqual(['executed_measured_settled', 'refuse_replay']);
    expect(state.actuator.invocationCount()).toBe(1);
  });
});

describe('Action State adapter honesty', () => {
  it('capsule_id changes under payload tamper and the statement fails verification', async () => {
    const state = runtime();
    const { result } = await run({ state });
    const tampered = structuredClone(result.action_state);
    tampered.capsule.effect.response_digest = '0'.repeat(64);
    expect(actionStateCapsuleId(tampered.capsule)).not.toBe(tampered.capsule.capsule_id);
    expect(verifyActionStateSignedStatement(tampered, {
      publicKeySpkiB64u: state.capsuleKey.trust.public_key_spki,
      keyId: state.capsuleKey.keyId,
    }).valid).toBe(false);
  });

  it('cannot build confirmed effect evidence without the signed meter digest', () => {
    expect(() => buildActionStateCapsule({
      action,
      operator: 'operator:us-west-dc-17',
      developer: 'cosa-reference-adapter/1.0',
      timestamp: '2026-07-15T21:45:02.000Z',
      dispatchRequestDigest: `sha256:${'1'.repeat(64)}`,
      meterDigest: null,
      authorizationDigest: `sha256:${'2'.repeat(64)}`,
    })).toThrow();
  });

  it('does not upgrade the reference meter into a physical meter claim', async () => {
    const meterKey = ed25519('ep:key:meter-reference-2');
    const meter = createReferenceMeter({ ...meterKey, clock: () => '2026-07-15T21:45:01.000Z' });
    const ack = signGraceArtifact({
      '@version': 'EP-GRACE-COSA-ACK-v1',
      adapter: 'cosa-reference', adapter_version: '1.0.0', actuator_id: 'cosa:reference:1',
      event_id: action.action_id, action_hash: graceDigest(action),
      request_digest: `sha256:${'3'.repeat(64)}`, idempotency_key: 'grace:test',
      status: 'dispatched', dispatched_at: '2026-07-15T20:15:00.000Z', simulation: true,
    }, ed25519('ep:key:throwaway'));
    const statement = await meter.observe({ action, acknowledgment: ack });
    expect(statement.simulation).toBe(true);
    expect(statement.measurement_class).toBe('reference_simulation');
    expect(statement).not.toHaveProperty('baseline_method_hash');
    expect(statement['@version']).toBe(GRACE_METER_VERSION);
  });
});

describe('GRACE live control-room artifact', () => {
  it('runs the public one-command circuit and all attacks refuse', () => {
    const output = execFileSync('node', [
      path.join(ROOT, 'examples/grace/live-control-room.mjs'),
    ], { encoding: 'utf8' });
    expect(output).toContain('MOBILE      2 distinct Class-A handshakes: VERIFIED');
    expect(output).toContain('SETTLEMENT  CONSUMED ONCE');
    expect(output.match(/ATTACK\s+.*REFUSED/g)).toHaveLength(3);
    expect(output).toContain('no physical grid event is claimed');
  });
});
