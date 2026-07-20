// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import {
  buildMobileActionIdentity,
  buildMobileAuthorizationContext,
  hashCanonical,
} from '../../packages/mobile/index.js';
import { FLEX_ENVELOPE_VERSION } from './curtailment.js';
import {
  buildCurtailmentControlledAction,
  buildCurtailmentPresentation,
  createCurtailmentAction,
  executeGraceCurtailment,
  graceDigest,
} from './mobile-grid.js';
import {
  createCosaReferenceActuator,
  createFencedMemoryStore,
  createReferenceMeter,
  verifyReferenceMeterStatement,
} from './reference-adapters.js';

const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';
const PROFILE_HASH = `sha256:${'9'.repeat(64)}`;

function p256() {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { pair, spki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
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

function approval({ action, presentation, policy, approver, role, index }) {
  const key = p256();
  const credentialId = crypto.randomBytes(32).toString('base64url');
  const deviceKeyId = `ep:key:reference-${index}`;
  const controlledAction = buildCurtailmentControlledAction(action);
  const actionIdentity = buildMobileActionIdentity({
    actionReference: action.action_id,
    action: controlledAction,
  });
  const context = buildMobileAuthorizationContext({
    actionHash: graceDigest(controlledAction),
    actionReference: action.action_id,
    actionCaid: actionIdentity.action_caid,
    actionDigest: actionIdentity.action_digest,
    policyId: policy.policy_id,
    policyHash: graceDigest(policy),
    initiatorId: action.requested_by,
    approverId: approver,
    approverIndex: index,
    requiredApprovals: 2,
    nonce: `sig_reference_${index}`,
    issuedAt: `2026-07-15T20:0${index}:00.000Z`,
    expiresAt: '2026-07-15T20:10:00.000Z',
    decision: 'approved',
    displayHash: graceDigest(presentation),
    profileHash: PROFILE_HASH,
    platform: 'ios',
    appId: 'ai.emiliaprotocol.approver',
    deviceKeyId,
    credentialId,
    attestationKeyId: `appattest_reference_${index}`,
  });
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: Buffer.from(graceDigest(context).slice(7), 'hex').toString('base64url'),
    origin: ORIGIN,
    crossOrigin: false,
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
    crypto.createHash('sha256').update(clientData).digest(),
  ]);
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
          client_data_json: clientData.toString('base64url'),
          signature: crypto.sign('sha256', signed, key.pair.privateKey).toString('base64url'),
        },
      },
    },
    roster: {
      role,
      approver,
      device_key_id: deviceKeyId,
      public_key_spki: key.spki,
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      credential_id: credentialId,
    },
  };
}

function scenario() {
  const envelope = {
    '@version': FLEX_ENVELOPE_VERSION,
    envelope_id: 'grace:envelope:reference-summer-2026',
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
    actionId: 'grace:event:caiso-reference-0042',
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
  const first = approval({
    action, presentation, policy, approver: policy.approvers[0], role: 'grid_operator', index: 1,
  });
  const second = approval({
    action, presentation, policy, approver: policy.approvers[1], role: 'facility_operator', index: 2,
  });
  return {
    envelope,
    action,
    presentation,
    policy,
    authorizationEvidence: [first.evidence, second.evidence],
    authorizationProfile: {
      required: 2,
      rp_id: RP_ID,
      allowed_origins: [ORIGIN],
      mobile_profile_hash: PROFILE_HASH,
      max_challenge_age_ms: 600000,
      window_sec: 900,
      approvers: [first.roster, second.roster],
    },
  };
}

function runtime() {
  const actuatorKey = ed25519('ep:key:cosa-reference');
  const meterKey = ed25519('ep:key:meter-reference');
  const capsuleKey = ed25519('ep:key:action-state-reference');
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
      baselineMw: '64.000',
      clock: () => '2026-07-15T21:45:01.000Z',
    }),
    executionStore: createFencedMemoryStore(),
    settlementStore: createFencedMemoryStore(),
  };
}

async function execute(input, state, overrides = {}) {
  return executeGraceCurtailment({
    ...input,
    executionStore: state.executionStore,
    actuator: overrides.actuator || state.actuator,
    actuatorTrust: state.actuatorKey.trust,
    meter: overrides.meter || state.meter,
    meterTrust: state.meterKey.trust,
    settlementStore: state.settlementStore,
    settle: async ({ key }) => ({ settlement_id: 'settlement:reference:0042', entitlement_key: key }),
    operator: 'operator:us-west-dc-17',
    developer: 'cosa-reference-adapter/1.0',
    capsuleSigner: state.capsuleKey,
    clock: () => '2026-07-15T20:15:00.000Z',
  });
}

export async function runGraceReferenceScenario() {
  const input = scenario();
  const state = runtime();
  const positive = await execute(input, state);
  const replay = await execute(input, state);

  const changed = { ...input.action, target_delta_kw: '19000' };
  const substitution = await execute({ ...input, action: changed }, runtime());

  const meterState = runtime();
  const meter = {
    verify: verifyReferenceMeterStatement,
    async observe(args) {
      const statement = await meterState.meter.observe(args);
      return { ...statement, baseline_method_hash: input.action.baseline_method_hash };
    },
  };
  const meterSmuggling = await execute(input, meterState, { meter });

  return {
    reference_only: true,
    physical_claim: false,
    description: 'Synthetic reference adapters exercise the production verification and one-time state machine. They do not claim a physical grid event.',
    positive,
    attacks: {
      replay: { verdict: replay.verdict, refused: replay.ok === false },
      action_substitution: { verdict: substitution.verdict, refused: substitution.ok === false },
      meter_rule_smuggling: { verdict: meterSmuggling.verdict, refused: meterSmuggling.ok === false },
    },
    pins: {
      action_state_commit: '8e3895d1b2afb1f794a43b679b986048805c9d3f',
      cosa_commit: '3e4916d37a3cead972951223b806002eed0e1c26',
    },
  };
}

const graceReferenceScenario = { runGraceReferenceScenario };

export default graceReferenceScenario;
