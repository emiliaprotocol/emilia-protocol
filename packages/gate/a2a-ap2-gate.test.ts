// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import {
  AP2_NATIVE_AEB_ADAPTER_ID,
  AP2_NATIVE_AEB_CONFIG_VERSION,
  createAp2NativeAebAdapter,
  type Ap2NativeVerifier,
} from '../verify/ap2-native-adapter.js';
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  type AebDurableConsumptionStore,
  type AebPinnedConfig,
  type AebStatusInput,
} from '../verify/aeb-adapter-contract.js';
import {
  A2A_AP2_NATIVE_PRESENTATION_METHOD,
  createA2AAuthorizationChallengeTask,
} from '../verify/a2a-evidence-challenge.js';

import {
  A2AAp2Gate,
  type A2AAp2ChallengeStore,
  type A2AAp2GateDecision,
} from './a2a-ap2-gate.js';
import {
  CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
  ConsequenceActuator,
  createMemoryConsequenceActuatorStore,
  signConsequenceExecutionEnvelope,
} from './consequence-actuator.js';

const NOW = '2026-08-09T17:00:00.000Z';
const NOW_MS = Date.parse(NOW);
const CAID = 'caid:1:payment.release.1:jcs-sha256:chfoX029yd-_1Y4U7hwHdDP5xcCjNbh01o5CS4yPsqE';
const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  payment_instruction_id: 'pi-gate-1',
  amount: '184.00',
  currency: 'USD',
  beneficiary_account: `sha256:${'a'.repeat(64)}`,
});
const ACTION_DEFINITIONS = Object.freeze([{
  action_type: 'payment.release.1',
  required_fields: [
    { name: 'amount', type: 'amount-string' },
    { name: 'currency', type: 'enum' },
    { name: 'beneficiary_account', type: 'digest' },
    { name: 'payment_instruction_id', type: 'string' },
  ],
  optional_fields: [],
}]);
const TARGET_DIGEST = `sha256:${'c'.repeat(64)}`;

type Action = typeof ACTION | Readonly<Record<string, unknown>>;
type NativeArtifact = { mandate_id: string; serialized: string };
type NativeAssertion = {
  accepted: boolean;
  role: string;
  subject: { id: string; kind: 'human' | 'organization' };
  action: Action;
};

function status(overrides: Partial<AebStatusInput> = {}): AebStatusInput {
  return {
    checked_at: '2026-08-09T16:59:30.000Z',
    expires_at: '2026-08-09T17:05:00.000Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
}

function ap2Verifier(assertions: Map<string, NativeAssertion>): Ap2NativeVerifier {
  return {
    id: 'external:ap2-reference',
    version: '0.2-test',
    implementation_digest: digestAeb({ implementation: 'external-ap2-reference', version: '0.2-test' }),
    verify({ artifact }) {
      const native = artifact as NativeArtifact;
      const assertion = assertions.get(native.mandate_id);
      if (!assertion) throw new Error('unknown native mandate');
      return {
        verified: true,
        accepted: assertion.accepted,
        native_artifact_digest: digestAeb(native),
        replay_unit: digestAeb({ protocol: 'AP2', mandate_id: native.mandate_id }),
        evidence_role: assertion.role,
        subject: assertion.subject,
        normalized_action: assertion.action,
        action_digest: digestAeb(assertion.action),
        reasons: [],
      };
    },
  };
}

function registryEntry(id: string, kind: 'mapping-profile' | 'evidence-role', definition: unknown) {
  const base = { kind, version: '1', status: 'active' as const, definition };
  return { ...base, definition_digest: registryEntryDigest(id, base) };
}

function aebSetup(assertions: Map<string, NativeAssertion>) {
  const verifier = ap2Verifier(assertions);
  const adapter = createAp2NativeAebAdapter(verifier);
  const profileId = 'ap2-native-action';
  const mapperId = 'mapper:ap2-native-action-v1';
  const profile = {
    version: '1',
    definition: { suite: 'jcs-sha256', definitions: ACTION_DEFINITIONS },
    registry_entry_ref: 'mapping:ap2-native-action',
    mapper_id: mapperId,
    resolver: {
      id: 'resolver:ap2-native-action',
      version: '1',
      implementation_digest: digestAeb({ resolver: 'ap2-native-action-v1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE' as const,
      loss_policy: 'NO_MATERIAL_FIELD_LOSS' as const,
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
    profile_digest: '' as `sha256:${string}`,
  };
  profile.profile_digest = mappingProfileDigest(profileId, profile);
  const entries = {
    'mapping:ap2-native-action': registryEntry(
      'mapping:ap2-native-action',
      'mapping-profile',
      { profile_digest: profile.profile_digest },
    ),
    'role:ap2-native-authorization': registryEntry(
      'role:ap2-native-authorization',
      'evidence-role',
      { role: 'ap2-native-authorization', subject_kinds: ['human'] },
    ),
    'role:authorization-server-confirmation': registryEntry(
      'role:authorization-server-confirmation',
      'evidence-role',
      { role: 'authorization-server-confirmation', subject_kinds: ['organization'] },
    ),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1' as const,
    registry_id: 'registry:a2a-ap2-test',
    epoch: 1,
    entries,
    registry_digest: '' as `sha256:${string}`,
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const adapterPin = {
    version: adapter.version,
    trust_roots: [{ issuer: 'https://wallet.example', key_id: 'wallet-1' }],
    config: {
      '@version': AP2_NATIVE_AEB_CONFIG_VERSION,
      source_revision: 'ap2-agent-authorization-v0.2',
      evidence_role: 'ap2-native-authorization',
      subject: { id: 'human:alice', kind: 'human' },
      max_status_age_seconds: 300,
      verifier: {
        id: verifier.id,
        version: verifier.version,
        implementation_digest: verifier.implementation_digest,
      },
    },
    max_status_age_sec: 300,
    config_digest: '' as `sha256:${string}`,
  };
  adapterPin.config_digest = adapterPinDigest(AP2_NATIVE_AEB_ADAPTER_ID, adapterPin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const config: AebPinnedConfig = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'executor:a2a-ap2-test',
    evaluator_keys: {
      'evaluator:a2a-ap2-test': {
        public_key: evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    registry,
    accepted_mappers: [mapperId],
    adapters: { [AP2_NATIVE_AEB_ADAPTER_ID]: adapterPin },
    profiles: { [profileId]: profile },
    requirements: {
      'requirement:a2a-ap2': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['ap2-native-authorization'],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  return { adapter, config, evaluator, profileId };
}

class TestDurableAebStore implements AebDurableConsumptionStore {
  readonly durable = true as const;
  readonly ownershipFenced = true as const;
  readonly permanentConsumption = true as const;
  readonly atomicReplayFenced = true as const;
  readonly records = new Map<string, 'RESERVED' | 'CONSUMED'>();
  readonly replayOwners = new Map<string, string>();

  async reserve(key: string, replayKeys: readonly string[]) {
    if (this.records.has(key)) return 'CONSUMPTION_CONFLICT' as const;
    if (replayKeys.some((replay) => this.replayOwners.has(replay))) return 'NATIVE_REPLAY_CONFLICT' as const;
    this.records.set(key, 'RESERVED');
    for (const replay of replayKeys) this.replayOwners.set(replay, key);
    return 'RESERVED' as const;
  }

  async commit(key: string) {
    if (this.records.get(key) !== 'RESERVED') return false;
    this.records.set(key, 'CONSUMED');
    return true;
  }

  async release(key: string) {
    if (this.records.get(key) !== 'RESERVED') return false;
    this.records.delete(key);
    for (const [replay, owner] of this.replayOwners) if (owner === key) this.replayOwners.delete(replay);
    return true;
  }
}

class TestChallengeStore implements A2AAp2ChallengeStore {
  readonly durable = true as const;
  readonly atomicRegistration = true as const;
  readonly bodyBound = true as const;
  readonly permanentConsumption = true as const;
  readonly registered = new Set<string>();
  readonly consumed = new Set<string>();

  register(challenge: unknown) {
    this.registered.add(digestAeb(challenge));
  }

  async consume(challenge: unknown) {
    const key = digestAeb(challenge);
    if (!this.registered.has(key) || this.consumed.has(key)) return false;
    this.consumed.add(key);
    return true;
  }
}

function nativeArtifact(mandateId = 'ap2-mandate-1'): NativeArtifact {
  return { mandate_id: mandateId, serialized: `native-ap2:${mandateId}` };
}

function challenge(action: Action = ACTION, nonce = 'challenge-nonce-a2a-0001') {
  return {
    '@version': 'AE-CHALLENGE-v1',
    challenge_id: `challenge-${nonce}`,
    nonce,
    action_digest: digestAeb(action),
    action_profile: 'https://emiliaprotocol.ai/profiles/artifact-digest-v1',
    reliance_purpose: 'authorize one payment release',
    policy_id: 'policy:a2a-ap2:test',
    policy_digest: digestAeb({ policy: 'a2a-ap2-test' }),
    required_evidence: [{ requirement_id: 'ap2-native-authorization', type: 'ap2-native-authorization', status: 'current' }],
    present_as: [A2A_AP2_NATIVE_PRESENTATION_METHOD],
    obtain_hints: [],
    expires_at: '2026-08-09T17:05:00.000Z',
    audience: 'executor:a2a-ap2-test',
  };
}

function task(taskId = 'task-a2a-1', nonce = 'challenge-nonce-a2a-0001', action: Action = ACTION) {
  const body = challenge(action, nonce);
  return {
    challenge: body,
    task: createA2AAuthorizationChallengeTask({
      task_id: taskId,
      context_id: 'context-a2a-1',
      message_id: `message-${taskId}`,
      timestamp: '2026-08-09T16:59:30.000Z',
      challenge: body,
    }),
  };
}

function record(
  setup: ReturnType<typeof aebSetup>,
  artifact: NativeArtifact,
  taskId = 'task-a2a-1',
  nonce = 'challenge-nonce-a2a-0001',
  currentStatus = status(),
) {
  return evaluateAebEvidence({
    config: setup.config,
    adapters: { [AP2_NATIVE_AEB_ADAPTER_ID]: setup.adapter },
    operation_id: taskId,
    consumption_nonce: nonce,
    initiator_id: 'agent:a2a-client',
    executor_id: 'executor:a2a-ap2-test',
    requirement_ref: 'requirement:a2a-ap2',
    caid: CAID,
    expected_action: ACTION,
    legs: [{
      adapter_id: AP2_NATIVE_AEB_ADAPTER_ID,
      profile_id: setup.profileId,
      artifact_ref: `urn:ap2:mandate:${artifact.mandate_id}`,
      artifact,
      status: currentStatus,
    }],
    evaluated_at: NOW,
    signer: { key_id: 'evaluator:a2a-ap2-test', private_key: setup.evaluator.privateKey },
  }).record;
}

function executionHarness(providerThrows = false) {
  const signer = crypto.generateKeyPairSync('ed25519');
  let calls = 0;
  const actuator = new ConsequenceActuator({
    pins: {
      tenantId: 'tenant-a2a-ap2',
      caid: CAID,
      providerAccountId: 'provider-account-1',
      targetDigest: TARGET_DIGEST,
      operation: 'payment.release',
      envelopeIssuerId: 'authorization-service',
      envelopeKeyId: 'actuator-key-1',
      envelopePublicKey: signer.publicKey,
    },
    store: createMemoryConsequenceActuatorStore(),
    testOnly: true,
    now: () => NOW_MS,
    async perform() {
      calls += 1;
      if (providerThrows) throw new Error('provider acknowledgement lost');
      return { provider_reference: 'provider-result-1' };
    },
  });
  function execution(taskId: string, action: Action = ACTION) {
    const body = {
      '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
      issuer_id: 'authorization-service',
      tenant_id: 'tenant-a2a-ap2',
      attempt_id: taskId,
      action_digest: digestAeb(action),
      caid: CAID,
      provider_account_id: 'provider-account-1',
      target_digest: TARGET_DIGEST,
      operation: 'payment.release',
      idempotency_key: taskId,
      nonce: crypto.randomBytes(24).toString('base64url'),
      issued_at: '2026-08-09T16:59:59.000Z',
      expires_at: '2026-08-09T17:00:30.000Z',
    };
    return {
      envelope: signConsequenceExecutionEnvelope(body, { privateKey: signer.privateKey, keyId: 'actuator-key-1' }),
      attemptId: taskId,
      actionDigest: digestAeb(action),
      idempotencyKey: taskId,
    };
  }
  return { actuator, execution, calls: () => calls };
}

function gateFixture(providerThrows = false) {
  const assertions = new Map<string, NativeAssertion>([[
    'ap2-mandate-1',
    { accepted: true, role: 'ap2-native-authorization', subject: { id: 'human:alice', kind: 'human' }, action: ACTION },
  ]]);
  const setup = aebSetup(assertions);
  const harness = executionHarness(providerThrows);
  const aebStore = new TestDurableAebStore();
  const challengeStore = new TestChallengeStore();
  const statuses: Record<string, AebStatusInput> = {
    'urn:ap2:mandate:ap2-mandate-1': status(),
  };
  let expectedAction: Action = ACTION;
  let expectedCaid = CAID;
  let localAuthorization = true;
  const gate = new A2AAp2Gate({
    aeb_config: setup.config,
    adapters: { [AP2_NATIVE_AEB_ADAPTER_ID]: setup.adapter },
    aeb_store: aebStore,
    challenge_store: challengeStore,
    actuator: harness.actuator,
    now: () => NOW,
    resolve_action: () => ({ expected_action: expectedAction, expected_caid: expectedCaid }),
    resolve_current_statuses: () => ({ ...statuses }),
    authorize_local: () => localAuthorization,
    resolve_execution: ({ task_id, expected_action }) => harness.execution(task_id, expected_action as Action),
  });
  return {
    setup,
    assertions,
    aebStore,
    challengeStore,
    statuses,
    gate,
    ...harness,
    setExpected(action: Action, caid: string) { expectedAction = action; expectedCaid = caid; },
    denyLocal() { localAuthorization = false; },
  };
}

function request(fixture: ReturnType<typeof gateFixture>) {
  const artifact = nativeArtifact();
  const issued = task();
  fixture.challengeStore.register(issued.challenge);
  return {
    task: issued.task,
    evaluation: record(fixture.setup, artifact),
    artifacts: { [`urn:ap2:mandate:${artifact.mandate_id}`]: artifact },
  };
}

function state(result: A2AAp2GateDecision<unknown>) {
  return result.state;
}

describe('EMILIA Gate for A2A/AP2', () => {
  it('joins native AP2 evidence to CAID/AEB, reserves before effect, and returns ADMIT', async () => {
    const fixture = gateFixture();
    const result = await fixture.gate.execute(request(fixture));
    assert.equal(state(result), 'ADMIT', JSON.stringify(result));
    assert.equal(result.invoked, true);
    assert.equal(result.native_authorization.protocol, 'AP2');
    assert.equal(result.native_authorization.emilia_originated, false);
    assert.equal(fixture.calls(), 1);
  });

  it('refuses approve-A/execute-B using the executor-owned action before provider invocation', async () => {
    const fixture = gateFixture();
    const actionB = Object.freeze({ ...ACTION, payment_instruction_id: 'pi-gate-2' });
    const caidB = 'caid:1:payment.release.1:jcs-sha256:6TpWaRXORGYVDkPm92Lu4IcLGqmMKIufZiz_k17NIqM';
    fixture.setExpected(actionB, caidB);
    const candidate = request(fixture);
    const issuedB = task('task-a2a-1', 'challenge-nonce-a2a-0001', actionB);
    fixture.challengeStore.register(issuedB.challenge);
    const result = await fixture.gate.execute({ ...candidate, task: issuedB.task });
    assert.equal(state(result), 'REFUSE');
    assert.equal(result.reason, 'aeb_exact_action_mismatch');
    assert.equal(result.invoked, false);
    assert.equal(fixture.calls(), 0);
  });

  it('admits one concurrent attempt and refuses the rest', async () => {
    const fixture = gateFixture();
    const candidate = request(fixture);
    const results = await Promise.all([
      fixture.gate.execute(candidate),
      fixture.gate.execute(candidate),
      fixture.gate.execute(candidate),
    ]);
    assert.equal(results.filter((result) => result.state === 'ADMIT').length, 1);
    assert.equal(results.filter((result) => result.state === 'REFUSE').length, 2);
    assert.equal(fixture.calls(), 1);
  });

  it('refuses the same AP2 mandate replayed under another A2A task', async () => {
    const fixture = gateFixture();
    const first = await fixture.gate.execute(request(fixture));
    assert.equal(first.state, 'ADMIT', JSON.stringify(first));

    const artifact = nativeArtifact();
    const taskId = 'task-a2a-2';
    const nonce = 'challenge-nonce-a2a-0002';
    const issued = task(taskId, nonce);
    fixture.challengeStore.register(issued.challenge);
    const replay = await fixture.gate.execute({
      task: issued.task,
      evaluation: record(fixture.setup, artifact, taskId, nonce),
      artifacts: { [`urn:ap2:mandate:${artifact.mandate_id}`]: artifact },
    });
    assert.equal(replay.state, 'REFUSE');
    assert.equal(replay.reason, 'native_replay_conflict');
    assert.equal(fixture.calls(), 1);
  });

  it('refuses revoked evidence and AS-only evidence that does not satisfy the AP2 role', async () => {
    const revokedFixture = gateFixture();
    const revokedRequest = request(revokedFixture);
    revokedFixture.statuses['urn:ap2:mandate:ap2-mandate-1'] = status({ revoked: true });
    const revoked = await revokedFixture.gate.execute(revokedRequest);
    assert.equal(revoked.state, 'REFUSE');
    assert.equal(revoked.reason, 'evidence_revoked');
    assert.equal(revokedFixture.calls(), 0);

    const asFixture = gateFixture();
    asFixture.assertions.set('as-assertion-1', {
      accepted: true,
      role: 'authorization-server-confirmation',
      subject: { id: 'organization:malicious-as', kind: 'organization' },
      action: ACTION,
    });
    const asArtifact = nativeArtifact('as-assertion-1');
    const issued = task();
    asFixture.challengeStore.register(issued.challenge);
    asFixture.statuses['urn:ap2:mandate:as-assertion-1'] = status();
    const asOnly = await asFixture.gate.execute({
      task: issued.task,
      evaluation: record(asFixture.setup, asArtifact),
      artifacts: { 'urn:ap2:mandate:as-assertion-1': asArtifact },
    });
    assert.equal(asOnly.state, 'REFUSE');
    assert.equal(asFixture.calls(), 0);
  });

  it('returns INDETERMINATE and permanently prevents blind retry after provider timeout', async () => {
    const fixture = gateFixture(true);
    const candidate = request(fixture);
    const first = await fixture.gate.execute(candidate);
    assert.equal(first.state, 'INDETERMINATE', JSON.stringify(first));
    assert.equal(first.invoked, true);
    assert.equal(first.retry_allowed, false);

    const replay = await fixture.gate.execute(candidate);
    assert.equal(replay.state, 'REFUSE');
    assert.equal(replay.reason, 'challenge_unregistered_or_replayed');
    assert.equal(replay.invoked, false);
    assert.equal(fixture.calls(), 1);
  });
});
