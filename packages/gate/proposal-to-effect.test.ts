// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import {
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  pinnedConfigDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  createEg1Harness,
  createTrustedActionFirewall,
  EG1_DEFAULT_SELECTOR,
} from './index.js';
import {
  PROPOSAL_TO_EFFECT_VERSION,
  createProposalToEffect,
  proposalToEffectConsumptionNonce,
} from './proposal-to-effect.js';

const NOW = '2026-07-22T12:00:00Z';
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const PROPOSAL_INTEGRITY_DOMAIN = `${PROPOSAL_TO_EFFECT_VERSION}:INTEGRITY\0`;
const PROPOSAL_INTEGRITY_KEY = crypto.createHash('sha256').update('proposal-to-effect-test-key').digest();
const SERVER_CONTEXT = Object.freeze({
  tenant_id: 'tenant:acme',
  provider_id: 'provider:payments',
  provider_account_id: 'account:merchant-1',
  environment: 'sandbox',
  executor_id: 'executor:gate-1',
});
const VECTOR_SUITE = JSON.parse(fs.readFileSync(
  new URL('../../conformance/vectors/proposal-to-effect.v1.json', import.meta.url),
  'utf8',
));

function vector(id: string): any {
  const found = VECTOR_SUITE.vectors.find((candidate: any) => candidate.id === id);
  assert.ok(found, `missing proposal-to-effect vector: ${id}`);
  return found;
}

function registryEntry(entryId: string, kind: string, version: string, definition: unknown) {
  const entry: any = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function aebFixture(
  action: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
  executorId = SERVER_CONTEXT.executor_id,
) {
  const adapter = {
    id: 'test:human',
    version: '1',
    verifyNative({ artifact, status, trust_roots }: any) {
      const trusted = trust_roots.includes(artifact.root);
      return {
        native_verification: trusted ? 'VERIFIED' : 'FAILED',
        acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: status.checked_at,
          expires_at: status.expires_at,
          revocation_checked: status.revocation_checked,
          revoked: status.revoked,
          consumed: status.consumed,
          unavailable: status.unavailable === true,
        }),
        replay_unit: digestAeb({
          root: artifact.root,
          caid: artifact.caid,
          subject: 'human:alice',
        }),
        evidence_role: 'human-authorization',
        subject: { id: 'human:alice', kind: 'human' },
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, native, expected_action }: any) {
      return {
        mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
        caid: artifact.caid,
        action_digest: digestAeb(expected_action),
        reasons: [],
      };
    },
  };
  const profile: any = {
    version: 'payment-release-v1',
    definition: { action_type: 'payment.release' },
    registry_entry_ref: 'mapping:payment-release',
    mapper_id: 'mapper:payment-release',
    resolver: {
      id: 'resolver:payment-release',
      version: '1',
      implementation_digest: digestAeb({ implementation: 'resolver:payment-release:1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = mappingProfileDigest('payment-release', profile);
  const entries: any = {
    'mapping:payment-release': registryEntry(
      'mapping:payment-release',
      'mapping-profile',
      '1',
      { profile_digest: profile.profile_digest },
    ),
    'role:human-authorization': registryEntry(
      'role:human-authorization',
      'evidence-role',
      '1',
      { role: 'human-authorization', subject_kinds: ['human'] },
    ),
  };
  const registry: any = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:proposal-to-effect-test',
    epoch: 1,
    entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin: any = {
    version: '1',
    trust_roots: ['root:test'],
    config: { mode: 'offline' },
    max_status_age_sec: 300,
  };
  pin.config_digest = adapterPinDigest('test:human', pin);
  const evaluator = crypto.generateKeyPairSync('ed25519');
  const evaluatorPublicKey = evaluator.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const config: any = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:proposal-to-effect-test',
    evaluator_keys: { 'eval:test': { public_key: evaluatorPublicKey } },
    registry,
    accepted_mappers: ['mapper:payment-release'],
    adapters: { 'test:human': pin },
    profiles: { 'payment-release': profile },
    requirements: {
      'requirement:proposal-to-effect': {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: ['human-authorization'],
        terms: [
          { type: 'initiator-exclusion', roles: ['human-authorization'] },
          { type: 'executor-exclusion', roles: ['human-authorization'] },
          { type: 'one-time-consumption' },
        ],
      },
    },
  };
  const artifact = {
    root: 'root:test',
    caid: CAID,
    action,
  };
  const status = {
    checked_at: '2026-07-22T11:59:00Z',
    expires_at: '2026-07-22T12:05:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
  const evaluated = evaluateAebEvidence({
    config,
    adapters: { 'test:human': adapter },
    operation_id: 'operation:release-1',
    consumption_nonce: proposalToEffectConsumptionNonce(
      'operation:release-1',
      pinnedConfigDigest(config),
    ),
    initiator_id: 'agent:buyer',
    executor_id: executorId,
    requirement_ref: 'requirement:proposal-to-effect',
    caid: CAID,
    expected_action: action,
    legs: [{
      adapter_id: 'test:human',
      profile_id: 'payment-release',
      artifact_ref: 'artifact:human-approval',
      artifact,
      status,
    }],
    evaluated_at: NOW,
    signer: { key_id: 'eval:test', private_key: evaluator.privateKey },
  });
  return {
    adapters: { 'test:human': adapter },
    artifacts: { 'artifact:human-approval': artifact },
    current_statuses: { 'artifact:human-approval': status },
    config,
    evaluation: evaluated.record,
  };
}

function durableStore() {
  const states = new Map<string, 'RESERVED' | 'CONSUMED'>();
  const replayOwners = new Map<string, string>();
  return {
    durable: true as const,
    ownershipFenced: true as const,
    permanentConsumption: true as const,
    atomicReplayFenced: true as const,
    states,
    async reserve(key: string, replayKeys: readonly string[]) {
      if (states.has(key)) return false;
      if (replayKeys.some((replayKey) => replayOwners.has(replayKey))) return 'NATIVE_REPLAY_CONFLICT';
      states.set(key, 'RESERVED');
      for (const replayKey of replayKeys) replayOwners.set(replayKey, key);
      return 'RESERVED';
    },
    async commit(key: string) {
      if (states.get(key) !== 'RESERVED') return false;
      states.set(key, 'CONSUMED');
      return true;
    },
    async release(key: string) {
      if (states.get(key) !== 'RESERVED') return false;
      states.delete(key);
      for (const [replayKey, owner] of replayOwners) {
        if (owner === key) replayOwners.delete(replayKey);
      }
      return true;
    },
  };
}

type TestAttemptState = 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED' | 'ESCALATED';

function consequenceAttemptStore() {
  let ownerSequence = 0;
  const entries = new Map<string, any>();
  const keyFor = (tenantId: string, attemptId: string) => `${tenantId}\0${attemptId}`;
  return {
    durable: true as const,
    ownershipFenced: true as const,
    compareAndSwap: true as const,
    atomicEvidenceBinding: true as const,
    entries,
    async reserve(binding: any) {
      const key = keyFor(binding.tenant_id, binding.attempt_id);
      if (entries.has(key)) return { reserved: false, reason: 'attempt_exists' };
      const owner = `owner:${++ownerSequence}:${crypto.randomBytes(12).toString('base64url')}`;
      entries.set(key, { ...structuredClone(binding), owner, state: 'RESERVED' as TestAttemptState, evidence: null });
      return { reserved: true, owner };
    },
    async transition(input: any) {
      const key = keyFor(input.tenant_id, input.attempt_id);
      const entry = entries.get(key);
      if (!entry || entry.owner !== input.owner || entry.state !== input.expected_state) return false;
      const allowed = (input.expected_state === 'RESERVED' && input.next_state === 'INVOKING')
        || (input.expected_state === 'INVOKING' && input.next_state === 'INDETERMINATE')
        || (input.expected_state === 'INDETERMINATE'
          && ['COMMITTED', 'RELEASED', 'ESCALATED'].includes(input.next_state));
      if (!allowed) return false;
      entry.state = input.next_state;
      return true;
    },
    async reconcile(input: any) {
      const key = keyFor(input.tenant_id, input.attempt_id);
      const entry = entries.get(key);
      if (!entry || entry.owner !== input.owner || input.expected_state !== 'INDETERMINATE'
          || entry.state !== 'INDETERMINATE') return false;
      if (entry.tenant_id !== input.evidence.tenant_id
          || entry.request_digest !== input.evidence.request_digest
          || entry.provider_id !== input.evidence.provider_id
          || entry.provider_account_id !== input.evidence.provider_account_id
          || entry.environment !== input.evidence.environment
          || entry.attempt_id !== input.evidence.attempt_id) return false;
      entry.evidence = structuredClone(input.evidence);
      entry.state = input.next_state;
      return true;
    },
    async read(binding: any) {
      const entry = entries.get(keyFor(binding.tenant_id, binding.attempt_id));
      if (!entry
          || entry.provider_id !== binding.provider_id
          || entry.provider_account_id !== binding.provider_account_id
          || entry.environment !== binding.environment
          || entry.request_digest !== binding.request_digest) return null;
      return { state: entry.state, evidence_digest: entry.evidence?.evidence_digest ?? null };
    },
  };
}

function signProposalIntegrity(proposal: any): void {
  const unsigned = structuredClone(proposal);
  delete unsigned.integrity;
  proposal.integrity = {
    alg: 'HMAC-SHA256',
    value: crypto.createHmac('sha256', PROPOSAL_INTEGRITY_KEY)
      .update(PROPOSAL_INTEGRITY_DOMAIN)
      .update(digestAeb(unsigned))
      .digest('base64url'),
  };
}

function providerEvidence(proposal: any, attempt: any, outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'ESCALATED') {
  return {
    authenticated: true,
    evidence_id: `evidence:${attempt.attempt_id}`,
    observed_at: NOW,
    outcome,
    operation_id: proposal.operation_id,
    caid: proposal.caid,
    action_digest: proposal.aeb_action_digest,
    tenant_id: proposal.consequence.tenant_id,
    request_digest: proposal.consequence.request_digest,
    provider_id: proposal.consequence.provider_id,
    provider_account_id: proposal.consequence.provider_account_id,
    environment: proposal.consequence.environment,
    attempt_id: attempt.attempt_id,
  };
}

function fixture({
  status = {},
  gate_override = null,
  current_status = null,
  aeb_executor_id = SERVER_CONTEXT.executor_id,
  provider_verifier = null,
  attempt_ids = ['attempt:release-1', 'attempt:release-2', 'attempt:release-3'],
  now = () => Date.parse(NOW),
}: {
  status?: Record<string, unknown>;
  gate_override?: any;
  current_status?: Record<string, unknown> | null;
  aeb_executor_id?: string;
  provider_verifier?: any;
  attempt_ids?: string[];
  now?: () => number;
} = {}) {
  const harness = createEg1Harness({ now });
  const aeb = aebFixture(harness.action as Record<string, unknown>, status, aeb_executor_id);
  const aebStore = durableStore();
  const attemptStore = consequenceAttemptStore();
  const queuedAttemptIds = [...attempt_ids];
  const gate = gate_override ?? createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
    now,
  });
  const controller = createProposalToEffect({
    gate,
    proposal_integrity: { hmac_sha256_key: PROPOSAL_INTEGRITY_KEY },
    consequence: {
      ...SERVER_CONTEXT,
      store: attemptStore,
      create_attempt_id: async () => queuedAttemptIds.shift() ?? `attempt:${crypto.randomUUID()}`,
    },
    profiles: {
      'payment-release': {
        id: 'payment-release',
        action_type: 'payment.release',
        selector: EG1_DEFAULT_SELECTOR,
        required_fields: Object.keys(harness.action),
        authorization: {
          authorization_endpoint: 'https://approve.example.test/v1/approvals',
          flow: 'EP-APPROVAL-v1',
        },
        aeb_requirement_ref: 'requirement:proposal-to-effect',
        ttl_sec: 300,
        canonicalize_action(input: unknown) {
          return { action: structuredClone(input), caid: CAID };
        },
      },
    },
    aeb: {
      config: aeb.config,
      adapters: aeb.adapters,
      store: aebStore,
      resolve_artifacts: async () => aeb.artifacts,
      currentStatusResolver: async ({ leg }: any) => current_status
        ?? aeb.current_statuses[leg.artifact_ref],
      statusVerifier: async ({ status_artifact }: any) => {
        if (!status_artifact || status_artifact.unavailable === true) {
          return { valid: false, outcome: 'indeterminate', reason: 'status_unavailable' };
        }
        if (status_artifact.revoked === true) {
          return { valid: true, outcome: 'revoked', status: structuredClone(status_artifact) };
        }
        return { valid: true, outcome: 'current_not_revoked', status: structuredClone(status_artifact) };
      },
      verify_provider_evidence: provider_verifier ?? (async ({ evidence, expected }: any) => {
        const valid = evidence?.authenticated === true
          && evidence.operation_id === expected.operation_id
          && evidence.caid === expected.caid
          && evidence.action_digest === expected.action_digest
          && typeof evidence.evidence_id === 'string'
          && typeof evidence.observed_at === 'string'
          && evidence.tenant_id === expected.tenant_id
          && evidence.request_digest === expected.request_digest
          && evidence.provider_id === expected.provider_id
          && evidence.provider_account_id === expected.provider_account_id
          && evidence.environment === expected.environment
          && evidence.attempt_id === expected.attempt_id
          && ['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(evidence.outcome);
        return {
          valid,
          outcome: evidence?.outcome,
          evidence_id: evidence?.evidence_id,
          observed_at: evidence?.observed_at,
          tenant_id: evidence?.tenant_id,
          request_digest: evidence?.request_digest,
          provider_id: evidence?.provider_id,
          provider_account_id: evidence?.provider_account_id,
          environment: evidence?.environment,
          attempt_id: evidence?.attempt_id,
          operation_id: evidence?.operation_id,
          caid: evidence?.caid,
          action_digest: evidence?.action_digest,
          evidence_digest: evidence ? digestAeb(evidence) : null,
        };
      }),
    },
    now,
  });
  const proposal = controller.prepare({
    proposal_id: 'proposal:release-1',
    profile_id: 'payment-release',
    operation_id: 'operation:release-1',
    initiator_id: 'agent:buyer',
    action: harness.action,
  });
  return { aeb, aebStore, attemptStore, controller, gate, harness, proposal };
}

function attemptEntry(store: ReturnType<typeof consequenceAttemptStore>, attempt: any) {
  return store.entries.get(`${attempt.tenant_id}\0${attempt.attempt_id}`);
}

async function enterIndeterminate(f: ReturnType<typeof fixture>, message = 'provider response lost') {
  let attempt: any = null;
  await assert.rejects(
    f.controller.execute({
      proposal: f.proposal,
      receipt: f.harness.mint(),
      evaluation: f.aeb.evaluation,
    }, async () => {
      throw new Error(message);
    }),
    (error: any) => {
      const publicAttempt = error?.proposalToEffect?.attempt;
      const handle = f.controller.getReconciliationHandle(error);
      attempt = handle ? { ...publicAttempt, ...handle } : null;
      return error?.emiliaGateOutcome?.outcome === 'indeterminate'
        && typeof attempt?.attempt_id === 'string'
        && typeof attempt?.owner === 'string';
    },
  );
  return attempt;
}

test('proposal is a server-derived request object, not a second authorization artifact', () => {
  const f = fixture();
  const expected = VECTOR_SUITE.expected;
  assert.equal(f.proposal['@version'], PROPOSAL_TO_EFFECT_VERSION);
  assert.deepEqual(f.proposal.action, VECTOR_SUITE.action);
  assert.equal(f.proposal.caid, expected.caid);
  assert.equal(f.proposal.action_digest, expected.action_digest);
  assert.equal(f.proposal.aeb_action_digest, expected.aeb_action_digest);
  assert.equal(f.proposal.aeb.consumption_nonce, f.aeb.evaluation.consumption_nonce);
  assert.equal(f.proposal.challenge.action_hash, f.proposal.action_digest);
  assert.equal(f.proposal.authorization.flow, VECTOR_SUITE.profile.authorization_flow);
  assert.deepEqual(
    { ...f.proposal.consequence, request_digest: undefined },
    { ...SERVER_CONTEXT, request_digest: undefined },
  );
  assert.match(f.proposal.consequence.request_digest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(f.proposal.integrity).sort(), ['alg', 'value']);
  assert.equal(f.proposal.integrity.alg, 'HMAC-SHA256');
  assert.match(f.proposal.integrity.value, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Object.hasOwn(f.proposal, 'attempt_id'), false, 'attempt IDs are selected per server-side invocation');
  const claim = vector('proposal_is_not_authority').expect;
  assert.equal(Object.hasOwn(f.proposal, 'signature'), claim.signature);
  assert.equal(Object.hasOwn(f.proposal, 'permit'), claim.permit);
  assert.equal(Object.hasOwn(f.proposal, 'authorized'), claim.authorized);
});

test('exact proposal mutation refuses before Gate, reservation, or effect', async () => {
  const f = fixture();
  const mutated = structuredClone(f.proposal);
  const mutation = vector('mutated_material_action_refused');
  mutated.action[mutation.mutation.field] = mutation.mutation.value;
  let invoked = false;
  await assert.rejects(
    f.controller.execute({ proposal: mutated, receipt: f.harness.mint(), evaluation: f.aeb.evaluation }, async () => {
      invoked = true;
    }),
    /proposal_integrity_invalid/,
  );
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('recomputed proposal digests cannot detach the action from signed AEB evidence', async () => {
  const f = fixture();
  const action = structuredClone(f.proposal.action);
  action.amount_usd = 40001;
  const mutated = f.controller.prepare({
    proposal_id: f.proposal.proposal_id,
    profile_id: f.proposal.profile_id,
    operation_id: f.proposal.operation_id,
    initiator_id: f.proposal.initiator_id,
    action,
  });
  let invoked = false;
  const out = await f.controller.execute({
    proposal: mutated,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'aeb_evaluation_binding_mismatch');
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('evaluation consumption nonce is bound to the server-derived proposal operation', async () => {
  const f = fixture();
  const evaluation = structuredClone(f.aeb.evaluation);
  evaluation.consumption_nonce = 'nonce:alternate-valid-evaluation';
  let invoked = false;
  const out = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation,
  }, async () => { invoked = true; });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'aeb_evaluation_binding_mismatch');
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('proposal AEB block is closed and refuses presenter-added control fields', () => {
  const f = fixture();
  const proposal = structuredClone(f.proposal);
  proposal.aeb.authorized = true;
  signProposalIntegrity(proposal);
  assert.throws(() => f.controller.verifyProposal(proposal), /proposal_aeb_pin_mismatch/);
});

test('server proposal integrity cannot bless a non-exact TTL or future creation time', () => {
  let clock = Date.parse(NOW);
  const f = fixture({ now: () => clock });
  const wrongTtl = structuredClone(f.proposal);
  wrongTtl.expires_at = new Date(Date.parse(wrongTtl.expires_at) + 1).toISOString();
  signProposalIntegrity(wrongTtl);
  assert.throws(() => f.controller.verifyProposal(wrongTtl), /proposal_ttl_mismatch/);

  clock -= 1;
  assert.throws(() => f.controller.verifyProposal(f.proposal), /proposal_created_in_future/);
});

test('server-resolved authenticated current status and exact executor are required at execution', async () => {
  const indeterminate = fixture({ current_status: { unavailable: true } });
  let invoked = false;
  const missing = await indeterminate.controller.execute({
    proposal: indeterminate.proposal,
    receipt: indeterminate.harness.mint(),
    evaluation: indeterminate.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(missing.ok, false);
  assert.equal(missing.reason, 'aeb_current_status_refused');
  assert.equal(invoked, false);
  assert.equal(indeterminate.aebStore.states.size, 0);
  assert.equal(indeterminate.attemptStore.entries.size, 0);

  const wrongExecutor = fixture({ aeb_executor_id: 'executor:other' });
  const mismatched = await wrongExecutor.controller.execute({
    proposal: wrongExecutor.proposal,
    receipt: wrongExecutor.harness.mint(),
    evaluation: wrongExecutor.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(mismatched.ok, false);
  assert.equal(mismatched.reason, 'aeb_evaluation_binding_mismatch');
  assert.equal(wrongExecutor.aebStore.states.size, 0);
});

test('presenter current_statuses are ignored in favor of the configured resolver and verifier', async () => {
  const f = fixture();
  const result = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
    current_statuses: {
      'artifact:human-approval': { unavailable: true, revoked: true },
    },
  } as any, async () => ({ released: true }));
  assert.equal(result.ok, true, JSON.stringify(result));
});

test('verified AEB plus Gate authorization reserves once and executes the exact effect', async () => {
  const f = fixture();
  let effects = 0;
  const first = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async ({ action }: any) => {
    effects += 1;
    return { released: action.payment_instruction_id };
  });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.result.released, f.harness.action.payment_instruction_id);
  assert.equal(effects, 1);
  assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
  assert.equal(first.consequence.state, 'COMMITTED');
  assert.equal(Object.hasOwn(first.consequence.attempt, 'owner'), false);
  assert.equal(attemptEntry(f.attemptStore, first.consequence.attempt).state, 'COMMITTED');
  assert.equal(first.consequence.attempt.request_digest, f.proposal.consequence.request_digest);

  const replay = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    effects += 1;
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, vector('fresh_receipt_cannot_replay_consumed_operation').expect.reason);
  assert.equal(effects, 1, 'a fresh receipt cannot replay one proposal operation');
});

test('failed AEB commit keeps an executed effect indeterminate and repairable', async () => {
  const f = fixture();
  f.aebStore.commit = async () => false;
  let effects = 0;
  await assert.rejects(
    f.controller.execute({
      proposal: f.proposal,
      receipt: f.harness.mint(),
      evaluation: f.aeb.evaluation,
    }, async () => {
      effects += 1;
      return { released: true };
    }),
    (error: any) => error?.code === vector('executed_effect_commit_failure_stays_reserved').expect.error,
  );
  assert.equal(effects, 1);
  assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
  assert.deepEqual([...f.attemptStore.entries.values()].map((entry) => entry.state), ['INDETERMINATE']);
});

test('owner capability is non-enumerable and retrieved only from the exact in-process object', async () => {
  const f = fixture();
  let captured: any;
  await assert.rejects(f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    throw new Error('lost acknowledgement');
  }), (error: any) => {
    captured = error;
    return true;
  });
  assert.equal(Object.hasOwn(captured.proposalToEffect.attempt, 'owner'), false);
  assert.equal(JSON.stringify(captured).includes('owner:'), false);
  const handle = f.controller.getReconciliationHandle(captured);
  assert.equal(typeof handle?.owner, 'string');
  assert.equal(f.controller.getReconciliationHandle(structuredClone(captured)), null);
});

test('provider verifier cannot assert valid while omitting exact-action reflected claims', async () => {
  const f = fixture({
    provider_verifier: async ({ evidence }: any) => ({
      valid: true,
      outcome: evidence.outcome,
      evidence_id: evidence.evidence_id,
      observed_at: evidence.observed_at,
      tenant_id: evidence.tenant_id,
      request_digest: evidence.request_digest,
      provider_id: evidence.provider_id,
      provider_account_id: evidence.provider_account_id,
      environment: evidence.environment,
      attempt_id: evidence.attempt_id,
      evidence_digest: digestAeb(evidence),
    }),
  });
  const attempt = await enterIndeterminate(f);
  const out = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt,
    provider_evidence: providerEvidence(f.proposal, attempt, 'COMMITTED'),
  });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'provider_evidence_binding_mismatch');
  assert.equal(attemptEntry(f.attemptStore, attempt).state, 'INDETERMINATE');
});

test('provider evidence predating the proposal cannot terminalize an attempt', async () => {
  const f = fixture();
  const attempt = await enterIndeterminate(f);
  const evidence = providerEvidence(f.proposal, attempt, 'COMMITTED');
  evidence.observed_at = '2026-07-22T09:59:59.000Z';
  const out = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt,
    provider_evidence: evidence,
  });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'provider_evidence_unverified');
  assert.equal(attemptEntry(f.attemptStore, attempt).state, 'INDETERMINATE');
});

test('repairAeb converges legacy terminal consequence states without invoking an effect', async () => {
  const committedFixture = fixture();
  const committedAttempt = await enterIndeterminate(committedFixture);
  attemptEntry(committedFixture.attemptStore, committedAttempt).state = 'COMMITTED';
  const committedPublic = { ...committedAttempt };
  delete committedPublic.owner;
  const committed = await committedFixture.controller.repairAeb({
    proposal: committedFixture.proposal,
    evaluation: committedFixture.aeb.evaluation,
    attempt: committedPublic,
  });
  assert.equal(committed.ok, true, JSON.stringify(committed));
  assert.equal(committed.aeb.state, 'CONSUMED');

  const releasedFixture = fixture();
  const releasedAttempt = await enterIndeterminate(releasedFixture);
  attemptEntry(releasedFixture.attemptStore, releasedAttempt).state = 'RELEASED';
  const releasedPublic = { ...releasedAttempt };
  delete releasedPublic.owner;
  const released = await releasedFixture.controller.repairAeb({
    proposal: releasedFixture.proposal,
    evaluation: releasedFixture.aeb.evaluation,
    attempt: releasedPublic,
  });
  assert.equal(released.ok, true, JSON.stringify(released));
  assert.equal(released.aeb.state, 'AVAILABLE');
});

test('stale AEB evidence fails closed before Gate reservation and effect', async () => {
  const f = fixture({ status: { checked_at: '2026-07-22T10:00:00Z' } });
  let invoked = false;
  const out = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(out.ok, false);
  assert.equal(out.reason, vector('stale_aeb_refused').expect.reason);
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('Gate refusal never consumes the proposal operation reservation', async () => {
  const f = fixture();
  let invoked = false;
  const out = await f.controller.execute({
    proposal: f.proposal,
    receipt: null,
    evaluation: f.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(out.ok, false);
  assert.match(out.reason, /receipt_required/);
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('Gate pass-through cannot satisfy a Proposal-to-Effect profile', async () => {
  let runCalled = false;
  const f = fixture({
    gate_override: {
      async check() {
        return { allow: true, status: 200, reason: 'not_guarded', requirement: null };
      },
      async run() {
        runCalled = true;
        return { ok: true };
      },
    },
  });
  let invoked = false;
  const out = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => { invoked = true; });
  assert.equal(out.ok, false);
  assert.equal(out.reason, vector('unguarded_gate_selector_refused').expect.reason);
  assert.equal(runCalled, false);
  assert.equal(invoked, false);
  assert.equal(f.aebStore.states.size, 0);
});

test('indeterminate effect freezes replay until authenticated provider reconciliation', async () => {
  const f = fixture();
  const attempt = await enterIndeterminate(f);
  assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
  assert.equal(attemptEntry(f.attemptStore, attempt).state, 'INDETERMINATE');

  const blocked = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => assert.fail('blind replay crossed the effect boundary'));
  assert.equal(blocked.ok, false);
  assert.equal(blocked.reason, 'aeb_consumption_conflict');

  const wrong = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt,
    provider_evidence: { ...providerEvidence(f.proposal, attempt, 'COMMITTED'), authenticated: false },
  });
  assert.equal(wrong.ok, false);
  assert.equal(wrong.reason, 'provider_evidence_unverified');
  assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);

  const reconciled = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt,
    provider_evidence: providerEvidence(f.proposal, attempt, 'COMMITTED'),
  });
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.state, 'COMMITTED');
  assert.equal(attemptEntry(f.attemptStore, attempt).state, 'COMMITTED');
  assert.equal(attemptEntry(f.attemptStore, attempt).evidence.evidence_id, `evidence:${attempt.attempt_id}`);
  assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
});

test('authenticated NOT_COMMITTED reconciliation permits one explicit retry', async () => {
  const f = fixture();
  let effects = 0;
  let firstAttempt: any = null;
  await assert.rejects(f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    effects += 1;
    throw new Error('provider rejected before commit but response was lost');
  }), (error: any) => {
    const publicAttempt = error?.proposalToEffect?.attempt;
    const handle = f.controller.getReconciliationHandle(error);
    firstAttempt = handle ? { ...publicAttempt, ...handle } : null;
    return error?.emiliaGateOutcome?.outcome === 'indeterminate' && Boolean(firstAttempt);
  });
  const reconciled = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt: firstAttempt,
    provider_evidence: providerEvidence(f.proposal, firstAttempt, 'NOT_COMMITTED'),
  });
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.state, 'RELEASED');
  assert.equal(attemptEntry(f.attemptStore, firstAttempt).state, 'RELEASED');

  const retried = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    effects += 1;
    return { released: true };
  });
  assert.equal(retried.ok, true);
  assert.equal(effects, 2);
  assert.notEqual(retried.consequence.attempt.attempt_id, firstAttempt.attempt_id);
  assert.equal(attemptEntry(f.attemptStore, retried.consequence.attempt).state, 'COMMITTED');
  assert.deepEqual([...f.aebStore.states.values()], ['CONSUMED']);
});

test('NOT_COMMITTED reconciliation cannot run concurrently with an invoking effect', async () => {
  let effectStarted!: () => void;
  let finishEffect!: () => void;
  const started = new Promise<void>((resolve) => { effectStarted = resolve; });
  const finish = new Promise<void>((resolve) => { finishEffect = resolve; });
  const f = fixture({
    gate_override: {
      async check() {
        return { allow: true, reason: 'authorized', requirement: { receipt_required: true } };
      },
      async run(_input: any, callback: any) {
        const result = await callback({ decision: 'authorized' });
        return { ok: true, result };
      },
    },
  });
  const executing = f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    effectStarted();
    await finish;
    return { released: true };
  });
  const phase = await Promise.race([
    started.then(() => 'started' as const),
    executing.then(() => 'ended' as const, () => 'ended' as const),
  ]);
  if (phase !== 'started') {
    finishEffect();
    assert.fail('execution refused before reaching the controlled effect');
  }
  const entry = [...f.attemptStore.entries.values()][0];
  assert.equal(entry.state, 'INVOKING');
  const attempt = { tenant_id: entry.tenant_id, attempt_id: entry.attempt_id, owner: entry.owner };
  const raced = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt,
    provider_evidence: providerEvidence(f.proposal, attempt, 'NOT_COMMITTED'),
  });
  const stateDuringRace = entry.state;
  const aebDuringRace = [...f.aebStore.states.values()];
  finishEffect();
  const completion = await executing.then(
    (value: any) => ({ value, error: null }),
    (error: any) => ({ value: null, error }),
  );
  assert.equal(raced.ok, false);
  assert.equal(raced.reason, 'consequence_attempt_not_indeterminate');
  assert.equal(stateDuringRace, 'INVOKING');
  assert.deepEqual(aebDuringRace, ['RESERVED']);
  assert.equal(completion.error, null);
  assert.equal(completion.value.ok, true);
  assert.equal(entry.state, 'COMMITTED');
});

test('attempt-1 evidence and delayed owner transitions cannot mutate attempt-2 or reopen attempt-1', async () => {
  const f = fixture({
    provider_verifier: async ({ evidence }: any) => ({
      valid: true,
      outcome: evidence.outcome,
      evidence_id: evidence.evidence_id,
      observed_at: evidence.observed_at,
      tenant_id: evidence.tenant_id,
      request_digest: evidence.request_digest,
      provider_id: evidence.provider_id,
      provider_account_id: evidence.provider_account_id,
      environment: evidence.environment,
      attempt_id: evidence.attempt_id,
      operation_id: evidence.operation_id,
      caid: evidence.caid,
      action_digest: evidence.action_digest,
      evidence_digest: digestAeb(evidence),
    }),
  });
  const attempt1 = await enterIndeterminate(f, 'attempt 1 response lost');
  const evidence1 = providerEvidence(f.proposal, attempt1, 'NOT_COMMITTED');
  const released = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt: attempt1,
    provider_evidence: evidence1,
  });
  assert.equal(released.state, 'RELEASED');

  const attempt2 = await enterIndeterminate(f, 'attempt 2 response lost');
  assert.notEqual(attempt2.attempt_id, attempt1.attempt_id);
  const replayed = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt: attempt2,
    provider_evidence: evidence1,
  });
  assert.equal(replayed.ok, false);
  assert.equal(replayed.reason, 'provider_evidence_binding_mismatch');
  assert.equal(attemptEntry(f.attemptStore, attempt2).state, 'INDETERMINATE');

  const wrongOwner = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt: { ...attempt2, owner: attempt1.owner },
    provider_evidence: providerEvidence(f.proposal, attempt2, 'NOT_COMMITTED'),
  });
  assert.equal(wrongOwner.ok, false);
  assert.equal(wrongOwner.reason, 'consequence_attempt_not_indeterminate');
  assert.equal(attemptEntry(f.attemptStore, attempt2).state, 'INDETERMINATE');

  const delayed = await f.controller.reconcile({
    proposal: f.proposal,
    evaluation: f.aeb.evaluation,
    attempt: attempt1,
    provider_evidence: providerEvidence(f.proposal, attempt1, 'COMMITTED'),
  });
  assert.equal(delayed.ok, false);
  assert.equal(delayed.reason, 'consequence_attempt_not_indeterminate');
  assert.equal(attemptEntry(f.attemptStore, attempt1).state, 'RELEASED');
  assert.equal(attemptEntry(f.attemptStore, attempt2).state, 'INDETERMINATE');
});

test('a duck-typed Gate that invokes the callback then returns refusal freezes custody', async () => {
  let effects = 0;
  const f = fixture({
    gate_override: {
      async check() {
        return { allow: true, reason: 'authorized', requirement: { receipt_required: true } };
      },
      async run(_input: any, callback: any) {
        await callback({ decision: 'authorized' });
        return { ok: false, reason: 'dishonest_refusal' };
      },
    },
  });
  const refused = await f.controller.execute({
    proposal: f.proposal,
    receipt: f.harness.mint(),
    evaluation: f.aeb.evaluation,
  }, async () => {
    effects += 1;
    return { released: true };
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.reason, 'dishonest_refusal');
  assert.equal(effects, 1);
  assert.equal(refused.consequence.state, 'INDETERMINATE');
  assert.equal(attemptEntry(f.attemptStore, refused.consequence.attempt).state, 'INDETERMINATE');
  assert.deepEqual([...f.aebStore.states.values()], ['RESERVED']);
});

test('beginApproval uses the existing pinned EP-APPROVAL-v1 acquisition rail', async () => {
  const f = fixture();
  let posted: any = null;
  const pending = await f.controller.beginApproval({
    proposal: f.proposal,
    approver_id: 'approver@example.test',
    idempotency_key: 'proposal-release-0001',
    requester_authorization: 'Bearer ep_requester_test_12345678',
    fetch_impl: async (_url: any, init: any) => {
      posted = JSON.parse(init.body);
      return new Response(JSON.stringify({
        request_id: `apr_${'a'.repeat(32)}`,
        approval_url: 'https://approve.example.test/review/1',
        poll_token: `apt_${'b'.repeat(48)}`,
        status: 'pending',
        expires_at: '2026-07-22T12:05:00Z',
      }), { status: 201, headers: { 'content-type': 'application/json' } });
    },
  });
  assert.equal(pending.status, 'pending');
  assert.equal(posted.flow, 'EP-APPROVAL-v1');
  assert.deepEqual(posted.action, f.proposal.action);
  assert.equal(posted.challenge.action_hash, f.proposal.action_digest);
  assert.equal(posted.permit, undefined);
});
