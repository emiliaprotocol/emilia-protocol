// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createConsequenceControlRuntime,
  publicAttemptBinding,
} from '../src/runtime.js';

const PRINCIPAL = Object.freeze({ id: 'principal:operator' });
const OTHER_PRINCIPAL = Object.freeze({ id: 'principal:other' });

function proposal(overrides = {}) {
  return {
    '@version': 'EMILIA-PROPOSAL-TO-EFFECT-v1',
    proposal_id: 'proposal:0000000000000001',
    operation_id: 'operation:0000000000000001',
    initiator_id: PRINCIPAL.id,
    profile_id: 'github.repo.delete.v1',
    action: {
      action_type: 'github.repo.delete',
      owner: 'emiliaprotocol',
      repo: 'gate-smoke-target',
    },
    consequence: {
      tenant_id: 'tenant:emilia',
      provider_id: 'github',
      provider_account_id: 'emiliaprotocol',
      environment: 'production-smoke',
      executor_id: 'executor:managed-gate',
      request_digest: `sha256:${'1'.repeat(64)}`,
    },
    ...overrides,
  };
}

function publicAttempt(overrides = {}) {
  return {
    tenant_id: 'tenant:emilia',
    provider_id: 'github',
    provider_account_id: 'emiliaprotocol',
    environment: 'production-smoke',
    attempt_id: 'attempt:0000000000000001',
    request_digest: `sha256:${'1'.repeat(64)}`,
    ...overrides,
  };
}

function evidence() {
  return {
    artifacts: { 'artifact:approval': { signed: true } },
    statuses: { 'artifact:approval': { current: true } },
  };
}

function fixture(overrides = {}) {
  const calls = [];
  const controller = {
    verifyProposal(candidate) {
      calls.push(['verifyProposal', candidate]);
      if (candidate?.['@version'] !== 'EMILIA-PROPOSAL-TO-EFFECT-v1') {
        throw new Error('proposal_shape_invalid');
      }
      return { proposal: structuredClone(candidate), profile: { id: candidate.profile_id } };
    },
    prepare(input) {
      calls.push(['prepare', input]);
      return proposal({
        proposal_id: input.proposal_id,
        operation_id: input.operation_id,
        initiator_id: input.initiator_id,
        profile_id: input.profile_id,
        action: structuredClone(input.action),
      });
    },
    async beginApproval(input) {
      calls.push(['beginApproval', input]);
      return { request_id: 'approval:1', status: 'pending', poll_token: 'poll:1' };
    },
    async pollApproval(input) {
      calls.push(['pollApproval', input]);
      return { request_id: input.request_id, status: 'approved', receipt: { id: 'receipt:1' } };
    },
    async execute(input, effect) {
      calls.push(['execute', input]);
      const effectResult = await effect({
        action: structuredClone(input.proposal.action),
        proposal: structuredClone(input.proposal),
        authorization: { allow: true },
        attempt: publicAttempt(),
      });
      return { ok: true, consequence: { state: 'COMMITTED', attempt: publicAttempt() }, effect: effectResult };
    },
    async reconcile(input) {
      calls.push(['reconcile', input]);
      return { ok: true, state: 'COMMITTED', consequence: { state: 'COMMITTED', attempt: publicAttempt() } };
    },
    async repairAeb(input) {
      calls.push(['repairAeb', input]);
      return { ok: true, state: 'COMMITTED', consequence: { state: 'COMMITTED', attempt: publicAttempt() } };
    },
    getReconciliationHandle(error) {
      return error?.handle ?? null;
    },
  };
  const config = {
    controller,
    authenticateRequest: async () => PRINCIPAL,
    authorizeProfile: async () => true,
    effectForProfile: async () => async () => ({ provider_status: 204 }),
    requesterAuthorization: async () => 'Bearer acquisition-token',
    lookupAttempt: async ({ lookup }) => ({
      ...lookup,
      attempt_id: 'attempt:0000000000000001',
      state: 'INDETERMINATE',
    }),
    recoverAttempt: async ({ attempt }) => ({
      tenant_id: attempt.tenant_id,
      attempt_id: attempt.attempt_id,
      owner: 'pto-owner:v1:server-only-owner-capability',
    }),
    aebRecoveryAuthorization: async () => ({ recovery: 'server-only' }),
    withEvidenceContext: async (context, work) => {
      calls.push(['withEvidenceContext', context]);
      return work();
    },
    readiness: async () => ({ ok: true }),
    idFactory: () => 'proposal:0000000000000001',
    ...overrides,
  };
  return { runtime: createConsequenceControlRuntime(config), calls, controller, config };
}

test('prepare derives initiator and proposal id on the server', async () => {
  const { runtime, calls } = fixture();
  const result = await runtime.prepare({
    principal: PRINCIPAL,
    body: {
      profile_id: 'github.repo.delete.v1',
      operation_id: 'operation:0000000000000001',
      action: {
        action_type: 'github.repo.delete',
        owner: 'emiliaprotocol',
        repo: 'gate-smoke-target',
      },
    },
  });

  assert.equal(result.status, 201);
  assert.equal(result.body.proposal.initiator_id, PRINCIPAL.id);
  assert.equal(result.body.proposal.proposal_id, 'proposal:0000000000000001');
  assert.equal(calls.find(([name]) => name === 'prepare')[1].initiator_id, PRINCIPAL.id);
});

test('prepare rejects caller-controlled initiator and extra fields', async () => {
  const { runtime, calls } = fixture();
  const result = await runtime.prepare({
    principal: PRINCIPAL,
    body: {
      profile_id: 'github.repo.delete.v1',
      operation_id: 'operation:0000000000000001',
      initiator_id: OTHER_PRINCIPAL.id,
      action: {},
    },
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error.code, 'request_fields_invalid');
  assert.equal(calls.some(([name]) => name === 'prepare'), false);
});

test('authorization denial happens before proposal preparation', async () => {
  const { runtime, calls } = fixture({ authorizeProfile: async () => false });
  const result = await runtime.prepare({
    principal: PRINCIPAL,
    body: {
      profile_id: 'github.repo.delete.v1',
      operation_id: 'operation:0000000000000001',
      action: { action_type: 'github.repo.delete' },
    },
  });

  assert.equal(result.status, 403);
  assert.equal(result.body.error.code, 'profile_not_authorized');
  assert.equal(calls.some(([name]) => name === 'prepare'), false);
});

test('execute rejects a proposal owned by another principal before effect selection', async () => {
  let effectSelected = false;
  const { runtime, calls } = fixture({
    effectForProfile: async () => {
      effectSelected = true;
      return async () => ({ provider_status: 204 });
    },
  });
  const result = await runtime.execute({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal({ initiator_id: OTHER_PRINCIPAL.id }),
      receipt: { id: 'receipt:1' },
      evaluation: { verdict: 'SATISFIED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 404);
  assert.equal(result.body.error.code, 'proposal_not_found');
  assert.equal(effectSelected, false);
  assert.equal(calls.some(([name]) => name === 'execute'), false);
});

test('execute invokes only the server-selected effect and returns no owner capability', async () => {
  const { runtime, calls } = fixture();
  const result = await runtime.execute({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      receipt: { id: 'receipt:1' },
      evaluation: { verdict: 'SATISFIED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 200);
  assert.equal(result.body.result.ok, true);
  assert.equal(JSON.stringify(result.body).includes('pto-owner:'), false);
  assert.equal(calls.filter(([name]) => name === 'execute').length, 1);
});

test('indeterminate execution exposes only the public attempt binding', async () => {
  const handle = {
    tenant_id: 'tenant:emilia',
    attempt_id: 'attempt:0000000000000001',
    owner: 'pto-owner:v1:server-only-owner-capability',
  };
  const error = Object.assign(new Error('provider_timeout'), { handle });
  const { runtime } = fixture({
    controller: {
      ...fixture().controller,
      async execute() {
        throw error;
      },
      getReconciliationHandle(candidate) {
        return candidate === error ? handle : null;
      },
    },
  });

  const result = await runtime.execute({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      receipt: { id: 'receipt:1' },
      evaluation: { verdict: 'SATISFIED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 202);
  assert.equal(result.body.status, 'indeterminate');
  assert.deepEqual(result.body.attempt, {
    tenant_id: 'tenant:emilia',
    attempt_id: 'attempt:0000000000000001',
  });
  assert.equal(JSON.stringify(result.body).includes('server-only-owner-capability'), false);
});

test('lost indeterminate response is rediscovered after restart and reconciled without re-execution', async () => {
  const durableAttempt = {
    ...publicAttempt(),
    state: 'INVOKING',
  };
  let providerCalls = 0;
  const firstBase = fixture();
  const first = fixture({
    controller: {
      ...firstBase.controller,
      async execute() {
        providerCalls += 1;
        const error = new Error('response_lost_after_provider_call');
        error.proposalToEffect = { attempt: durableAttempt };
        throw error;
      },
    },
  });
  const lost = await first.runtime.execute({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      receipt: { id: 'receipt:1' },
      evaluation: { verdict: 'SATISFIED' },
      evidence: evidence(),
    },
  });
  assert.equal(lost.status, 202);

  let lookupInput;
  let recoveryInput;
  const restarted = fixture({
    lookupAttempt: async (input) => {
      lookupInput = input;
      return structuredClone(durableAttempt);
    },
    recoverAttempt: async (input) => {
      recoveryInput = input;
      return {
        tenant_id: input.attempt.tenant_id,
        attempt_id: input.attempt.attempt_id,
        owner: 'pto-owner:v1:restart-recovery-capability',
      };
    },
  });
  const discovered = await restarted.runtime.lookupAttempt({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: { proposal: proposal() },
  });

  assert.equal(discovered.status, 200);
  assert.equal(discovered.body.status, 'found');
  assert.equal(discovered.body.state, 'INVOKING');
  assert.deepEqual(discovered.body.attempt, publicAttempt());
  assert.deepEqual(lookupInput.lookup, {
    tenant_id: 'tenant:emilia',
    provider_id: 'github',
    provider_account_id: 'emiliaprotocol',
    environment: 'production-smoke',
    request_digest: `sha256:${'1'.repeat(64)}`,
  });

  const reconciled = await restarted.runtime.reconcile({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      evaluation: { verdict: 'SATISFIED' },
      attempt: discovered.body.attempt,
      provider_evidence: { outcome: 'COMMITTED' },
      evidence: evidence(),
    },
  });
  assert.equal(reconciled.status, 200);
  assert.equal(recoveryInput.attempt.attempt_id, durableAttempt.attempt_id);
  assert.equal(providerCalls, 1);
  assert.equal(restarted.calls.some(([name]) => name === 'execute'), false);
});

test('attempt lookup fails closed when durable state drifts from the verified provider tuple', async () => {
  const { runtime } = fixture({
    lookupAttempt: async ({ lookup }) => ({
      ...lookup,
      provider_account_id: 'attacker-account',
      attempt_id: 'attempt:0000000000000001',
      state: 'INDETERMINATE',
    }),
  });
  const result = await runtime.lookupAttempt({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: { proposal: proposal() },
  });

  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, 'attempt_lookup_unavailable');
});

test('attempt lookup requires authentication and a durable lookup implementation', async () => {
  let lookupCalls = 0;
  const unauthenticated = fixture({
    lookupAttempt: async () => {
      lookupCalls += 1;
      return null;
    },
  });
  const denied = await unauthenticated.runtime.lookupAttempt({
    principal: null,
    proposalId: 'proposal:0000000000000001',
    body: { proposal: proposal() },
  });
  assert.equal(denied.status, 401);
  assert.equal(lookupCalls, 0);

  const unavailable = fixture({ lookupAttempt: undefined });
  const result = await unavailable.runtime.lookupAttempt({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: { proposal: proposal() },
  });
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, 'attempt_lookup_unavailable');
});

test('reconcile rejects caller-supplied owner material', async () => {
  const { runtime, calls } = fixture();
  const result = await runtime.reconcile({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      evaluation: { verdict: 'SATISFIED' },
      attempt: {
        ...publicAttempt(),
        owner: 'pto-owner:v1:caller-controlled',
      },
      provider_evidence: { outcome: 'COMMITTED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error.code, 'attempt_fields_invalid');
  assert.equal(calls.some(([name]) => name === 'reconcile'), false);
});

test('reconcile recovers owner and AEB authorization on the server', async () => {
  const { runtime, calls } = fixture();
  const result = await runtime.reconcile({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      evaluation: { verdict: 'SATISFIED' },
      attempt: publicAttempt(),
      provider_evidence: { outcome: 'COMMITTED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 200);
  const input = calls.find(([name]) => name === 'reconcile')[1];
  assert.equal(input.attempt.owner, 'pto-owner:v1:server-only-owner-capability');
  assert.deepEqual(input.aeb_recovery_authorization, { recovery: 'server-only' });
  assert.equal(JSON.stringify(result.body).includes('server-only-owner-capability'), false);
  const context = calls.find(([name]) => name === 'withEvidenceContext')[1];
  assert.deepEqual(context.evidence, evidence());
});

test('reconcile authorizes durable recovery inside the request evidence context', async () => {
  let activeContext = null;
  const { runtime } = fixture({
    withEvidenceContext: async (context, work) => {
      assert.equal(activeContext, null);
      activeContext = structuredClone(context);
      try {
        return await work();
      } finally {
        activeContext = null;
      }
    },
    recoverAttempt: async ({ attempt }) => {
      assert.deepEqual(activeContext?.evidence, evidence());
      return {
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner: 'pto-owner:v1:context-bound-recovery-capability',
      };
    },
    aebRecoveryAuthorization: async () => {
      assert.deepEqual(activeContext?.evidence, evidence());
      return { recovery: 'context-bound' };
    },
  });

  const result = await runtime.reconcile({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      evaluation: { verdict: 'SATISFIED' },
      attempt: publicAttempt(),
      provider_evidence: { outcome: 'COMMITTED' },
      evidence: evidence(),
    },
  });

  assert.equal(result.status, 200);
  assert.equal(activeContext, null);
});

test('execute refuses malformed evidence before selecting an effect', async () => {
  let effectSelected = false;
  const { runtime, calls } = fixture({
    effectForProfile: async () => {
      effectSelected = true;
      return async () => ({ provider_status: 204 });
    },
  });
  const result = await runtime.execute({
    principal: PRINCIPAL,
    proposalId: 'proposal:0000000000000001',
    body: {
      proposal: proposal(),
      receipt: { id: 'receipt:1' },
      evaluation: { verdict: 'SATISFIED' },
      evidence: {
        artifacts: { 'artifact:approval': { signed: true } },
        statuses: [],
      },
    },
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error.code, 'evidence_fields_invalid');
  assert.equal(effectSelected, false);
  assert.equal(calls.some(([name]) => name === 'execute'), false);
});

test('publicAttemptBinding removes owner and rejects malformed attempts', () => {
  assert.deepEqual(publicAttemptBinding({
    ...publicAttempt(),
    owner: 'pto-owner:v1:secret',
  }), publicAttempt());
  assert.equal(publicAttemptBinding({ tenant_id: 'tenant:emilia' }), null);
});

test('readiness fails closed when a dependency is unavailable', async () => {
  const { runtime } = fixture({ readiness: async () => ({ ok: false }) });
  await assert.rejects(runtime.initialize(), /dependency_not_ready/);
  const result = await runtime.ready();
  assert.equal(result.status, 503);
  assert.equal(result.body.status, 'unavailable');
});
