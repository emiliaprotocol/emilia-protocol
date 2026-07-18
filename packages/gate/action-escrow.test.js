// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ACTION_ESCROW_PROFILE_VERSION,
  ACTION_ESCROW_STATES,
  createActionEscrowKernel,
} from './action-escrow.js';

const digest = (character) => `sha256:${character.repeat(64)}`;

const AGREEMENT_DIGEST = digest('a');
const BINDING_DIGEST = digest('b');
const RELEASE_ACTION_DIGEST = digest('c');
const EVIDENCE_DIGEST = digest('d');
const PARTIES = Object.freeze([
  Object.freeze({ party_id: 'ep:principal:client', role: 'client' }),
  Object.freeze({ party_id: 'ep:principal:contractor', role: 'contractor' }),
]);
const PROFILE = Object.freeze({
  '@version': ACTION_ESCROW_PROFILE_VERSION,
  profile_id: 'contractor-milestone-release',
  provider_id: 'provider.test',
  required_acceptance_party_ids: Object.freeze(PARTIES.map((party) => party.party_id)),
  required_release_approver_party_ids: Object.freeze(PARTIES.map((party) => party.party_id)),
  prohibit_self_approval: false,
});

function durableCasStore() {
  const values = new Map();
  return {
    durable: true,
    atomicExpectedRevisionCas: true,
    linearizableReads: true,
    monotonicRevisions: true,
    nonExpiring: true,
    async read(key) {
      const current = values.get(key);
      return current ? { ...current } : null;
    },
    async compareAndSwap(key, expectedRevision, value) {
      const current = values.get(key);
      const currentRevision = current?.revision ?? null;
      if (currentRevision !== expectedRevision) {
        return { applied: false, revision: currentRevision };
      }
      const revision = expectedRevision === null ? 0 : expectedRevision + 1;
      values.set(key, { revision, value });
      return { applied: true, revision };
    },
    _values: values,
  };
}

function common(idempotencyKey, overrides = {}) {
  return {
    agreement_digest: AGREEMENT_DIGEST,
    document_action_binding_digest: BINDING_DIGEST,
    milestone_id: 'milestone-01',
    release_action_digest: RELEASE_ACTION_DIGEST,
    parties: PARTIES,
    profile: PROFILE,
    idempotency_key: idempotencyKey,
    ...overrides,
  };
}

function bindingArtifact(overrides = {}) {
  return {
    kind: 'document_action_binding',
    agreement_digest: AGREEMENT_DIGEST,
    document_action_binding_digest: BINDING_DIGEST,
    milestone_id: 'milestone-01',
    release_action_digest: RELEASE_ACTION_DIGEST,
    ...overrides,
  };
}

function acceptanceArtifact(partyId, overrides = {}) {
  return {
    kind: 'e_sign_acceptance',
    party_id: partyId,
    agreement_digest: AGREEMENT_DIGEST,
    document_action_binding_digest: BINDING_DIGEST,
    ...overrides,
  };
}

function milestoneEvidence(submitterPartyId = 'ep:principal:contractor', overrides = {}) {
  return {
    kind: 'milestone_evidence',
    evidence_digest: EVIDENCE_DIGEST,
    submitter_party_id: submitterPartyId,
    ...overrides,
  };
}

function resolution(partyId, overrides = {}) {
  return {
    profile: 'EP-RESOLUTION-v1',
    signoff: {
      context: {
        principal: partyId,
        envelope_hash: BINDING_DIGEST,
        action_hash: RELEASE_ACTION_DIGEST,
        resolution: { outcome: 'approved', selected_option: 0 },
      },
    },
    ...overrides,
  };
}

function fundingStatement(overrides = {}) {
  return {
    statement_type: 'funding',
    status: 'funded',
    statement_digest: digest('e'),
    ...overrides,
  };
}

function releaseStatement(providerIdempotencyKey, overrides = {}) {
  return {
    statement_type: 'release',
    status: 'released',
    statement_digest: digest('f'),
    provider_idempotency_key: providerIdempotencyKey,
    ...overrides,
  };
}

function verifierBindings(expected) {
  return {
    agreement_digest: expected.agreement_digest,
    document_action_binding_digest: expected.document_action_binding_digest,
    milestone_id: expected.milestone_id,
    release_action_digest: expected.release_action_digest,
    parties_digest: expected.parties_digest,
    profile_digest: expected.profile_digest,
  };
}

function defaultVerifiers() {
  return {
    async verifyDocumentActionBinding(artifact, expected) {
      if (artifact?.kind !== 'document_action_binding') return { valid: false };
      if (expected.supersedes_document_action_binding_digest !== undefined
        && artifact.supersedes_document_action_binding_digest
          !== expected.supersedes_document_action_binding_digest) {
        return { valid: false };
      }
      return {
        valid: true,
        verification_digest: digest('1'),
        ...verifierBindings(expected),
        ...(expected.supersedes_document_action_binding_digest === undefined
          ? {}
          : {
            supersedes_document_action_binding_digest:
              expected.supersedes_document_action_binding_digest,
          }),
        agreement_digest: artifact.agreement_digest,
        document_action_binding_digest: artifact.document_action_binding_digest,
        milestone_id: artifact.milestone_id,
        release_action_digest: artifact.release_action_digest,
      };
    },
    async verifyAgreementAcceptance(artifact, expected) {
      if (artifact?.kind !== 'e_sign_acceptance') return { valid: false };
      return {
        valid: true,
        acceptance_digest: digest(artifact.party_id.endsWith('client') ? '2' : '3'),
        party_id: artifact.party_id,
        ...verifierBindings(expected),
        agreement_digest: artifact.agreement_digest,
        document_action_binding_digest: artifact.document_action_binding_digest,
      };
    },
    async verifyMilestoneEvidence(artifact, expected) {
      if (artifact?.kind !== 'milestone_evidence') return { valid: false };
      return {
        valid: true,
        evidence_digest: artifact.evidence_digest,
        submitter_party_id: artifact.submitter_party_id,
        ...verifierBindings(expected),
      };
    },
    async verifyResolutionReceipt(artifact) {
      const outcome = artifact?.signoff?.context?.resolution?.outcome;
      return {
        valid: artifact?.profile === 'EP-RESOLUTION-v1',
        authorizes_action: outcome === 'approved',
        outcome,
      };
    },
    async verifyProviderStatement(statement, expected) {
      return {
        valid: statement?.valid !== false,
        authenticated: statement?.authenticated !== false,
        statement_type: statement?.statement_type,
        status: statement?.status,
        statement_digest: statement?.statement_digest,
        provider_id: expected.provider_id,
        ...verifierBindings(expected),
        ...(statement?.provider_idempotency_key === undefined
          ? {}
          : { provider_idempotency_key: statement.provider_idempotency_key }),
        ...(statement?.override_bindings || {}),
      };
    },
  };
}

function successfulProvider(overrides = {}) {
  const calls = [];
  return {
    calls,
    async release(request) {
      calls.push({ method: 'release', request });
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key),
      };
    },
    async getRelease(request) {
      calls.push({ method: 'getRelease', request });
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key),
      };
    },
    ...overrides,
  };
}

function kernelFor({ store = durableCasStore(), provider = successfulProvider(), profile, ...overrides } = {}) {
  const verifiers = defaultVerifiers();
  const pinnedProfile = profile ?? PROFILE;
  const kernel = createActionEscrowKernel({
    store,
    provider,
    profilesById: { [pinnedProfile.profile_id]: pinnedProfile },
    now: () => '2026-07-17T12:00:00.000Z',
    ...verifiers,
    ...overrides,
  });
  return { kernel, store, provider, profile: pinnedProfile };
}

function assertState(result, state) {
  assert.equal(result.state, state, result.code);
  assert.equal(result.record?.state, state, result.code);
}

async function createAndEffectuate(kernel, profile = PROFILE) {
  assertState(await kernel.create(common('create', {
    profile,
    document_action_binding: bindingArtifact(),
  })), 'draft');
  assertState(await kernel.beginAcceptance(common('begin-acceptance', { profile })), 'awaiting_acceptance');
  assertState(await kernel.acceptAgreement(common('accept-client', {
    profile,
    party_id: 'ep:principal:client',
    agreement_acceptance: acceptanceArtifact('ep:principal:client'),
  })), 'awaiting_acceptance');
  assertState(await kernel.acceptAgreement(common('accept-contractor', {
    profile,
    party_id: 'ep:principal:contractor',
    agreement_acceptance: acceptanceArtifact('ep:principal:contractor'),
  })), 'effective');
}

async function readyForRelease(kernel, profile = PROFILE) {
  await createAndEffectuate(kernel, profile);
  assertState(await kernel.requestFunding(common('request-funding', { profile })), 'awaiting_funding');
  assertState(await kernel.recordFunding(common('record-funding', {
    profile,
    provider_statement: fundingStatement(),
  })), 'funded');
  assertState(await kernel.submitMilestone(common('submit-milestone', {
    profile,
    milestone_evidence: milestoneEvidence(),
  })), 'milestone_submitted');
  for (const partyId of profile.required_release_approver_party_ids) {
    const suffix = partyId.split(':').at(-1);
    assertState(await kernel.approveRelease(common(`approve-${suffix}`, {
      profile,
      party_id: partyId,
      resolution: resolution(partyId),
    })), 'milestone_submitted');
  }
}

test('exports the complete explicit Action Escrow state vocabulary', () => {
  assert.deepEqual(ACTION_ESCROW_STATES, [
    'draft',
    'awaiting_acceptance',
    'effective',
    'awaiting_funding',
    'funded',
    'milestone_submitted',
    'release_reserved',
    'released',
    'disputed',
    'amendment_pending',
    'cancelled',
    'completed',
    'release_indeterminate',
  ]);
});

test('runs the complete milestone lifecycle and releases exactly once', async () => {
  const { kernel, provider } = kernelFor();

  await readyForRelease(kernel);
  const released = await kernel.release(common('release-operation'));
  assert.equal(released.ok, true);
  assert.equal(released.code, 'release_committed');
  assertState(released, 'released');
  assert.match(released.record.release.provider_idempotency_key, /^ep-ae-release:[0-9a-f]{64}$/);

  const replay = await kernel.release(common('release-operation-replay'));
  assert.equal(replay.ok, false);
  assert.equal(replay.code, 'release_already_applied');
  assertState(replay, 'released');
  assert.equal(provider.calls.filter((call) => call.method === 'release').length, 1);
  assert.deepEqual(
    provider.calls.map((call) => call.method),
    ['release', 'getRelease'],
    'POST acknowledgement is never substituted for authoritative GET reconciliation',
  );

  const completed = await kernel.complete(common('complete'));
  assert.equal(completed.ok, true);
  assertState(completed, 'completed');
});

test('mutual e-sign acceptance makes the agreement effective but never approves release', async () => {
  const { kernel, provider } = kernelFor();

  await createAndEffectuate(kernel);
  assertState(await kernel.requestFunding(common('fund-request')), 'awaiting_funding');
  assertState(await kernel.recordFunding(common('fund-record', {
    provider_statement: fundingStatement(),
  })), 'funded');
  assertState(await kernel.submitMilestone(common('evidence', {
    milestone_evidence: milestoneEvidence(),
  })), 'milestone_submitted');

  const refused = await kernel.release(common('release-with-only-esign'));
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'release_approval_missing');
  assert.deepEqual(refused.details.missing_party_ids, PROFILE.required_release_approver_party_ids);
  assert.equal(provider.calls.length, 0);

  const esignAsResolution = await kernel.approveRelease(common('esign-is-not-resolution', {
    party_id: 'ep:principal:client',
    resolution: acceptanceArtifact('ep:principal:client'),
  }));
  assert.equal(esignAsResolution.ok, false);
  assert.equal(esignAsResolution.code, 'resolution_profile_invalid');
});

test('fails closed before funding, verified evidence, and every required approval', async () => {
  const { kernel, provider } = kernelFor();
  await createAndEffectuate(kernel);

  let refused = await kernel.release(common('release-before-funding'));
  assert.equal(refused.code, 'invalid_state_transition');

  assertState(await kernel.requestFunding(common('fund-request')), 'awaiting_funding');
  refused = await kernel.release(common('release-before-funded'));
  assert.equal(refused.code, 'invalid_state_transition');

  assertState(await kernel.recordFunding(common('fund-record', {
    provider_statement: fundingStatement(),
  })), 'funded');
  refused = await kernel.release(common('release-before-evidence'));
  assert.equal(refused.code, 'invalid_state_transition');

  assertState(await kernel.submitMilestone(common('evidence', {
    milestone_evidence: milestoneEvidence(),
  })), 'milestone_submitted');
  assertState(await kernel.approveRelease(common('client-approval', {
    party_id: 'ep:principal:client',
    resolution: resolution('ep:principal:client'),
  })), 'milestone_submitted');
  refused = await kernel.release(common('release-before-all-approvals'));
  assert.equal(refused.code, 'release_approval_missing');
  assert.equal(provider.calls.length, 0);
});

test('joins resolutions to the exact current binding, action, and party', async () => {
  const { kernel } = kernelFor();
  await createAndEffectuate(kernel);
  await kernel.requestFunding(common('fund-request'));
  await kernel.recordFunding(common('fund-record', { provider_statement: fundingStatement() }));
  await kernel.submitMilestone(common('evidence', { milestone_evidence: milestoneEvidence() }));

  const wrongBinding = resolution('ep:principal:client');
  wrongBinding.signoff.context.envelope_hash = digest('9');
  let refused = await kernel.approveRelease(common('wrong-binding-approval', {
    party_id: 'ep:principal:client',
    resolution: wrongBinding,
  }));
  assert.equal(refused.code, 'resolution_binding_mismatch');

  const wrongAction = resolution('ep:principal:client');
  wrongAction.signoff.context.action_hash = digest('8');
  refused = await kernel.approveRelease(common('wrong-action-approval', {
    party_id: 'ep:principal:client',
    resolution: wrongAction,
  }));
  assert.equal(refused.code, 'resolution_action_mismatch');

  refused = await kernel.approveRelease(common('wrong-party-approval', {
    party_id: 'ep:principal:client',
    resolution: resolution('ep:principal:contractor'),
  }));
  assert.equal(refused.code, 'resolution_party_mismatch');
});

test('enforces initiator exclusion when the bound profile prohibits self-approval', async () => {
  const profile = {
    ...PROFILE,
    required_release_approver_party_ids: ['ep:principal:contractor'],
    prohibit_self_approval: true,
  };
  const { kernel } = kernelFor({ profile });
  await createAndEffectuate(kernel, profile);
  await kernel.requestFunding(common('fund-request', { profile }));
  await kernel.recordFunding(common('fund-record', {
    profile,
    provider_statement: fundingStatement(),
  }));
  await kernel.submitMilestone(common('evidence', {
    profile,
    milestone_evidence: milestoneEvidence('ep:principal:contractor'),
  }));

  const refused = await kernel.approveRelease(common('self-approval', {
    profile,
    party_id: 'ep:principal:contractor',
    resolution: resolution('ep:principal:contractor'),
  }));
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'self_approval_refused');
});

test('provider timeout becomes release_indeterminate and requires authenticated GET reconciliation', async () => {
  let releaseCalls = 0;
  let reconciledKey;
  const provider = successfulProvider({
    async release(request) {
      releaseCalls++;
      reconciledKey = request.idempotency_key;
      throw new Error('response lost after request');
    },
    async getRelease(request) {
      assert.equal(request.method, 'GET');
      assert.equal(request.idempotency_key, reconciledKey);
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);

  const unknown = await kernel.release(common('release-timeout'));
  assert.equal(unknown.ok, false);
  assert.equal(unknown.outcome, 'indeterminate');
  assert.equal(unknown.code, 'release_effect_indeterminate');
  assertState(unknown, 'release_indeterminate');

  const retry = await kernel.release(common('automatic-retry-refused'));
  assert.equal(retry.code, 'release_reconciliation_required');
  assert.equal(releaseCalls, 1);

  const reconciled = await kernel.reconcileRelease(common('authenticated-get'));
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.code, 'release_reconciled_released');
  assertState(reconciled, 'released');
  assert.equal(releaseCalls, 1);
});

test('authenticated reconciliation of no effect reopens release with the same provider key', async () => {
  const providerKeys = [];
  let releaseAttempt = 0;
  let reconciliationReads = 0;
  const provider = successfulProvider({
    async release(request) {
      providerKeys.push(request.idempotency_key);
      releaseAttempt++;
      if (releaseAttempt === 1) throw new Error('timeout');
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key),
      };
    },
    async getRelease(request) {
      providerKeys.push(request.idempotency_key);
      reconciliationReads++;
      return {
        authenticated: true,
        statement: reconciliationReads === 1
          ? releaseStatement(request.idempotency_key, {
            status: 'not_released',
            statement_digest: digest('7'),
          })
          : releaseStatement(request.idempotency_key),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);

  assertState(await kernel.release(common('release-unknown')), 'release_indeterminate');
  const reconciled = await kernel.reconcileRelease(common('reconcile-not-released'));
  assert.equal(reconciled.code, 'release_reconciled_not_released');
  assertState(reconciled, 'milestone_submitted');

  const released = await kernel.release(common('release-after-reconcile'));
  assert.equal(released.code, 'release_committed');
  assertState(released, 'released');
  assert.equal(new Set(providerKeys).size, 1, 'agreement + milestone + action derive one stable provider key');
});

test('unauthenticated or unverifiable reconciliation stays indeterminate', async () => {
  const provider = successfulProvider({
    async release() {
      throw new Error('timeout');
    },
    async getRelease(request) {
      return {
        authenticated: false,
        statement: releaseStatement(request.idempotency_key),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);
  await kernel.release(common('release-timeout'));

  const refused = await kernel.reconcileRelease(common('unauthenticated-get'));
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'provider_reconciliation_unauthenticated');
  assertState(refused, 'release_indeterminate');
});

test('concurrent release requests durably reserve once before provider invocation', async () => {
  let releaseCalls = 0;
  let startProvider;
  const providerStarted = new Promise((resolve) => { startProvider = resolve; });
  let finishProvider;
  const providerMayFinish = new Promise((resolve) => { finishProvider = resolve; });
  const provider = successfulProvider({
    async release(request) {
      releaseCalls++;
      startProvider();
      await providerMayFinish;
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);

  const firstPromise = kernel.release(common('release-worker-1'));
  await providerStarted;
  const second = await kernel.release(common('release-worker-2'));
  assert.equal(second.ok, false);
  assert.equal(second.code, 'release_reconciliation_required');
  finishProvider();
  const first = await firstPromise;

  assert.equal(first.code, 'release_committed');
  assert.equal(releaseCalls, 1);
});

test('amendment supersedes the exact binding and invalidates old release authorization', async () => {
  const { kernel, provider } = kernelFor();
  await readyForRelease(kernel);
  const nextBinding = digest('4');
  const nextAction = digest('5');

  const pending = await kernel.proposeAmendment(common('propose-amendment', {
    next_document_action_binding_digest: nextBinding,
    next_release_action_digest: nextAction,
    next_document_action_binding: bindingArtifact({
      document_action_binding_digest: nextBinding,
      release_action_digest: nextAction,
      supersedes_document_action_binding_digest: BINDING_DIGEST,
    }),
  }));
  assertState(pending, 'amendment_pending');
  assert.deepEqual(pending.record.release_approvals, []);
  assert.equal(pending.record.funding, null);
  assert.equal(pending.record.milestone_evidence, null);

  const staleRelease = await kernel.release(common('stale-release'));
  assert.equal(staleRelease.code, 'invalid_state_transition');
  assert.equal(provider.calls.length, 0);

  const pendingCommon = (idempotencyKey, partyId) => common(idempotencyKey, {
    document_action_binding_digest: nextBinding,
    release_action_digest: nextAction,
    party_id: partyId,
    agreement_acceptance: acceptanceArtifact(partyId, {
      document_action_binding_digest: nextBinding,
    }),
  });
  assertState(await kernel.acceptAmendment(
    pendingCommon('amend-client', 'ep:principal:client'),
  ), 'amendment_pending');
  const effective = await kernel.acceptAmendment(
    pendingCommon('amend-contractor', 'ep:principal:contractor'),
  );
  assertState(effective, 'effective');
  assert.equal(effective.record.document_action_binding_digest, nextBinding);
  assert.equal(effective.record.release_action_digest, nextAction);
  assert.equal(effective.record.superseded_bindings.at(-1).document_action_binding_digest, BINDING_DIGEST);

  const oldBindingOperation = await kernel.requestFunding(common('old-binding-after-amendment'));
  assert.equal(oldBindingOperation.code, 'operation_binding_mismatch');
});

test('provider or post-effect CAS failures return closed indeterminate outcomes without throwing', async () => {
  const base = durableCasStore();
  let failReleasedCommit = true;
  const store = {
    ...base,
    async compareAndSwap(key, expectedRevision, value) {
      if (failReleasedCommit && value.includes('"state":"released"')) {
        failReleasedCommit = false;
        throw new Error('store response lost');
      }
      return base.compareAndSwap(key, expectedRevision, value);
    },
  };
  const { kernel } = kernelFor({ store });
  await readyForRelease(kernel);

  const result = await kernel.release(common('release-store-failure'));
  assert.equal(result.ok, false);
  assert.equal(result.outcome, 'indeterminate');
  assert.equal(result.code, 'release_commit_indeterminate');
  assertState(result, 'release_indeterminate');

  const retry = await kernel.release(common('release-store-failure-retry'));
  assert.equal(retry.code, 'release_reconciliation_required');
});

test('missing durability, corrupt stores, and hostile inputs produce typed refusal outcomes', async () => {
  const verifiers = defaultVerifiers();
  let kernel;
  assert.doesNotThrow(() => {
    kernel = createActionEscrowKernel({
      store: { durable: false },
      provider: successfulProvider(),
      profilesById: { [PROFILE.profile_id]: PROFILE },
      ...verifiers,
    });
  });
  const noStore = await kernel.create(common('no-store', {
    document_action_binding: bindingArtifact(),
  }));
  assert.equal(noStore.ok, false);
  assert.equal(noStore.code, 'durable_cas_store_required');

  const throwingStore = durableCasStore();
  const originalRead = throwingStore.read;
  let failReads = false;
  let failedReadCalls = 0;
  throwingStore.read = async (...args) => {
    if (failReads) {
      failedReadCalls++;
      throw new Error('backend unavailable');
    }
    return originalRead(...args);
  };
  ({ kernel } = kernelFor({ store: throwingStore }));
  await kernel.create(common('create-before-outage', {
    document_action_binding: bindingArtifact(),
  }));
  failReads = true;
  const unavailable = await kernel.beginAcceptance(common('read-outage'));
  assert.equal(unavailable.ok, false);
  assert.equal(unavailable.code, 'store_unavailable');
  assert.equal(failedReadCalls, 1, 'the kernel must call the captured read() contract');

  const hostile = {};
  Object.defineProperty(hostile, 'agreement_digest', {
    enumerable: true,
    get() {
      throw new Error('getter must not run');
    },
  });
  const hostileResult = await kernel.beginAcceptance(hostile);
  assert.equal(hostileResult.ok, false);
  assert.equal(hostileResult.code, 'invalid_operation_input');
});

test('idempotency keys are bound to the complete operation request', async () => {
  const { kernel } = kernelFor();
  const createRequest = common('same-key', {
    document_action_binding: bindingArtifact(),
  });
  const first = await kernel.create(createRequest);
  const replay = await kernel.create(structuredClone(createRequest));
  assert.equal(first.ok, true);
  assert.equal(replay.ok, true);
  assert.equal(replay.outcome, 'idempotent');
  assertState(replay, 'draft');

  const conflict = await kernel.beginAcceptance(common('same-key'));
  assert.equal(conflict.ok, false);
  assert.equal(conflict.code, 'idempotency_key_conflict');
});

test('a presenter cannot bootstrap a weaker policy profile at create', async () => {
  const { kernel } = kernelFor();
  const presenterProfile = {
    ...PROFILE,
    required_release_approver_party_ids: ['ep:principal:contractor'],
  };

  const refused = await kernel.create(common('presenter-profile', {
    profile: presenterProfile,
    document_action_binding: bindingArtifact(),
  }));

  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'profile_not_pinned');
  assert.equal(refused.record, null);
});

test('a provider that never resolves is timed out and frozen indeterminate', async () => {
  const provider = successfulProvider({
    async release() {
      return new Promise(() => {});
    },
  });
  const { kernel } = kernelFor({ provider, providerTimeoutMs: 5 });
  await readyForRelease(kernel);

  const result = await kernel.release(common('provider-never-resolves'));

  assert.equal(result.ok, false);
  assert.equal(result.code, 'release_effect_indeterminate');
  assertState(result, 'release_indeterminate');
  assert.equal(provider.calls.length, 0, 'the overridden provider records no synthetic GET');
});

test('malformed expected-revision CAS acknowledgements fail closed', async () => {
  const store = durableCasStore();
  store.compareAndSwap = async () => ({ applied: true, revision: 99 });
  const { kernel } = kernelFor({ store });

  const result = await kernel.create(common('malformed-cas-ack', {
    document_action_binding: bindingArtifact(),
  }));

  assert.equal(result.ok, false);
  assert.equal(result.code, 'store_revision_invalid');
  assert.equal(result.record, null);
});

test('a provider release statement for another action cannot commit release', async () => {
  const provider = successfulProvider({
    async getRelease(request) {
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key, {
          override_bindings: { release_action_digest: digest('9') },
        }),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);

  const result = await kernel.release(common('provider-action-substitution'));

  assert.equal(result.ok, false);
  assert.equal(result.code, 'release_effect_indeterminate');
  assertState(result, 'release_indeterminate');
});

test('an amendment racing a reserved release freezes until GET proves no effect', async () => {
  let providerStarted;
  const started = new Promise((resolve) => { providerStarted = resolve; });
  let finishProvider;
  const mayFinish = new Promise((resolve) => { finishProvider = resolve; });
  const provider = successfulProvider({
    async release() {
      providerStarted();
      await mayFinish;
      return { accepted: true };
    },
    async getRelease(request) {
      return {
        authenticated: true,
        statement: releaseStatement(request.idempotency_key, {
          status: 'not_released',
          statement_digest: digest('7'),
        }),
      };
    },
  });
  const { kernel } = kernelFor({ provider });
  await readyForRelease(kernel);

  const releasePromise = kernel.release(common('racing-release'));
  await started;
  const nextBinding = digest('4');
  const nextAction = digest('5');
  const amendment = await kernel.proposeAmendment(common('racing-amendment', {
    next_document_action_binding_digest: nextBinding,
    next_release_action_digest: nextAction,
    next_document_action_binding: bindingArtifact({
      document_action_binding_digest: nextBinding,
      release_action_digest: nextAction,
      supersedes_document_action_binding_digest: BINDING_DIGEST,
    }),
  }));
  assert.equal(amendment.outcome, 'indeterminate');
  assertState(amendment, 'release_indeterminate');

  finishProvider();
  const releaseResult = await releasePromise;
  assert.equal(releaseResult.ok, false);
  assertState(releaseResult, 'release_indeterminate');

  const reconciled = await kernel.reconcileRelease(common('racing-reconcile'));
  assert.equal(reconciled.code, 'release_reconciled_not_released');
  assertState(reconciled, 'amendment_pending');
});

test('generic apply closes over hostile operation selectors instead of throwing', async () => {
  const { kernel } = kernelFor();
  const hostileOperation = {
    [Symbol.toPrimitive]() {
      throw new Error('selector coercion');
    },
  };

  const result = await kernel.apply(hostileOperation, {});

  assert.equal(result.ok, false);
  assert.equal(result.code, 'invalid_operation_input');
});
