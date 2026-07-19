// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { actionDigest, verifyAuthorizationChain } from '../packages/verify/evidence-chain.js';
import { createAECExecutionGate } from '../packages/gate/aec-execution.js';
import { createEvidenceLog } from '../packages/gate/evidence.js';
import { MemoryConsumptionStore } from '../packages/gate/store.js';

const suite = JSON.parse(readFileSync(new URL('../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));
const vector = (id) => structuredClone(suite.vectors.find((entry) => entry.id === id));

function evaluate(v) {
  const stub = (evidence) => ({ valid: evidence?.valid !== false, action_digest: evidence?.action_digest });
  return verifyAuthorizationChain(v.aec_chain, {
    keysByType: v.keys_by_type,
    policiesByType: v.policies_by_type,
    verifiers: Object.fromEntries((v.stub_types || []).map((type) => [type, stub])),
    requirement: v.requirement,
    expectedActionDigest: v.expected_action_digest,
    verificationTime: v.verification_time,
  });
}

describe('isolated AEC human-profile refusals', () => {
  it('isolates every quorum directory and audience predicate', () => {
    const cases = [
      ['missing policy', (v) => { v.policies_by_type['ep-quorum'].policy = null; }],
      ['missing RP ID', (v) => { v.policies_by_type['ep-quorum'].rp_id = ''; }],
      ['non-string RP ID', (v) => { v.policies_by_type['ep-quorum'].rp_id = 1; }],
      ['missing context policy', (v) => { v.policies_by_type['ep-quorum'].context_policy = ''; }],
      ['non-string context policy', (v) => { v.policies_by_type['ep-quorum'].context_policy = 1; }],
      ['missing origins', (v) => { delete v.policies_by_type['ep-quorum'].allowed_origins; }],
      ['non-integer max age', (v) => { v.policies_by_type['ep-quorum'].max_age_sec = 1.5; }],
      ['negative max age', (v) => { v.policies_by_type['ep-quorum'].max_age_sec = -1; }],
      ['future registry snapshot', (v) => { v.policies_by_type['ep-quorum'].registry_checked_at = '2026-06-11T00:03:01.000Z'; }],
      ['non-integer registry age', (v) => { v.policies_by_type['ep-quorum'].max_registry_age_sec = 1.5; }],
      ['missing approver directory', (v) => { v.policies_by_type['ep-quorum'].approvers = null; }],
      ['unknown directory key', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        delete profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key];
      }],
      ['inactive directory key', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].status = 'inactive';
      }],
      ['directory public-key mismatch', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].public_key = 'other';
      }],
      ['directory identity mismatch', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].approver_id = 'ep:approver:other';
      }],
      ['roles is not an array', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].roles = 'reviewer';
      }],
      ['role absent', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].roles = [];
      }],
      ['not-yet-valid directory key', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].valid_from = '2026-06-11T00:03:01.000Z';
      }],
      ['expired directory key', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].valid_to = '2026-06-11T00:02:59.000Z';
      }],
      ['revoked directory key', (v) => {
        const profile = v.policies_by_type['ep-quorum'];
        profile.approvers[v.aec_chain.components[0].evidence.members[0].approver_public_key].revoked_at = '2026-06-11T00:03:00.000Z';
      }],
      ['signed context policy mismatch', (v) => { v.policies_by_type['ep-quorum'].context_policy = 'other-policy'; }],
    ];
    for (const [name, mutate] of cases) {
      const v = vector('accept_profile_bound_quorum');
      mutate(v);
      expect(evaluate(v).allow, name).toBe(false);
    }
  });

  it('refuses a jointly presented and pinned one-person threshold', () => {
    const v = vector('accept_profile_bound_quorum');
    v.policies_by_type['ep-quorum'].policy.required = 1;
    v.aec_chain.components[0].evidence.policy.required = 1;
    expect(evaluate(v).allow).toBe(false);
  });

  it('isolates every receipt profile and directory predicate', () => {
    const cases = [
      ['missing approver keys', (v) => { v.policies_by_type['ep-receipt'].approver_keys = null; }],
      ['missing log key', (v) => { v.policies_by_type['ep-receipt'].log_public_key = ''; }],
      ['missing RP ID', (v) => { v.policies_by_type['ep-receipt'].rp_id = ''; }],
      ['non-string RP ID', (v) => { v.policies_by_type['ep-receipt'].rp_id = 1; }],
      ['missing origins', (v) => { delete v.policies_by_type['ep-receipt'].allowed_origins; }],
      ['bad policy hash', (v) => { v.policies_by_type['ep-receipt'].expected_policy_hash = 'bad'; }],
      ['non-integer max age', (v) => { v.policies_by_type['ep-receipt'].max_age_sec = 1.5; }],
      ['negative max age', (v) => { v.policies_by_type['ep-receipt'].max_age_sec = -1; }],
      ['future registry snapshot', (v) => { v.policies_by_type['ep-receipt'].registry_checked_at = '2026-06-13T11:31:01.000Z'; }],
      ['missing directory key', (v) => {
        const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
        delete v.policies_by_type['ep-receipt'].approver_keys[keyId];
      }],
      ['non-Class-A directory key', (v) => {
        const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
        v.policies_by_type['ep-receipt'].approver_keys[keyId].key_class = 'B';
      }],
      ['directory identity mismatch', (v) => {
        const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
        v.policies_by_type['ep-receipt'].approver_keys[keyId].approver_id = 'ep:approver:other';
      }],
      ['not-yet-valid directory key', (v) => {
        const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
        v.policies_by_type['ep-receipt'].approver_keys[keyId].valid_from = '2026-06-13T11:31:01.000Z';
      }],
      ['expired directory key', (v) => {
        const keyId = v.aec_chain.components[0].evidence.signoffs[0].approver_key_id;
        v.policies_by_type['ep-receipt'].approver_keys[keyId].valid_to = '2026-06-13T11:30:59.000Z';
      }],
      ['wrong receipt RP ID', (v) => { v.policies_by_type['ep-receipt'].rp_id = 'wrong-rp'; }],
      ['policy mismatch', (v) => { v.policies_by_type['ep-receipt'].expected_policy_hash = `sha256:${'f'.repeat(64)}`; }],
    ];
    for (const [name, mutate] of cases) {
      const v = vector('accept_pinned_human_receipt');
      mutate(v);
      expect(evaluate(v).allow, name).toBe(false);
    }
  });
});

describe('isolated AEC composition refusals', () => {
  const action = { action_type: 'test.effect', target: 'simulator', sequence: 1 };
  const digest = `sha256:${actionDigest(action)}`;
  const component = { type: 'policy_decision', evidence: { valid: true, action_digest: digest } };
  const baseChain = {
    '@version': 'EP-AEC-v1', action, action_digest: digest,
    requirement: 'policy_decision', components: [component],
  };
  const stub = (evidence) => ({ valid: evidence.valid, action_digest: evidence.action_digest });
  const baseOptions = {
    requirement: 'policy_decision', expectedAction: action,
    expectedActionDigest: digest, verifiers: { policy_decision: stub },
  };

  const run = (chain = baseChain, options = baseOptions) => verifyAuthorizationChain(
    structuredClone(chain), options,
  );

  it('accepts the isolated custom-component control', () => {
    expect(run()).toMatchObject({
      allow: true, action_digest: digest.slice(7), expected_action_bound: true,
      requirement_source: 'relying_party',
      components: [{ type: 'policy_decision', label: 'policy_decision', valid: true, bound: true, reason: null }],
    });
  });

  it('isolates outer chain and expected-action validation', () => {
    const cases = [
      ['wrong version', (chain) => { chain['@version'] = 'wrong'; }, /unexpected @version/],
      ['missing action', (chain) => { chain.action = null; }, /missing action object/],
      ['array action', (chain) => { chain.action = []; }, /missing action object/],
      ['missing components', (chain) => { chain.components = null; }, /no components/],
      ['empty components', (chain) => { chain.components = []; }, /no components/],
      ['too many components', (chain) => { chain.components = Array.from({ length: 65 }, () => structuredClone(component)); }, /too many components/],
      ['missing requirement', (chain, options) => { chain.requirement = ''; options.requirement = ''; }, /missing requirement expression/],
      ['overlong requirement', (_chain, options) => { options.requirement = 'a'.repeat(4097); }, /requirement expression exceeds size limit/],
      ['declared digest mismatch', (chain) => { chain.action_digest = `sha256:${'f'.repeat(64)}`; }, /declared action_digest/],
      ['malformed expected digest', (_chain, options) => { options.expectedActionDigest = 'bad'; }, /expectedActionDigest is malformed/],
      ['expected object and digest disagree', (_chain, options) => { options.expectedActionDigest = `sha256:${'f'.repeat(64)}`; }, /expectedAction and expectedActionDigest disagree/],
      ['invalid expected action', (_chain, options) => { options.expectedAction = []; delete options.expectedActionDigest; }, /expectedAction is not a bounded/],
    ];
    for (const [name, mutate, reason] of cases) {
      const chain = structuredClone(baseChain);
      const options = { ...baseOptions, verifiers: { ...baseOptions.verifiers } };
      mutate(chain, options);
      const result = run(chain, options);
      expect(result.allow, name).toBe(false);
      expect(result.reasons.join('; '), name).toMatch(reason);
    }
  });

  it('accepts exact component and requirement resource boundaries', () => {
    const components = Array.from({ length: 64 }, (_, index) => ({
      type: 'policy_decision', label: `component-${index}`,
      evidence: { valid: true, action_digest: digest },
    }));
    expect(run({ ...structuredClone(baseChain), components }).allow).toBe(true);

    const longRequirement = 'a'.repeat(4096);
    const result = run(baseChain, { ...baseOptions, requirement: longRequirement });
    expect(result.allow).toBe(false);
    expect(result.reasons.join('; ')).toMatch(/requirement not satisfied/);
    expect(result.reasons.join('; ')).not.toMatch(/size limit/);
  });

  it('emits exact audit reasons for each requirement and action-binding refusal', () => {
    const malformed = run(
      { ...baseChain, requirement: 'policy_decision!!!' },
      { ...baseOptions, requirement: 'policy_decision!!!' },
    );
    expect(malformed.reasons).toEqual(['requirement expression is malformed or exceeds parser limits']);

    const unsatisfied = run(
      { ...baseChain, requirement: 'missing_role' },
      { ...baseOptions, requirement: 'missing_role' },
    );
    expect(unsatisfied.reasons).toEqual([
      'requirement not satisfied: "missing_role" over {policy_decision}',
    ]);

    const presenterOnly = run(baseChain, {
      expectedAction: action,
      expectedActionDigest: digest,
      verifiers: { policy_decision: stub },
    });
    expect(presenterOnly.reasons).toEqual([
      'presenter requirement is descriptive only; relying-party requirement is required for satisfaction',
    ]);

    const noExpectedAction = run(baseChain, {
      requirement: 'policy_decision',
      verifiers: { policy_decision: stub },
    });
    expect(noExpectedAction.reasons).toEqual([
      'relying-party expected action is required for satisfaction',
    ]);

    const mismatchedPresenterClaim = run(
      { ...baseChain, requirement: 'presenter_claim' },
      baseOptions,
    );
    expect(mismatchedPresenterClaim.allow).toBe(true);
    expect(mismatchedPresenterClaim.reasons).toEqual([
      'presenter requirement ignored in favor of relying-party requirement (presenter claimed: "presenter_claim")',
    ]);

    expect(run().reasons).toEqual([]);
  });

  it('returns typed outer-boundary failures instead of generic exceptions', () => {
    for (const [value, reason] of [
      [null, 'chain is not an object'],
      [[], 'chain is not an object'],
      [{}, 'unexpected @version (want EP-AEC-v1)'],
    ]) {
      expect(verifyAuthorizationChain(value, baseOptions)).toMatchObject({
        allow: false, action_digest: null, expected_action_bound: false,
        components: [], reasons: [reason], requirement_source: 'relying_party',
      });
    }
    const cyclic = structuredClone(baseChain);
    cyclic.self = cyclic;
    expect(verifyAuthorizationChain(cyclic, baseOptions).reasons[0]).toMatch(/canonical JSON safety profile/);
  });

  it('isolates component shape, verifier, validity, and binding failures', () => {
    const cases = [
      ['null component', null, baseOptions, { type: null, label: '#0', valid: false, bound: false, reason: 'component is not an object' }],
      ['non-string type', { ...component, type: 1 }, baseOptions, { type: 1, label: 1, valid: false, bound: false, reason: 'component type or evidence is malformed' }],
      ['invalid type characters', { ...component, type: 'policy!' }, baseOptions, { type: 'policy!', label: 'policy!', valid: false, bound: false, reason: 'component type or evidence is malformed' }],
      ['overlong type', { ...component, type: 'a'.repeat(129) }, baseOptions, { type: 'a'.repeat(129), label: 'a'.repeat(129), valid: false, bound: false, reason: 'component type or evidence is malformed' }],
      ['non-object evidence', { ...component, evidence: null }, baseOptions, { type: 'policy_decision', label: 'policy_decision', valid: false, bound: false, reason: 'component type or evidence is malformed' }],
      ['no verifier', { ...component, type: 'unknown' }, baseOptions, { type: 'unknown', label: 'unknown', valid: false, bound: false, reason: 'no verifier registered for type "unknown"' }],
      ['verifier not a function', component, { ...baseOptions, verifiers: { policy_decision: true } }, { type: 'policy_decision', label: 'policy_decision', valid: false, bound: false, reason: 'no verifier registered for type "policy_decision"' }],
      ['verifier throws', component, { ...baseOptions, verifiers: { policy_decision: () => { throw new Error('fail'); } } }, { type: 'policy_decision', label: 'policy_decision', valid: false, bound: false, reason: 'verifier threw: fail' }],
      ['verifier returns null', component, { ...baseOptions, verifiers: { policy_decision: () => null } }, { type: 'policy_decision', label: 'policy_decision', valid: false, bound: false, reason: 'component evidence did not verify' }],
      ['truthy validity', component, { ...baseOptions, verifiers: { policy_decision: () => ({ valid: 1, action_digest: digest }) } }, { type: 'policy_decision', label: 'policy_decision', valid: false, bound: true, reason: 'component evidence did not verify' }],
      ['wrong binding', component, { ...baseOptions, verifiers: { policy_decision: () => ({ valid: true, action_digest: `sha256:${'f'.repeat(64)}` }) } }, { type: 'policy_decision', label: 'policy_decision', valid: true, bound: false, reason: 'component binds a DIFFERENT action than the chain' }],
    ];
    for (const [name, value, options, expectedRow] of cases) {
      const result = run({ ...structuredClone(baseChain), components: [structuredClone(value)] }, options);
      expect(result.allow, name).toBe(false);
      expect(result.components[0], name).toEqual(expectedRow);
    }
  });

  it('keeps non-string labels display-only and accepts the exact type-length boundary', () => {
    const nonStringLabel = run({
      ...structuredClone(baseChain),
      components: [{ ...structuredClone(component), label: 123 }],
    });
    expect(nonStringLabel.allow).toBe(true);
    expect(nonStringLabel.components[0].label).toBe('policy_decision');

    const type = 'a'.repeat(128);
    const boundary = verifyAuthorizationChain({
      ...structuredClone(baseChain), requirement: type,
      components: [{ type, evidence: { valid: true, action_digest: digest } }],
    }, {
      ...baseOptions, requirement: type,
      verifiers: { [type]: stub },
    });
    expect(boundary.allow).toBe(true);
  });
});

describe('isolated AEC execution-boundary refusals', () => {
  const accepted = vector('accept_pinned_human_receipt');
  const makeConfig = (overrides = {}) => ({
    requirement: accepted.requirement,
    policiesByType: accepted.policies_by_type,
    humanFloor: 'class_a',
    store: new MemoryConsumptionStore(),
    log: createEvidenceLog({ strict: true }),
    allowEphemeralState: true,
    now: () => Date.parse(accepted.verification_time),
    ...overrides,
  });
  const args = () => ({ chain: structuredClone(accepted.aec_chain), expectedAction: structuredClone(accepted.aec_chain.action) });

  it('rejects each malformed constructor capability independently', () => {
    const cases = [
      ['missing requirement', { requirement: '' }, /AEC execution gate requires a relying-party requirement/],
      ['blank requirement', { requirement: '   ' }, /AEC execution gate requires a relying-party requirement/],
      ['non-string requirement', { requirement: 1 }, /AEC execution gate requires a relying-party requirement/],
      ['missing policies', { policiesByType: null }, /policiesByType/],
      ['array policies', { policiesByType: [] }, /policiesByType/],
      ['uncloneable policies', { policiesByType: { fn: () => true } }, /cloneable/],
      ['missing verifier registry', { verifiers: null }, /verifiers must be a relying-party-owned object/],
      ['array verifier registry', { verifiers: [] }, /verifiers must be a relying-party-owned object/],
      ['non-function verifier', { verifiers: { policy_decision: true } }, /named custom verifier functions/],
      ['reserved verifier override', { verifiers: { 'ep-receipt': () => true } }, /named custom verifier functions/],
      ['invalid verifier type', { verifiers: { 'policy decision': () => true } }, /named custom verifier functions/],
      ['overlong verifier type', { verifiers: { ['a'.repeat(129)]: () => true } }, /named custom verifier functions/],
      ['missing key registry', { keysByType: null }, /keysByType must be a relying-party-owned object/],
      ['array key registry', { keysByType: [] }, /keysByType must be a relying-party-owned object/],
      ['uncloneable key registry', { keysByType: { key: () => true } }, /cloneable/],
      ['unknown human floor', { humanFloor: 'software' }, /humanFloor/],
      ['missing store', { store: null, allowEphemeralState: false }, /durable consumption store/],
      ['missing log', { log: null, allowEphemeralState: false }, /durable strict evidence log/],
      ['missing reserve method', { store: { commit: async () => true } }, /reserve/],
      ['missing commit method', { store: { reserve: async () => true } }, /commit/],
      ['missing record method', { log: {} }, /record/],
    ];
    for (const [name, overrides, error] of cases) {
      expect(() => createAECExecutionGate(makeConfig(overrides)), name).toThrow(error);
    }
  });

  it('requires every production storage and log capability independently', () => {
    const validStore = {
      durable: true,
      ownershipFenced: true,
      permanentConsumption: true,
      reserve: async () => true,
      commit: async () => true,
    };
    const validLog = {
      durable: true,
      strict: true,
      forkAware: true,
      atomicAppend: true,
      record: async () => ({
        seq: 0, prev_hash: 'genesis', record_id: '1234567890abcdef', hash: 'a'.repeat(64),
      }),
    };
    for (const field of ['durable', 'ownershipFenced', 'permanentConsumption']) {
      expect(() => createAECExecutionGate(makeConfig({
        store: { ...validStore, [field]: false }, log: validLog, allowEphemeralState: false,
      })), `store.${field}`).toThrow(/ownership-fenced durable store/);
    }
    for (const field of ['durable', 'strict', 'forkAware', 'atomicAppend']) {
      expect(() => createAECExecutionGate(makeConfig({
        store: validStore, log: { ...validLog, [field]: false }, allowEphemeralState: false,
      })), `log.${field}`).toThrow(/atomic shared-head append/);
    }
  });

  it('constructs explicit ephemeral defaults as strict local test state', () => {
    const gate = createAECExecutionGate(makeConfig({ store: undefined, log: undefined }));
    expect(gate.store).toBeInstanceOf(MemoryConsumptionStore);
    expect(gate.evidence).toMatchObject({ strict: true, durable: false, forkAware: false, atomicAppend: false });
  });

  it('turns invalid or throwing clocks and uncloneable actions into logged refusals', async () => {
    for (const now of [() => Number.NaN, () => { throw new Error('clock down'); }]) {
      const gate = createAECExecutionGate(makeConfig({ now }));
      await expect(gate.run(args(), async () => 'never')).resolves.toMatchObject({
        ok: false, allow: false, reason: 'invalid_verification_time',
      });
    }
    const gate = createAECExecutionGate(makeConfig());
    const expectedAction = new Proxy({}, { ownKeys() { throw new Error('trap'); } });
    await expect(gate.run({ chain: accepted.aec_chain, expectedAction }, async () => 'never')).resolves.toMatchObject({
      ok: false, allow: false, reason: 'invalid_expected_action',
    });
  });

  it('refuses transaction-scoped trust configuration and malformed request envelopes', async () => {
    for (const field of ['verifiers', 'keysByType', 'policiesByType']) {
      const gate = createAECExecutionGate(makeConfig());
      await expect(gate.run({ ...args(), [field]: {} }, async () => 'never'), field).resolves.toMatchObject({
        ok: false, allow: false, reason: 'runtime_trust_configuration_refused',
      });
    }
    for (const request of [null, 1, [], new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error('request trap'); },
    })]) {
      const gate = createAECExecutionGate(makeConfig());
      await expect(gate.run(request, async () => 'never')).resolves.toMatchObject({
        ok: false, allow: false, reason: 'invalid_execution_request',
      });
    }
  });

  it('isolates store outage, replay, and deny-log failure paths', async () => {
    const unavailable = createAECExecutionGate(makeConfig({
      store: { reserve: async () => { throw new Error('down'); }, commit: async () => true },
    }));
    await expect(unavailable.run(args(), async () => 'never')).resolves.toMatchObject({
      ok: false, allow: false, reason: 'consumption_store_unavailable',
    });

    const replay = createAECExecutionGate(makeConfig({
      store: { reserve: async () => false, commit: async () => true },
    }));
    await expect(replay.run(args(), async () => 'never')).resolves.toMatchObject({
      ok: false, allow: false, reason: 'replay_refused',
    });

    const logFailure = createAECExecutionGate(makeConfig({
      now: () => Number.NaN,
      log: { record: async () => { throw new Error('down'); } },
    }));
    await expect(logFailure.run(args(), async () => 'never')).resolves.toEqual({
      ok: false, allow: false, reason: 'evidence_log_failed', result: null, decision: null,
    });
  });

  it('refuses malformed authorization acknowledgements before effect', async () => {
    const malformedRecords = [
      null, {}, [],
      { seq: -1, prev_hash: 'genesis', hash: 'a'.repeat(64) },
      { seq: 0, prev_hash: 'bad', hash: 'a'.repeat(64) },
      { seq: 0, prev_hash: 'genesis', hash: 'bad' },
    ];
    for (const record of malformedRecords) {
      const store = new MemoryConsumptionStore();
      const gate = createAECExecutionGate(makeConfig({ store, log: { record: async () => record } }));
      let effects = 0;
      const result = await gate.run(args(), async () => { effects++; });
      expect(result).toMatchObject({ ok: false, allow: false, reason: 'evidence_log_failed' });
      expect(effects).toBe(0);
    }
  });
});
