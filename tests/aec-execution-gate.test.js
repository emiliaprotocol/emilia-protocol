// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { createAECExecutionGate } from '../packages/gate/aec-execution.js';
import { createAtomicEvidenceLog, createEvidenceLog, createMemoryAtomicEvidenceBackend } from '../packages/gate/evidence.js';
import { createDurableConsumptionStore, createMemoryBackend, MemoryConsumptionStore } from '../packages/gate/store.js';
import { actionDigest } from '../packages/verify/evidence-chain.js';

const suite = JSON.parse(readFileSync(new URL('../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8'));
const vector = (id) => structuredClone(suite.vectors.find((entry) => entry.id === id));

function gateFor(v, humanFloor, overrides = {}) {
  return createAECExecutionGate({
    requirement: v.requirement,
    policiesByType: v.policies_by_type,
    humanFloor,
    store: new MemoryConsumptionStore(),
    log: createEvidenceLog({ strict: true }),
    allowEphemeralState: true,
    now: () => Date.parse(v.verification_time),
    ...overrides,
  });
}

describe('stateful AEC execution gate', () => {
  it('executes a Class-A chain once and refuses replay', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    let effects = 0;
    const args = { chain: v.aec_chain, expectedAction: v.aec_chain.action };

    const first = await gate.run(args, async () => { effects++; return 'ok'; });
    const replay = await gate.run(args, async () => { effects++; return 'never'; });

    expect(first).toMatchObject({ ok: true, allow: true, value: 'ok' });
    expect(replay).toMatchObject({ ok: false, allow: false, reason: 'replay_refused' });
    expect(effects).toBe(1);
    expect(gate.evidence.verify().ok).toBe(true);
  });

  it('admits exactly one concurrent presentation', async () => {
    const v = vector('accept_profile_bound_quorum');
    const gate = gateFor(v, 'quorum');
    let effects = 0;
    const attempts = await Promise.all(Array.from({ length: 50 }, () => gate.run(
      { chain: v.aec_chain, expectedAction: v.aec_chain.action },
      async () => { effects++; return effects; },
    )));

    expect(attempts.filter((attempt) => attempt.ok)).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.reason === 'replay_refused')).toHaveLength(49);
    expect(effects).toBe(1);
  });

  it('captures validated store and logger methods against post-construction replacement', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    const args = { chain: v.aec_chain, expectedAction: v.aec_chain.action };
    let effects = 0;
    let replacementLogCalls = 0;
    const originalRecord = gate.evidence.record.bind(gate.evidence);

    const first = await gate.run(args, async () => { effects++; });
    gate.store.reserve = async () => true;
    gate.store.commit = async () => true;
    gate.evidence.record = async (entry) => {
      replacementLogCalls++;
      return originalRecord(entry);
    };
    const replay = await gate.run(args, async () => { effects++; });

    expect(first).toMatchObject({ ok: true, allow: true });
    expect(replay).toMatchObject({ ok: false, allow: false, reason: 'replay_refused' });
    expect(effects).toBe(1);
    expect(replacementLogCalls).toBe(0);
  });

  it('refuses executor-action substitution before the effect starts', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    let effects = 0;
    const out = await gate.run({
      chain: v.aec_chain,
      expectedAction: { ...v.aec_chain.action, action_type: 'different.action' },
    }, async () => { effects++; });
    expect(out).toMatchObject({ ok: false, reason: 'aec_refused' });
    expect(effects).toBe(0);
  });

  it('enforces the human floor independently of a weaker Boolean requirement', async () => {
    const action = { action_type: 'test.effect', target: 'simulator' };
    const chain = {
      '@version': 'EP-AEC-v1', action, requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: {} }],
    };
    const gate = createAECExecutionGate({
      requirement: 'policy_decision',
      policiesByType: {},
      verifiers: { policy_decision: (_evidence, ctx) => ({
        valid: true,
        action_digest: `sha256:${actionDigest(ctx.action)}`,
      }) },
      humanFloor: 'class_a',
      store: new MemoryConsumptionStore(),
      log: createEvidenceLog({ strict: true }),
      allowEphemeralState: true,
      now: () => Date.parse('2026-07-11T12:00:00.000Z'),
    });
    let effects = 0;
    const out = await gate.run({
      chain,
      expectedAction: action,
    }, async () => { effects++; });
    expect(out).toMatchObject({ ok: false, reason: 'human_floor_unsatisfied' });
    expect(effects).toBe(0);
  });

  it('never accepts presenter-supplied verifier code as relying-party evidence policy', async () => {
    const v = vector('accept_pinned_human_receipt');
    const requirement = 'ep-receipt AND policy_decision';
    const chain = structuredClone(v.aec_chain);
    chain.requirement = requirement;
    chain.components.push({ type: 'policy_decision', evidence: { attacker_claim: true } });
    const forgedVerifier = (_evidence, ctx) => ({
      valid: true,
      action_digest: `sha256:${actionDigest(ctx.action)}`,
    });
    const gate = gateFor(v, 'class_a', { requirement });
    let effects = 0;

    const injected = await gate.run({
      chain,
      expectedAction: chain.action,
      verifiers: { policy_decision: forgedVerifier },
    }, async () => { effects++; });

    expect(injected).toMatchObject({
      ok: false,
      allow: false,
      reason: 'runtime_trust_configuration_refused',
    });
    expect(effects).toBe(0);

    const pinnedGate = gateFor(v, 'class_a', {
      requirement,
      verifiers: { policy_decision: forgedVerifier },
    });
    const pinned = await pinnedGate.run({ chain, expectedAction: chain.action }, async () => { effects++; });
    expect(pinned).toMatchObject({ ok: true, allow: true });
    expect(effects).toBe(1);
  });

  it('burns an indeterminate authorization after the effect starts', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    const args = { chain: v.aec_chain, expectedAction: v.aec_chain.action };
    await expect(gate.run(args, async () => { throw new Error('response lost'); })).rejects.toThrow('response lost');
    const replay = await gate.run(args, async () => 'never');
    expect(replay).toMatchObject({ ok: false, reason: 'replay_refused' });
    expect(gate.evidence.all().some((entry) => entry.outcome === 'indeterminate')).toBe(true);
  });

  it('cannot mint a fresh replay key with an invalid decoy component', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    const chain = structuredClone(v.aec_chain);
    chain.components.unshift({
      type: 'ep-receipt',
      evidence: { receipt_id: 'attacker-decoy-1' },
    });
    let effects = 0;

    const first = await gate.run({ chain, expectedAction: chain.action }, async () => { effects++; });
    chain.components[0].evidence.receipt_id = 'attacker-decoy-2';
    const replay = await gate.run({ chain, expectedAction: chain.action }, async () => { effects++; });

    expect(first).toMatchObject({ ok: true, allow: true });
    expect(replay).toMatchObject({ ok: false, allow: false, reason: 'replay_refused' });
    expect(effects).toBe(1);
  });

  it('fails before execution when the strict evidence sink is unavailable', async () => {
    const v = vector('accept_pinned_human_receipt');
    const log = createEvidenceLog({ strict: true, sink: async () => { throw new Error('down'); } });
    const gate = gateFor(v, 'class_a', { log });
    let effects = 0;
    const out = await gate.run(
      { chain: v.aec_chain, expectedAction: v.aec_chain.action },
      async () => { effects++; },
    );
    expect(out).toMatchObject({ ok: false, reason: 'evidence_log_failed' });
    expect(effects).toBe(0);
  });

  it('requires explicit state custody and exposes tampering', async () => {
    const v = vector('accept_pinned_human_receipt');
    expect(() => createAECExecutionGate({
      requirement: v.requirement,
      policiesByType: v.policies_by_type,
      humanFloor: 'class_a',
    })).toThrow(/durable consumption store/);
    expect(() => createAECExecutionGate({
      requirement: v.requirement,
      policiesByType: v.policies_by_type,
      humanFloor: 'class_a',
      store: new MemoryConsumptionStore(),
      log: createEvidenceLog({ strict: true }),
    })).toThrow(/ownership-fenced durable store/);

    const gate = gateFor(v, 'class_a');
    await gate.run({ chain: v.aec_chain, expectedAction: v.aec_chain.action }, async () => 'ok');
    gate.evidence.all()[0].allow = false;
    expect(gate.evidence.verify()).toMatchObject({ ok: false, reason: 'hash_mismatch' });
  });

  it('refuses expiring consumption and process-local evidence in production mode', () => {
    const v = vector('accept_pinned_human_receipt');
    const config = {
      requirement: v.requirement,
      policiesByType: v.policies_by_type,
      humanFloor: 'class_a',
    };
    // These in-memory implementations model backend contracts in this unit
    // test; the explicit capability flags stand in for a real durable backend.
    const durableStoreBackend = Object.assign(createMemoryBackend(), { durable: true });
    const atomicLogBackend = Object.assign(createMemoryAtomicEvidenceBackend(), { durable: true });
    const atomicLog = createAtomicEvidenceLog(atomicLogBackend);

    expect(() => createAECExecutionGate({
      ...config,
      store: createDurableConsumptionStore(durableStoreBackend, { ttlSeconds: 60 }),
      log: atomicLog,
    })).toThrow(/non-expiring committed keys/);

    const permanentStore = createDurableConsumptionStore(durableStoreBackend);
    expect(() => createAECExecutionGate({
      ...config,
      store: permanentStore,
      log: createEvidenceLog({ strict: true, sink: async () => {} }),
    })).toThrow(/atomic shared-head append/);

    expect(() => createAECExecutionGate({
      ...config,
      store: permanentStore,
      log: atomicLog,
    })).not.toThrow();
  });

  it('treats false commit and malformed log acknowledgements as failures', async () => {
    const v = vector('accept_pinned_human_receipt');
    const args = { chain: v.aec_chain, expectedAction: v.aec_chain.action };

    const falseCommitStore = new MemoryConsumptionStore();
    falseCommitStore.commit = async () => false;
    const gate = gateFor(v, 'class_a', { store: falseCommitStore });
    let effects = 0;
    await expect(gate.run(args, async () => { effects++; })).rejects.toThrow(/commit_refused/);
    const replay = await gate.run(args, async () => { effects++; });
    expect(replay).toMatchObject({ ok: false, reason: 'replay_refused' });
    expect(effects).toBe(1);

    const malformedLogGate = gateFor(v, 'class_a', {
      log: { record: async () => ({}) },
    });
    const refused = await malformedLogGate.run(args, async () => { effects++; });
    expect(refused).toMatchObject({ ok: false, reason: 'evidence_log_failed' });
    expect(effects).toBe(1);

    const plausibleForgeryGate = gateFor(v, 'class_a', {
      log: { record: async () => ({ seq: 0, prev_hash: 'genesis', hash: 'a'.repeat(64) }) },
    });
    const forged = await plausibleForgeryGate.run(args, async () => { effects++; });
    expect(forged).toMatchObject({ ok: false, reason: 'evidence_log_failed' });
    expect(effects).toBe(1);

    const wrongContentLog = createEvidenceLog({ strict: true });
    const substitutedAckGate = gateFor(v, 'class_a', {
      log: { record: async () => wrongContentLog.record({ type: 'unrelated.record', allow: false }) },
    });
    const substituted = await substitutedAckGate.run(args, async () => { effects++; });
    expect(substituted).toMatchObject({ ok: false, reason: 'evidence_log_failed' });
    expect(effects).toBe(1);
  });

  it('passes a frozen pre-await action snapshot to the effect', async () => {
    const v = vector('accept_pinned_human_receipt');
    const gate = gateFor(v, 'class_a');
    const expectedAction = structuredClone(v.aec_chain.action);
    let seen;
    const pending = gate.run({ chain: v.aec_chain, expectedAction }, async ({ action }) => {
      seen = action;
      return 'ok';
    });
    expectedAction.params.amount = 1;
    const result = await pending;

    expect(result.ok).toBe(true);
    expect(seen.params.amount).toBe(v.aec_chain.action.params.amount);
    expect(Object.isFrozen(seen)).toBe(true);
    expect(Object.isFrozen(seen.params)).toBe(true);
  });
});
