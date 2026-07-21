// SPDX-License-Identifier: Apache-2.0
// Generated from settlement.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { SETTLEMENT_PROFILE_VERSION, evaluateSettlementEligibility, settlementProfileDigest, } from './settlement.js';
import { acceptNetworkWitnessStatement, createMemoryWitnessSequenceStore, signNetworkWitnessStatement, } from './network-witness.js';
const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const ACTION = `sha256:${'11'.repeat(32)}`;
const AUTH = `sha256:${'22'.repeat(32)}`;
const EXEC = `sha256:${'33'.repeat(32)}`;
const OUTCOME = `sha256:${'44'.repeat(32)}`;
const COVERAGE = `sha256:${'55'.repeat(32)}`;
const CONFIG = `sha256:${'66'.repeat(32)}`;
const profile = {
    '@version': SETTLEMENT_PROFILE_VERSION,
    profile_id: 'profile:grid-settlement-v1',
    require_witness: true,
    require_outcome: true,
    require_coverage: true,
    required_witness_event: 'effect_observed',
    required_witness_id: 'witness:edge-1',
    required_capture_point_id: 'capture:grid-a',
    required_coverage_state: 'gated',
    required_surface_id: 'surface:grid-a',
};
function fixture() {
    const kp = crypto.generateKeyPairSync('ed25519');
    const witness = signNetworkWitnessStatement({
        witness_id: 'witness:edge-1', capture_point_id: 'capture:grid-a', sequence: 9,
        observed_at: '2026-07-16T19:59:45.000Z', event: 'effect_observed', direction: 'egress',
        action_digest: ACTION, config_digest: CONFIG,
    }, kp.privateKey);
    return {
        witnessPrivateKey: kp.privateKey,
        bundle: {
            action_digest: ACTION,
            authorization: { raw: 'auth' }, execution: { raw: 'execution' }, witness,
            outcome: { raw: 'outcome' }, coverage: { raw: 'coverage' },
        },
        options: {
            profile: { ...profile },
            now: NOW,
            pinnedWitnesses: [{
                    witness_id: 'witness:edge-1', key_id: witness.witness.key_id,
                    public_key: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                    capture_point_ids: ['capture:grid-a'], config_digests: [CONFIG],
                }],
            witnessSequenceStore: createMemoryWitnessSequenceStore(),
            allowEphemeralWitnessStore: true,
            verifyAuthorization: async () => ({ accepted: true, action_digest: ACTION, decision_digest: AUTH }),
            verifyExecution: async () => ({
                accepted: true, action_digest: ACTION, authorization_digest: AUTH,
                execution_digest: EXEC, outcome: 'executed',
            }),
            verifyOutcome: async () => ({
                accepted: true, action_digest: ACTION, execution_digest: EXEC,
                outcome_digest: OUTCOME, within_tolerance: true,
            }),
            verifyCoverage: async () => ({ accepted: true, state: 'gated', surface_id: 'surface:grid-a', report_hash: COVERAGE }),
        },
    };
}
test('eligible requires every independently verified row joined on one action digest', async () => {
    const { bundle, options } = fixture();
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.eligible, true);
    assert.equal(result.verdict, 'eligible');
    assert.equal(result.profile_hash, settlementProfileDigest(profile));
    assert.equal(result.checks.digest_join, true);
    assert.equal(result.evidence.witness_digest.startsWith('sha256:'), true);
});
test('missing or failing pinned verifiers refuse their own evidence row', async () => {
    for (const [field, verdict] of [
        ['verifyAuthorization', 'refuse_authorization'],
        ['verifyExecution', 'refuse_execution'],
        ['verifyOutcome', 'refuse_outcome'],
        ['verifyCoverage', 'refuse_coverage'],
    ]) {
        const { bundle, options } = fixture();
        delete options[field];
        const result = await evaluateSettlementEligibility(bundle, options);
        assert.equal(result.verdict, verdict, field);
    }
});
test('cross-action substitution and authorization-execution splice attacks refuse', async () => {
    const wrong = `sha256:${'99'.repeat(32)}`;
    {
        const { bundle, options } = fixture();
        options.verifyAuthorization = async () => ({ accepted: true, action_digest: wrong, decision_digest: AUTH });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_authorization');
    }
    {
        const { bundle, options } = fixture();
        options.verifyExecution = async () => ({
            accepted: true, action_digest: ACTION, authorization_digest: wrong,
            execution_digest: EXEC, outcome: 'executed',
        });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_binding');
    }
    {
        const { bundle, options } = fixture();
        options.verifyOutcome = async () => ({
            accepted: true, action_digest: wrong, execution_digest: EXEC,
            outcome_digest: OUTCOME, within_tolerance: true,
        });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_outcome');
    }
});
test('witness mutation, wrong event, wrong key, and stale observation refuse', async () => {
    {
        const { bundle, options } = fixture();
        bundle.witness.observation.action_digest = `sha256:${'99'.repeat(32)}`;
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_witness');
    }
    {
        const { bundle, options } = fixture();
        options.profile = { ...profile, required_witness_event: 'request_observed' };
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_witness');
    }
    {
        const { bundle, options } = fixture();
        options.pinnedWitnesses = [];
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_witness');
    }
    {
        const { bundle, options } = fixture();
        options.witnessMaxAgeSec = 1;
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_witness');
    }
    {
        const { bundle, options } = fixture();
        options.profile = { ...profile, required_capture_point_id: 'capture:another-actuator' };
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_binding');
    }
});
test('a sequence-equivocating witness rejected by ingestion cannot satisfy settlement', async () => {
    const { bundle, options, witnessPrivateKey, } = fixture();
    const store = createMemoryWitnessSequenceStore();
    const ingestionOptions = {
        pinnedWitnesses: options.pinnedWitnesses,
        now: NOW,
        sequenceStore: store,
        allowEphemeralStore: true,
    };
    const first = signNetworkWitnessStatement({
        witness_id: profile.required_witness_id,
        capture_point_id: profile.required_capture_point_id,
        sequence: 7,
        observed_at: '2026-07-16T19:59:35.000Z',
        event: 'response_observed',
        direction: 'egress',
        action_digest: ACTION,
        config_digest: CONFIG,
    }, witnessPrivateKey);
    const conflicting = signNetworkWitnessStatement({
        witness_id: profile.required_witness_id,
        capture_point_id: profile.required_capture_point_id,
        sequence: 7,
        observed_at: '2026-07-16T19:59:45.000Z',
        event: profile.required_witness_event,
        direction: 'egress',
        action_digest: ACTION,
        config_digest: CONFIG,
    }, witnessPrivateKey);
    bundle.witness = conflicting;
    assert.equal((await acceptNetworkWitnessStatement(first, ingestionOptions)).accepted, true);
    assert.equal((await acceptNetworkWitnessStatement(conflicting, ingestionOptions)).reason, 'sequence_equivocation');
    const result = await evaluateSettlementEligibility(bundle, {
        ...options,
        witnessSequenceStore: store,
        allowEphemeralWitnessStore: true,
    });
    assert.equal(result.verdict, 'refuse_witness');
    assert.equal(result.reason, 'sequence_equivocation');
    assert.equal(result.eligible, false);
});
test('settlement can operate offline only on the matching RP-trusted durable acceptance', async () => {
    const { bundle, options } = fixture();
    const memory = createMemoryWitnessSequenceStore();
    const acceptance = await acceptNetworkWitnessStatement(bundle.witness, {
        pinnedWitnesses: options.pinnedWitnesses,
        now: NOW,
        sequenceStore: { durable: true, advance: (...args) => memory.advance(...args) },
    });
    delete options.witnessSequenceStore;
    delete options.allowEphemeralWitnessStore;
    options.trustedWitnessAcceptance = acceptance;
    assert.equal((await evaluateSettlementEligibility(bundle, options)).eligible, true);
    options.trustedWitnessAcceptance = {
        ...acceptance,
        statement_digest: `sha256:${'99'.repeat(32)}`,
    };
    const mismatch = await evaluateSettlementEligibility(bundle, options);
    assert.equal(mismatch.verdict, 'refuse_witness');
    assert.equal(mismatch.reason, 'witness_acceptance_digest_mismatch');
});
test('out-of-tolerance outcome, non-gated coverage, callback errors, and bad profiles refuse', async () => {
    {
        const { bundle, options } = fixture();
        options.verifyOutcome = async () => ({
            accepted: true, action_digest: ACTION, execution_digest: EXEC,
            outcome_digest: OUTCOME, within_tolerance: false,
        });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_outcome');
    }
    {
        const { bundle, options } = fixture();
        options.verifyCoverage = async () => ({ accepted: true, state: 'witness_only', surface_id: 's', report_hash: COVERAGE });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_coverage');
    }
    {
        const { bundle, options } = fixture();
        options.verifyCoverage = async () => ({ accepted: true, state: 'gated', surface_id: 'surface:other', report_hash: COVERAGE });
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_coverage');
    }
    {
        const { bundle, options } = fixture();
        options.verifyExecution = async () => { throw new Error('down'); };
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_execution');
    }
    {
        const { bundle, options } = fixture();
        options.profile = { ...profile, require_witness: 'yes' };
        assert.equal((await evaluateSettlementEligibility(bundle, options)).verdict, 'refuse_profile_invalid');
    }
});
test('optional rows can be omitted only when the pinned profile says so', async () => {
    const { bundle, options } = fixture();
    options.profile = {
        '@version': SETTLEMENT_PROFILE_VERSION,
        profile_id: 'profile:minimal',
        require_witness: false,
        require_outcome: false,
        require_coverage: false,
    };
    delete bundle.witness;
    delete bundle.outcome;
    delete bundle.coverage;
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.eligible, true);
    assert.equal(result.checks.witness, true);
});
test('outcome evidence must bind the exact accepted execution digest', async () => {
    const { bundle, options } = fixture();
    options.verifyOutcome = async () => ({
        accepted: true,
        action_digest: ACTION,
        execution_digest: `sha256:${'99'.repeat(32)}`,
        outcome_digest: OUTCOME,
        within_tolerance: true,
    });
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.verdict, 'refuse_outcome');
});
test('disabled rows cannot smuggle contradictory profile fields', async () => {
    const { bundle, options } = fixture();
    options.profile = {
        '@version': SETTLEMENT_PROFILE_VERSION,
        profile_id: 'profile:ambiguous',
        require_witness: false,
        require_outcome: false,
        require_coverage: false,
        required_surface_id: 'surface:grid-a',
    };
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.verdict, 'refuse_profile_invalid');
    assert.equal(result.reason, 'profile_coverage_fields_forbidden');
});
test('action and profile mutation during async verification cannot change the decision context', async () => {
    const { bundle, options } = fixture();
    const wrong = `sha256:${'99'.repeat(32)}`;
    options.verifyAuthorization = async () => {
        bundle.action_digest = wrong;
        options.profile.require_coverage = false;
        return { accepted: true, action_digest: ACTION, decision_digest: AUTH };
    };
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.eligible, true);
    assert.equal(result.action_digest, ACTION);
    assert.equal(result.checks.coverage, true);
});
test('trusted witness and verifier results are snapshotted before later awaits', async () => {
    const { bundle, options } = fixture();
    const memory = createMemoryWitnessSequenceStore();
    const accepted = await acceptNetworkWitnessStatement(bundle.witness, {
        pinnedWitnesses: options.pinnedWitnesses,
        now: NOW,
        sequenceStore: { durable: true, advance: (...args) => memory.advance(...args) },
    });
    const mutableAcceptance = structuredClone(accepted);
    const mutableAuthorization = {
        accepted: true,
        action_digest: ACTION,
        decision_digest: AUTH,
    };
    delete options.witnessSequenceStore;
    delete options.allowEphemeralWitnessStore;
    options.trustedWitnessAcceptance = mutableAcceptance;
    options.verifyAuthorization = async () => {
        await Promise.resolve();
        mutableAcceptance.accepted = false;
        mutableAcceptance.statement_digest = `sha256:${'99'.repeat(32)}`;
        return mutableAuthorization;
    };
    options.verifyExecution = async () => {
        mutableAuthorization.decision_digest = `sha256:${'88'.repeat(32)}`;
        await Promise.resolve();
        return {
            accepted: true,
            action_digest: ACTION,
            authorization_digest: AUTH,
            execution_digest: EXEC,
            outcome: 'executed',
        };
    };
    const result = await evaluateSettlementEligibility(bundle, options);
    assert.equal(result.eligible, true);
    assert.equal(result.evidence.authorization_digest, AUTH);
});
test('non-canonical and accessor-backed evidence bundles refuse without throwing', async () => {
    const { options } = fixture();
    const hostile = {};
    Object.defineProperty(hostile, 'action_digest', {
        enumerable: true,
        get() { throw new Error('boom'); },
    });
    await assert.doesNotReject(() => evaluateSettlementEligibility(hostile, options));
    const result = await evaluateSettlementEligibility(hostile, options);
    assert.equal(result.verdict, 'refuse_binding');
    assert.equal(result.reason, 'evidence_bundle_not_canonical_json');
});
