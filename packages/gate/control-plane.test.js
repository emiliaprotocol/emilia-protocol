// SPDX-License-Identifier: Apache-2.0
// Generated from control-plane.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CONTROL_PLANE_MAX_SETTLEMENTS, evaluateGateControlPlane, } from './control-plane.js';
import { DEPLOYMENT_PROFILE_VERSION, deploymentProfileDigest } from './deployment-attestation.js';
import { COVERAGE_INVENTORY_VERSION, signEnforcementProbe } from './coverage.js';
import { SETTLEMENT_PROFILE_VERSION } from './settlement.js';
import { acceptNetworkWitnessStatement, createMemoryWitnessSequenceStore, signNetworkWitnessStatement, } from './network-witness.js';
const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const ACTION = `sha256:${'11'.repeat(32)}`;
const CONFIG = `sha256:${'22'.repeat(32)}`;
const AUTH = `sha256:${'33'.repeat(32)}`;
const EXEC = `sha256:${'44'.repeat(32)}`;
const OUTCOME = `sha256:${'55'.repeat(32)}`;
function scenario({ includeGate = true } = {}) {
    const probeKeys = crypto.generateKeyPairSync('ed25519');
    const witnessKeys = crypto.generateKeyPairSync('ed25519');
    const deploymentProfile = {
        '@version': DEPLOYMENT_PROFILE_VERSION,
        profile_id: 'dp', verifier_id: 'verifier:rat', evidence_type: 'application/eat+cwt',
        gate_id: 'gate:grid', environment_id: 'env:prod', audience: 'rp:grid',
        nonce: 'attestation:grid:1',
        max_age_sec: 300, max_future_skew_sec: 30,
        required_measurements: { image: `sha256:${'66'.repeat(32)}`, config: CONFIG },
    };
    const surface = {
        surface_id: 'surface:grid-curtailment', action_family: 'grid.curtailment',
        gate_id: 'gate:grid', environment_id: 'env:prod',
        deployment_profile_hash: deploymentProfileDigest(deploymentProfile),
        probe_action_digest: ACTION, required: true,
        witness: { witness_id: 'witness:grid', capture_point_id: 'capture:grid', event: 'effect_observed', required: true },
    };
    const coverageInventory = {
        '@version': COVERAGE_INVENTORY_VERSION, inventory_id: 'grid-v1', surfaces: [surface],
    };
    const settlementProfile = {
        '@version': SETTLEMENT_PROFILE_VERSION, profile_id: 'settle-grid-v1',
        require_witness: true, require_outcome: true, require_coverage: true,
        required_witness_event: 'effect_observed', required_witness_id: 'witness:grid',
        required_capture_point_id: 'capture:grid', required_coverage_state: 'gated',
        required_surface_id: surface.surface_id,
    };
    const probe = signEnforcementProbe({
        probe_id: 'probe:grid', surface_id: surface.surface_id, gate_id: surface.gate_id,
        environment_id: surface.environment_id, action_family: surface.action_family,
        action_digest: ACTION, tested_at: '2026-07-16T19:59:30.000Z', nonce: 'canary-1',
        result: 'blocked_without_receipt', response_status: 428,
    }, probeKeys.privateKey);
    const witness = signNetworkWitnessStatement({
        witness_id: 'witness:grid', capture_point_id: 'capture:grid', sequence: 1,
        observed_at: '2026-07-16T19:59:45.000Z', event: 'effect_observed', direction: 'egress',
        action_digest: ACTION, config_digest: CONFIG,
    }, witnessKeys.privateKey);
    return {
        input: {
            coverage: {
                deployments: includeGate ? [{ profile: deploymentProfile, evidence: { eat: 'opaque' } }] : [],
                probes: includeGate ? [probe] : [],
                witnesses: [witness],
            },
            settlements: [{
                    bundle: {
                        action_digest: ACTION, authorization: {}, execution: {}, witness, outcome: {},
                        coverage: { surface_id: surface.surface_id },
                    },
                }],
            usage: {
                org: 'ep:org:grid-operator',
                period: { periodStart: '2026-07-01T00:00:00.000Z', periodEnd: '2026-08-01T00:00:00.000Z' },
                entries: [{
                        kind: 'decision', at: '2026-07-16T19:59:00.000Z', action: 'grid.curtailment',
                        allow: true, status: 200, reason: 'allow', required_tier: 'quorum', hash: 'h1',
                    }],
            },
        },
        options: {
            now: NOW,
            coverageInventory,
            settlementProfile,
            attestationVerifiers: { 'verifier:rat': async () => ({
                    verified: true, verifier_id: 'verifier:rat', evidence_type: 'application/eat+cwt',
                    gate_id: 'gate:grid', environment_id: 'env:prod', audience: 'rp:grid',
                    nonce: deploymentProfile.nonce,
                    issued_at: '2026-07-16T19:59:20.000Z', expires_at: '2026-07-16T20:04:20.000Z',
                    measurements: { ...deploymentProfile.required_measurements },
                }) },
            pinnedProbes: [{
                    probe_id: 'probe:grid', key_id: probe.probe.key_id,
                    surface_ids: [surface.surface_id],
                    public_key: probeKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                }],
            expectedProbeNonces: { [surface.surface_id]: 'canary-1' },
            pinnedWitnesses: [{
                    witness_id: 'witness:grid', key_id: witness.witness.key_id,
                    public_key: witnessKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                    capture_point_ids: ['capture:grid'], config_digests: [CONFIG],
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
        },
    };
}
test('joins enforcement, witness, outcome, coverage, settlement, and metering', async () => {
    const { input, options } = scenario();
    const verifyAttestation = options.attestationVerifiers['verifier:rat'];
    options.attestationVerifiers = {
        'verifier:rat': async (...args) => {
            input.usage.period = {};
            input.usage.entries.length = 0;
            return verifyAttestation(...args);
        },
    };
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, true);
    assert.equal(result.settlement_results[0].eligible, true);
    assert.equal(result.usage_complete, true);
    assert.match(result.control_plane_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(result.artifacts.usage.protected_actions, 1);
});
test('a healthy passive witness without the Gate remains witness_only and blocks settlement', async () => {
    const { input, options } = scenario({ includeGate: false });
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, false);
    assert.equal(result.artifacts.coverage.surfaces[0].state, 'witness_only');
    assert.equal(result.settlement_results[0].eligible, false);
    assert.equal(result.settlement_results[0].verdict, 'refuse_coverage');
});
test('invalid metering input is surfaced without taking down enforcement evidence', async () => {
    const { input, options } = scenario();
    input.usage.period = {};
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, true);
    assert.equal(result.usage_complete, false);
    assert.equal(result.usage_error, 'usage_statement_refused');
    assert.equal(result.artifacts.usage, null);
});
test('presenter-supplied policy and inventory cannot weaken relying-party pins', async () => {
    const { input, options } = scenario({ includeGate: false });
    input.coverage.inventory = { '@version': COVERAGE_INVENTORY_VERSION, inventory_id: 'empty', surfaces: [] };
    input.settlements[0].profile = {
        '@version': SETTLEMENT_PROFILE_VERSION,
        profile_id: 'attacker-permissive',
        require_witness: false,
        require_outcome: false,
        require_coverage: false,
    };
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, false);
    assert.equal(result.artifacts.coverage.inventory_id, 'grid-v1');
    assert.equal(result.settlement_results[0].eligible, false);
    assert.equal(result.settlement_results[0].verdict, 'refuse_coverage');
});
test('missing durable witness storage fails coverage and settlement closed', async () => {
    const { input, options } = scenario();
    delete options.witnessSequenceStore;
    delete options.allowEphemeralWitnessStore;
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, false);
    assert.equal(result.artifacts.coverage.surfaces[0].witness_verified, false);
    assert.equal(result.settlement_results[0].eligible, false);
    assert.equal(result.settlement_results[0].verdict, 'refuse_witness');
});
test('one control-plane ingestion can satisfy both coverage and settlement', async () => {
    const { input, options } = scenario();
    options.witnessSequenceStore = createMemoryWitnessSequenceStore();
    options.allowEphemeralWitnessStore = true;
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, true);
    assert.equal(result.settlement_results[0].eligible, true);
    assert.equal(result.artifacts.coverage.surfaces[0].witness_verified, true);
});
test('witness storage outage fails control-plane decisions closed', async () => {
    const { input, options } = scenario();
    delete options.allowEphemeralWitnessStore;
    options.witnessSequenceStore = {
        durable: true,
        advance: async () => { throw new Error('down'); },
    };
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, false);
    assert.equal(result.artifacts.coverage.surfaces[0].witness_acceptance_reason, 'sequence_store_unavailable');
    assert.equal(result.settlement_results[0].verdict, 'refuse_witness');
});
test('control plane can explicitly reuse an RP-trusted durable acceptance without a store', async () => {
    const { input, options } = scenario();
    const memory = createMemoryWitnessSequenceStore();
    const acceptance = await acceptNetworkWitnessStatement(input.coverage.witnesses[0], {
        pinnedWitnesses: options.pinnedWitnesses,
        now: NOW,
        sequenceStore: { durable: true, advance: (...args) => memory.advance(...args) },
    });
    const mutableAcceptance = structuredClone(acceptance);
    const verifyAttestation = options.attestationVerifiers['verifier:rat'];
    options.attestationVerifiers = {
        'verifier:rat': async (...args) => {
            mutableAcceptance.accepted = false;
            mutableAcceptance.statement_digest = `sha256:${'99'.repeat(32)}`;
            return verifyAttestation(...args);
        },
    };
    delete options.witnessSequenceStore;
    delete options.allowEphemeralWitnessStore;
    options.trustedWitnessAcceptances = [mutableAcceptance];
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.coverage_complete, true);
    assert.equal(result.settlement_results[0].eligible, true);
    assert.equal(mutableAcceptance.accepted, false);
});
test('oversized and accessor-backed settlement collections fail closed without verifier work', async () => {
    {
        const { input, options } = scenario();
        let authorizationCalls = 0;
        options.verifyAuthorization = async () => { authorizationCalls++; return {}; };
        input.settlements = new Array(CONTROL_PLANE_MAX_SETTLEMENTS + 1);
        const result = await evaluateGateControlPlane(input, options);
        assert.equal(result.settlement_input_complete, false);
        assert.equal(result.settlement_error, 'settlements_limit_exceeded');
        assert.deepEqual(result.settlement_results, []);
        assert.equal(authorizationCalls, 0);
    }
    {
        const { input, options } = scenario();
        const hostile = [];
        Object.defineProperty(hostile, '0', {
            enumerable: true,
            get() { throw new Error('boom'); },
        });
        hostile.length = 1;
        input.settlements = hostile;
        await assert.doesNotReject(() => evaluateGateControlPlane(input, options));
        const result = await evaluateGateControlPlane(input, options);
        assert.equal(result.settlement_error, 'settlements_hostile_input');
        assert.deepEqual(result.settlement_results, []);
    }
});
test('accessor-backed trusted acceptance configuration fails closed without throwing', async () => {
    const { input, options } = scenario();
    const hostileAcceptance = {};
    Object.defineProperty(hostileAcceptance, 'statement_digest', {
        enumerable: true,
        get() { throw new Error('boom'); },
    });
    options.trustedWitnessAcceptances = [hostileAcceptance];
    await assert.doesNotReject(() => evaluateGateControlPlane(input, options));
    const result = await evaluateGateControlPlane(input, options);
    assert.equal(result.configuration_error, 'rp_configuration_invalid');
    assert.equal(result.coverage_complete, false);
    assert.equal(result.settlement_results[0].eligible, false);
});
