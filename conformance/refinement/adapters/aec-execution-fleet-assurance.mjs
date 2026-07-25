// SPDX-License-Identifier: Apache-2.0
// Generated from aec-execution-fleet-assurance.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Selected deterministic runtime traces for the stateful AEC fleet boundary.
 *
 * These scenarios call the public production entry points with shared local
 * deterministic backends. They exercise the runtime contracts but do not
 * establish physical durability or database linearizability.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createAECExecutionGate } from '../../../packages/gate/aec-execution.js';
import { createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend, } from '../../../packages/gate/evidence.js';
import { createDurableConsumptionStore, createMemoryBackend, } from '../../../packages/gate/store.js';
import { actionDigest } from '../../../packages/verify/evidence-chain.js';
const AEC_ROLE_SUITE = JSON.parse(readFileSync(resolve(process.cwd(), 'conformance/vectors/aec-role.v1.json'), 'utf8'));
export const AEC_EXECUTION_FLEET_ASSURANCE_SCENARIOS = Object.freeze([
    'aec-fleet-pinned-boundary',
    'aec-fleet-owner-reservation',
    'aec-fleet-atomic-evidence',
    'aec-fleet-reservation-failure',
    'aec-fleet-response-loss',
    'aec-fleet-replica-restart',
]);
function vector(id) {
    const found = AEC_ROLE_SUITE.vectors.find((entry) => entry.id === id);
    if (!found)
        throw new Error(`missing AEC role vector: ${id}`);
    return structuredClone(found);
}
function deterministicIds(prefix) {
    let next = 0;
    return () => (`${prefix}-${String(++next).padStart(8, '0')}-0000-0000-000000000000`);
}
function deterministicTokens(prefix) {
    let next = 0;
    return () => `${prefix}-${String(++next).padStart(20, '0')}`;
}
function durableConsumptionBackend() {
    return Object.assign(createMemoryBackend(), { durable: true });
}
function durableEvidenceBackend() {
    return Object.assign(createMemoryAtomicEvidenceBackend(), { durable: true });
}
function productionState(consumptionBackend, evidenceBackend, identity, streamId = 'aec-fleet-assurance') {
    return {
        store: createDurableConsumptionStore(consumptionBackend, {
            reservationTokenFactory: deterministicTokens(`${identity}-owner`),
        }),
        log: createAtomicEvidenceLog(evidenceBackend, {
            streamId,
            maxRetries: 64,
            recordIdFactory: deterministicIds(`${identity}-record`),
        }),
    };
}
function productionGate({ v, consumptionBackend, evidenceBackend, identity, streamId, requirement = v.requirement, policiesByType = v.policies_by_type, verifiers = {}, keysByType = {}, }) {
    const state = productionState(consumptionBackend, evidenceBackend, identity, streamId);
    return createAECExecutionGate({
        requirement,
        policiesByType,
        verifiers,
        keysByType,
        humanFloor: 'class_a',
        store: state.store,
        log: state.log,
        now: () => Date.parse(v.verification_time),
    });
}
function step(operator, accepted, projection) {
    return { operator, accepted, projection };
}
function policyVerifier(evidence, context) {
    const key = context?.keysByType?.policy_decision?.key;
    const policy = context?.policiesByType?.policy_decision?.policy;
    return {
        valid: evidence?.key === key && evidence?.policy === policy,
        action_digest: `sha256:${actionDigest(context.action)}`,
    };
}
function chainWithPolicy(v, key, policy) {
    const chain = structuredClone(v.aec_chain);
    chain.requirement = `${v.requirement} AND policy_decision`;
    chain.components.push({
        type: 'policy_decision',
        evidence: { key, policy },
    });
    return chain;
}
async function pinnedBoundaryScenario() {
    const v = vector('accept_pinned_human_receipt');
    const requirement = `${v.requirement} AND policy_decision`;
    const baselinePolicies = {
        ...structuredClone(v.policies_by_type),
        policy_decision: { policy: 'rp-policy' },
    };
    const baselineKeys = { policy_decision: { key: 'rp-key' } };
    const baselineVerifiers = { policy_decision: policyVerifier };
    const baseline = productionGate({
        v,
        consumptionBackend: durableConsumptionBackend(),
        evidenceBackend: durableEvidenceBackend(),
        identity: 'pinned-baseline',
        streamId: 'pinned-baseline',
        requirement,
        policiesByType: baselinePolicies,
        keysByType: baselineKeys,
        verifiers: baselineVerifiers,
    });
    let baselineExecutions = 0;
    const baselineResult = await baseline.run({
        chain: chainWithPolicy(v, 'rp-key', 'rp-policy'),
        expectedAction: v.aec_chain.action,
    }, async () => {
        baselineExecutions += 1;
        return 'baseline';
    });
    if (!baselineResult.ok || baselineExecutions !== 1) {
        throw new Error('constructor-pinned baseline did not execute exactly once');
    }
    const mutablePolicies = {
        ...structuredClone(v.policies_by_type),
        policy_decision: { policy: 'rp-policy' },
    };
    const mutableKeys = { policy_decision: { key: 'rp-key' } };
    const mutableVerifiers = {
        policy_decision: policyVerifier,
    };
    const hardened = productionGate({
        v,
        consumptionBackend: durableConsumptionBackend(),
        evidenceBackend: durableEvidenceBackend(),
        identity: 'pinned-mutated',
        streamId: 'pinned-mutated',
        requirement,
        policiesByType: mutablePolicies,
        keysByType: mutableKeys,
        verifiers: mutableVerifiers,
    });
    mutablePolicies.policy_decision.policy = 'attacker-policy';
    mutableKeys.policy_decision.key = 'attacker-key';
    mutableVerifiers.policy_decision = (_evidence, context) => ({
        valid: true,
        action_digest: `sha256:${actionDigest(context.action)}`,
    });
    let mutationExecutions = 0;
    const mutationResult = await hardened.run({
        chain: chainWithPolicy(v, 'attacker-key', 'attacker-policy'),
        expectedAction: v.aec_chain.action,
    }, async () => {
        mutationExecutions += 1;
    });
    if (mutationResult.ok || mutationExecutions !== 0) {
        throw new Error('post-construction trust mutation admitted authority');
    }
    const captured = productionGate({
        v,
        consumptionBackend: durableConsumptionBackend(),
        evidenceBackend: durableEvidenceBackend(),
        identity: 'captured-methods',
        streamId: 'captured-methods',
    });
    let replacementCalls = 0;
    captured.store.reserve = async () => {
        replacementCalls += 1;
        return false;
    };
    captured.store.commit = async () => {
        replacementCalls += 1;
        return false;
    };
    captured.evidence.record = async () => {
        replacementCalls += 1;
        throw new Error('replacement evidence method must not be called');
    };
    let capturedExecutions = 0;
    const capturedResult = await captured.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        capturedExecutions += 1;
        return 'captured';
    });
    if (!capturedResult.ok || capturedExecutions !== 1 || replacementCalls !== 0) {
        throw new Error('validated store or evidence methods were not captured');
    }
    const transaction = productionGate({
        v,
        consumptionBackend: durableConsumptionBackend(),
        evidenceBackend: durableEvidenceBackend(),
        identity: 'runtime-config',
        streamId: 'runtime-config',
    });
    let transactionExecutions = 0;
    const transactionResult = await transaction.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
        verifiers: { attacker: () => ({ valid: true }) },
        keysByType: { attacker: 'key' },
        policiesByType: { attacker: 'allow' },
    }, async () => {
        transactionExecutions += 1;
    });
    const runtimeConfigRefused = transactionResult.reason === 'runtime_trust_configuration_refused'
        && transactionExecutions === 0;
    if (!runtimeConfigRefused) {
        throw new Error('transaction-scoped trust configuration was not refused');
    }
    return {
        scenario: 'aec-fleet-pinned-boundary',
        steps: [
            step('ExecuteWithPinnedTrust', true, {
                provider_executions: baselineExecutions,
            }),
            step('MutateConstructorTrustInputs', false, {
                provider_executions: mutationExecutions,
                trust_mutation_admitted: mutationResult.ok,
            }),
            step('ReplaceCapturedMethods', true, {
                provider_executions: capturedExecutions,
                replacement_calls: replacementCalls,
            }),
            step('InjectTransactionTrust', false, {
                provider_executions: transactionExecutions,
                runtime_config_refused: runtimeConfigRefused,
            }),
        ],
    };
}
async function ownerReservationScenario() {
    const base = createMemoryBackend();
    const reservationOptions = [];
    const backend = {
        durable: true,
        addIfAbsent: async (key, value, options) => {
            reservationOptions.push(options);
            return base.addIfAbsent(key, value);
        },
        compareAndSet: (key, expected, replacement) => (base.compareAndSet(key, expected, replacement)),
        deleteIfValue: (key, expected) => base.deleteIfValue(key, expected),
        has: (key) => base.has(key),
        get: (key) => base.get(key),
    };
    const owner = createDurableConsumptionStore(backend, {
        reservationTokenFactory: deterministicTokens('pre-restart-owner'),
    });
    const key = 'aec:action:owner-fence';
    const reserved = await owner.reserve(key);
    if (!reserved)
        throw new Error('initial owner reservation failed');
    const restarted = createDurableConsumptionStore(backend, {
        reservationTokenFactory: deterministicTokens('post-restart-owner'),
    });
    let commitRefused = false;
    let releaseRefused = false;
    try {
        await restarted.commit(key);
    }
    catch {
        commitRefused = true;
    }
    try {
        await restarted.release(key);
    }
    catch {
        releaseRefused = true;
    }
    const replayBlocked = (await restarted.reserve(key)) === false;
    const reservationHadNoExpiry = reservationOptions[0] === undefined;
    if (!commitRefused || !releaseRefused || !replayBlocked
        || restarted.permanentConsumption !== true || !reservationHadNoExpiry) {
        throw new Error('owner-fenced permanent reservation boundary failed');
    }
    return {
        scenario: 'aec-fleet-owner-reservation',
        steps: [
            step('ReserveAsOwner', true, { reservation_created: reserved }),
            step('RestartCannotAdopt', false, {
                commit_refused: commitRefused,
                release_refused: releaseRefused,
            }),
            step('ReservationDoesNotExpire', true, {
                replay_blocked: replayBlocked,
                permanent_consumption: restarted.permanentConsumption === true,
            }),
        ],
    };
}
async function atomicEvidenceScenario() {
    const base = createMemoryAtomicEvidenceBackend();
    let loseFirstAppendResponse = true;
    const responseLossBackend = {
        durable: true,
        readHead: (streamId) => base.readHead(streamId),
        getById: (streamId, recordId) => base.getById(streamId, recordId),
        readAll: (streamId) => base.readAll(streamId),
        async appendIfHead(streamId, expectedHeadHash, record) {
            const appended = await base.appendIfHead(streamId, expectedHeadHash, record);
            if (appended && loseFirstAppendResponse) {
                loseFirstAppendResponse = false;
                throw new Error('connection_lost_after_append');
            }
            return appended;
        },
    };
    const first = createAtomicEvidenceLog(responseLossBackend, {
        streamId: 'shared-response-loss',
        recordIdFactory: () => 'response-loss-record-0001-0000-000000000001',
    });
    const recovered = await first.record({ type: 'decision', allow: true });
    const persisted = await base.getById('shared-response-loss', 'response-loss-record-0001-0000-000000000001');
    const recoveredSameRecord = recovered.record_id === 'response-loss-record-0001-0000-000000000001'
        && recovered.hash === persisted?.hash;
    if (!recoveredSameRecord) {
        throw new Error('atomic append response loss did not recover exact record');
    }
    const restarted = createAtomicEvidenceLog(responseLossBackend, {
        streamId: 'shared-response-loss',
        recordIdFactory: () => 'after-restart-record-0001-0000-000000000001',
    });
    const continued = await restarted.record({ type: 'decision', allow: false });
    const predecessorMatches = continued.prev_hash === recovered.hash;
    if (continued.seq !== 1 || !predecessorMatches) {
        throw new Error('restarted evidence writer did not continue the shared head');
    }
    let substituted = null;
    const substitutedBackend = {
        durable: true,
        readHead: async () => null,
        getById: async () => structuredClone(substituted),
        async appendIfHead(_streamId, _expectedHeadHash, record) {
            substituted = {
                ...structuredClone(record),
                seq: 7,
                prev_hash: 'b'.repeat(64),
                allow: false,
            };
            return true;
        },
    };
    const strict = createAtomicEvidenceLog(substitutedBackend, {
        streamId: 'substituted-readback',
        recordIdFactory: () => 'substituted-readback-0001-0000-000000000001',
    });
    let exactReadbackRefused = false;
    try {
        await strict.record({ type: 'decision', allow: true });
    }
    catch {
        exactReadbackRefused = true;
    }
    if (!exactReadbackRefused) {
        throw new Error('substituted evidence readback was accepted');
    }
    return {
        scenario: 'aec-fleet-atomic-evidence',
        steps: [
            step('RecoverAppendAfterResponseLoss', true, {
                recovered_same_record: recoveredSameRecord,
            }),
            step('ContinueSharedHeadAfterRestart', true, {
                sequence: continued.seq,
                predecessor_matches: predecessorMatches,
            }),
            step('RejectSubstitutedReadback', false, {
                exact_readback_refused: exactReadbackRefused,
            }),
        ],
    };
}
async function reservationFailureScenario() {
    const v = vector('accept_pinned_human_receipt');
    const base = createMemoryBackend();
    const unavailableBackend = {
        durable: true,
        async addIfAbsent() {
            throw new Error('reservation_backend_unavailable');
        },
        compareAndSet: (key, expected, replacement) => (base.compareAndSet(key, expected, replacement)),
        deleteIfValue: (key, expected) => base.deleteIfValue(key, expected),
        has: (key) => base.has(key),
    };
    const gate = productionGate({
        v,
        consumptionBackend: unavailableBackend,
        evidenceBackend: durableEvidenceBackend(),
        identity: 'reservation-failure',
        streamId: 'reservation-failure',
    });
    let providerExecutions = 0;
    const result = await gate.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        providerExecutions += 1;
    });
    const reservationFailureRefused = result.reason === 'consumption_store_unavailable'
        && providerExecutions === 0;
    if (!reservationFailureRefused) {
        throw new Error('reservation failure reached provider entry');
    }
    return {
        scenario: 'aec-fleet-reservation-failure',
        steps: [
            step('RefuseProviderWhenReservationFails', false, {
                provider_executions: providerExecutions,
                reservation_failure_refused: reservationFailureRefused,
            }),
        ],
    };
}
async function responseLossScenario() {
    const v = vector('accept_pinned_human_receipt');
    const consumptionBackend = durableConsumptionBackend();
    const evidenceBackend = durableEvidenceBackend();
    const first = productionGate({
        v,
        consumptionBackend,
        evidenceBackend,
        identity: 'response-loss-first',
        streamId: 'response-loss-gate',
    });
    let providerExecutions = 0;
    let responseWasLost = false;
    try {
        await first.run({
            chain: v.aec_chain,
            expectedAction: v.aec_chain.action,
        }, async () => {
            providerExecutions += 1;
            throw new Error('provider_response_lost');
        });
    }
    catch (error) {
        responseWasLost =
            error instanceof Error && error.message === 'provider_response_lost';
    }
    const restarted = productionGate({
        v,
        consumptionBackend,
        evidenceBackend,
        identity: 'response-loss-restart',
        streamId: 'response-loss-gate',
    });
    const replay = await restarted.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        providerExecutions += 1;
    });
    const records = await restarted.evidence.all();
    const indeterminateRecorded = records.some((record) => record.outcome === 'indeterminate');
    const replayRefused = replay.reason === 'replay_refused' && providerExecutions === 1;
    if (!responseWasLost || !indeterminateRecorded || !replayRefused) {
        throw new Error('provider response loss did not freeze replay');
    }
    return {
        scenario: 'aec-fleet-response-loss',
        steps: [
            step('LoseProviderResponse', false, {
                provider_executions: providerExecutions,
                indeterminate_recorded: indeterminateRecorded,
            }),
            step('RefuseReplayAfterResponseLoss', false, {
                provider_executions: providerExecutions,
                replay_refused: replayRefused,
            }),
        ],
    };
}
async function replicaRestartScenario() {
    const v = vector('accept_pinned_human_receipt');
    const consumptionBackend = durableConsumptionBackend();
    const evidenceBackend = durableEvidenceBackend();
    let providerExecutions = 0;
    const first = productionGate({
        v,
        consumptionBackend,
        evidenceBackend,
        identity: 'replica-a',
        streamId: 'fleet-shared-head',
    });
    const firstResult = await first.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        providerExecutions += 1;
        return 'executed';
    });
    if (!firstResult.ok)
        throw new Error('first replica did not execute');
    const expectedKey = `aec:action:${firstResult.result.action_digest}`;
    const canonicalActionKey = (await consumptionBackend.get(expectedKey)) === 'committed:v2';
    const decoyChain = structuredClone(v.aec_chain);
    decoyChain.components.unshift({
        type: 'ep-receipt',
        evidence: { receipt_id: 'presenter-selected-decoy' },
    });
    const second = productionGate({
        v,
        consumptionBackend,
        evidenceBackend,
        identity: 'replica-b',
        streamId: 'fleet-shared-head',
    });
    const decoyReplay = await second.run({
        chain: decoyChain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        providerExecutions += 1;
    });
    const decoyReplayRefused = decoyReplay.reason === 'replay_refused' && providerExecutions === 1;
    const restarted = productionGate({
        v,
        consumptionBackend,
        evidenceBackend,
        identity: 'replica-a-restart',
        streamId: 'fleet-shared-head',
    });
    const restartReplay = await restarted.run({
        chain: v.aec_chain,
        expectedAction: v.aec_chain.action,
    }, async () => {
        providerExecutions += 1;
    });
    const restartReplayRefused = restartReplay.reason === 'replay_refused' && providerExecutions === 1;
    if (!canonicalActionKey || !decoyReplayRefused || !restartReplayRefused) {
        throw new Error('canonical action replay escaped the shared fleet boundary');
    }
    return {
        scenario: 'aec-fleet-replica-restart',
        steps: [
            step('ExecuteCanonicalActionOnReplicaA', true, {
                provider_executions: providerExecutions,
                canonical_action_key: canonicalActionKey,
            }),
            step('RefuseDecoyReplayOnReplicaB', false, {
                provider_executions: providerExecutions,
                replay_refused: decoyReplayRefused,
            }),
            step('RefuseReplayAfterRestart', false, {
                provider_executions: providerExecutions,
                replay_refused: restartReplayRefused,
            }),
        ],
    };
}
export async function runAecExecutionFleetAssuranceScenario(scenario) {
    if (scenario === 'aec-fleet-pinned-boundary')
        return pinnedBoundaryScenario();
    if (scenario === 'aec-fleet-owner-reservation')
        return ownerReservationScenario();
    if (scenario === 'aec-fleet-atomic-evidence')
        return atomicEvidenceScenario();
    if (scenario === 'aec-fleet-reservation-failure')
        return reservationFailureScenario();
    if (scenario === 'aec-fleet-response-loss')
        return responseLossScenario();
    if (scenario === 'aec-fleet-replica-restart')
        return replicaRestartScenario();
    throw new Error(`unknown AEC fleet assurance runtime scenario: ${scenario}`);
}
