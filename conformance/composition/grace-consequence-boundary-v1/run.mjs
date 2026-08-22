// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * GRACE through the canonical protected consequence boundary.
 *
 * This profile composes the existing synthetic GRACE authorization, actuator,
 * meter, and settlement path with AEB evaluation, Gate admission, and a signed
 * state-domain-owned aggregate consequence envelope. It proves a reference
 * composition, not a physical curtailment event.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { adapterPinDigest, canonicalizeAeb, digestAeb, evaluateAebEvidence, mappingProfileDigest, registryEntryDigest, unifiedRegistryDigest, } from '../../../packages/verify/aeb-adapter-contract.js';
import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';
import { loadDefaultAgilityMldsaBackend } from '../../../packages/verify/pq-signature-agility.js';
import { createConsequenceBoundary, } from '../../../packages/gate/consequence-boundary.js';
import { GRACE_CURTAILMENT_IMPACT_PROFILE, createConsequenceEnvelopeBoundary, createMemoryConsequenceEnvelopeStore, issueConsequenceEnvelope, } from '../../../packages/gate/consequence-envelope.js';
import { createGraceReferenceInput, createGraceReferenceRuntime, executeGraceReferenceInput, } from '../../../lib/grace/reference-scenario.js';
import { verifyGraceMobileAuthorization } from '../../../lib/grace/mobile-grid.js';
export const PROFILE = 'EP-GRACE-CONSEQUENCE-BOUNDARY-COMPOSITION-v1';
const REPORT_VERSION = 'GRACE-CONSEQUENCE-BOUNDARY-REFERENCE-REPORT-v1';
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');
const NOW = '2026-07-15T20:15:00.000Z';
const EVALUATED_AT = '2026-07-15T20:14:59.000Z';
const EXECUTOR = 'executor:grace-consequence-boundary';
const PROVIDER = Object.freeze({
    tenant_id: 'tenant:grace-reference',
    provider_id: 'provider:grace-synthetic-actuator',
    provider_account_id: 'facility:us-west-dc-17',
    environment: 'synthetic-reference',
});
const ED_PRIVATE_JWK = {
    crv: 'Ed25519',
    d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
    x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
    kty: 'OKP',
};
const ED_PRIVATE = crypto.createPrivateKey({ key: ED_PRIVATE_JWK, format: 'jwk' });
const ED_PUBLIC = crypto.createPublicKey(ED_PRIVATE);
const ED_PUBLIC_SPKI = ED_PUBLIC.export({ type: 'spki', format: 'der' }).toString('base64url');
const ACTION_DEFINITION = {
    action_type: 'grid.curtailment.1',
    status: 'active',
    required_fields: [
        { name: 'action_id', type: 'string' },
        { name: 'effect_class', type: 'string' },
        { name: 'facility', type: 'string' },
        { name: 'target_delta_kw', type: 'amount-string' },
        { name: 'window_not_before', type: 'timestamp' },
        { name: 'window_not_after', type: 'timestamp' },
        { name: 'issued_at', type: 'timestamp' },
        { name: 'expires_at', type: 'timestamp' },
        { name: 'baseline_method_hash', type: 'digest' },
        { name: 'control_mode', type: 'string' },
        { name: 'envelope_id', type: 'string' },
        { name: 'requested_by', type: 'string' },
    ],
    optional_fields: [],
};
function materialAction(action) {
    return {
        action_type: 'grid.curtailment.1',
        action_id: action.action_id,
        effect_class: action.effect_class,
        facility: action.facility,
        target_delta_kw: action.target_delta_kw,
        window_not_before: action.window.not_before,
        window_not_after: action.window.not_after,
        issued_at: action.issued_at,
        expires_at: action.expires_at,
        baseline_method_hash: action.baseline_method_hash,
        control_mode: action.control_mode,
        envelope_id: action.envelope_id,
        requested_by: action.requested_by,
    };
}
function sha256(value) {
    return `sha256:${crypto.hash('sha256', value, 'hex')}`;
}
function registryEntry(entryId, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(entryId, entry);
    return entry;
}
function evaluationFixture(operationId) {
    const grace = createGraceReferenceInput();
    const action = materialAction(grace.action);
    const caid = computeCaid(action, { suite: 'jcs-sha256', definitions: [ACTION_DEFINITION] });
    if (!('caid' in caid) || typeof caid.caid !== 'string') {
        throw new Error(`GRACE CAID failed: ${JSON.stringify(caid)}`);
    }
    const adapter = {
        id: 'ep:adapter:grace-mobile-authorization:v1',
        version: '1',
        verifyNative({ artifact, status, trust_roots }) {
            const verified = trust_roots.includes('trust:grace-reference')
                && verifyGraceMobileAuthorization({
                    action: artifact.action,
                    presentation: artifact.presentation,
                    policy: artifact.policy,
                    evidence: artifact.authorizationEvidence,
                    profile: artifact.authorizationProfile,
                }).valid;
            return {
                native_verification: verified ? 'VERIFIED' : 'FAILED',
                acceptance: verified ? 'ACCEPTED' : 'REJECTED',
                evidence_digest: digestAeb(artifact),
                status_digest: digestAeb({
                    checked_at: status.checked_at,
                    expires_at: status.expires_at,
                    revocation_checked: status.revocation_checked,
                    revoked: status.revoked,
                    consumed: status.consumed,
                    unavailable: status.unavailable === true,
                }),
                evidence_role: 'human-authorization',
                subject: { id: 'organization:grid-and-facility-operators', kind: 'organization' },
                replay_unit: digestAeb({
                    adapter: 'ep:adapter:grace-mobile-authorization:v1',
                    action_id: artifact.action.action_id,
                    approvals: artifact.authorizationEvidence
                        .map((entry) => digestAeb(entry.signoff))
                        .sort(),
                }),
                reasons: verified ? [] : ['grace_mobile_authorization_refused'],
            };
        },
        mapAction({ artifact, native, expected_action }) {
            const exact = digestAeb(materialAction(artifact.action)) === digestAeb(expected_action);
            return {
                mapping: native.native_verification === 'VERIFIED' && exact ? 'MATCH' : 'INDETERMINATE',
                caid: caid.caid,
                action_digest: digestAeb(expected_action),
                reasons: exact ? [] : ['grace_action_substitution'],
            };
        },
    };
    const profile = {
        version: '1',
        definition: { definitions: [ACTION_DEFINITION] },
        registry_entry_ref: 'mapping:grace-curtailment',
        mapper_id: 'mapper:grace-curtailment:v1',
        resolver: {
            id: 'resolver:grace-curtailment:v1',
            version: '1',
            implementation_digest: digestAeb({ implementation: 'resolver:grace-curtailment:v1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [],
        },
    };
    profile.profile_digest = mappingProfileDigest('grace-curtailment', profile);
    const entries = {
        'mapping:grace-curtailment': registryEntry('mapping:grace-curtailment', 'mapping-profile', { profile_digest: profile.profile_digest }),
        'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', { role: 'human-authorization', subject_kinds: ['organization'] }),
    };
    const registry = {
        '@version': 'EP-EVIDENCE-REGISTRY-v1',
        registry_id: 'registry:grace-consequence-boundary',
        epoch: 1,
        entries,
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const pin = {
        version: '1',
        trust_roots: ['trust:grace-reference'],
        config: { mode: 'synthetic-reference' },
        max_status_age_sec: 300,
    };
    pin.config_digest = adapterPinDigest(adapter.id, pin);
    const config = {
        '@version': 'AEB-ADAPTER-v1',
        relying_party_id: 'rp:grace-grid-operator',
        evaluator_keys: { 'evaluator:grace-reference': { public_key: ED_PUBLIC_SPKI } },
        registry,
        accepted_mappers: [profile.mapper_id],
        adapters: { [adapter.id]: pin },
        profiles: { 'grace-curtailment': profile },
        requirements: {
            'requirement:grace-human-authorization': {
                '@version': 'AEB-REQUIREMENT-v1',
                all_of: ['human-authorization'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const artifactRef = 'artifact:grace-human-authorization';
    const artifact = {
        action: grace.action,
        presentation: grace.presentation,
        policy: grace.policy,
        authorizationEvidence: grace.authorizationEvidence,
        authorizationProfile: grace.authorizationProfile,
    };
    const status = {
        checked_at: EVALUATED_AT,
        expires_at: '2026-07-15T20:20:00.000Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
    };
    const evaluation = evaluateAebEvidence({
        config,
        adapters: { [adapter.id]: adapter },
        operation_id: operationId,
        consumption_nonce: `nonce:${operationId}`,
        initiator_id: 'agent:grid-coordinator',
        executor_id: EXECUTOR,
        requirement_ref: 'requirement:grace-human-authorization',
        caid: caid.caid,
        expected_action: action,
        legs: [{
                adapter_id: adapter.id,
                profile_id: 'grace-curtailment',
                artifact_ref: artifactRef,
                artifact,
                status,
            }],
        evaluated_at: EVALUATED_AT,
        signer: { key_id: 'evaluator:grace-reference', private_key: ED_PRIVATE },
    });
    assert.equal(evaluation.valid, true, JSON.stringify(evaluation.reasons));
    return {
        grace,
        action,
        config,
        adapters: { [adapter.id]: adapter },
        evaluation: evaluation.record,
        artifacts: { [artifactRef]: artifact },
        statuses: { [artifactRef]: status },
    };
}
function aebStore() {
    const rows = new Map();
    const replay = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        atomicReplayFenced: true,
        async reserve(key, replayKeys) {
            if (rows.has(key))
                return 'CONSUMPTION_CONFLICT';
            if (replayKeys.some((item) => replay.has(item)))
                return 'NATIVE_REPLAY_CONFLICT';
            rows.set(key, 'RESERVED');
            for (const item of replayKeys)
                replay.set(item, key);
            return 'RESERVED';
        },
        async commit(key) {
            if (rows.get(key) !== 'RESERVED')
                return false;
            rows.set(key, 'CONSUMED');
            return true;
        },
        async release(key) {
            if (rows.get(key) !== 'RESERVED')
                return false;
            rows.delete(key);
            for (const [item, owner] of replay)
                if (owner === key)
                    replay.delete(item);
            return true;
        },
    };
}
function attemptStore() {
    const rows = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        compareAndSwap: true,
        atomicEvidenceBinding: true,
        rows,
        async reserve(binding) {
            if (rows.has(binding.attempt_id))
                return { reserved: false, reason: 'attempt_exists' };
            const owner = `owner:${binding.attempt_id}`;
            rows.set(binding.attempt_id, { binding: structuredClone(binding), owner, state: 'RESERVED' });
            return { reserved: true, owner: owner };
        },
        async transition(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner || row.state !== input.expected_state)
                return false;
            row.state = input.next_state;
            return true;
        },
        async reconcile(input) {
            const row = rows.get(input.attempt_id);
            if (!row || row.owner !== input.owner || row.state !== input.expected_state)
                return false;
            const evidence = input.evidence;
            for (const field of [
                'tenant_id', 'provider_id', 'provider_account_id', 'environment',
                'attempt_id', 'request_digest', 'provider_idempotency_key',
            ])
                if (evidence[field] !== row.binding[field])
                    return false;
            row.state = input.next_state;
            return true;
        },
    };
}
async function consequenceEnvelope(capacityUnits) {
    const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x71));
    const mldsaBackend = await loadDefaultAgilityMldsaBackend();
    assert.ok(mldsaBackend);
    const envelope = await issueConsequenceEnvelope({
        envelope_id: `envelope:grace:${capacityUnits}`,
        state_domain_id: 'state-domain:grace-reference',
        epoch: 1,
        capacity_units: capacityUnits,
        impact_profile_id: GRACE_CURTAILMENT_IMPACT_PROFILE.id,
        impact_profile_digest: GRACE_CURTAILMENT_IMPACT_PROFILE.digest,
        validity: {
            not_before: '2026-07-15T20:00:00.000Z',
            not_after: '2026-07-15T22:00:00.000Z',
        },
        issuer: { id: 'authority:grace-grid-operator', key_id: 'envelope-ed' },
        parent_allocation: null,
        renewable: false,
    }, {
        signing_keys: [
            { alg: 'Ed25519', key_id: 'envelope-ed', private_key: ED_PRIVATE },
            { alg: 'ML-DSA-65', key_id: 'envelope-pq', private_key: pqPair.secretKey },
        ],
        mldsaBackend,
    });
    return createConsequenceEnvelopeBoundary({
        envelope,
        verification_keys: [
            { alg: 'Ed25519', key_id: 'envelope-ed', public_key: ED_PUBLIC_SPKI },
            {
                alg: 'ML-DSA-65',
                key_id: 'envelope-pq',
                public_key: Buffer.from(pqPair.publicKey).toString('base64url'),
            },
        ],
        mldsaBackend,
        profile: GRACE_CURTAILMENT_IMPACT_PROFILE,
        store: createMemoryConsequenceEnvelopeStore(),
        allow_test_store: true,
        now: () => NOW,
        authorize_recovery: ({ recovery_authorization }) => recovery_authorization === 'recovery:approved',
    });
}
function input(fixture, action = fixture.action) {
    return {
        evaluation: fixture.evaluation,
        action,
        artifacts: fixture.artifacts,
        current_statuses: fixture.statuses,
    };
}
function graceResultSummary(value) {
    const result = value;
    return {
        ok: result?.ok === true,
        verdict: typeof result?.verdict === 'string' ? result.verdict : 'unknown',
    };
}
function harness(fixture, envelope, options = {}) {
    const store = aebStore();
    const attempts = attemptStore();
    let providerCalls = 0;
    let lastResult = null;
    const boundary = createConsequenceBoundary({
        executor_id: EXECUTOR,
        provider: PROVIDER,
        aeb: { config: fixture.config, adapters: fixture.adapters, store },
        attempts: {
            store: attempts,
            create_id: () => `attempt:${fixture.evaluation.operation_id}`,
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
            },
        },
        consequence_envelope: envelope,
        allow_test_consequence_envelope: true,
        local_authorize: () => true,
        invoke: async () => {
            providerCalls += 1;
            lastResult = await executeGraceReferenceInput(fixture.grace, createGraceReferenceRuntime());
            if (options.lose_response)
                throw new Error('synthetic_response_lost');
            return {
                state: 'EXECUTED',
                evidence: {
                    evidence_id: `provider-evidence:${fixture.evaluation.operation_id}`,
                    observed_at: '2026-07-15T21:45:01.000Z',
                    evidence_digest: digestAeb(graceResultSummary(lastResult)),
                },
                result: graceResultSummary(lastResult),
            };
        },
        now: () => NOW,
    });
    return { boundary, providerCalls: () => providerCalls, lastResult: () => lastResult };
}
function caseResult(id, category, passed, expected, observed) {
    return { id, category, passed, expected, observed };
}
export async function buildReferenceReport() {
    const cases = [];
    const throughFixture = evaluationFixture('operation:grace:through');
    const throughEnvelope = await consequenceEnvelope('18000000');
    const through = harness(throughFixture, throughEnvelope);
    const throughResult = await through.boundary.run(input(throughFixture));
    cases.push(caseResult('GRACE-THROUGH-CANONICAL-BOUNDARY', 'positive', throughResult.state === 'EXECUTED'
        && through.providerCalls() === 1
        && through.lastResult()?.ok === true
        && throughEnvelope.snapshot().committed_units === '18000000', 'one synthetic GRACE execution under one 18 MW aggregate reservation', {
        state: throughResult.state,
        provider_calls: through.providerCalls(),
        grace_verdict: through.lastResult()?.verdict ?? null,
        committed_watts: throughEnvelope.snapshot().committed_units,
    }));
    const exhaustedFixture = evaluationFixture('operation:grace:exhausted');
    const exhausted = harness(exhaustedFixture, throughEnvelope);
    const exhaustedResult = await exhausted.boundary.run(input(exhaustedFixture));
    cases.push(caseResult('AGGREGATE-ENVELOPE-REFUSES-SECOND-EVENT', 'hostile', exhaustedResult.state === 'REFUSED'
        && exhaustedResult.reason === 'consequence_envelope_capacity_exceeded'
        && exhausted.providerCalls() === 0, 'capacity refusal before provider entry', {
        state: exhaustedResult.state,
        reason: exhaustedResult.state === 'REFUSED' ? exhaustedResult.reason : null,
        provider_calls: exhausted.providerCalls(),
    }));
    const substitutionFixture = evaluationFixture('operation:grace:substitution');
    const substitution = harness(substitutionFixture, await consequenceEnvelope('20000000'));
    const changed = { ...substitutionFixture.action, target_delta_kw: '19000' };
    const substitutionResult = await substitution.boundary.run(input(substitutionFixture, changed));
    cases.push(caseResult('CURTAILMENT-SUBSTITUTION-REFUSED', 'hostile', substitutionResult.state === 'REFUSED'
        && substitutionResult.reason === 'exact_action_binding_mismatch'
        && substitution.providerCalls() === 0, 'exact-action refusal before provider entry', {
        state: substitutionResult.state,
        reason: substitutionResult.state === 'REFUSED' ? substitutionResult.reason : null,
        provider_calls: substitution.providerCalls(),
    }));
    const lostFixture = evaluationFixture('operation:grace:lost-response');
    const lostEnvelope = await consequenceEnvelope('18000000');
    const lost = harness(lostFixture, lostEnvelope, { lose_response: true });
    const lostResult = await lost.boundary.run(input(lostFixture));
    const retryResult = await lost.boundary.run(input(lostFixture));
    cases.push(caseResult('LOST-RESPONSE-KEEPS-CAPACITY-UNAVAILABLE', 'boundary', lostResult.state === 'INDETERMINATE'
        && lostResult.retry_allowed === false
        && retryResult.state === 'REFUSED'
        && lost.providerCalls() === 1
        && lostEnvelope.snapshot().committed_units === '18000000', 'INDETERMINATE, no blind retry, capacity remains unavailable', {
        first: lostResult.state,
        retry: retryResult.state,
        provider_calls: lost.providerCalls(),
        committed_watts: lostEnvelope.snapshot().committed_units,
    }));
    assert.equal(lostResult.state, 'INDETERMINATE');
    assert.ok(lostResult.attempt);
    const reconciled = await lost.boundary.reconcile({
        evaluation: lostFixture.evaluation,
        action: lostFixture.action,
        artifacts: lostFixture.artifacts,
        attempt: lostResult.attempt,
        outcome: {
            state: 'EXECUTED',
            evidence: {
                evidence_id: 'provider-evidence:grace:reconciled',
                observed_at: '2026-07-15T21:45:01.000Z',
                evidence_digest: digestAeb(graceResultSummary(lost.lastResult())),
            },
            result: graceResultSummary(lost.lastResult()),
        },
        recovery_authorization: 'recovery:approved',
    });
    cases.push(caseResult('AUTHENTICATED-RECONCILIATION-DOES-NOT-REEXECUTE', 'positive', reconciled.state === 'EXECUTED' && lost.providerCalls() === 1, 'terminal reconciliation with the original provider-call count unchanged', { state: reconciled.state, provider_calls: lost.providerCalls() }));
    const impact = GRACE_CURTAILMENT_IMPACT_PROFILE.derive({
        ...throughFixture.action,
        telemetry: { delivered_kw: '999999', anomaly_score: 0 },
    });
    cases.push(caseResult('TELEMETRY-CANNOT-MINT-CAPACITY', 'boundary', impact.ok === true && impact.impact_units === 18000000n, 'impact derives only from the material requested curtailment', { impact_watts: impact.ok ? impact.impact_units.toString() : null }));
    const base = {
        '@version': REPORT_VERSION,
        profile: PROFILE,
        cases,
        passed: cases.every((entry) => entry.passed),
        composition: {
            native_authority: 'GRACE mobile Class-A authorization',
            exact_action: 'CAID under a relying-party-pinned mapping',
            admission: 'AEB plus Gate at-most-one provider entry',
            aggregate_limit: 'hybrid-signed state-domain-owned consequence envelope',
            provider: 'synthetic GRACE actuator, meter, and settlement adapters',
        },
        known_limits: [
            'This is an EMILIA reference composition, not an independent implementation.',
            'The actuator and meter are synthetic; no physical grid event is claimed.',
            'The envelope bounds admitted requested watts in one owning state domain; it does not prove delivered power.',
            'At-most-one provider entry is not exactly-once physical effect.',
            'Rate, entropy, anomaly, and telemetry signals do not create or enlarge hard capacity.',
        ],
    };
    return { ...base, results_digest: sha256(canonicalizeAeb(base)) };
}
export async function runProfile(runner = {
    name: 'EMILIA reference runner',
    affiliation: 'EMILIA Protocol',
    revision: 'grace-consequence-boundary-v1',
    executed_at: NOW,
}) {
    return { ...(await buildReferenceReport()), runner };
}
function argument(name) {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : undefined;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const report = await runProfile();
    const writePath = argument('--write');
    if (writePath)
        writeFileSync(resolve(writePath), `${JSON.stringify(report, null, 2)}\n`);
    if (process.argv.includes('--reference')) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(await buildReferenceReport(), null, 2)}\n`);
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
