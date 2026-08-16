// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-acceptance-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { InMemoryAebConsumptionStore, adapterPinDigest, digestAeb, evaluateAebEvidence, mappingProfileDigest, pinnedConfigDigest, reconcileAebExecution, registryEntryDigest, unifiedRegistryDigest, verifyAebEvaluation, } from './aeb-adapter-contract.js';
import { AEB_ACCEPTANCE_PROFILE_VERSION, aebAcceptanceReservationKey, applyAebAcceptanceProfile, defineAebAcceptanceProfile, verifyAebAcceptanceProfile, } from './aeb-acceptance-profile.js';
import { OASNT_AEB_ADAPTER_ID, OASNT_AEB_ADAPTER_VERSION, OASNT_AEB_CONFIG_VERSION, OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, OASNT_TRUST_ROOT_VERSION, createOasntActionDefinition, createOasntAebAdapter, } from './aeb-oasnt-adapter.js';
const NOW = new Date(1_800_000_000 * 1000).toISOString();
const LATER = new Date(1_800_000_001 * 1000).toISOString();
const ACTION_TYPE = 'payment.transfer.1';
const ARTIFACT_REF = 'oasnt:published-v5';
const PROFILE_ID = 'oasnt:payment-transfer';
const REQUIREMENT_REF = 'requirement:human-authorization';
const TOKEN = [
    'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hc250K2p3dCJ9',
    'eyJzdWIiOiJhZ2VudC0xIiwiYWRnIjoiWWxIcDNNNEpJV0ZQUFpJVkF3QW1ZT0JPTWZVeWIyYmpFNnZlM0FEMmlhUSIsImRzcCI6InVTRWdPRzlVQzFJV0d4ekJhbEp2NWNJYmZ4RThreG1vS0YyNXlyUmwxZnMiLCJycWYiOiIxR0w3Q0lnMUprS0dhR2ZIZ2RGNV85M3JWeDRGcWZqb1kwbFlaNnhialEwIiwiaW50IjoiY2xlYW4iLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwLCJjbmYiOnsiamt0IjoieGNEYmMyLU1zUklFTlF5bkFZR3RKMFZjMHhQVEJkZmpfMWlBZUk5TU1GbyJ9fQ',
    '1rS6k1Yz9ZsYWpk51vTv0GDJX4VJ9vp3Qb9v4ZNG1VjQQwvVvUpUjNao7ZA0hxmBqEOHPLv8NY5C_Jqjl-SJzA',
].join('.');
const expectedAction = Object.freeze({
    action_type: ACTION_TYPE,
    native_action: {
        type: 'payment.transfer',
        parameters: { amount: '100.00', payee: 'acct_9' },
    },
    request: {
        method: 'POST',
        path: '/v1/transfers',
        org_id: 'org_acme',
        scope: 'payments:write',
        body_sha256: '05be0ab936cd56cf971cc8b57f7132a690d4ed3bf63b37ac3cb81d6e289f847a',
    },
});
const adapterConfig = Object.freeze({
    '@version': OASNT_AEB_CONFIG_VERSION,
    evidence_role: 'human-authorization',
    subject: { id: 'human:agent-1', kind: 'human', native_id: 'agent-1' },
    action_type: ACTION_TYPE,
    require_request_binding: true,
    clock_skew_seconds: 5,
    max_token_lifetime_seconds: 120,
    max_status_age_seconds: 120,
    required_assurance_level: null,
});
const trustRoot = Object.freeze({
    '@version': OASNT_TRUST_ROOT_VERSION,
    use: 'enrolled-oasnt-signing-key',
    native_subject: 'agent-1',
    public_jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'P7Vp3OZi4XYii2VHo4T08zkjKrKhCt-gY-oAATkXaao',
        y: 'QNEaWqPG2EI5-2AdT8oX-S4odj8TH9wj_JW2I2ILBoc',
    },
    jwk_thumbprint: 'xcDbc2-MsRIENQynAYGtJ0Vc0xPTBdfj_1iAeI9MMFo',
    enrollment: {
        hardware_attested: true,
        evidence_digest: `sha256:${'a'.repeat(64)}`,
    },
});
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function status() {
    return {
        checked_at: NOW,
        expires_at: new Date(Date.parse(NOW) + 60_000).toISOString(),
        revocation_checked: true,
        revoked: false,
        consumed: false,
    };
}
function registryEntry(id, kind, definition) {
    const entry = { kind, version: '1', status: 'active', definition };
    entry.definition_digest = registryEntryDigest(id, entry);
    return entry;
}
function buildFixture() {
    const adapter = createOasntAebAdapter({ config: adapterConfig, trust_roots: [trustRoot] });
    const profile = {
        version: OASNT_CAID_MAPPING_VERSION,
        definition: createOasntActionDefinition(ACTION_TYPE, true),
        registry_entry_ref: 'mapping:oasnt-payment-transfer',
        mapper_id: OASNT_CAID_MAPPER_ID,
        resolver: {
            id: OASNT_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: OASNT_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: ['token.int', 'token.cnf.jkt', 'token.jti', 'token.iat', 'token.exp'],
        },
        profile_digest: digestAeb(null),
    };
    profile.profile_digest = mappingProfileDigest(PROFILE_ID, profile);
    const nativeInput = {
        artifact: TOKEN,
        artifact_ref: ARTIFACT_REF,
        status: status(),
        trust_roots: [trustRoot],
        adapter_config: adapterConfig,
        expected_action: expectedAction,
        now: NOW,
    };
    const native = adapter.verifyNative(nativeInput);
    const mapped = adapter.mapAction({ ...nativeInput, profile, native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.ok(mapped.caid);
    const registry = {
        '@version': 'EP-EVIDENCE-REGISTRY-v1',
        registry_id: 'registry:foreign-proof-convergence',
        epoch: 1,
        entries: {
            [profile.registry_entry_ref]: registryEntry(profile.registry_entry_ref, 'mapping-profile', {
                profile_digest: profile.profile_digest,
            }),
            'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', {
                role: 'human-authorization', subject_kinds: ['human'],
            }),
        },
        registry_digest: digestAeb(null),
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const adapterPin = {
        version: adapter.version,
        trust_roots: [trustRoot],
        config: adapterConfig,
        config_digest: digestAeb(null),
        max_status_age_sec: adapterConfig.max_status_age_seconds,
    };
    adapterPin.config_digest = adapterPinDigest(adapter.id, adapterPin);
    const evaluatorKey = crypto.generateKeyPairSync('ed25519');
    const config = {
        '@version': 'AEB-ADAPTER-v1',
        relying_party_id: 'rp:foreign-proof-convergence',
        evaluator_keys: {
            'eval:foreign-proof-convergence': { public_key: spki(evaluatorKey.publicKey) },
        },
        registry,
        accepted_mappers: [OASNT_CAID_MAPPER_ID],
        adapters: { [adapter.id]: adapterPin },
        profiles: { [PROFILE_ID]: profile },
        requirements: {
            [REQUIREMENT_REF]: {
                '@version': 'AEB-REQUIREMENT-v1',
                all_of: ['human-authorization'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const evaluation = evaluateAebEvidence({
        config,
        adapters: { [adapter.id]: adapter },
        operation_id: 'operation:payment-transfer-001',
        consumption_nonce: 'aeb-nonce:payment-transfer-001',
        initiator_id: 'workload:payment-agent',
        executor_id: 'workload:payments-api',
        requirement_ref: REQUIREMENT_REF,
        caid: mapped.caid,
        expected_action: expectedAction,
        legs: [{
                adapter_id: adapter.id,
                profile_id: PROFILE_ID,
                artifact_ref: ARTIFACT_REF,
                artifact: TOKEN,
                status: status(),
            }],
        evaluated_at: NOW,
        signer: { key_id: 'eval:foreign-proof-convergence', private_key: evaluatorKey.privateKey },
    });
    assert.equal(evaluation.valid, true, evaluation.reasons.join('; '));
    const verification = verifyAebEvaluation(evaluation.record, {
        mode: 'execution',
        config,
        adapters: { [adapter.id]: adapter },
        artifacts: { [ARTIFACT_REF]: TOKEN },
        expected_action: expectedAction,
        current_statuses: { [ARTIFACT_REF]: status() },
        now: LATER,
    });
    assert.equal(verification.valid, true, verification.reasons.join('; '));
    assert.equal(verification.execution_authorizing, true);
    const acceptanceProfile = defineAebAcceptanceProfile({
        '@version': AEB_ACCEPTANCE_PROFILE_VERSION,
        profile_id: 'acceptance:payment-transfer',
        version: 1,
        authored_by: 'rp:foreign-proof-convergence',
        relying_party_id: config.relying_party_id,
        action_type: ACTION_TYPE,
        pinned_config_digest: pinnedConfigDigest(config),
        requirement_ref: evaluation.record.requirement_ref,
        requirement_digest: evaluation.record.requirement_digest,
        registry_digest: evaluation.record.registry_digest,
        required_roles: ['human-authorization'],
        accepted_inputs: [{
                adapter_id: OASNT_AEB_ADAPTER_ID,
                adapter_version: OASNT_AEB_ADAPTER_VERSION,
                profile_id: PROFILE_ID,
                profile_digest: profile.profile_digest,
                evidence_role: 'human-authorization',
            }],
    });
    return { adapter, acceptanceProfile, config, evaluation, verification };
}
test('one content-addressed profile has fixed monitor and enforce semantics', () => {
    const { acceptanceProfile } = buildFixture();
    assert.equal(acceptanceProfile.modes.monitor.authorizes_execution, false);
    assert.equal(acceptanceProfile.modes.monitor.consumes_evidence, false);
    assert.equal(acceptanceProfile.modes.enforce.requires_execution_verification, true);
    assert.equal(acceptanceProfile.modes.enforce.requires_local_authorization, true);
    assert.equal(acceptanceProfile.modes.enforce.requires_one_time_consumption, true);
    assert.equal(verifyAebAcceptanceProfile(acceptanceProfile, acceptanceProfile.profile_digest).valid, true);
    const tampered = structuredClone(acceptanceProfile);
    tampered.modes.monitor.authorizes_execution = true;
    const result = verifyAebAcceptanceProfile(tampered, acceptanceProfile.profile_digest);
    assert.equal(result.valid, false);
    assert.ok(result.reasons.includes('acceptance_profile_digest_mismatch'));
});
test('monitor reports the enforce decision without authorizing or consuming', () => {
    const { acceptanceProfile, evaluation, verification } = buildFixture();
    const store = new InMemoryAebConsumptionStore();
    const result = applyAebAcceptanceProfile(acceptanceProfile, evaluation.record, {
        mode: 'monitor',
        expected_profile_digest: acceptanceProfile.profile_digest,
        verification,
        local_authorization: true,
        store,
    });
    assert.equal(result.state, 'MONITOR_WOULD_ACCEPT');
    assert.equal(result.would_enforce, true);
    assert.equal(result.allowed, false);
    assert.equal(result.invoke_allowed, false);
    assert.equal(result.reservation_key, undefined);
    assert.equal(store.state(aebAcceptanceReservationKey(evaluation.record)), 'AVAILABLE');
});
test('hostile or extended acceptance profiles fail closed without throwing', () => {
    const { acceptanceProfile, evaluation, verification } = buildFixture();
    const extended = { ...structuredClone(acceptanceProfile), presenter_mode: 'enforce' };
    assert.equal(verifyAebAcceptanceProfile(extended).valid, false);
    const cyclic = {};
    cyclic.self = cyclic;
    const hostile = new Proxy({}, {
        ownKeys() { throw new Error('presenter trap'); },
    });
    for (const value of [cyclic, hostile]) {
        assert.doesNotThrow(() => verifyAebAcceptanceProfile(value));
        assert.equal(verifyAebAcceptanceProfile(value).valid, false);
    }
    assert.doesNotThrow(() => applyAebAcceptanceProfile(hostile, evaluation.record, {
        mode: 'enforce',
        expected_profile_digest: acceptanceProfile.profile_digest,
        verification,
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
    }));
    assert.equal(applyAebAcceptanceProfile(hostile, evaluation.record, {
        mode: 'enforce',
        expected_profile_digest: acceptanceProfile.profile_digest,
        verification,
        local_authorization: true,
        store: new InMemoryAebConsumptionStore(),
    }).invoke_allowed, false);
});
test('attempt -> challenge -> approve -> consume -> execute -> reconcile is one replay-safe path', () => {
    const { acceptanceProfile, evaluation, verification } = buildFixture();
    const store = new InMemoryAebConsumptionStore();
    const stages = [];
    stages.push('attempt');
    const challenge = {
        acceptance_profile_digest: acceptanceProfile.profile_digest,
        requirement_ref: acceptanceProfile.requirement_ref,
        requirement_digest: acceptanceProfile.requirement_digest,
        required_roles: acceptanceProfile.required_roles,
    };
    stages.push('challenge');
    assert.deepEqual(challenge.required_roles, ['human-authorization']);
    assert.equal(evaluation.record.legs[0].adapter_id, OASNT_AEB_ADAPTER_ID);
    assert.equal(evaluation.record.verdict, 'SATISFIED');
    stages.push('approve');
    const decision = applyAebAcceptanceProfile(acceptanceProfile, evaluation.record, {
        mode: 'enforce',
        expected_profile_digest: challenge.acceptance_profile_digest,
        verification,
        local_authorization: true,
        store,
    });
    assert.equal(decision.state, 'AUTHORIZED');
    assert.equal(decision.invoke_allowed, true);
    assert.ok(decision.reservation_key);
    assert.equal(store.state(decision.reservation_key), 'RESERVED');
    stages.push('consume');
    let effects = 0;
    if (decision.invoke_allowed)
        effects += 1;
    assert.equal(effects, 1);
    stages.push('execute');
    const reconciled = reconcileAebExecution(store, decision.reservation_key, 'COMMITTED');
    assert.equal(reconciled.state, 'CONSUMED');
    assert.equal(reconciled.retry_allowed, false);
    stages.push('reconcile');
    const replay = applyAebAcceptanceProfile(acceptanceProfile, evaluation.record, {
        mode: 'enforce',
        expected_profile_digest: acceptanceProfile.profile_digest,
        verification,
        local_authorization: true,
        store,
    });
    assert.equal(replay.state, 'REFUSED');
    assert.equal(replay.reason, 'consumption_conflict');
    assert.equal(replay.invoke_allowed, false);
    assert.equal(effects, 1);
    assert.deepEqual(stages, ['attempt', 'challenge', 'approve', 'consume', 'execute', 'reconcile']);
});
test('profile refuses presenter-swapped requirements, adapter pins, or local authority', () => {
    const { acceptanceProfile, evaluation, verification } = buildFixture();
    const store = new InMemoryAebConsumptionStore();
    const wrongRequirement = structuredClone(evaluation.record);
    wrongRequirement.requirement_digest = `sha256:${'f'.repeat(64)}`;
    const refusedRequirement = applyAebAcceptanceProfile(acceptanceProfile, wrongRequirement, {
        mode: 'enforce', expected_profile_digest: acceptanceProfile.profile_digest,
        verification, local_authorization: true, store,
    });
    assert.equal(refusedRequirement.state, 'REFUSED');
    assert.equal(refusedRequirement.reason, 'acceptance_profile_record_mismatch');
    const wrongAdapter = structuredClone(evaluation.record);
    wrongAdapter.legs[0].adapter_version = '999';
    const refusedAdapter = applyAebAcceptanceProfile(acceptanceProfile, wrongAdapter, {
        mode: 'enforce', expected_profile_digest: acceptanceProfile.profile_digest,
        verification, local_authorization: true, store,
    });
    assert.equal(refusedAdapter.state, 'REFUSED');
    assert.equal(refusedAdapter.reason, 'acceptance_profile_input_refused');
    const refusedLocal = applyAebAcceptanceProfile(acceptanceProfile, evaluation.record, {
        mode: 'enforce', expected_profile_digest: acceptanceProfile.profile_digest,
        verification, local_authorization: false, store,
    });
    assert.equal(refusedLocal.state, 'REFUSED');
    assert.equal(refusedLocal.reason, 'local_authorization_denied');
});
