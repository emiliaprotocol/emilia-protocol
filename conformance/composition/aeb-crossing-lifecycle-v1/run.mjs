// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Canonical protected-consequence-boundary lifecycle reproduction.
 *
 * Two native authority systems enter through their own pinned adapters and
 * traverse one Gate lifecycle contract. The runner preserves native
 * provenance and replay identity; it does not claim the native systems are
 * semantically identical.
 */
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { adapterPinDigest, canonicalizeAeb, digestAeb, evaluateAebEvidence, mappingProfileDigest, registryEntryDigest, unifiedRegistryDigest, } from '../../../packages/verify/aeb-adapter-contract.js';
import { OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID, OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION, OAUTH_TXN_CHALLENGE_CONFIG_VERSION, OAUTH_TXN_CHALLENGE_MAPPING_VERSION, OAUTH_TXN_CHALLENGE_MAPPER_ID, OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION, createOAuthTransactionChallengeActionDefinition, createOAuthTransactionChallengeAebAdapter, } from '../../../packages/verify/aeb-oauth-transaction-challenge-adapter.js';
import { OASNT_AEB_ADAPTER_ID, OASNT_AEB_ADAPTER_VERSION, OASNT_AEB_CONFIG_VERSION, OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, OASNT_TRUST_ROOT_VERSION, createOasntActionDefinition, createOasntAebAdapter, } from '../../../packages/verify/aeb-oasnt-adapter.js';
import { issueAebCrossingRecord, mapBcrCrossingAuthority, verifyAebCrossingRecord, } from '../../../packages/verify/aeb-crossing-record.js';
import { loadDefaultAgilityMldsaBackend } from '../../../packages/verify/pq-signature-agility.js';
import { createConsequenceBoundary, } from '../../../packages/gate/consequence-boundary.js';
export const PROFILE = 'EP-AEB-CROSSING-LIFECYCLE-COMPOSITION-v1';
const REPORT_VERSION = 'AEB-CROSSING-LIFECYCLE-REFERENCE-REPORT-v1';
const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');
const DECISION_NOW = '2027-01-15T08:00:30.000Z';
const EVALUATED_AT = '2027-01-15T08:00:29.000Z';
const EXECUTOR = 'executor:canonical-boundary';
const PROVIDER = Object.freeze({
    tenant_id: 'tenant:canonical-boundary',
    provider_id: 'provider:payment-sandbox',
    provider_account_id: 'account:canonical-boundary',
    environment: 'sandbox',
});
const ED_PRIVATE_JWK = {
    crv: 'Ed25519',
    d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
    x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
    kty: 'OKP',
};
const ED_PUBLIC_JWK = {
    crv: 'Ed25519',
    x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
    kty: 'OKP',
};
const EVALUATOR_PRIVATE = crypto.createPrivateKey({ key: ED_PRIVATE_JWK, format: 'jwk' });
const EVALUATOR_PUBLIC = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: 'jwk' });
const EVALUATOR_PUBLIC_SPKI = EVALUATOR_PUBLIC
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
function compactEs256(header, claims, privateKey) {
    const encodedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const encodedClaims = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
    const signingInput = `${encodedHeader}.${encodedClaims}`;
    const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
    });
    return `${signingInput}.${signature.toString('base64url')}`;
}
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
const OASNT_TOKEN = [
    'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hc250K2p3dCJ9',
    'eyJzdWIiOiJhZ2VudC0xIiwiYWRnIjoiWWxIcDNNNEpJV0ZQUFpJVkF3QW1ZT0JPTWZVeWIyYmpFNnZlM0FEMmlhUSIsImRzcCI6InVTRWdPRzlVQzFJV0d4ekJhbEp2NWNJYmZ4RThreG1vS0YyNXlyUmwxZnMiLCJycWYiOiIxR0w3Q0lnMUprS0dhR2ZIZ2RGNV85M3JWeDRGcWZqb1kwbFlaNnhialEwIiwiaW50IjoiY2xlYW4iLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwLCJjbmYiOnsiamt0IjoieGNEYmMyLU1zUklFTlF5bkFZR3RKMFZjMHhQVEJkZmpfMWlBZUk5TU1GbyJ9fQ',
    '1rS6k1Yz9ZsYWpk51vTv0GDJX4VJ9vp3Qb9v4ZNG1VjQQwvVvUpUjNao7ZA0hxmBqEOHPLv8NY5C_Jqjl-SJzA',
].join('.');
function sorted(value) {
    if (Array.isArray(value))
        return value.map(sorted);
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
    }
    return value;
}
function sha256(value) {
    return `sha256:${crypto.hash('sha256', value, 'hex')}`;
}
function registryEntry(entryId, kind, definition) {
    const entry = {
        kind,
        version: '1',
        status: 'active',
        definition,
        definition_digest: digestAeb(null),
    };
    entry.definition_digest = registryEntryDigest(entryId, entry);
    return entry;
}
function oauthFixture() {
    const resourceKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const authorizationServerKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const details = [{
            type: 'payment',
            actions: ['initiate'],
            locations: ['https://payments.example/accounts/123'],
            instructedAmount: { currency: 'USD', amount: '500.00' },
            creditorName: 'Example Ltd',
        }];
    const action = {
        action_type: 'payment.initiate.1',
        oauth_transaction: {
            txn: 'txn-canonical-boundary-1',
            authorization_details: details,
            actor: { sub: 'workload:payment-agent' },
        },
    };
    const descriptor = {
        id: 'reference:oauth-details-exact-match',
        version: '1',
        implementation_digest: digestAeb({ implementation: 'reference:oauth-details-exact-match', version: '1' }),
    };
    const challengeClaims = {
        iss: 'https://payments.example',
        aud: 'https://as.example',
        iat: 1_800_000_010,
        exp: 1_800_000_070,
        jti: 'challenge-jti-1',
        txn: action.oauth_transaction.txn,
        authorization_details: details,
        reason: 'Approve this exact payment',
        act: action.oauth_transaction.actor,
    };
    const accessClaims = {
        iss: 'https://as.example',
        sub: 'principal:customer-42',
        aud: 'https://payments.example',
        iat: 1_800_000_025,
        exp: 1_800_000_145,
        jti: 'access-token-jti-1',
        client_id: 'agent-client-42',
        txn: action.oauth_transaction.txn,
        authorization_details: details,
        act: action.oauth_transaction.actor,
    };
    const config = {
        '@version': OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
        evidence_role: 'transaction-authorization',
        subject: { id: 'organization:authorization-server', kind: 'organization', native_id: 'https://as.example' },
        action_type: action.action_type,
        protected_resource: 'https://payments.example',
        authorization_server: 'https://as.example',
        oauth_client_id: 'agent-client-42',
        oauth_subject: 'principal:customer-42',
        require_actor_context: true,
        clock_skew_seconds: 2,
        max_challenge_lifetime_seconds: 120,
        max_access_token_lifetime_seconds: 180,
        max_status_age_seconds: 120,
        details_verifier: descriptor,
    };
    const trust_roots = [
        {
            '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
            use: 'protected-resource-challenge',
            issuer: 'https://payments.example',
            key_id: 'resource-es256-1',
            algorithm: 'ES256',
            public_key: spki(resourceKey.publicKey),
        },
        {
            '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
            use: 'authorization-server-access-token',
            issuer: 'https://as.example',
            key_id: 'as-es256-1',
            algorithm: 'ES256',
            public_key: spki(authorizationServerKey.publicKey),
        },
    ];
    const detailsVerifier = {
        ...descriptor,
        verify(input) {
            return digestAeb(input.granted) === digestAeb(input.expected)
                && digestAeb(input.requested) === digestAeb(input.granted)
                ? { verified: true, reason: null }
                : { verified: false, reason: 'authorization_details_broadened_or_mismatched' };
        },
    };
    const profile = {
        version: OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
        definition: createOAuthTransactionChallengeActionDefinition(action.action_type, true),
        registry_entry_ref: 'mapping:oauth-transaction-payment',
        mapper_id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
        resolver: {
            id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: OAUTH_TXN_CHALLENGE_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'challenge.reason', 'challenge.jti', 'challenge.iat', 'challenge.exp',
                'access_token.jti', 'access_token.iat', 'access_token.exp',
            ],
        },
        profile_digest: digestAeb(null),
    };
    return {
        native_system: 'oauth-transaction-challenge',
        adapter: createOAuthTransactionChallengeAebAdapter({ config, trust_roots, details_verifier: detailsVerifier }),
        adapter_id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
        adapter_version: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
        config,
        trust_roots,
        role: 'transaction-authorization',
        subject_kind: 'organization',
        profile_id: 'oauth-transaction-payment',
        profile,
        artifact_ref: 'artifact:oauth-issued-transaction',
        artifact: {
            challenge_jwt: compactEs256({ alg: 'ES256', typ: 'txn-authz-challenge+jwt', kid: 'resource-es256-1' }, challengeClaims, resourceKey.privateKey),
            access_token_jwt: compactEs256({ alg: 'ES256', typ: 'at+jwt', kid: 'as-es256-1' }, accessClaims, authorizationServerKey.privateKey),
        },
        status: {
            checked_at: '2027-01-15T08:00:29.000Z',
            expires_at: '2027-01-15T08:01:00.000Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        action,
    };
}
function oasntFixture() {
    const action = {
        action_type: 'payment.transfer.1',
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
    };
    const config = {
        '@version': OASNT_AEB_CONFIG_VERSION,
        evidence_role: 'human-authorization',
        subject: { id: 'human:agent-1', kind: 'human', native_id: 'agent-1' },
        action_type: action.action_type,
        require_request_binding: true,
        clock_skew_seconds: 5,
        max_token_lifetime_seconds: 120,
        max_status_age_seconds: 120,
        required_assurance_level: null,
    };
    const trustRoot = {
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
    };
    const profile = {
        version: OASNT_CAID_MAPPING_VERSION,
        definition: createOasntActionDefinition(action.action_type, true),
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
    return {
        native_system: 'oasnt',
        adapter: createOasntAebAdapter({ config, trust_roots: [trustRoot] }),
        adapter_id: OASNT_AEB_ADAPTER_ID,
        adapter_version: OASNT_AEB_ADAPTER_VERSION,
        config,
        trust_roots: [trustRoot],
        role: 'human-authorization',
        subject_kind: 'human',
        profile_id: 'oasnt-payment-transfer',
        profile,
        artifact_ref: 'artifact:oasnt-human-authorization',
        artifact: OASNT_TOKEN,
        status: {
            checked_at: '2027-01-15T08:00:29.000Z',
            expires_at: '2027-01-15T08:01:00.000Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        action,
    };
}
function evaluateFixture(native, operationId) {
    const profile = structuredClone(native.profile);
    profile.profile_digest = mappingProfileDigest(native.profile_id, profile);
    const entries = {
        [profile.registry_entry_ref]: registryEntry(profile.registry_entry_ref, 'mapping-profile', { profile_digest: profile.profile_digest }),
        [`role:${native.role}`]: registryEntry(`role:${native.role}`, 'evidence-role', { role: native.role, subject_kinds: [native.subject_kind] }),
    };
    const registry = {
        '@version': 'EP-EVIDENCE-REGISTRY-v1',
        registry_id: `registry:${native.native_system}`,
        epoch: 1,
        entries,
        registry_digest: digestAeb(null),
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const pin = {
        version: native.adapter_version,
        trust_roots: native.trust_roots,
        config: native.config,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    pin.config_digest = adapterPinDigest(native.adapter_id, pin);
    const config = {
        '@version': 'AEB-ADAPTER-v1',
        relying_party_id: 'rp:canonical-boundary-reference',
        evaluator_keys: { 'eval:canonical-boundary': { public_key: EVALUATOR_PUBLIC_SPKI } },
        registry,
        accepted_mappers: [profile.mapper_id],
        adapters: { [native.adapter_id]: pin },
        profiles: { [native.profile_id]: profile },
        requirements: {
            [`requirement:${native.role}`]: {
                '@version': 'AEB-REQUIREMENT-v1',
                all_of: [native.role],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const nativeResult = native.adapter.verifyNative({
        artifact: structuredClone(native.artifact),
        artifact_ref: native.artifact_ref,
        status: structuredClone(native.status),
        trust_roots: structuredClone(native.trust_roots),
        adapter_config: structuredClone(native.config),
        expected_action: structuredClone(native.action),
        now: EVALUATED_AT,
    });
    const mapped = native.adapter.mapAction({
        artifact: structuredClone(native.artifact),
        artifact_ref: native.artifact_ref,
        status: structuredClone(native.status),
        trust_roots: structuredClone(native.trust_roots),
        adapter_config: structuredClone(native.config),
        profile,
        expected_action: structuredClone(native.action),
        now: EVALUATED_AT,
        native: nativeResult,
    });
    assert.equal(nativeResult.native_verification, 'VERIFIED', JSON.stringify(nativeResult));
    assert.equal(nativeResult.acceptance, 'ACCEPTED', JSON.stringify(nativeResult));
    assert.equal(mapped.mapping, 'MATCH', JSON.stringify(mapped));
    assert.ok(mapped.caid);
    const evaluation = evaluateAebEvidence({
        config,
        adapters: { [native.adapter_id]: native.adapter },
        operation_id: operationId,
        consumption_nonce: `nonce:${operationId}`,
        initiator_id: 'agent:payment-orchestrator',
        executor_id: EXECUTOR,
        requirement_ref: `requirement:${native.role}`,
        caid: mapped.caid,
        expected_action: native.action,
        legs: [{
                adapter_id: native.adapter_id,
                profile_id: native.profile_id,
                artifact_ref: native.artifact_ref,
                artifact: native.artifact,
                status: native.status,
            }],
        evaluated_at: EVALUATED_AT,
        signer: { key_id: 'eval:canonical-boundary', private_key: EVALUATOR_PRIVATE },
    });
    assert.equal(evaluation.valid, true, JSON.stringify(evaluation.reasons));
    return {
        native,
        config,
        adapters: { [native.adapter_id]: native.adapter },
        evaluation: evaluation.record,
        artifacts: { [native.artifact_ref]: native.artifact },
        statuses: { [native.artifact_ref]: native.status },
    };
}
function aebStore() {
    const operations = new Map();
    const replayOwners = new Map();
    return {
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        atomicReplayFenced: true,
        operations,
        async reserve(key, replayKeys) {
            if (operations.has(key))
                return 'CONSUMPTION_CONFLICT';
            if (replayKeys.some((replayKey) => replayOwners.has(replayKey)))
                return 'NATIVE_REPLAY_CONFLICT';
            operations.set(key, 'RESERVED');
            for (const replayKey of replayKeys)
                replayOwners.set(replayKey, key);
            return 'RESERVED';
        },
        async commit(key) {
            if (operations.get(key) !== 'RESERVED')
                return false;
            operations.set(key, 'CONSUMED');
            return true;
        },
        async release(key) {
            if (operations.get(key) !== 'RESERVED')
                return false;
            operations.delete(key);
            for (const [replayKey, owner] of replayOwners)
                if (owner === key)
                    replayOwners.delete(replayKey);
            return true;
        },
    };
}
function attemptStore() {
    const rows = new Map();
    let ownerCounter = 0;
    return {
        durable: true,
        ownershipFenced: true,
        compareAndSwap: true,
        atomicEvidenceBinding: true,
        rows,
        async reserve(binding) {
            if (rows.has(binding.attempt_id))
                return { reserved: false, reason: 'attempt_exists' };
            const owner = `owner:canonical-boundary:${++ownerCounter}`;
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
function boundaryHarness(fixture, options = {}) {
    const store = options.store ?? aebStore();
    const attempts = options.attempts ?? attemptStore();
    let providerCalls = 0;
    let attemptCounter = 0;
    const boundary = createConsequenceBoundary({
        executor_id: EXECUTOR,
        provider: PROVIDER,
        aeb: { config: fixture.config, adapters: fixture.adapters, store },
        attempts: {
            store: attempts,
            create_id: () => `attempt:${fixture.evaluation.operation_id}:${++attemptCounter}`,
            recover: ({ attempt, recovery_authorization }) => {
                if (recovery_authorization !== 'recovery:approved')
                    return null;
                const row = attempts.rows.get(attempt.attempt_id);
                return row ? { ...structuredClone(row.binding), owner: row.owner } : null;
            },
        },
        local_authorize: () => true,
        invoke: async (context) => {
            providerCalls += 1;
            if (options.invoke)
                return options.invoke(context);
            return {
                state: 'EXECUTED',
                evidence: {
                    evidence_id: `provider-evidence:${fixture.evaluation.operation_id}`,
                    observed_at: '2027-01-15T08:00:31.000Z',
                    evidence_digest: digestAeb({ provider: 'payment-sandbox', operation: fixture.evaluation.operation_id }),
                },
                result: { accepted: true },
            };
        },
        now: () => DECISION_NOW,
    });
    return { boundary, store, attempts, providerCalls: () => providerCalls };
}
function runInput(fixture, action = fixture.native.action) {
    return {
        evaluation: fixture.evaluation,
        action,
        artifacts: fixture.artifacts,
        current_statuses: fixture.statuses,
    };
}
function result(id, category, passed, expected, observed) {
    return { id, category, passed, expected, observed };
}
async function validCrossingRecord(source) {
    const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x41));
    const pqBackend = await loadDefaultAgilityMldsaBackend();
    assert.ok(pqBackend);
    const native = mapBcrCrossingAuthority({
        native_verification: 'VERIFIED',
        rp_acceptance: 'ACCEPTED',
        issuer: 'authority:finance-controller',
        subject: 'agent:payment-orchestrator',
        capability_id: 'capability:canonical-boundary',
        generation: 1,
        receipt_digest: digestAeb({ receipt: 'canonical-boundary' }),
        mapping_profile_digest: digestAeb({ mapping: 'bcr-crossing-v1' }),
        constraints_digest: digestAeb({ limit: 1 }),
        status: {
            value: 'CURRENT',
            checked_at: DECISION_NOW,
            source_head_digest: digestAeb({ status: 'current' }),
        },
        validity: {
            not_before: '2027-01-15T08:00:00.000Z',
            not_after: '2027-01-15T08:05:00.000Z',
        },
    });
    assert.equal(native.ok, true);
    const record = await issueAebCrossingRecord({
        record_id: 'crossing:lifecycle:0001',
        operation_id: source.evaluation.operation_id,
        issued_at: DECISION_NOW,
        native_authority: native.authority,
        action: {
            caid: source.evaluation.caid,
            action_digest: digestAeb(source.native.action),
        },
        boundary: {
            relying_party_id: 'rp:canonical-boundary-reference',
            audience: 'provider:payment-sandbox',
            executor_id: EXECUTOR,
            state_domain_id: 'state-domain:canonical-boundary',
        },
        requirements: {
            admission_digest: digestAeb({ admission: 'past' }),
            review_digest: digestAeb({ review: 'past' }),
        },
        admission_reference: { state: 'PRESENT', digest: digestAeb({ admission: 'past' }) },
        lifecycle_records: {
            evaluation_digest: digestAeb(source.evaluation),
            consumption_digest: digestAeb({ consumed: true }),
            provider_entry_digest: digestAeb({ entered: true }),
        },
        evaluated_evidence_digests: [digestAeb(source.native.artifact)],
        configuration_digests: [digestAeb(source.config)],
        referee: {
            native_verification: 'VERIFIED',
            rp_acceptance: 'ACCEPTED',
            action_relation: 'EXACT_MATCH',
            status: 'CURRENT',
            replay: 'FRESH',
            admission: 'ADMIT',
            custody: 'TERMINAL',
            provider_commitment: 'COMMITTED',
            observed_effect: 'NOT_OBSERVED',
            retry: 'REFUSE',
            reconciliation: 'NOT_APPLICABLE',
            reason_codes: [],
        },
    }, {
        deterministic: true,
        mldsaBackend: pqBackend,
        signing_keys: [
            { alg: 'Ed25519', key_id: 'crossing-ed', private_key: EVALUATOR_PRIVATE },
            { alg: 'ML-DSA-65', key_id: 'crossing-pq', private_key: pqPair.secretKey },
        ],
    });
    const verification = await verifyAebCrossingRecord(record, {
        mldsaBackend: pqBackend,
        verification_keys: [
            { alg: 'Ed25519', key_id: 'crossing-ed', public_key: EVALUATOR_PUBLIC_SPKI },
            { alg: 'ML-DSA-65', key_id: 'crossing-pq', public_key: Buffer.from(pqPair.publicKey).toString('base64url') },
        ],
    });
    assert.equal(verification.verified, true, JSON.stringify(verification));
    return record;
}
export async function buildReferenceReport() {
    const cases = [];
    const oauth = evaluateFixture(oauthFixture(), 'operation:oauth-through');
    const oauthRun = boundaryHarness(oauth);
    const oauthResult = await oauthRun.boundary.run(runInput(oauth));
    cases.push(result('OAUTH-ISSUED-ARTIFACT-THROUGH', 'positive', oauthResult.state === 'EXECUTED' && oauthRun.providerCalls() === 1, 'EXECUTED with one provider call', {
        native_system: oauth.native.native_system,
        state: oauthResult.state,
        provider_calls: oauthRun.providerCalls(),
        replay_unit: oauth.evaluation.legs[0]?.replay_unit ?? null,
    }));
    const human = evaluateFixture(oasntFixture(), 'operation:human-through');
    const humanRun = boundaryHarness(human);
    const humanResult = await humanRun.boundary.run(runInput(human));
    cases.push(result('HUMAN-AUTHORIZATION-THROUGH', 'positive', humanResult.state === 'EXECUTED' && humanRun.providerCalls() === 1, 'EXECUTED with one provider call', {
        native_system: human.native.native_system,
        state: humanResult.state,
        provider_calls: humanRun.providerCalls(),
        replay_unit: human.evaluation.legs[0]?.replay_unit ?? null,
    }));
    const wrapperNative = oauthFixture();
    const wrapperOne = evaluateFixture(wrapperNative, 'operation:wrapper-one');
    const wrapperTwo = evaluateFixture(wrapperNative, 'operation:wrapper-two');
    const wrapperStore = aebStore();
    const wrapperFirst = boundaryHarness(wrapperOne, { store: wrapperStore });
    const wrapperSecond = boundaryHarness(wrapperTwo, { store: wrapperStore });
    const wrapperFirstResult = await wrapperFirst.boundary.run(runInput(wrapperOne));
    const wrapperSecondResult = await wrapperSecond.boundary.run(runInput(wrapperTwo));
    cases.push(result('WRAPPER-INDEPENDENT-REPLAY', 'hostile', wrapperFirstResult.state === 'EXECUTED'
        && wrapperSecondResult.state === 'REFUSED'
        && wrapperSecondResult.reason === 'native_replay_conflict'
        && wrapperSecond.providerCalls() === 0, 'native_replay_conflict before provider entry', {
        first: wrapperFirstResult.state,
        second: wrapperSecondResult.state,
        reason: wrapperSecondResult.state === 'REFUSED' ? wrapperSecondResult.reason : null,
        provider_calls_second: wrapperSecond.providerCalls(),
    }));
    const concurrent = evaluateFixture(oasntFixture(), 'operation:concurrent');
    const concurrentRun = boundaryHarness(concurrent);
    const concurrentResults = await Promise.all([
        concurrentRun.boundary.run(runInput(concurrent)),
        concurrentRun.boundary.run(runInput(concurrent)),
    ]);
    cases.push(result('CONCURRENT-ADMISSION-AT-MOST-ONE', 'hostile', concurrentRun.providerCalls() === 1
        && concurrentResults.filter((entry) => entry.state === 'EXECUTED').length === 1
        && concurrentResults.filter((entry) => entry.state === 'REFUSED').length === 1, 'one EXECUTED, one REFUSED, one provider call', {
        states: concurrentResults.map((entry) => entry.state).sort(),
        provider_calls: concurrentRun.providerCalls(),
    }));
    const substitution = evaluateFixture(oauthFixture(), 'operation:substitution');
    const substitutionRun = boundaryHarness(substitution);
    const changed = structuredClone(substitution.native.action);
    changed.oauth_transaction.authorization_details[0].instructedAmount.amount = '5000.00';
    const substitutionResult = await substitutionRun.boundary.run(runInput(substitution, changed));
    cases.push(result('EXECUTOR-OBSERVED-SUBSTITUTION-REFUSED', 'hostile', substitutionResult.state === 'REFUSED'
        && substitutionResult.reason === 'exact_action_binding_mismatch'
        && substitutionRun.providerCalls() === 0, 'exact_action_binding_mismatch before provider entry', {
        state: substitutionResult.state,
        reason: substitutionResult.state === 'REFUSED' ? substitutionResult.reason : null,
        provider_calls: substitutionRun.providerCalls(),
    }));
    const lost = evaluateFixture(oasntFixture(), 'operation:lost-response');
    const lostRun = boundaryHarness(lost, { invoke: async () => { throw new Error('connection_lost'); } });
    const lostResult = await lostRun.boundary.run(runInput(lost));
    cases.push(result('LOST-RESPONSE-INDETERMINATE', 'boundary', lostResult.state === 'INDETERMINATE'
        && lostResult.invoked === true
        && lostResult.retry_allowed === false
        && lostRun.providerCalls() === 1, 'INDETERMINATE with retry refused', {
        state: lostResult.state,
        invoked: lostResult.invoked,
        retry_allowed: lostResult.retry_allowed,
        provider_calls: lostRun.providerCalls(),
    }));
    const blindRetry = await lostRun.boundary.run(runInput(lost));
    cases.push(result('BLIND-RETRY-REFUSED', 'hostile', blindRetry.state === 'REFUSED' && lostRun.providerCalls() === 1, 'REFUSED without another provider call', {
        state: blindRetry.state,
        reason: blindRetry.state === 'REFUSED' ? blindRetry.reason : null,
        provider_calls: lostRun.providerCalls(),
    }));
    assert.equal(lostResult.state, 'INDETERMINATE');
    assert.ok(lostResult.attempt);
    const reconciled = await lostRun.boundary.reconcile({
        evaluation: lost.evaluation,
        action: lost.native.action,
        artifacts: lost.artifacts,
        attempt: lostResult.attempt,
        outcome: {
            state: 'EXECUTED',
            evidence: {
                evidence_id: 'provider-evidence:reconciled',
                observed_at: '2027-01-15T08:00:45.000Z',
                evidence_digest: digestAeb({ provider: 'payment-sandbox', reconciliation: true }),
            },
            result: { accepted: true },
        },
        recovery_authorization: 'recovery:approved',
    });
    cases.push(result('AUTHENTICATED-RECONCILIATION-NO-REEXECUTION', 'positive', reconciled.state === 'EXECUTED' && lostRun.providerCalls() === 1, 'EXECUTED by reconciliation with original provider-call count unchanged', { state: reconciled.state, provider_calls: lostRun.providerCalls() }));
    const recordFixture = evaluateFixture(oasntFixture(), 'operation:crossing-record-is-not-authority');
    const crossingRecord = await validCrossingRecord(recordFixture);
    const crossingVerification = await verifyAebCrossingRecord(crossingRecord, {
        verification_keys: [],
    });
    // The empty-key check is intentionally not credited. The valid result was
    // established inside validCrossingRecord under pinned keys; presenting the
    // record to Gate below still cannot replace native authority.
    assert.equal(crossingVerification.verified, false);
    const crossingRun = boundaryHarness(recordFixture);
    const crossingArtifacts = { [recordFixture.native.artifact_ref]: crossingRecord };
    const crossingResult = await crossingRun.boundary.run({
        ...runInput(recordFixture),
        artifacts: crossingArtifacts,
    });
    cases.push(result('CROSSING-RECORD-NONAUTHORIZING', 'boundary', crossingResult.state === 'REFUSED' && crossingRun.providerCalls() === 0, 'verified historical evidence cannot replace native authority', {
        crossing_record_valid: true,
        state: crossingResult.state,
        reason: crossingResult.state === 'REFUSED' ? crossingResult.reason : null,
        provider_calls: crossingRun.providerCalls(),
    }));
    const oauthLeg = oauth.evaluation.legs[0];
    const humanLeg = human.evaluation.legs[0];
    cases.push(result('NATIVE-PROVENANCE-PRESERVED', 'boundary', oauthLeg?.adapter_id === OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID
        && humanLeg?.adapter_id === OASNT_AEB_ADAPTER_ID
        && oauthLeg?.evidence_role === 'transaction-authorization'
        && humanLeg?.evidence_role === 'human-authorization'
        && oauthLeg?.replay_unit !== humanLeg?.replay_unit, 'distinct native adapters, roles, and replay units remain visible', {
        oauth_adapter: oauthLeg?.adapter_id ?? null,
        oauth_role: oauthLeg?.evidence_role ?? null,
        human_adapter: humanLeg?.adapter_id ?? null,
        human_role: humanLeg?.evidence_role ?? null,
        replay_units_distinct: oauthLeg?.replay_unit !== humanLeg?.replay_unit,
    }));
    const base = {
        '@version': REPORT_VERSION,
        profile: PROFILE,
        cases,
        passed: cases.every((entry) => entry.passed),
        defining_contract: {
            exact_action_from_executor_observation: true,
            native_authority_open_set: true,
            replay_unit_wrapper_independent: true,
            provider_entry_attempts: 'AT_MOST_ONE',
            uncertainty_retry_policy: 'REFUSE',
            crossing_record_authority: 'NONE',
        },
        known_limits: [
            'This run exercises the EMILIA reference implementation; it is not an independent implementation.',
            'At-most-one provider entry is not exactly-once physical effect.',
            'The OAuth and OASNT artifacts conform to one lifecycle contract; their native semantics are not asserted equivalent.',
            'A verified crossing record is historical evidence and never authorizes a later action.',
            'Guarantees apply only to completely mediated protected boundaries using durable owning stores.',
        ],
    };
    return { ...base, results_digest: sha256(canonicalizeAeb(base)) };
}
export async function runProfile(runner = {
    name: 'EMILIA reference runner',
    affiliation: 'EMILIA Protocol',
    revision: 'aeb-crossing-lifecycle-v1',
    executed_at: DECISION_NOW,
}) {
    const reference = await buildReferenceReport();
    return {
        ...reference,
        runner,
        reproduction_statement: `${runner.name} (${runner.affiliation}) reproduced ${reference.cases.filter((entry) => entry.passed).length}/${reference.cases.length} protected-consequence-boundary lifecycle checks at ${runner.revision}. This is a reproduction of the EMILIA reference implementation, not an independent implementation, deployment, certification, or standards adoption.`,
    };
}
function argument(name) {
    const index = process.argv.indexOf(name);
    return index === -1 ? undefined : process.argv[index + 1];
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const report = await runProfile({
        name: argument('--runner-name') ?? 'EMILIA reference runner',
        affiliation: argument('--runner-affiliation') ?? 'EMILIA Protocol',
        revision: argument('--runner-revision') ?? 'aeb-crossing-lifecycle-v1',
        executed_at: argument('--executed-at') ?? DECISION_NOW,
    });
    if (process.argv.includes('--write-reference')) {
        writeFileSync(REFERENCE_PATH, `${JSON.stringify(sorted(await buildReferenceReport()), null, 2)}\n`, 'utf8');
    }
    const output = argument('--output');
    if (output)
        writeFileSync(resolve(output), `${JSON.stringify(sorted(report), null, 2)}\n`, 'utf8');
    else
        process.stdout.write(`${JSON.stringify(sorted(report), null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
