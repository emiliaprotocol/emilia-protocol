// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-mcgraw-delegation-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- the runtime result is checked before use.
import { computeCaid } from './vendor/caid.mjs';
import { AEB_ADAPTER_VERSION, AEB_REGISTRY_VERSION, AEB_REQUIREMENT_VERSION, InMemoryAebConsumptionStore, adapterPinDigest, aebNativeReplayKeys, authorizeAebExecution, digestAeb, evaluateAebEvidence, mappingProfileDigest, registryEntryDigest, unifiedRegistryDigest, verifyAebEvaluation, } from './aeb-adapter-contract.js';
import { MCGRAW_BUDGET_AEB_ADAPTER_ID, MCGRAW_BUDGET_AEB_ADAPTER_VERSION, MCGRAW_BUDGET_CONFIG_VERSION, MCGRAW_BUDGET_COSE_ALGORITHM, MCGRAW_BUDGET_DRAFT_REVISION, MCGRAW_BUDGET_MAPPING_VERSION, MCGRAW_BUDGET_MAPPER_ID, MCGRAW_BUDGET_TRUST_ROOT_VERSION, createMcGrawBudgetActionDefinition, createMcGrawBudgetAebAdapter, encodeDeterministicCbor, tagDeterministicCbor, } from './aeb-mcgraw-delegation-adapter.js';
const NOW = '2026-08-06T12:00:30.000Z';
const NOW_MS = Date.parse(NOW);
const ACTION_TYPE = 'dataset.export.1';
const ISSUER = 'https://issuer.example';
const REQUESTER = 'workload:export-agent';
const VERIFIER = 'https://api.example';
const KID = Buffer.from('issuer-key-2026-08', 'utf8');
const CHALLENGE = crypto.createHash('sha256').update('challenge').digest().subarray(0, 16);
const BODY = Buffer.from('{"format":"jsonl","limit":1000}', 'utf8');
const BODY_HASH = crypto.createHash('sha256').update(BODY).digest();
function makeFixture() {
    const keypair = ml_dsa65.keygen(crypto.randomBytes(32));
    const expectedAction = {
        action_type: ACTION_TYPE,
        delegation_action: {
            delegated_requester: REQUESTER,
            required_authority: 'dataset:export',
            method: 'POST',
            origin: 'https://api.example',
            target: '/export?format=jsonl',
            body_sha256: BODY_HASH.toString('hex'),
        },
    };
    const chainBytes = Buffer.from('profile-defined-authority-chain-v1', 'utf8');
    const claims = new Map([
        [1, 1],
        [2, ISSUER],
        [3, REQUESTER],
        [4, '100.00'],
        [5, '75.00'],
        [6, 'USD'],
        [7, ['dataset:export']],
        [8, NOW_MS - 20_000],
        [9, NOW_MS + 100_000],
        [10, CHALLENGE],
        [11, chainBytes],
        [12, BODY_HASH],
        [13, VERIFIER],
        [14, new Map([
                ['method', expectedAction.delegation_action.method],
                ['uri-h', crypto.createHash('sha256').update(expectedAction.delegation_action.target).digest()],
                ['origin', expectedAction.delegation_action.origin],
                ['body-h', BODY_HASH],
            ])],
    ]);
    const protectedBytes = encodeDeterministicCbor(new Map([
        [1, MCGRAW_BUDGET_COSE_ALGORITHM],
        [3, 'application/delegation-proof+cose'],
        [4, KID],
    ]));
    const payloadBytes = encodeDeterministicCbor(claims);
    const sigStructure = encodeDeterministicCbor([
        'Signature1', protectedBytes, Buffer.alloc(0), payloadBytes,
    ]);
    const signature = Buffer.from(ml_dsa65.sign(sigStructure, keypair.secretKey));
    const coseParts = [protectedBytes, new Map(), payloadBytes, signature];
    // RFC 9052 allows COSE_Sign1 tagged (tag 18) or untagged. The tag sits
    // outside Sig_structure, so both carry the exact same signed proof.
    const cose = encodeDeterministicCbor(tagDeterministicCbor(18, coseParts));
    const untaggedCose = encodeDeterministicCbor(coseParts);
    const chainVerifierDescriptor = {
        id: 'test:mcgraw-budget-chain',
        version: '1',
        implementation_digest: digestAeb({ implementation: 'test:mcgraw-budget-chain', version: '1' }),
    };
    const mldsaDescriptor = {
        id: 'noble:ml-dsa-65',
        version: '0.6.1',
        implementation_digest: digestAeb({ implementation: 'noble:ml-dsa-65', version: '0.6.1' }),
    };
    const config = {
        '@version': MCGRAW_BUDGET_CONFIG_VERSION,
        evidence_role: 'delegated-authority',
        subject: { id: 'workload:export-agent', kind: 'workload', native_id: REQUESTER },
        action_type: ACTION_TYPE,
        issuer: ISSUER,
        verifier_binding: VERIFIER,
        required_authority: 'dataset:export',
        budget_unit: 'USD',
        minimum_remaining_budget: '2.50',
        challenge_nonce: CHALLENGE.toString('base64url'),
        content_type: 'application/delegation-proof+cose',
        representation_digest_semantics: 'http-request-content-sha256',
        require_request_binding: true,
        clock_skew_seconds: 30,
        max_lifetime_seconds: 300,
        max_status_age_seconds: 120,
        chain_verifier: chainVerifierDescriptor,
        mldsa_verifier: mldsaDescriptor,
    };
    const trustRoots = [{
            '@version': MCGRAW_BUDGET_TRUST_ROOT_VERSION,
            issuer: ISSUER,
            key_id: KID.toString('base64url'),
            algorithm: 'ML-DSA-65',
            public_key: Buffer.from(keypair.publicKey).toString('base64url'),
        }];
    const chainVerifier = {
        ...chainVerifierDescriptor,
        verify(input) {
            return Buffer.from(input.chain).equals(chainBytes)
                && input.issuer === ISSUER
                && input.delegated_requester === REQUESTER
                ? { verified: true, reason: null }
                : { verified: false, reason: 'chain_invalid' };
        },
    };
    const mldsaVerifier = {
        ...mldsaDescriptor,
        verify(signatureBytes, message, publicKey) {
            return ml_dsa65.verify(signatureBytes, message, publicKey);
        },
    };
    return {
        keypair,
        expectedAction,
        config,
        trustRoots,
        chainVerifier,
        mldsaVerifier,
        artifact: cose.toString('base64url'),
        untaggedArtifact: untaggedCose.toString('base64url'),
    };
}
function profile() {
    return {
        version: MCGRAW_BUDGET_MAPPING_VERSION,
        definition: createMcGrawBudgetActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:mcgraw-budget-dataset-export',
        mapper_id: MCGRAW_BUDGET_MAPPER_ID,
        resolver: {
            id: MCGRAW_BUDGET_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: MCGRAW_BUDGET_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'budget.total', 'budget.remaining', 'budget.issued_at', 'budget.expires_at',
                'budget.challenge_nonce', 'budget.authorization_chain',
            ],
        },
        profile_digest: digestAeb(null),
    };
}
function input(fixture, overrides = {}) {
    return {
        artifact: fixture.artifact,
        artifact_ref: 'delegation:budget:test-1',
        status: {
            checked_at: '2026-08-06T12:00:29.000Z',
            expires_at: '2026-08-06T12:01:00.000Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: fixture.trustRoots,
        adapter_config: fixture.config,
        expected_action: fixture.expectedAction,
        now: NOW,
        ...overrides,
    };
}
test('McGraw Budget -03 real ML-DSA-65 COSE proof verifies and maps', () => {
    const fixture = makeFixture();
    const adapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    assert.equal(adapter.id, MCGRAW_BUDGET_AEB_ADAPTER_ID);
    assert.equal(adapter.version, MCGRAW_BUDGET_AEB_ADAPTER_VERSION);
    const native = adapter.verifyNative(input(fixture));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    assert.deepEqual(native.reasons, []);
    const mapped = adapter.mapAction({ ...input(fixture), profile: profile(), native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.match(mapped.caid ?? '', /^caid:1:dataset\.export\.1:jcs-sha256:/);
});
test('McGraw adapter refuses a changed target and a changed ML-DSA signature', () => {
    const fixture = makeFixture();
    const adapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    const changedAction = structuredClone(fixture.expectedAction);
    changedAction.delegation_action.target = '/admin';
    const mismatch = adapter.verifyNative(input(fixture, { expected_action: changedAction }));
    assert.equal(mismatch.acceptance, 'REJECTED');
    assert.ok(mismatch.reasons.includes('mcgraw-budget:request_binding_mismatch'));
    const bytes = Buffer.from(fixture.artifact, 'base64url');
    bytes[bytes.length - 1] ^= 1;
    const forged = adapter.verifyNative(input(fixture, { artifact: bytes.toString('base64url') }));
    assert.equal(forged.native_verification, 'FAILED');
    assert.equal(forged.acceptance, 'REJECTED');
});
test('McGraw adapter keeps challenge replay and chain verification fail closed', () => {
    const fixture = makeFixture();
    const refusingChain = {
        ...fixture.chainVerifier,
        verify: () => ({ verified: false, reason: 'chain_invalid' }),
    };
    const adapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: refusingChain,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    const result = adapter.verifyNative(input(fixture));
    assert.equal(result.acceptance, 'REJECTED');
    assert.ok(result.reasons.includes('mcgraw-budget:chain_invalid'));
    const validAdapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    const consumed = validAdapter.verifyNative(input(fixture, {
        status: { ...input(fixture).status, consumed: true },
    }));
    assert.equal(consumed.native_verification, 'VERIFIED');
    assert.equal(consumed.acceptance, 'REJECTED');
    assert.ok(consumed.reasons.includes('evidence_consumed'));
});
test('McGraw source and RFC 9964 algorithm locks are explicit', () => {
    assert.equal(MCGRAW_BUDGET_DRAFT_REVISION, 'draft-mcgraw-httpapi-agent-budget-03');
    assert.equal(MCGRAW_BUDGET_COSE_ALGORITHM, -49);
});
test('deterministic CBOR map order is RFC 8949 bytewise, not RFC 7049 length-first', () => {
    // {100: "c", -1: "b"}: RFC 8949 sorts encoded key 0x1864 (100) before 0x20
    // (-1) bytewise; the retired RFC 7049 length-first order put -1 first.
    const mixed = encodeDeterministicCbor(new Map([[100, 'c'], [-1, 'b']]));
    assert.equal(mixed.toString('hex'), 'a218646163206162');
    // Profile-domain coincidence: for the adapter's actual key domain
    // (non-negative int labels, short text keys) both orders agree, so the
    // realignment changes no bytes for well-formed McGraw artifacts.
    const labels = encodeDeterministicCbor(new Map([[4, 'k'], [1, -49], [3, 'ct']]));
    assert.equal(labels.toString('hex'), 'a30138300362637404616b');
});
test('one signed delegation proof is one replay unit whether COSE-tagged or untagged', () => {
    const fixture = makeFixture();
    const adapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    const tagged = adapter.verifyNative(input(fixture));
    const untagged = adapter.verifyNative(input(fixture, {
        artifact: fixture.untaggedArtifact,
        artifact_ref: 'delegation:budget:test-1:untagged',
    }));
    assert.equal(tagged.native_verification, 'VERIFIED');
    assert.equal(tagged.acceptance, 'ACCEPTED');
    assert.equal(untagged.native_verification, 'VERIFIED');
    assert.equal(untagged.acceptance, 'ACCEPTED');
    assert.notEqual(tagged.evidence_digest, untagged.evidence_digest);
    assert.equal(untagged.replay_unit, tagged.replay_unit);
    const keys = (native) => aebNativeReplayKeys({
        evaluator: { id: 'rp:mcgraw-test' },
        legs: [{ replay_unit: native.replay_unit }],
    });
    const store = new InMemoryAebConsumptionStore();
    assert.equal(store.reserve('aeb:operation-1', keys(untagged)), true);
    assert.equal(store.reserve('aeb:operation-2', keys(tagged)), false);
});
test('a distinct signed delegation proof keeps its own replay unit', () => {
    const first = makeFixture();
    const second = makeFixture();
    const adapterFor = (fixture) => createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    const a = adapterFor(first).verifyNative(input(first));
    const b = adapterFor(second).verifyNative(input(second));
    assert.equal(a.acceptance, 'ACCEPTED');
    assert.equal(b.acceptance, 'ACCEPTED');
    assert.notEqual(b.replay_unit, a.replay_unit);
});
test('a McGraw leg reaches ACCEPTED and AUTHORIZED through evaluateAebEvidence', () => {
    const fixture = makeFixture();
    const adapter = createMcGrawBudgetAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        chain_verifier: fixture.chainVerifier,
        mldsa_verifier: fixture.mldsaVerifier,
    });
    // The evaluator derives base.evidence_digest itself and hard fails the leg on
    // any disagreement, so the adapter must use the same convention.
    assert.equal(adapter.verifyNative(input(fixture)).evidence_digest, digestAeb(fixture.artifact));
    const mapping = profile();
    mapping.profile_digest = mappingProfileDigest('mcgraw-budget', mapping);
    const pin = {
        version: MCGRAW_BUDGET_AEB_ADAPTER_VERSION,
        trust_roots: fixture.trustRoots,
        config: fixture.config,
        config_digest: digestAeb(null),
        max_status_age_sec: 120,
    };
    pin.config_digest = adapterPinDigest(MCGRAW_BUDGET_AEB_ADAPTER_ID, pin);
    const entry = (id, kind, definition) => {
        const value = { kind, version: '1', status: 'active', definition };
        value.definition_digest = registryEntryDigest(id, value);
        return value;
    };
    const registry = {
        '@version': AEB_REGISTRY_VERSION,
        registry_id: 'registry:mcgraw-budget-test',
        epoch: 1,
        entries: {
            'mapping:mcgraw-budget-dataset-export': entry('mapping:mcgraw-budget-dataset-export', 'mapping-profile', { profile_digest: mapping.profile_digest }),
            'role:delegated-authority': entry('role:delegated-authority', 'evidence-role', { role: 'delegated-authority', subject_kinds: ['workload'] }),
        },
        registry_digest: digestAeb(null),
    };
    registry.registry_digest = unifiedRegistryDigest(registry);
    const evaluatorKey = crypto.generateKeyPairSync('ed25519');
    const config = {
        '@version': AEB_ADAPTER_VERSION,
        relying_party_id: 'rp:mcgraw-budget-test',
        evaluator_keys: {
            'evaluator:mcgraw': {
                public_key: evaluatorKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
        registry,
        accepted_mappers: [MCGRAW_BUDGET_MAPPER_ID],
        adapters: { [MCGRAW_BUDGET_AEB_ADAPTER_ID]: pin },
        profiles: { 'mcgraw-budget': mapping },
        requirements: {
            'requirement:delegated': {
                '@version': AEB_REQUIREMENT_VERSION,
                all_of: ['delegated-authority'],
                terms: [{ type: 'one-time-consumption' }],
            },
        },
    };
    const adapters = { [MCGRAW_BUDGET_AEB_ADAPTER_ID]: adapter };
    const expectedCaid = computeCaid(fixture.expectedAction, {
        suite: 'jcs-sha256',
        definitions: mapping.definition.definitions,
    }).caid;
    const base = input(fixture);
    const store = new InMemoryAebConsumptionStore();
    const run = (artifact, artifactRef, operationId) => {
        const evaluation = evaluateAebEvidence({
            config,
            adapters,
            operation_id: operationId,
            consumption_nonce: `nonce:${operationId}`,
            initiator_id: 'workload:export-agent-caller',
            executor_id: 'workload:gate',
            requirement_ref: 'requirement:delegated',
            caid: expectedCaid,
            expected_action: fixture.expectedAction,
            evaluated_at: NOW,
            signer: { key_id: 'evaluator:mcgraw', private_key: evaluatorKey.privateKey },
            legs: [{
                    adapter_id: MCGRAW_BUDGET_AEB_ADAPTER_ID,
                    profile_id: 'mcgraw-budget',
                    artifact_ref: artifactRef,
                    artifact,
                    status: base.status,
                }],
        });
        const verification = verifyAebEvaluation(evaluation.record, {
            config,
            adapters,
            artifacts: { [artifactRef]: artifact },
            mode: 'execution',
            now: NOW,
            expected_action: fixture.expectedAction,
            current_statuses: { [artifactRef]: base.status },
        });
        return {
            evaluation,
            decision: authorizeAebExecution(evaluation.record, {
                verification,
                local_authorization: true,
                store,
            }),
        };
    };
    const untagged = run(fixture.untaggedArtifact, 'delegation:budget:proof-1', 'operation-1');
    assert.deepEqual(untagged.evaluation.record.legs[0].reasons, []);
    assert.equal(untagged.evaluation.record.legs[0].acceptance, 'ACCEPTED');
    assert.equal(untagged.decision.state, 'AUTHORIZED');
    // The same proof re-presented under the COSE tag is refused, not executed.
    const retagged = run(fixture.artifact, 'delegation:budget:proof-1:retagged', 'operation-2');
    assert.equal(retagged.evaluation.record.legs[0].acceptance, 'ACCEPTED');
    assert.equal(retagged.decision.state, 'REFUSED');
    assert.equal(retagged.decision.reason, 'consumption_conflict');
});
