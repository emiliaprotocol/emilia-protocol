// SPDX-License-Identifier: Apache-2.0
// Generated from field-origin-evidence.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { manifestFromPack } from './adapters/_kit.js';
import { createEg1Harness, createGate, MemoryConsumptionStore, } from './src/index.js';
import { FIELD_ORIGIN_CLAIM_BOUNDARY, FIELD_ORIGIN_EVIDENCE_VERSION, fieldOriginProfileDigest, signFieldOriginEvidence, verifyFieldOriginEvidence, } from './src/field-origin-evidence.js';
import { signBoundedExecutionProgram } from './src/bounded-execution-program.js';
const NOW = '2026-08-15T22:30:00.000Z';
const NOW_MS = Date.parse(NOW);
const BASE_ACTION = Object.freeze({
    action_type: 'finops.vendor.bank_detail_change',
    vendor_id: 'V-88012',
    erp: 'netsuite.prod.example',
    change_ticket: 'CHG-2026-4471',
    new_routing_digest: 'sha256:8c1f00a3b7e2d94c5a6b1e0f2d3c4b5a6978e0d1c2b3a4958677e8f9a0b1c2d3',
    new_account_digest: 'sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
});
const PINNED_TRANSFORM = Object.freeze({
    transform_id: 'transform:bank-digest-normalization',
    version: '1.0.0',
    digest: `sha256:${'4'.repeat(64)}`,
});
const FIELD_ORIGIN_PROFILE = Object.freeze({
    profile_id: 'profile:finops-field-origin:01',
    relying_party_id: 'rp:gap6-finops',
    action_type: BASE_ACTION.action_type,
    fields: [
        rule('/action_type', 'control', true, ['operator_pinned'], 'immutable'),
        rule('/vendor_id', 'control', true, ['operator_pinned', 'approver_supplied'], 'immutable'),
        rule('/erp', 'control', true, ['operator_pinned'], 'immutable'),
        rule('/change_ticket', 'control', true, ['operator_pinned', 'approver_supplied'], 'immutable'),
        rule('/new_routing_digest', 'control', true, ['approver_supplied', 'derived_via_versioned_transform'], 'immutable', [PINNED_TRANSFORM.transform_id]),
        rule('/new_account_digest', 'control', true, ['approver_supplied', 'derived_via_versioned_transform'], 'immutable', [PINNED_TRANSFORM.transform_id]),
        rule('/memo', 'bounded_data', false, ['operator_pinned', 'approver_supplied', 'untrusted_bounded'], 'either'),
    ],
    transforms: [PINNED_TRANSFORM],
});
const ACTION_PACK = Object.freeze([Object.freeze({
        id: BASE_ACTION.action_type,
        label: 'Vendor bank-detail change',
        action_type: BASE_ACTION.action_type,
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: 'finops', tool: 'vendor_bank_detail_change' },
        execution_binding: {
            required_fields: Object.keys(BASE_ACTION),
        },
    })]);
function rule(path, role, required, allowedOrigins, snapshotPolicy, allowedTransformIds = []) {
    return {
        path,
        role,
        required,
        allowed_origins: allowedOrigins,
        snapshot_policy: snapshotPolicy,
        max_snapshot_age_sec: snapshotPolicy === 'immutable' ? null : 300,
        allowed_transform_ids: allowedTransformIds,
    };
}
function immutable() {
    return { kind: 'immutable', observed_at: null, source_version: null };
}
function annotationsFor(action, overrides = {}) {
    return Object.keys(action).sort().map((key) => ({
        path: `/${key}`,
        origin_class: key === 'action_type' || key === 'erp' || key === 'vendor_id'
            ? 'operator_pinned'
            : (key === 'memo' ? 'untrusted_bounded' : 'approver_supplied'),
        snapshot: immutable(),
        transform: null,
        ...(overrides[`/${key}`] ?? {}),
    }));
}
function evidenceHarness() {
    const keys = generateKeyPairSync('ed25519');
    const keyId = 'key:field-origin-issuer';
    const issuerId = FIELD_ORIGIN_PROFILE.relying_party_id;
    const signer = { issuer_id: issuerId, key_id: keyId, private_key: keys.privateKey };
    const trustedKeys = {
        [keyId]: {
            issuer_id: issuerId,
            public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
    };
    return { signer, trustedKeys };
}
function executionProgramHarness(profileDigest = fieldOriginProfileDigest(FIELD_ORIGIN_PROFILE)) {
    const keys = generateKeyPairSync('ed25519');
    const keyId = 'key:customer-field-origin-program';
    const authorizerId = 'customer:finance-operations';
    const artifact = signBoundedExecutionProgram({
        program_id: 'program:finance-field-origin-pilot:01',
        tenant_id: 'tenant:design-partner',
        version: 1,
        subject_id: 'agent:finance-operations:01',
        audience: 'gate:finance-operations:01',
        objective_digest: `sha256:${'1'.repeat(64)}`,
        authorization_digest: `sha256:${'2'.repeat(64)}`,
        presentation_digest: `sha256:${'3'.repeat(64)}`,
        supersedes_program_digest: null,
        issued_at: '2026-08-15T22:00:00.000Z',
        valid_from: '2026-08-15T22:10:00.000Z',
        expires_at: '2026-08-15T23:30:00.000Z',
        max_total_occurrences: 1,
        max_concurrent_effects: 1,
        budgets: [{ budget_id: 'vendor-change-attempts', unit: 'attempt', limit: 1 }],
        nodes: [{
                node_id: 'vendor-bank-detail-change',
                action: {
                    mode: 'profile',
                    profile_id: FIELD_ORIGIN_PROFILE.profile_id,
                    profile_digest: profileDigest,
                },
                trust_program_digest: `sha256:${'4'.repeat(64)}`,
                depends_on: [],
                max_occurrences: 1,
                charges: [{ budget_id: 'vendor-change-attempts', amount: 1 }],
            }],
    }, {
        issuer_id: authorizerId,
        key_id: keyId,
        private_key: keys.privateKey,
    });
    return {
        artifact,
        verification_options: {
            trusted_keys: {
                [keyId]: {
                    issuer_id: authorizerId,
                    public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                },
            },
            now: NOW,
            expected_program_id: 'program:finance-field-origin-pilot:01',
            expected_tenant_id: 'tenant:design-partner',
            expected_authorizer_id: authorizerId,
            expected_authorization_digest: `sha256:${'2'.repeat(64)}`,
            expected_audience: 'gate:finance-operations:01',
        },
        node_id: 'vendor-bank-detail-change',
    };
}
function signEvidence(signer, action, annotations = annotationsFor(action), profile = FIELD_ORIGIN_PROFILE) {
    return signFieldOriginEvidence({
        evidence_id: `evidence:field-origin:${Math.random().toString(16).slice(2)}`,
        profile,
        observed_action: action,
        observed_at: NOW,
        annotations,
    }, signer);
}
test('signs and verifies exact per-field origin plus snapshot evidence', () => {
    const h = evidenceHarness();
    const action = { ...BASE_ACTION, memo: 'Quarterly vendor refresh' };
    const artifact = signEvidence(h.signer, action);
    assert.equal(artifact['@version'], FIELD_ORIGIN_EVIDENCE_VERSION);
    assert.equal(artifact.claim_boundary, FIELD_ORIGIN_CLAIM_BOUNDARY);
    assert.equal(artifact.profile_digest, fieldOriginProfileDigest(FIELD_ORIGIN_PROFILE));
    assert.equal(artifact.fields.find((field) => field.path === '/memo').origin_class, 'untrusted_bounded');
    assert.deepEqual(artifact.fields.find((field) => field.path === '/memo').snapshot, immutable());
    const verified = verifyFieldOriginEvidence(artifact, {
        trusted_keys: h.trustedKeys,
        pinned_profile: FIELD_ORIGIN_PROFILE,
        expected_relying_party_id: FIELD_ORIGIN_PROFILE.relying_party_id,
        observed_action: action,
        now: NOW,
    });
    assert.equal(verified.accepted, true);
    assert.equal(verified.reason, null);
    assert.equal(verified.action_digest, artifact.action_digest);
    assert.equal(verified.field_count, 7);
});
test('keeps mutable-state snapshot time separate from field origin', () => {
    const h = evidenceHarness();
    const action = { ...BASE_ACTION, memo: 'Mutable source snapshot' };
    const artifact = signEvidence(h.signer, action, annotationsFor(action, {
        '/memo': {
            snapshot: {
                kind: 'mutable_snapshot',
                observed_at: '2026-08-15T22:29:00.000Z',
                source_version: 'mailbox-version:0042',
            },
        },
    }));
    const context = {
        trusted_keys: h.trustedKeys,
        pinned_profile: FIELD_ORIGIN_PROFILE,
        expected_relying_party_id: FIELD_ORIGIN_PROFILE.relying_party_id,
        observed_action: action,
        now: NOW,
    };
    assert.equal(verifyFieldOriginEvidence(artifact, context).accepted, true);
    const stale = signEvidence(h.signer, action, annotationsFor(action, {
        '/memo': {
            snapshot: {
                kind: 'mutable_snapshot',
                observed_at: '2026-08-15T22:00:00.000Z',
                source_version: 'mailbox-version:0041',
            },
        },
    }));
    assert.equal(verifyFieldOriginEvidence(stale, context).reason, 'field_origin_snapshot_stale:/memo');
    const snapshotAfterEvidence = signEvidence(h.signer, action, annotationsFor(action, {
        '/memo': {
            snapshot: {
                kind: 'mutable_snapshot',
                observed_at: '2026-08-15T22:31:00.000Z',
                source_version: 'mailbox-version:0043',
            },
        },
    }));
    assert.equal(verifyFieldOriginEvidence(snapshotAfterEvidence, {
        ...context,
        now: '2026-08-15T22:32:00.000Z',
    }).reason, 'field_origin_snapshot_after_evidence:/memo');
});
test('Gate names all five hostile field-origin refusals and admits bounded untrusted data', async () => {
    const h = evidenceHarness();
    const receiptHarness = createEg1Harness({ action: BASE_ACTION, now: () => NOW_MS, idPrefix: 'm01' });
    const configuredProfile = JSON.parse(JSON.stringify(FIELD_ORIGIN_PROFILE));
    const configuredTrustedKeys = JSON.parse(JSON.stringify(h.trustedKeys));
    const executionProgram = executionProgramHarness();
    const gate = createGate({
        manifest: manifestFromPack([...ACTION_PACK]),
        trustedKeys: [receiptHarness.publicKey],
        approverKeys: receiptHarness.approverKeys,
        rpId: receiptHarness.rpId,
        allowedOrigins: receiptHarness.allowedOrigins,
        quorumPolicy: receiptHarness.quorumPolicy,
        store: new MemoryConsumptionStore(),
        allowEphemeralStore: true,
        now: () => NOW_MS,
        requiredFieldOriginProfile: configuredProfile,
        fieldOriginTrustedKeys: configuredTrustedKeys,
        fieldOriginExecutionProgram: executionProgram,
    });
    configuredProfile.fields.find((field) => field.path === '/vendor_id').role = 'bounded_data';
    configuredProfile.fields.find((field) => field.path === '/vendor_id').allowed_origins = ['untrusted_bounded'];
    configuredTrustedKeys['key:field-origin-issuer'].issuer_id = 'rp:mutated-after-configuration';
    async function runCase(action, annotations, profile = FIELD_ORIGIN_PROFILE) {
        let effects = 0;
        const result = await gate.run({
            selector: { protocol: 'finops', tool: 'vendor_bank_detail_change' },
            receipt: receiptHarness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } }),
            observedAction: action,
            fieldOriginEvidence: signEvidence(h.signer, action, annotations, profile),
        }, async () => {
            effects += 1;
            return { changed: true };
        });
        return { result, effects };
    }
    let missingEvidenceEffects = 0;
    const missingEvidence = await gate.run({
        selector: { protocol: 'finops', tool: 'vendor_bank_detail_change' },
        receipt: receiptHarness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } }),
        observedAction: BASE_ACTION,
    }, async () => {
        missingEvidenceEffects += 1;
    });
    assert.equal(missingEvidence.ok, false);
    assert.equal(missingEvidence.authorization.reason, 'field_origin_evidence_required');
    assert.equal(missingEvidenceEffects, 0);
    const injectedEmail = await runCase(BASE_ACTION, annotationsFor(BASE_ACTION, {
        '/vendor_id': { origin_class: 'untrusted_bounded' },
    }));
    assert.equal(injectedEmail.result.ok, false);
    assert.equal(injectedEmail.result.authorization.reason, 'field_origin_control_untrusted:/vendor_id');
    assert.equal(injectedEmail.effects, 0);
    const webpageTarget = await runCase(BASE_ACTION, annotationsFor(BASE_ACTION, {
        '/erp': { origin_class: 'untrusted_bounded' },
    }));
    assert.equal(webpageTarget.result.authorization.reason, 'field_origin_control_untrusted:/erp');
    assert.equal(webpageTarget.effects, 0);
    const transformSubstitution = await runCase(BASE_ACTION, annotationsFor(BASE_ACTION, {
        '/new_account_digest': {
            origin_class: 'derived_via_versioned_transform',
            transform: {
                ...PINNED_TRANSFORM,
                digest: `sha256:${'9'.repeat(64)}`,
            },
        },
    }));
    assert.equal(transformSubstitution.result.authorization.reason, 'field_origin_transform_unpinned:/new_account_digest');
    assert.equal(transformSubstitution.effects, 0);
    const unknownOrigin = await runCase(BASE_ACTION, annotationsFor(BASE_ACTION, {
        '/change_ticket': { origin_class: 'unknown' },
    }));
    assert.equal(unknownOrigin.result.authorization.reason, 'field_origin_unknown:/change_ticket');
    assert.equal(unknownOrigin.effects, 0);
    const downgradedProfile = {
        ...FIELD_ORIGIN_PROFILE,
        profile_id: 'profile:finops-field-origin:downgraded',
        fields: FIELD_ORIGIN_PROFILE.fields.map((field) => field.path === '/vendor_id'
            ? { ...field, role: 'bounded_data', allowed_origins: ['untrusted_bounded'] }
            : field),
    };
    const profileDowngrade = await runCase(BASE_ACTION, annotationsFor(BASE_ACTION, {
        '/vendor_id': { origin_class: 'untrusted_bounded' },
    }), downgradedProfile);
    assert.equal(profileDowngrade.result.authorization.reason, 'field_origin_profile_mismatch');
    assert.equal(profileDowngrade.effects, 0);
    const positiveAction = { ...BASE_ACTION, memo: 'Untrusted invoice note, bounded as data' };
    const positive = await runCase(positiveAction, annotationsFor(positiveAction));
    assert.equal(positive.result.ok, true);
    assert.equal(positive.result.authorization.evidence.field_origin.accepted, true);
    assert.equal(positive.result.authorization.evidence.field_origin_program_binding.node_id, executionProgram.node_id);
    assert.equal(positive.effects, 1);
});
test('a pinned field-origin profile cannot be configured without issuer trust pins', () => {
    assert.throws(() => createGate({
        requiredFieldOriginProfile: FIELD_ORIGIN_PROFILE,
        allowEphemeralStore: true,
    }), /requires pinned fieldOriginTrustedKeys/);
    const h = evidenceHarness();
    assert.throws(() => createGate({
        requiredFieldOriginProfile: FIELD_ORIGIN_PROFILE,
        fieldOriginTrustedKeys: h.trustedKeys,
        fieldOriginExecutionProgram: executionProgramHarness(`sha256:${'9'.repeat(64)}`),
        allowEphemeralStore: true,
    }), /does not pin the required field-origin profile/);
});
