// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow-verifiers.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { signDocumentActionBinding, } from '@emilia-protocol/verify/document-action-binding';
import { hashCanonical } from './execution-binding.js';
import { ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION, computeActionEscrowAgreementDigest, createActionEscrowContractorDocumentBindingVerifier, createActionEscrowDocumentBindingVerifier, validateActionEscrowReleaseTemplate, } from './action-escrow-verifiers.js';
const documentBytes = Buffer.from('%PDF-1.7\nfinal agreement bytes\n', 'utf8');
const keyPair = crypto.generateKeyPairSync('ed25519');
const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const parties = [
    { party_id: 'ep:principal:client', role: 'client' },
    { party_id: 'ep:principal:contractor', role: 'contractor' },
];
const profile = {
    '@version': 'EP-ACTION-ESCROW-PROFILE-v1',
    profile_id: 'contractor-milestone-release',
    provider_id: 'licensed-custodian.test',
    required_acceptance_party_ids: parties.map(({ party_id }) => party_id),
    required_release_approver_party_ids: parties.map(({ party_id }) => party_id),
    prohibit_self_approval: false,
};
const profileDigest = `sha256:${hashCanonical(profile)}`;
const agreementId = 'agreement-kitchen-01';
const agreementDigest = computeActionEscrowAgreementDigest(agreementId);
const materialTerms = [
    { term_id: 'amendment_version', type: 'integer', value: 1 },
    { term_id: 'completion_requirements_digest', type: 'digest', value: `sha256:${'7'.repeat(64)}` },
    { term_id: 'document_authorizes_payment', type: 'boolean', value: false },
    { term_id: 'milestone_name', type: 'string', value: 'Cabinet installation' },
    { term_id: 'payee_id', type: 'identifier', value: 'contractor-01' },
    { term_id: 'release.amount', type: 'amount', value: '18400.00', currency: 'USD' },
    { term_id: 'release.destination_id', type: 'identifier', value: 'custody-destination-4821' },
    { term_id: 'release.milestone_id', type: 'identifier', value: 'milestone-01' },
    { term_id: 'release_requires_mutual_approval', type: 'boolean', value: true },
    { term_id: 'retainage_amount', type: 'amount', value: '4600.00', currency: 'USD' },
];
const actionTemplate = {
    action_type: 'escrow.milestone.release',
    action_escrow_profile_digest: profileDigest,
    agreement_id: agreementId,
    agreement_digest: agreementDigest,
    milestone_id: 'milestone-01',
    amount: '18400.00',
    currency: 'USD',
    destination_id: 'custody-destination-4821',
    payee_id: 'contractor-01',
    custodian_provider: 'escrow.com',
    custodian_environment: 'sandbox',
    custodian_transaction_id: 'provider-transaction-001',
    custodian_milestone_id: 'provider-milestone-001',
    document_sha256: `sha256:${crypto.createHash('sha256').update(documentBytes).digest('hex')}`,
    material_terms_sha256: `sha256:${hashCanonical(materialTerms)}`,
    completion_evidence_sha256: `sha256:${'6'.repeat(64)}`,
    amendment_version: 1,
};
function signedBinding(overrides = {}) {
    return signDocumentActionBinding({
        binding_id: overrides.binding_id ?? 'binding-kitchen-01',
        agreement_id: agreementId,
        document: { bytes: documentBytes, media_type: 'application/pdf' },
        material_terms: overrides.material_terms ?? materialTerms,
        release_action_template: overrides.release_action_template ?? actionTemplate,
        parties,
        required_parties: parties,
        validity: {
            not_before: '2026-07-17T00:00:00.000Z',
            not_after: '2026-07-18T00:00:00.000Z',
        },
        ...(overrides.supersedes_digest === undefined
            ? {}
            : { supersedes_digest: overrides.supersedes_digest }),
    }, {
        issuer_id: 'mapping-issuer.test',
        key_id: 'mapping-key-01',
        privateKey: keyPair.privateKey,
    });
}
function expected(binding, overrides = {}) {
    return {
        agreement_digest: agreementDigest,
        document_action_binding_digest: binding.binding_digest,
        release_action_digest: binding.release_action.digest,
        milestone_id: 'milestone-01',
        parties,
        parties_digest: `sha256:${hashCanonical(parties)}`,
        profile_digest: profileDigest,
        ...overrides,
    };
}
function verifier(bytes = documentBytes) {
    return createActionEscrowDocumentBindingVerifier({
        issuerKeys: {
            'mapping-key-01': {
                issuer_id: 'mapping-issuer.test',
                public_key: publicKey,
            },
        },
        resolveDocumentBytes: async () => bytes,
        now: () => '2026-07-17T12:00:00.000Z',
    });
}
function contractorVerifier(bytes = documentBytes) {
    return createActionEscrowContractorDocumentBindingVerifier({
        issuerKeys: {
            'mapping-key-01': {
                issuer_id: 'mapping-issuer.test',
                public_key: publicKey,
            },
        },
        resolveDocumentBytes: async () => bytes,
        now: () => '2026-07-17T12:00:00.000Z',
    });
}
test('maps a real signed DAB and final PDF into the exact kernel result contract', async () => {
    const binding = signedBinding();
    const result = await verifier()(binding, expected(binding));
    assert.equal(result.valid, true);
    assert.equal(result.agreement_digest, agreementDigest);
    assert.equal(result.document_action_binding_digest, binding.binding_digest);
    assert.equal(result.release_action_digest, binding.release_action.digest);
    assert.deepEqual(result.release_action_template, actionTemplate);
});
test('a second pinned but weaker profile cannot reinterpret the same binding', async () => {
    const binding = signedBinding();
    const result = await verifier()(binding, expected(binding, {
        profile_digest: `sha256:${'9'.repeat(64)}`,
    }));
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'material_action_mapping_mismatch');
});
test('changed document bytes and agreement aliases fail closed', async () => {
    const binding = signedBinding();
    assert.equal((await verifier(Buffer.from('%PDF-1.7\nchanged\n'))(binding, expected(binding))).valid, false);
    assert.equal((await verifier()(binding, expected(binding, {
        agreement_digest: `sha256:${'8'.repeat(64)}`,
    }))).reason, 'kernel_binding_context_mismatch');
});
test('material terms cannot disagree with the exact release template', async () => {
    const binding = signedBinding({
        material_terms: [
            ...materialTerms.filter((term) => term.term_id !== 'release.amount'),
            { term_id: 'release.amount', type: 'amount', value: '184000.00', currency: 'USD' },
        ],
    });
    const result = await verifier()(binding, expected(binding));
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'material_action_mapping_mismatch');
});
test('the contractor profile requires a project source digest bound to its signed term', async () => {
    const projectDigest = `sha256:${'4'.repeat(64)}`;
    const sourceTerms = [
        ...materialTerms,
        {
            term_id: 'project_record_snapshot_digest',
            type: 'digest',
            value: projectDigest,
        },
    ].sort((left, right) => (left.term_id < right.term_id ? -1 : left.term_id > right.term_id ? 1 : 0));
    const sourceTemplate = {
        ...actionTemplate,
        action_escrow_template_profile: ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION,
        material_terms_sha256: `sha256:${hashCanonical(sourceTerms)}`,
        project_record_snapshot_digest: projectDigest,
    };
    const binding = signedBinding({
        material_terms: sourceTerms,
        release_action_template: sourceTemplate,
    });
    const validatedSourceTemplate = validateActionEscrowReleaseTemplate(binding.release_action.template, {
        profileDigest,
        agreementId,
        agreementDigest,
        milestoneId: 'milestone-01',
        documentDigest: binding.document.digest,
        materialTerms: binding.material_terms,
        contractorProjectSource: true,
    });
    assert.ok(validatedSourceTemplate);
    const result = await contractorVerifier()(binding, expected(binding));
    assert.equal(result.valid, true, result.reason);
    assert.equal(result.project_record_snapshot_digest, projectDigest);
    assert.equal((await verifier()(binding, expected(binding))).reason, 'material_action_mapping_mismatch');
    const { action_escrow_template_profile: _profileMarker, ...unmarkedSourceTemplate } = sourceTemplate;
    const unmarkedBinding = signedBinding({
        material_terms: sourceTerms,
        release_action_template: unmarkedSourceTemplate,
    });
    const unmarkedResult = await verifier()(unmarkedBinding, expected(unmarkedBinding));
    assert.equal(unmarkedResult.valid, true, unmarkedResult.reason);
    assert.equal(unmarkedResult.project_record_snapshot_digest, projectDigest);
    assert.equal((await contractorVerifier()(unmarkedBinding, expected(unmarkedBinding))).reason, 'material_action_mapping_mismatch');
    const substitutedTerms = sourceTerms.map((term) => (term.term_id === 'project_record_snapshot_digest'
        ? { ...term, value: `sha256:${'5'.repeat(64)}` }
        : term));
    const substitutedBinding = signedBinding({
        material_terms: substitutedTerms,
        release_action_template: {
            ...sourceTemplate,
            material_terms_sha256: `sha256:${hashCanonical(substitutedTerms)}`,
        },
    });
    const substitutedResult = await contractorVerifier()(substitutedBinding, expected(substitutedBinding));
    assert.equal(substitutedResult.valid, false);
    assert.equal(substitutedResult.reason, 'material_action_mapping_mismatch');
});
test('supersession is explicit and mapped to the kernel amendment join', async () => {
    const prior = signedBinding();
    const next = signedBinding({
        binding_id: 'binding-kitchen-02',
        supersedes_digest: prior.binding_digest,
    });
    const result = await verifier()(next, expected(next, {
        supersedes_document_action_binding_digest: prior.binding_digest,
    }));
    assert.equal(result.valid, true);
    assert.equal(result.supersedes_document_action_binding_digest, prior.binding_digest);
});
test('hostile values and resolver failures return typed refusal results', async () => {
    const binding = signedBinding();
    const throwing = createActionEscrowDocumentBindingVerifier({
        issuerKeys: {
            'mapping-key-01': {
                issuer_id: 'mapping-issuer.test',
                public_key: publicKey,
            },
        },
        resolveDocumentBytes: async () => {
            throw new Error('storage unavailable');
        },
        now: () => '2026-07-17T12:00:00.000Z',
    });
    await assert.doesNotReject(throwing(binding, expected(binding)));
    assert.equal((await throwing(binding, expected(binding))).valid, false);
    assert.equal((await verifier()(new Proxy({}, {
        get() { throw new Error('hostile'); },
    }), expected(binding))).valid, false);
});
