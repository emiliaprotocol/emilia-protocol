// SPDX-License-Identifier: Apache-2.0
// Generated from cap1-coverage-composition.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import { CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY, CAP1_DOCUMENT_DIGEST_PROFILE, CAP1_OBSERVED_BUNDLE_SOURCE_LOCK, cap1CoverageSubjectDigest, verifyCap1CoverageComposition, } from './cap1-coverage-composition.js';
import { COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION, signCoverageReconciliationAttestationV3, } from './coverage-reconciliation-attestation.js';
import { COVERAGE_RECONCILIATION_REPORT_VERSION, COVERAGE_REPORT_CLAIM_BOUNDARY, } from './coverage-reconciliation-runner.js';
import { riskDigest } from './dist/reliance-risk-crypto.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character) => `sha256:${character.repeat(64)}`;
const PROGRAM = {
    program_id: 'rp.cap1.reconciliation.1',
    version: 1,
    source_digest: D('1'),
    program_digest: D('2'),
};
const EXAMINATION_PROFILE = {
    technique_id: 'cap1.static-examination',
    technique_version: 1,
    technique_digest: D('3'),
    depth_id: 'cap1.depth.full-artifact',
    depth_digest: D('4'),
};
const systemPin = {
    inventory_id: 'cap1.system.2026-08',
    population_root: D('5'),
    eligible_set_root: D('6'),
    examined_set_root: D('7'),
    eligible_count: 2,
    examined_count: 1,
    stratum_id: 'system-records',
};
const receiptPin = {
    inventory_id: 'cap1.receipts.2026-08',
    population_root: D('8'),
    eligible_set_root: D('9'),
    examined_set_root: D('a'),
    eligible_count: 2,
    examined_count: 1,
    stratum_id: 'receipt-records',
};
function nativeSource() {
    return {
        specification: 'draft-hillier-coverage-attestation-00',
        source_repository: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.repository,
        source_commit: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.commit,
        specification_sha256: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.draft.sha256,
        schema_sha256: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.schema.sha256,
        observed_vector_manifest_sha256: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.vector_manifest.sha256,
    };
}
function cap1Document() {
    const subjectDigest = cap1CoverageSubjectDigest({
        program: PROGRAM,
        claim_class_id: 'coverage.cap1.absence',
        examination_profile: EXAMINATION_PROFILE,
        system_of_record: systemPin,
        receipt_population: receiptPin,
    });
    return {
        profile: 'cap/1',
        subject: {
            kind: 'coverage-population-set',
            ref: 'emilia:cap1-composition:fixture',
            digest: subjectDigest,
        },
        strata: [
            {
                id: systemPin.stratum_id,
                population: 'system records',
                basis: { kind: 'enumeration', enumeration_method: 'pinned-fixture' },
                eligible: 2,
                examined: 1,
                unexamined: [{ unit: 'system-2', disposition: 'not_applicable' }],
                supports: ['coverage.cap1.absence'],
            },
            {
                id: receiptPin.stratum_id,
                population: 'receipt records',
                basis: { kind: 'enumeration', enumeration_method: 'pinned-fixture' },
                eligible: 2,
                examined: 1,
                unexamined: [{ unit: 'receipt-2', disposition: 'not_applicable' }],
                supports: ['coverage.cap1.absence'],
            },
        ],
        integrity: {
            complete: true,
            statement: 'All dispatched units reached a recorded outcome.',
            uncapped_verdict: 'bounded',
            capped_to: null,
            unaccounted: [],
        },
    };
}
async function fixture() {
    const ed = generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(randomBytes(32));
    const document = cap1Document();
    const report = {
        '@version': COVERAGE_RECONCILIATION_REPORT_VERSION,
        run_id: 'cap1.run.2026-08',
        relying_party_id: 'rp.cap1.example',
        program: PROGRAM,
        period: { start: '2026-08-01T00:00:00Z', end: '2026-08-02T00:00:00Z' },
        system_of_record: {
            inventory_id: systemPin.inventory_id,
            source_system_id: 'cap1.system',
            source_operator_id: 'operator.system',
            inventory_digest: D('b'),
            population_root: systemPin.population_root,
            count: systemPin.eligible_count,
        },
        receipt_population: {
            inventory_id: receiptPin.inventory_id,
            source_system_id: 'cap1.receipts',
            source_operator_id: 'operator.receipts',
            inventory_digest: D('c'),
            population_root: receiptPin.population_root,
            count: receiptPin.eligible_count,
        },
        joins: {
            matched: 1,
            effect_without_receipt: 1,
            receipted_without_observation: 1,
            indeterminate: 0,
            system_indeterminate: 0,
            excluded: 0,
            exception: 0,
        },
        findings: {
            matched: [], effect_without_receipt: [], receipted_without_observation: [],
            indeterminate: [], system_indeterminate: [], excluded: [], exception: [],
        },
        generated_at: '2026-08-02T01:00:00Z',
        claim_boundary: COVERAGE_REPORT_CLAIM_BOUNDARY,
    };
    const attestation = await signCoverageReconciliationAttestationV3({
        attestation_id: 'cap1.attestation.2026-08',
        relying_party_id: 'rp.cap1.example',
        program: PROGRAM,
        period: report.period,
        coverage_report_hash: riskDigest(report),
        census_digest: riskDigest(document),
        system_of_record: {
            inventory_id: systemPin.inventory_id,
            population_root: systemPin.population_root,
            count: systemPin.eligible_count,
        },
        receipt_population: {
            inventory_id: receiptPin.inventory_id,
            population_root: receiptPin.population_root,
            count: receiptPin.eligible_count,
        },
        joins: report.joins,
        issued_at: '2026-08-02T01:00:00Z',
        expires_at: '2026-08-09T01:00:00Z',
        timestamp_anchor: null,
        claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
    }, {
        issuer_id: 'rp.cap1.example',
        key_id: 'key.cap1.reconciler',
        private_key: ed.privateKey,
        pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
    });
    const options = {
        trusted_keys: {
            'key.cap1.reconciler': {
                issuer_id: 'rp.cap1.example',
                public_key: ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
            },
        },
        now: '2026-08-03T00:00:00Z',
        expected_relying_party_id: 'rp.cap1.example',
        expected_program: PROGRAM,
        system_of_record: systemPin,
        receipt_population: receiptPin,
        claim_class_id: 'coverage.cap1.absence',
        examination_profile: EXAMINATION_PROFILE,
        verify_cap1: async (candidate) => ({
            verdict: 'CONFORMS',
            primary_rule: null,
            source: nativeSource(),
            document_digest: riskDigest(candidate),
            violations: [],
        }),
        verify_examined_set_evidence: async () => ({
            verdict: 'SATISFIED',
            verified: [systemPin, receiptPin].map((pin) => ({
                stratum: pin.stratum_id,
                eligible_set_digest: pin.eligible_set_root,
                examined_set_digest: pin.examined_set_root,
                result_bindings: pin.examined_count,
            })),
        }),
    };
    return {
        input: { cap1_document: document, examined_set_evidence: { profile: 'fixture' }, coverage_report: report, coverage_attestation: attestation },
        options,
    };
}
test('accepts native CAP-1 plus strict set evidence only under the hybrid reconciliation binding', async () => {
    const { input, options } = await fixture();
    const result = await verifyCap1CoverageComposition(input, options);
    assert.equal(result.accepted, true, result.reason);
    assert.equal(result.claim_boundary, CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY);
    assert.equal(result.cap1.document_digest_profile, CAP1_DOCUMENT_DIGEST_PROFILE);
    assert.deepEqual(result.reconciliation.required_algorithms, ['Ed25519', 'ML-DSA-65']);
    assert.ok(result.nonclaims.includes('source_population_completeness'));
    assert.ok(result.nonclaims.includes('honest_enumeration'));
});
test('keeps native CAP-1 refusal distinct from EMILIA examined-set refusal', async () => {
    const native = await fixture();
    native.options.verify_cap1 = async () => ({
        verdict: 'REFUSES', primary_rule: 'R1', source: nativeSource(), document_digest: null, violations: [],
    });
    assert.equal((await verifyCap1CoverageComposition(native.input, native.options)).reason, 'cap1_native_refused');
    const strict = await fixture();
    strict.options.verify_examined_set_evidence = async () => ({ verdict: 'REFUSES', reason: 'examined_unexamined_overlap' });
    assert.equal((await verifyCap1CoverageComposition(strict.input, strict.options)).reason, 'cap1_examined_set_refused');
});
test('refuses a CAP-1 subject that does not bind the supplied sets and program', async () => {
    const { input, options } = await fixture();
    input.cap1_document = structuredClone(input.cap1_document);
    input.cap1_document.subject.digest.value = '0'.repeat(64);
    assert.equal((await verifyCap1CoverageComposition(input, options)).reason, 'cap1_subject_commitment_mismatch');
});
test('refuses a set verifier result whose roots do not match the pinned populations', async () => {
    const { input, options } = await fixture();
    options.verify_examined_set_evidence = async () => ({
        verdict: 'SATISFIED',
        verified: [
            { stratum: systemPin.stratum_id, eligible_set_digest: D('d'), examined_set_digest: systemPin.examined_set_root, result_bindings: 1 },
            { stratum: receiptPin.stratum_id, eligible_set_digest: receiptPin.eligible_set_root, examined_set_digest: receiptPin.examined_set_root, result_bindings: 1 },
        ],
    });
    assert.equal((await verifyCap1CoverageComposition(input, options)).reason, 'cap1_examined_set_binding_mismatch');
});
test('refuses hybrid leg stripping after CAP-1 and set evidence both pass', async () => {
    const { input, options } = await fixture();
    const stripped = structuredClone(input.coverage_attestation);
    assert.equal(stripped['@version'], COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION);
    stripped.proof.signatures = stripped.proof.signatures.filter((entry) => entry.alg === 'Ed25519');
    input.coverage_attestation = stripped;
    assert.equal((await verifyCap1CoverageComposition(input, options)).accepted, false);
});
