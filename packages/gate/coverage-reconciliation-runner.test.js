// SPDX-License-Identifier: Apache-2.0
// Generated from coverage-reconciliation-runner.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { COVERAGE_RECONCILIATION_REPORT_VERSION, COVERAGE_SOURCE_CLAIM_BOUNDARY, COVERAGE_SOURCE_INVENTORY_VERSION, COVERAGE_SOURCE_INVENTORY_V1_VERSION, coveragePopulationRoot, coveragePopulationRootV1, runCoverageReconciliation, signCoverageSourceInventory, verifyCoverageReconciliationReportBinding, verifyCoverageSourceInventory, } from './coverage-reconciliation-runner.js';
import { verifyCoverageReconciliationAttestation } from './coverage-reconciliation-attestation.js';
import { signRiskBody } from './dist/reliance-risk-crypto.js';
const D = (character) => `sha256:${character.repeat(64)}`;
const C = (character) => (`caid:1:health.medical-prior-authorization-review.1:jcs-sha256:${character.repeat(43)}`);
const PERIOD = {
    start: '2026-07-01T00:00:00Z',
    end: '2026-08-01T00:00:00Z',
};
const PROGRAM = {
    program_id: 'rp.payer.pas.1',
    version: 3,
    source_digest: D('1'),
    program_digest: D('2'),
};
const systemRecords = () => [
    { record_id: 'pas:effect:100', caid: C('A'), action_digest: D('a'), classification: 'effect' },
    { record_id: 'pas:effect:101', caid: C('B'), action_digest: D('b'), classification: 'effect' },
    {
        record_id: 'pas:effect:102', caid: C('C'), action_digest: D('c'),
        classification: 'excluded', classification_rule_id: 'rule:non-adverse-disposition',
    },
    {
        record_id: 'pas:effect:103', caid: C('D'), action_digest: D('d'),
        classification: 'exception', classification_rule_id: 'rule:manual-exception',
    },
];
const receiptRecords = () => [
    { record_id: 'gate:receipt:100', caid: C('A'), action_digest: D('a'), classification: 'receipt' },
    { record_id: 'gate:receipt:104', caid: C('E'), action_digest: D('e'), classification: 'receipt' },
    { record_id: 'gate:receipt:105', caid: C('F'), action_digest: D('f'), classification: 'indeterminate' },
];
function keys() {
    const systemKey = generateKeyPairSync('ed25519');
    const receiptKey = generateKeyPairSync('ed25519');
    const relyingParty = generateKeyPairSync('ed25519');
    return {
        systemKey,
        receiptKey,
        relyingParty,
        trusted_keys: {
            'key:pas-source': {
                issuer_id: 'operator:pas-system-of-record',
                public_key: systemKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
            'key:gate-receipts': {
                issuer_id: 'operator:emilia-gate',
                public_key: receiptKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
            'key:payer-reconciler': {
                issuer_id: 'payer:example',
                public_key: relyingParty.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
    };
}
function signedInputs() {
    const material = keys();
    const system = signCoverageSourceInventory({
        inventory_id: 'pas:sor:2026-07',
        inventory_kind: 'system_of_record',
        source_system_id: 'pas:synthetic-payer',
        source_operator_id: 'operator:pas-system-of-record',
        period: PERIOD,
        mapping_profile_digest: D('3'),
        issued_at: '2026-08-01T00:05:00Z',
        expires_at: '2026-08-08T00:05:00Z',
    }, systemRecords(), {
        issuer_id: 'operator:pas-system-of-record',
        key_id: 'key:pas-source',
        private_key: material.systemKey.privateKey,
    });
    const receipts = signCoverageSourceInventory({
        inventory_id: 'gate:receipts:2026-07',
        inventory_kind: 'receipt_population',
        source_system_id: 'emilia-gate:synthetic-payer',
        source_operator_id: 'operator:emilia-gate',
        period: PERIOD,
        mapping_profile_digest: D('4'),
        issued_at: '2026-08-01T00:05:00Z',
        expires_at: '2026-08-08T00:05:00Z',
    }, receiptRecords(), {
        issuer_id: 'operator:emilia-gate',
        key_id: 'key:gate-receipts',
        private_key: material.receiptKey.privateKey,
    });
    return { ...material, system, receipts };
}
test('signs deterministic source roots and verifies them against the supplied records', () => {
    const fixture = signedInputs();
    assert.equal(fixture.system['@version'], COVERAGE_SOURCE_INVENTORY_VERSION);
    assert.equal(fixture.system.population_root, coveragePopulationRoot('system_of_record', systemRecords()));
    assert.deepEqual(verifyCoverageSourceInventory(fixture.system, systemRecords(), {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        expected_inventory_kind: 'system_of_record',
        expected_source_system_id: 'pas:synthetic-payer',
        expected_mapping_profile_digest: D('3'),
    }).accepted, true);
    const altered = systemRecords();
    altered[1] = { ...altered[1], action_digest: D('9') };
    assert.equal(verifyCoverageSourceInventory(fixture.system, altered, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        expected_inventory_kind: 'system_of_record',
        expected_source_system_id: 'pas:synthetic-payer',
        expected_mapping_profile_digest: D('3'),
    }).reason, 'population_root_mismatch');
});
test('continues to verify already-issued v1 source inventories', () => {
    const fixture = keys();
    const records = systemRecords().map(({ classification_rule_id: _rule, ...record }) => record);
    const body = {
        '@version': COVERAGE_SOURCE_INVENTORY_V1_VERSION,
        inventory_id: 'pas:sor:legacy-v1',
        inventory_kind: 'system_of_record',
        source_system_id: 'pas:synthetic-payer',
        source_operator_id: 'operator:pas-system-of-record',
        period: PERIOD,
        record_count: records.length,
        population_root: coveragePopulationRootV1('system_of_record', records),
        mapping_profile_digest: D('3'),
        issued_at: '2026-08-01T00:05:00Z',
        expires_at: '2026-08-08T00:05:00Z',
        claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
    };
    const artifact = signRiskBody(COVERAGE_SOURCE_INVENTORY_V1_VERSION, body, {
        issuer_id: 'operator:pas-system-of-record',
        key_id: 'key:pas-source',
        private_key: fixture.systemKey.privateKey,
    });
    assert.equal(verifyCoverageSourceInventory(artifact, records, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        expected_inventory_kind: 'system_of_record',
        expected_source_system_id: 'pas:synthetic-payer',
        expected_mapping_profile_digest: D('3'),
    }).accepted, true);
});
test('reconciles exact CAID/action pairs and signs a report-bound attestation', () => {
    const fixture = signedInputs();
    const result = runCoverageReconciliation({
        run_id: 'coverage-run:2026-07',
        attestation_id: 'coverage-attestation:2026-07',
        relying_party_id: 'payer:example',
        program: PROGRAM,
        period: PERIOD,
        census_digest: D('5'),
        system_of_record: { artifact: fixture.system, records: systemRecords() },
        receipt_population: { artifact: fixture.receipts, records: receiptRecords() },
        generated_at: '2026-08-01T01:00:00Z',
        expires_at: '2026-08-08T01:00:00Z',
        timestamp_anchor: null,
    }, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        system_of_record_pin: {
            source_system_id: 'pas:synthetic-payer',
            mapping_profile_digest: D('3'),
        },
        receipt_population_pin: {
            source_system_id: 'emilia-gate:synthetic-payer',
            mapping_profile_digest: D('4'),
        },
    }, {
        issuer_id: 'payer:example',
        key_id: 'key:payer-reconciler',
        private_key: fixture.relyingParty.privateKey,
    });
    assert.equal(result.report['@version'], COVERAGE_RECONCILIATION_REPORT_VERSION);
    assert.deepEqual(result.report.joins, {
        matched: 1,
        observed_without_receipt: 1,
        receipted_without_observation: 1,
        indeterminate: 1,
        excluded: 1,
        exception: 1,
    });
    assert.deepEqual(result.report.findings.observed_without_receipt.map((entry) => entry.record_id), ['pas:effect:101']);
    assert.deepEqual(result.report.findings.receipted_without_observation.map((entry) => entry.record_id), ['gate:receipt:104']);
    assert.equal(result.report.findings.excluded[0].classification_rule_id, 'rule:non-adverse-disposition');
    assert.deepEqual(result.report.findings.indeterminate.map((entry) => entry.record_id), ['gate:receipt:105']);
    assert.equal(result.attestation.coverage_report_hash, result.report_hash);
    assert.equal(result.attestation.system_of_record.population_root, fixture.system.population_root);
    assert.equal(result.attestation.receipt_population.population_root, fixture.receipts.population_root);
    assert.equal(verifyCoverageReconciliationReportBinding(result.report, result.attestation).accepted, true);
    const alteredReport = structuredClone(result.report);
    alteredReport.findings.observed_without_receipt[0].record_id = 'pas:effect:forged';
    assert.equal(verifyCoverageReconciliationReportBinding(alteredReport, result.attestation).reason, 'coverage_report_hash_mismatch');
    assert.equal(verifyCoverageReconciliationAttestation(result.attestation, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        expected_program: PROGRAM,
        expected_census_digest: D('5'),
        expected_relying_party_id: 'payer:example',
        expected_coverage_report_hash: result.report_hash,
    }).accepted, true);
    assert.equal(verifyCoverageReconciliationAttestation(result.attestation, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        expected_program: PROGRAM,
        expected_census_digest: D('5'),
        expected_relying_party_id: 'payer:example',
        expected_coverage_report_hash: D('9'),
    }).reason, 'coverage_report_hash_mismatch');
});
test('requires independently controlled source and receipt issuers', () => {
    const fixture = signedInputs();
    const sameIssuerReceipts = signCoverageSourceInventory({
        inventory_id: 'gate:receipts:same-issuer',
        inventory_kind: 'receipt_population',
        source_system_id: 'emilia-gate:synthetic-payer',
        source_operator_id: 'operator:pas-system-of-record',
        period: PERIOD,
        mapping_profile_digest: D('4'),
        issued_at: '2026-08-01T00:05:00Z',
        expires_at: '2026-08-08T00:05:00Z',
    }, receiptRecords(), {
        issuer_id: 'operator:pas-system-of-record',
        key_id: 'key:pas-source',
        private_key: fixture.systemKey.privateKey,
    });
    assert.throws(() => runCoverageReconciliation({
        run_id: 'coverage-run:same-issuer',
        attestation_id: 'coverage-attestation:same-issuer',
        relying_party_id: 'payer:example',
        program: PROGRAM,
        period: PERIOD,
        census_digest: D('5'),
        system_of_record: { artifact: fixture.system, records: systemRecords() },
        receipt_population: { artifact: sameIssuerReceipts, records: receiptRecords() },
        generated_at: '2026-08-01T01:00:00Z',
        expires_at: '2026-08-08T01:00:00Z',
        timestamp_anchor: null,
    }, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        system_of_record_pin: {
            source_system_id: 'pas:synthetic-payer',
            mapping_profile_digest: D('3'),
        },
        receipt_population_pin: {
            source_system_id: 'emilia-gate:synthetic-payer',
            mapping_profile_digest: D('4'),
        },
    }, {
        issuer_id: 'payer:example',
        key_id: 'key:payer-reconciler',
        private_key: fixture.relyingParty.privateKey,
    }), /independent source issuers/i);
});
test('refuses ambiguous duplicate joins and CAID-to-digest conflicts', () => {
    assert.throws(() => coveragePopulationRoot('system_of_record', [
        ...systemRecords(),
        { ...systemRecords()[0], record_id: 'pas:effect:duplicate' },
    ]), /duplicate action join/i);
    const fixture = signedInputs();
    const conflictingReceipts = receiptRecords();
    conflictingReceipts[0] = { ...conflictingReceipts[0], action_digest: D('9') };
    const receiptArtifact = signCoverageSourceInventory({
        inventory_id: 'gate:receipts:conflict',
        inventory_kind: 'receipt_population',
        source_system_id: 'emilia-gate:synthetic-payer',
        source_operator_id: 'operator:emilia-gate',
        period: PERIOD,
        mapping_profile_digest: D('4'),
        issued_at: '2026-08-01T00:05:00Z',
        expires_at: '2026-08-08T00:05:00Z',
    }, conflictingReceipts, {
        issuer_id: 'operator:emilia-gate',
        key_id: 'key:gate-receipts',
        private_key: fixture.receiptKey.privateKey,
    });
    assert.throws(() => runCoverageReconciliation({
        run_id: 'coverage-run:conflict',
        attestation_id: 'coverage-attestation:conflict',
        relying_party_id: 'payer:example',
        program: PROGRAM,
        period: PERIOD,
        census_digest: D('5'),
        system_of_record: { artifact: fixture.system, records: systemRecords() },
        receipt_population: { artifact: receiptArtifact, records: conflictingReceipts },
        generated_at: '2026-08-01T01:00:00Z',
        expires_at: '2026-08-08T01:00:00Z',
        timestamp_anchor: null,
    }, {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
        system_of_record_pin: {
            source_system_id: 'pas:synthetic-payer',
            mapping_profile_digest: D('3'),
        },
        receipt_population_pin: {
            source_system_id: 'emilia-gate:synthetic-payer',
            mapping_profile_digest: D('4'),
        },
    }, {
        issuer_id: 'payer:example',
        key_id: 'key:payer-reconciler',
        private_key: fixture.relyingParty.privateKey,
    }), /CAID.*different action digest/i);
});
test('binds classification rules for every excluded or exceptional source record', () => {
    const records = systemRecords();
    const originalRoot = coveragePopulationRoot('system_of_record', records);
    const changedRule = structuredClone(records);
    changedRule[2].classification_rule_id = 'rule:different-exclusion';
    assert.notEqual(coveragePopulationRoot('system_of_record', changedRule), originalRoot);
    const missingRule = structuredClone(records);
    delete missingRule[2].classification_rule_id;
    assert.throws(() => coveragePopulationRoot('system_of_record', missingRule), /record is invalid/i);
    const unruledEffect = structuredClone(records);
    unruledEffect[0].classification_rule_id = 'rule:not-allowed-on-observation';
    assert.throws(() => coveragePopulationRoot('system_of_record', unruledEffect), /record is invalid/i);
    const receiptWithRule = receiptRecords();
    receiptWithRule[0].classification_rule_id = 'rule:not-allowed-on-receipt';
    assert.throws(() => coveragePopulationRoot('receipt_population', receiptWithRule), /record is invalid/i);
});
test('source verification fails closed without verifier-owned context', () => {
    const fixture = signedInputs();
    assert.equal(verifyCoverageSourceInventory(fixture.system, systemRecords(), {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-02T00:00:00Z',
    }).reason, 'context_binding_required');
    assert.equal(verifyCoverageSourceInventory(fixture.system, systemRecords(), {
        trusted_keys: fixture.trusted_keys,
        now: '2026-08-09T00:00:00Z',
        expected_inventory_kind: 'system_of_record',
        expected_source_system_id: 'pas:synthetic-payer',
        expected_mapping_profile_digest: D('3'),
    }).reason, 'inventory_expired');
});
