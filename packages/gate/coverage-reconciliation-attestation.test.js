// SPDX-License-Identifier: Apache-2.0
// Generated from coverage-reconciliation-attestation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { COVERAGE_RECONCILIATION_ATTESTATION_VERSION, signCoverageReconciliationAttestation, verifyCoverageReconciliationAttestation, } from './coverage-reconciliation-attestation.js';
import { riskDigest, signRiskBody } from './dist/reliance-risk-crypto.js';
import { RECEIPT_CENSUS_VERSION, createReceiptCensus, receiptCensusTaxonomyDigest, validateReceiptCensus, } from './receipt-census.js';
const D = (c) => `sha256:${c.repeat(64)}`;
const program = { program_id: 'rp.payer.pas.1', version: 3, source_digest: D('1'), program_digest: D('2') };
const taxonomy = {
    taxonomy_id: 'payer:receipt-census-taxonomy:v1',
    allowed_action_classes: ['Z', 'a', 'a.b', 'health.prior-authorization'],
    allowed_outcomes: ['executed', 'refused'],
};
function fixture() {
    const pair = generateKeyPairSync('ed25519');
    const hostilePair = generateKeyPairSync('ed25519');
    const trusted_keys = {
        'risk-key-1': {
            issuer_id: 'payer:example',
            public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
        'hostile-key-1': {
            issuer_id: 'carrier:example',
            public_key: hostilePair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
    };
    return { pair, hostilePair, trusted_keys };
}
test('signs a bounded reconciliation and conserves both supplied populations', () => {
    const { pair, trusted_keys } = fixture();
    const attestation = signCoverageReconciliationAttestation({
        attestation_id: 'coverage:2026-07', relying_party_id: 'payer:example', program,
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        coverage_report_hash: D('3'), census_digest: D('7'),
        system_of_record: { inventory_id: 'pas:sor:2026-07', population_root: D('4'), count: 100 },
        receipt_population: { inventory_id: 'ep:receipts:2026-07', population_root: D('5'), count: 98 },
        joins: { matched: 95, effect_without_receipt: 3, receipted_without_observation: 1, indeterminate: 2, system_indeterminate: 0, excluded: 2, exception: 0 },
        issued_at: '2026-08-01T01:00:00Z', expires_at: '2026-08-08T01:00:00Z',
        timestamp_anchor: { method: 'rfc3161', evidence_digest: D('6') },
        claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
    }, { issuer_id: 'payer:example', key_id: 'risk-key-1', private_key: pair.privateKey });
    assert.equal(attestation['@version'], COVERAGE_RECONCILIATION_ATTESTATION_VERSION);
    assert.equal(verifyCoverageReconciliationAttestation(attestation, {
        trusted_keys, now: '2026-08-02T00:00:00Z', expected_program: program,
        expected_census_digest: D('7'), expected_relying_party_id: 'payer:example',
    }).accepted, true);
    const tampered = structuredClone(attestation);
    tampered.joins.matched = 96;
    assert.equal(verifyCoverageReconciliationAttestation(tampered, { trusted_keys }).reason, 'digest_mismatch');
    const impossible = signable(attestation);
    impossible.joins.matched = 96;
    assert.throws(() => signCoverageReconciliationAttestation(impossible, {
        issuer_id: 'payer:example', key_id: 'risk-key-1', private_key: pair.privateKey,
    }), /conservation/i);
});
function signable(attestation) {
    const { issuer: _issuer, proof: _proof, '@version': _version, ...input } = structuredClone(attestation);
    return input;
}
test('receipt census suppresses small cells and refuses raw payload fields', () => {
    const input = {
        census_id: 'census:2026-07', relying_party_id: 'payer:example',
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        program, minimum_bucket_count: 5,
        buckets: [
            { action_class: 'health.prior-authorization', program_version: 3, outcome: 'executed', count: 12, open_exposure_amount_minor: '12000', reported_loss_amount_minor: '0', currency: 'USD' },
            { action_class: 'health.prior-authorization', program_version: 3, outcome: 'refused', count: 2, open_exposure_amount_minor: '0', reported_loss_amount_minor: '0', currency: 'USD' },
        ],
        source_inventory_digest: D('7'), generated_at: '2026-08-01T01:00:00Z',
    };
    const census = createReceiptCensus(input, taxonomy);
    assert.equal(census['@version'], RECEIPT_CENSUS_VERSION);
    assert.equal(census.taxonomy_digest, receiptCensusTaxonomyDigest(taxonomy));
    assert.equal(census.buckets.length, 1);
    assert.deepEqual(census.suppressed, { bucket_count: 1, record_count: 2 });
    assert.equal(validateReceiptCensus(census, taxonomy).valid, true);
    const privacyBypass = structuredClone(census);
    privacyBypass.buckets[0].count = 1;
    const { census_digest: _digest, ...privacyBypassBody } = privacyBypass;
    privacyBypass.census_digest = riskDigest(privacyBypassBody);
    assert.deepEqual(validateReceiptCensus(privacyBypass, taxonomy), {
        valid: false,
        reason: 'census_integrity_invalid',
    });
    assert.throws(() => createReceiptCensus({
        ...input,
        buckets: [{ ...input.buckets[0], raw_action: { member: 'PHI' } }],
    }, taxonomy), /field|bucket/i);
    assert.throws(() => createReceiptCensus({
        ...input,
        buckets: [{ ...input.buckets[0], action_class: 'patient:alice' }],
    }, taxonomy), /taxonomy/i);
    assert.deepEqual(validateReceiptCensus(census), {
        valid: false,
        reason: 'census_taxonomy_required',
    });
    assert.equal(validateReceiptCensus(census, {
        ...taxonomy,
        allowed_action_classes: ['health.prior-authorization'],
    }).valid, false);
});
test('receipt census uses one UTF-8 byte order for mixed case and punctuation', () => {
    const input = {
        census_id: 'census:ordering', relying_party_id: 'payer:example',
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        program, minimum_bucket_count: 2,
        buckets: ['Z', 'a', 'a.b'].map((action_class) => ({
            action_class, program_version: 3, outcome: 'executed', count: 2,
            open_exposure_amount_minor: '0', reported_loss_amount_minor: '0', currency: 'USD',
        })),
        source_inventory_digest: D('7'), generated_at: '2026-08-01T01:00:00Z',
    };
    const census = createReceiptCensus(input, taxonomy);
    assert.deepEqual(census.buckets.map((bucket) => bucket.action_class), ['Z', 'a', 'a.b']);
    assert.equal(validateReceiptCensus(census, taxonomy).valid, true);
});
test('coverage verification separates a valid signature from relying-party authority', () => {
    const { hostilePair, trusted_keys } = fixture();
    const legitimate = coverageInput();
    const hostile = signRiskBody(COVERAGE_RECONCILIATION_ATTESTATION_VERSION, {
        '@version': COVERAGE_RECONCILIATION_ATTESTATION_VERSION,
        ...legitimate,
    }, {
        issuer_id: 'carrier:example',
        key_id: 'hostile-key-1',
        private_key: hostilePair.privateKey,
    });
    assert.deepEqual(verifyCoverageReconciliationAttestation(hostile, {
        trusted_keys,
        now: '2026-08-02T00:00:00Z',
    }), {
        accepted: false,
        verified: true,
        reason: 'relying_party_issuer_mismatch',
        attestation_digest: riskDigest(hostile),
        claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
    });
});
function coverageInput() {
    return {
        attestation_id: 'coverage:2026-07-hostile', relying_party_id: 'payer:example', program,
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        coverage_report_hash: D('3'), census_digest: D('7'),
        system_of_record: { inventory_id: 'pas:sor:2026-07', population_root: D('4'), count: 100 },
        receipt_population: { inventory_id: 'ep:receipts:2026-07', population_root: D('5'), count: 98 },
        joins: { matched: 95, effect_without_receipt: 3, receipted_without_observation: 1, indeterminate: 2, system_indeterminate: 0, excluded: 2, exception: 0 },
        issued_at: '2026-08-01T01:00:00Z', expires_at: '2026-08-08T01:00:00Z',
        timestamp_anchor: null,
        claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
    };
}
test('checked-in coverage and census vector is deterministic and verifies', () => {
    const vector = JSON.parse(readFileSync(fileURLToPath(new URL('../../conformance/vectors/coverage-reconciliation.v1.json', import.meta.url)), 'utf8'));
    assert.equal(validateReceiptCensus(vector.census, vector.taxonomy).valid, true);
    assert.deepEqual(verifyCoverageReconciliationAttestation(vector.artifact, {
        trusted_keys: vector.trusted_keys,
        now: vector.verification_time,
        expected_program: vector.expected_program,
        expected_census_digest: vector.expected_census_digest,
        expected_relying_party_id: vector.expected_relying_party_id,
    }), vector.expected);
});
test('coverage verification rejects pre-issuance and missing verifier-owned context', () => {
    const { pair, trusted_keys } = fixture();
    const artifact = signCoverageReconciliationAttestation(coverageInput(), {
        issuer_id: 'payer:example', key_id: 'risk-key-1', private_key: pair.privateKey,
    });
    const base = { trusted_keys, expected_program: program, expected_census_digest: D('7'), expected_relying_party_id: 'payer:example' };
    assert.equal(verifyCoverageReconciliationAttestation(artifact, {
        ...base, now: '2026-08-01T00:59:59Z',
    }).reason, 'attestation_not_yet_issued');
    assert.equal(verifyCoverageReconciliationAttestation(artifact, {
        trusted_keys, now: '2026-08-02T00:00:00Z',
    }).reason, 'context_binding_required');
    assert.equal(verifyCoverageReconciliationAttestation(artifact, {
        ...base, now: '2026-08-02T00:00:00Z', expected_census_digest: D('9'),
    }).reason, 'census_digest_mismatch');
    assert.equal(verifyCoverageReconciliationAttestation(artifact, {
        ...base,
        now: '2026-08-02T00:00:00Z',
        expected_program: { ...program, version: 999 },
    }).reason, 'program_binding_mismatch');
});
test('receipt census requires every bucket version to match the complete pinned program', () => {
    const input = {
        census_id: 'census:program-mismatch', relying_party_id: 'payer:example',
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        program, minimum_bucket_count: 2,
        buckets: [{
                action_class: 'health.prior-authorization', program_version: 2,
                outcome: 'executed', count: 2, open_exposure_amount_minor: '0',
                reported_loss_amount_minor: '0', currency: 'USD',
            }],
        source_inventory_digest: D('7'), generated_at: '2026-08-01T01:00:00Z',
    };
    assert.throws(() => createReceiptCensus(input, taxonomy), /taxonomy/i);
});
