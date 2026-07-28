// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  COVERAGE_RECONCILIATION_ATTESTATION_VERSION,
  signCoverageReconciliationAttestation,
  verifyCoverageReconciliationAttestation,
} from './coverage-reconciliation-attestation.js';
import { riskDigest, signRiskBody } from './dist/reliance-risk-crypto.js';
import {
  RECEIPT_CENSUS_VERSION,
  createReceiptCensus,
  validateReceiptCensus,
} from './receipt-census.js';

const D = (c: string) => `sha256:${c.repeat(64)}`;
const program = { program_id: 'rp.payer.pas.1', version: 3, source_digest: D('1'), program_digest: D('2') };

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
    coverage_report_hash: D('3'),
    system_of_record: { inventory_id: 'pas:sor:2026-07', population_root: D('4'), count: 100 },
    receipt_population: { inventory_id: 'ep:receipts:2026-07', population_root: D('5'), count: 98 },
    joins: { matched: 95, effect_without_receipt: 3, receipt_without_effect: 1, indeterminate: 2, excluded: 2, exception: 0 },
    issued_at: '2026-08-01T01:00:00Z', expires_at: '2026-08-08T01:00:00Z',
    timestamp_anchor: { method: 'rfc3161', evidence_digest: D('6') },
    claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
  }, { issuer_id: 'payer:example', key_id: 'risk-key-1', private_key: pair.privateKey });
  assert.equal(attestation['@version'], COVERAGE_RECONCILIATION_ATTESTATION_VERSION);
  assert.equal(verifyCoverageReconciliationAttestation(attestation, {
    trusted_keys, now: '2026-08-02T00:00:00Z', expected_program_digest: D('2'),
  }).accepted, true);

  const tampered = structuredClone(attestation); tampered.joins.matched = 96;
  assert.equal(verifyCoverageReconciliationAttestation(tampered, { trusted_keys }).reason, 'digest_mismatch');
  const impossible = signable(attestation); impossible.joins.matched = 96;
  assert.throws(() => signCoverageReconciliationAttestation(impossible, {
    issuer_id: 'payer:example', key_id: 'risk-key-1', private_key: pair.privateKey,
  }), /conservation/i);
});

function signable(attestation: any) {
  const { issuer: _issuer, proof: _proof, '@version': _version, ...input } = structuredClone(attestation);
  return input;
}

test('receipt census suppresses small cells and refuses raw payload fields', () => {
  const input = {
    census_id: 'census:2026-07', relying_party_id: 'payer:example',
    period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
    program_digest: D('2'), minimum_bucket_count: 5,
    buckets: [
      { action_class: 'health.prior-authorization', program_version: 3, outcome: 'executed', count: 12, open_exposure_amount_minor: '12000', reported_loss_amount_minor: '0', currency: 'USD' },
      { action_class: 'health.prior-authorization', program_version: 3, outcome: 'refused', count: 2, open_exposure_amount_minor: '0', reported_loss_amount_minor: '0', currency: 'USD' },
    ],
    source_inventory_digest: D('7'), generated_at: '2026-08-01T01:00:00Z',
  };
  const census = createReceiptCensus(input);
  assert.equal(census['@version'], RECEIPT_CENSUS_VERSION);
  assert.equal(census.buckets.length, 1);
  assert.deepEqual(census.suppressed, { bucket_count: 1, record_count: 2 });
  assert.equal(validateReceiptCensus(census).valid, true);
  const privacyBypass = structuredClone(census);
  privacyBypass.buckets[0].count = 1;
  const { census_digest: _digest, ...privacyBypassBody } = privacyBypass;
  privacyBypass.census_digest = riskDigest(privacyBypassBody);
  assert.deepEqual(validateReceiptCensus(privacyBypass), {
    valid: false,
    reason: 'census_integrity_invalid',
  });
  assert.throws(() => createReceiptCensus({
    ...input,
    buckets: [{ ...input.buckets[0], raw_action: { member: 'PHI' } }],
  } as any), /field|bucket/i);
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
    coverage_report_hash: D('3'),
    system_of_record: { inventory_id: 'pas:sor:2026-07', population_root: D('4'), count: 100 },
    receipt_population: { inventory_id: 'ep:receipts:2026-07', population_root: D('5'), count: 98 },
    joins: { matched: 95, effect_without_receipt: 3, receipt_without_effect: 1, indeterminate: 2, excluded: 2, exception: 0 },
    issued_at: '2026-08-01T01:00:00Z', expires_at: '2026-08-08T01:00:00Z',
    timestamp_anchor: null,
    claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
  };
}

test('checked-in coverage and census vector is deterministic and verifies', () => {
  const vector = JSON.parse(readFileSync(fileURLToPath(new URL(
    '../../conformance/vectors/coverage-reconciliation.v1.json', import.meta.url,
  )), 'utf8'));
  assert.equal(validateReceiptCensus(vector.census).valid, true);
  assert.deepEqual(verifyCoverageReconciliationAttestation(vector.artifact, {
    trusted_keys: vector.trusted_keys,
    now: vector.verification_time,
    expected_program_digest: vector.artifact.program.program_digest,
  }), vector.expected);
});
