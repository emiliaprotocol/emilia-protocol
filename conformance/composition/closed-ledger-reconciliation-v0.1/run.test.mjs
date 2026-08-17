// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'vitest';

import {
  COMPLETENESS_LADDER,
  PINNED_DRAFT_SHA256,
  PROFILE,
  READINGS,
  classifyUnobservedReceipt,
  createFixtureLedgerAdapter,
  runHarness,
  settlementIdentity,
} from './run.mjs';

const sourceLock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));

function caseById(report, id) {
  const entry = report.cases.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing case ${id}`);
  return entry;
}

function readingFor(report, recordId) {
  const entry = report.runs.mixed.unobserved_receipt_readings
    .find((candidate) => candidate.record_id === recordId);
  assert.ok(entry, `missing reading for ${recordId}`);
  return entry;
}

test('the source lock pins the draft this commitment was made against', () => {
  assert.equal(sourceLock['@version'], 'CLOSED-LEDGER-RECONCILIATION-SOURCE-LOCK-v0.1');
  const pinned = sourceLock.ietf_archives.find(
    (entry) => entry.name === 'draft-hawkins-scitt-attested-agent-payment-01',
  );
  assert.ok(pinned);
  assert.equal(pinned.sha256, PINNED_DRAFT_SHA256);
});

test('the harness is deterministic across runs', () => {
  const first = runHarness();
  const second = runHarness();
  assert.equal(first.report_digest, second.report_digest);
  assert.equal(first.profile, PROFILE);
  assert.equal(first.passed, true);
});

test('the runner is imported as-is and its own bin names are used, whichever rename state it carries', () => {
  const report = runHarness();
  const bin = report.runner.unobserved_bin_name;
  assert.ok(
    bin === 'receipted_without_observation' || bin === 'receipt_without_effect',
    `unexpected unobserved bin name: ${bin}`,
  );
  assert.ok(report.runner.bin_names.includes(bin));
  assert.ok(report.runner.bin_names.includes('matched'));
  assert.ok(report.runner.bin_names.includes('effect_without_receipt'));
  // Receipt-side conservation: every receipt lands in exactly one bin.
  const joins = report.runs.mixed.joins;
  assert.equal(joins.matched + joins[bin] + joins.indeterminate, 5);
});

test('clean reconciliation: every receipt matches a finalized settlement', () => {
  const report = runHarness();
  assert.equal(caseById(report, 'clean-reconciliation').passed, true);
  assert.equal(report.runs.clean.joins.matched, 1);
  assert.equal(report.runs.clean.joins[report.runner.unobserved_bin_name], 0);
  assert.equal(report.runs.clean.attestation_verified.binding, true);
  assert.equal(report.runs.clean.attestation_verified.attestation, true);
});

test('a receipt absent from the finalized ledger after the horizon gets the strong reading, with its conditions stated', () => {
  const report = runHarness();
  const reading = readingFor(report, 'receipt:R-002-vendor-nomad');
  assert.equal(reading.outcome, READINGS.STRONG);
  assert.deepEqual(reading.strong_reading_conditions, {
    completeness_protocol_defined: true,
    settlement_would_land_on_ledger: true,
    finality_horizon_passed_outside_skew: true,
  });
});

test('an in-flight receipt is its own outcome, never collapsed into a reading', () => {
  const report = runHarness();
  const reading = readingFor(report, 'receipt:R-003-vendor-brook');
  assert.equal(reading.outcome, READINGS.IN_FLIGHT);
  assert.equal(reading.strong_reading_conditions, null);
});

test('a skew-boundary receipt lands indeterminate', () => {
  const report = runHarness();
  const reading = readingFor(report, 'receipt:R-004-vendor-quill');
  assert.equal(reading.outcome, READINGS.INDETERMINATE_SKEW);
});

test('an off-ledger-effect receipt gets the weak reading only', () => {
  const report = runHarness();
  const reading = readingFor(report, 'receipt:R-005-offledger-wire');
  assert.equal(reading.outcome, READINGS.WEAK_OFF_LEDGER);
  assert.equal(reading.strong_reading_conditions, null);
});

test('the strong reading collapses to weak when completeness drops below protocol_defined', () => {
  const meta = {
    record_id: 'receipt:ladder-check',
    settlement: { settlement_id: 'S-900', rail: 'rail:fixture-testnet', payee: 'payee:x', amount: 100, currency: 'USD' },
    settlement_target: 'on_ledger',
    expected_settled_at: '2026-08-16T10:00:00Z',
  };
  const context = {
    finalityBoundaryMs: Date.parse('2026-08-16T11:55:00Z'),
    skewBoundMs: 120000,
  };
  for (const level of COMPLETENESS_LADDER.filter((entry) => entry !== 'protocol_defined')) {
    const reading = classifyUnobservedReceipt(meta, {
      ...context,
      completeness: { level },
    });
    assert.equal(reading.outcome, READINGS.WEAK_COMPLETENESS, level);
    assert.equal(reading.strong_reading_conditions, null, level);
  }
  const strong = classifyUnobservedReceipt(meta, {
    ...context,
    completeness: { level: 'protocol_defined' },
  });
  assert.equal(strong.outcome, READINGS.STRONG);
});

test('the fixture ledger declares protocol_defined completeness with a stated finality rule and per-side clocks', () => {
  const adapter = createFixtureLedgerAdapter();
  assert.equal(adapter.completeness.level, 'protocol_defined');
  assert.deepEqual([...adapter.completeness.ladder], [...COMPLETENESS_LADDER]);
  assert.ok(adapter.completeness.finality_rule.length > 0);
  assert.equal(typeof adapter.clock.source, 'string');
  assert.equal(typeof adapter.clock.skew_bound_seconds, 'number');
  const report = runHarness();
  assert.equal(typeof report.clocks.receipt_side.source, 'string');
  assert.notEqual(report.clocks.ledger.source, report.clocks.receipt_side.source);
});

test('settlement identity is recomputable and stable on both sides of the join', () => {
  const settlement = { settlement_id: 'S-001', rail: 'rail:fixture-testnet', payee: 'payee:vendor-acme', amount: 250000, currency: 'USD' };
  const first = settlementIdentity(settlement);
  const second = settlementIdentity({ ...settlement });
  assert.deepEqual(first, second);
  assert.match(first.caid, /^caid:1:payment\.settlement\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
  assert.match(first.action_digest, /^sha256:[0-9a-f]{64}$/);
});
