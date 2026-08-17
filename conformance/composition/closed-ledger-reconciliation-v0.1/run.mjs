// SPDX-License-Identifier: Apache-2.0
/**
 * Closed-population comparison harness: EMILIA coverage reconciliation over a
 * source population that is CLOSED with respect to itself (a public ledger
 * after finality), testnet-ready.
 *
 * EMILIA committed on the SCITT list to running its coverage reconciliation
 * over such a population on the draft-hawkins testnet, at its own cost. The
 * testnet endpoint is not yet known, so this harness runs against a
 * deterministic FIXTURE ledger, with the ledger access isolated behind one
 * small adapter interface (fetch finalized settlements in a window and return
 * normalized records). Pointing it at the real testnet is an adapter swap,
 * not a harness change.
 *
 * The reconciliation itself is the repo's real machinery, imported from
 * packages/gate (runCoverageReconciliation and friends), used AS-IS. The
 * source-population COMPLETENESS DECLARATION is deliberately carried in this
 * harness layer and its report, not in the runner: the runner's own claim
 * boundary is that it proves what the supplied signed populations contain and
 * never self-proves source completeness. The completeness ladder discussed
 * on-list is:
 *
 *   protocol_defined   the population is closed by a stated protocol rule
 *                      (here: a finality rule); the strongest rung.
 *   measured           closure is estimated from observation, not guaranteed.
 *   operator_declared  the source operator asserts closure; take their word.
 *   undeclared         nothing is claimed about closure.
 *
 * Reading policy (what the report asserts, and when):
 *
 *   With a closed population, a record in the runner's
 *   receipted-without-observation bin (a receipt naming a settlement absent
 *   from the finalized ledger after the finality horizon) supports the STRONG
 *   reading: the effect did not occur. This report asserts that reading ONLY
 *   when all three conditions hold: (1) completeness is protocol_defined,
 *   (2) the receipt's settlement would land on this ledger, and (3) the
 *   finality horizon has passed at observation time, outside the declared
 *   clock-skew bound. A receipt still inside the finality horizon is IN
 *   FLIGHT, its own outcome, never collapsed into either reading. A receipt
 *   at the horizon boundary within the skew bound is INDETERMINATE. A receipt
 *   for an off-ledger effect gets the WEAK reading only: no observation
 *   recorded, effect status unknown.
 *
 * Clock skew (raised by the draft author on-list): each side declares its
 * clock source, and the harness declares a skew bound between them. Boundary
 * cases within the bound land indeterminate rather than being forced into a
 * reading.
 *
 * Claim boundary: fixture ledger, not the draft author's testnet. The strong
 * reading is conditional on the declared completeness and finality rule,
 * which this fixture defines and therefore satisfies by construction; a real
 * rail must prove its own rule before the strong reading transfers. Nothing
 * here characterizes his rail.
 *
 *   node conformance/composition/closed-ledger-reconciliation-v0.1/run.mjs
 *   node conformance/composition/closed-ledger-reconciliation-v0.1/run.mjs --emit
 */
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  COVERAGE_REPORT_CLAIM_BOUNDARY,
  COVERAGE_SOURCE_CLAIM_BOUNDARY,
  canonicalize,
  hashCanonical,
  runCoverageReconciliation,
  signCoverageSourceInventory,
  verifyCoverageReconciliationAttestation,
  verifyCoverageReconciliationReportBinding,
} from '../../../packages/gate/index.js';
import { receiptActionCaid } from '../../../packages/verify/dist/receipt-cose-encoding.js';

const HERE = dirname(fileURLToPath(import.meta.url));

export const PROFILE = 'EP-CLOSED-LEDGER-RECONCILIATION-HARNESS-v0.1';
export const PINNED_DRAFT = 'draft-hawkins-scitt-attested-agent-payment-01';
export const PINNED_DRAFT_SHA256 = '9e6deb7c735a5f776809e3e1431c7e67e1ecc664ab2c0a94895d51778f4080a7';

export const COMPLETENESS_LADDER = Object.freeze([
  'protocol_defined',
  'measured',
  'operator_declared',
  'undeclared',
]);

/** Fixed times. Observation happens shortly after the window closes. */
const PERIOD = Object.freeze({ start: '2026-08-16T00:00:00Z', end: '2026-08-16T12:00:00Z' });
const OBSERVED_AT = '2026-08-16T12:05:00Z';
const INVENTORY_ISSUED_AT = '2026-08-16T12:04:00Z';
const EXPIRES_AT = '2026-08-16T13:00:00Z';

// --- Fixed Ed25519 signers (fixture-only; never deployment credentials) -----
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function seededSigner(label, issuerId, keyId) {
  const seed = crypto.createHash('sha256').update(label, 'utf8').digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  return { issuer_id: issuerId, key_id: keyId, private_key: privateKey, public_key: publicKey };
}

const LEDGER_OPERATOR = seededSigner(
  'ep:closed-ledger-reconciliation:v0.1:ledger-operator',
  'op:fixture-ledger',
  'key:fixture-ledger-operator',
);
const RECEIPT_OPERATOR = seededSigner(
  'ep:closed-ledger-reconciliation:v0.1:receipt-operator',
  'op:emilia-gate-fixture',
  'key:emilia-gate-fixture',
);
const RELYING_PARTY = seededSigner(
  'ep:closed-ledger-reconciliation:v0.1:relying-party',
  'rp:closed-ledger-harness',
  'key:closed-ledger-harness',
);

const TRUSTED_KEYS = Object.freeze({
  [LEDGER_OPERATOR.key_id]: { issuer_id: LEDGER_OPERATOR.issuer_id, public_key: LEDGER_OPERATOR.public_key },
  [RECEIPT_OPERATOR.key_id]: { issuer_id: RECEIPT_OPERATOR.issuer_id, public_key: RECEIPT_OPERATOR.public_key },
  [RELYING_PARTY.key_id]: { issuer_id: RELYING_PARTY.issuer_id, public_key: RELYING_PARTY.public_key },
});

// --- Settlement identity (real CAID computation, shared by both sides) ------

/**
 * Both populations identify a settlement by the same material fields, so the
 * join key (caid, action_digest) is recomputable on either side without the
 * other's cooperation.
 */
export function settlementIdentity(settlement) {
  const action = {
    action_type: 'payment.settlement.1',
    settlement_id: settlement.settlement_id,
    rail: settlement.rail,
    payee: settlement.payee,
    amount: settlement.amount,
    currency: settlement.currency,
  };
  const result = receiptActionCaid(action);
  if (!result.ok) throw new Error(`settlement CAID refusal: ${result.reason}`);
  return { caid: result.value.caid, action_digest: result.value.digest };
}

// --- The ledger adapter interface -------------------------------------------

/**
 * The single seam a real testnet replaces. An adapter exposes:
 *
 *   ledger_id                      stable identifier of the ledger
 *   completeness                   the source-population completeness
 *                                  declaration on the ladder above, with the
 *                                  finality rule stated when protocol_defined
 *   finality.finality_horizon_seconds
 *   clock                          { source, skew_bound_seconds } for the
 *                                  ledger side
 *   fetchFinalizedSettlements({ window, observed_at })
 *     -> normalized records [{ settlement_id, rail, payee, amount, currency,
 *        settled_at }] containing exactly the settlements final at
 *        observed_at under the declared rule.
 *
 * Everything else in this harness is adapter-agnostic.
 */
export function createFixtureLedgerAdapter() {
  const HORIZON_SECONDS = 600;
  /** Raw fixture chain state: every settlement the fixture ledger ever saw. */
  const CHAIN = [
    { settlement_id: 'S-001', rail: 'rail:fixture-testnet', payee: 'payee:vendor-acme', amount: 250000, currency: 'USD', settled_at: '2026-08-16T09:00:00Z' },
    { settlement_id: 'S-006', rail: 'rail:fixture-testnet', payee: 'payee:vendor-zephyr', amount: 40000, currency: 'USD', settled_at: '2026-08-16T09:30:00Z' },
    // S-003 exists on-chain but is NOT final at the observation time below
    // (settled inside the finality horizon); the finalized view excludes it.
    { settlement_id: 'S-003', rail: 'rail:fixture-testnet', payee: 'payee:vendor-brook', amount: 12500, currency: 'USD', settled_at: '2026-08-16T11:58:00Z' },
  ];
  return {
    ledger_id: 'ledger:fixture-testnet-01',
    completeness: {
      level: 'protocol_defined',
      ladder: COMPLETENESS_LADDER,
      finality_rule: 'The finalized view of ledger:fixture-testnet-01 at observation time T contains exactly the settlements with consensus timestamp settled_at <= T minus 600 seconds. After that horizon the finalized set for a window is closed: no settlement can later appear in it, and none can leave it.',
      declared_by: 'the fixture itself. This harness defines the fixture ledger, so the rule holds by construction here; a real rail must prove its own finality rule before this declaration transfers.',
    },
    finality: { finality_horizon_seconds: HORIZON_SECONDS },
    clock: { source: 'fixture-consensus-timestamp', skew_bound_seconds: 120 },
    fetchFinalizedSettlements({ window, observed_at }) {
      const observedMs = Date.parse(observed_at);
      const startMs = Date.parse(window.start);
      const endMs = Date.parse(window.end);
      return CHAIN
        .filter((settlement) => {
          const settledMs = Date.parse(settlement.settled_at);
          return settledMs >= startMs
            && settledMs <= endMs
            && settledMs <= observedMs - HORIZON_SECONDS * 1000;
        })
        .map((settlement) => ({ ...settlement }));
    },
  };
}

// --- The receipt side (fixture gate population) -----------------------------

/** The receipt side declares its own clock source, per the skew concern. */
export const RECEIPT_SIDE_CLOCK = Object.freeze({ source: 'fixture-gate-clock', skew_bound_seconds: 120 });

/**
 * Fixture receipts: authorization receipts naming settlements. Harness-layer
 * metadata carries what the harness needs for the reading policy and stays
 * OUT of the records handed to the runner: the runner sees only
 * (record_id, caid, action_digest, classification).
 */
const RECEIPT_FIXTURES = [
  {
    record_id: 'receipt:R-001-vendor-acme',
    settlement: { settlement_id: 'S-001', rail: 'rail:fixture-testnet', payee: 'payee:vendor-acme', amount: 250000, currency: 'USD' },
    settlement_target: 'on_ledger',
    expected_settled_at: '2026-08-16T09:00:00Z',
  },
  {
    record_id: 'receipt:R-002-vendor-nomad',
    settlement: { settlement_id: 'S-002', rail: 'rail:fixture-testnet', payee: 'payee:vendor-nomad', amount: 90000, currency: 'USD' },
    settlement_target: 'on_ledger',
    expected_settled_at: '2026-08-16T10:00:00Z',
  },
  {
    record_id: 'receipt:R-003-vendor-brook',
    settlement: { settlement_id: 'S-003', rail: 'rail:fixture-testnet', payee: 'payee:vendor-brook', amount: 12500, currency: 'USD' },
    settlement_target: 'on_ledger',
    expected_settled_at: '2026-08-16T11:58:00Z',
  },
  {
    record_id: 'receipt:R-004-vendor-quill',
    settlement: { settlement_id: 'S-004', rail: 'rail:fixture-testnet', payee: 'payee:vendor-quill', amount: 33000, currency: 'USD' },
    settlement_target: 'on_ledger',
    expected_settled_at: '2026-08-16T11:55:00Z',
  },
  {
    record_id: 'receipt:R-005-offledger-wire',
    settlement: { settlement_id: 'W-005', rail: 'rail:offledger-wire', payee: 'payee:vendor-lumen', amount: 700000, currency: 'USD' },
    settlement_target: 'off_ledger',
    expected_settled_at: '2026-08-16T10:30:00Z',
  },
];

// --- Reading policy ---------------------------------------------------------

export const READINGS = Object.freeze({
  STRONG: 'strong_effect_did_not_occur',
  IN_FLIGHT: 'in_flight_within_finality_horizon',
  INDETERMINATE_SKEW: 'indeterminate_within_clock_skew',
  WEAK_OFF_LEDGER: 'weak_off_ledger_no_observation',
  WEAK_COMPLETENESS: 'weak_completeness_not_protocol_defined',
});

/**
 * Classify one receipted-without-observation record. Order matters: the
 * off-ledger and completeness gates come first (they cap the reading at
 * weak), then the skew band (boundary cases land indeterminate on BOTH sides
 * of the horizon), then in-flight, and only what survives all of that gets
 * the strong reading.
 */
export function classifyUnobservedReceipt(meta, { completeness, finalityBoundaryMs, skewBoundMs }) {
  const base = {
    record_id: meta.record_id,
    settlement_id: meta.settlement.settlement_id,
    settlement_target: meta.settlement_target,
    expected_settled_at: meta.expected_settled_at,
  };
  if (meta.settlement_target !== 'on_ledger') {
    return {
      ...base,
      outcome: READINGS.WEAK_OFF_LEDGER,
      asserted: 'no observation recorded; the closed population says nothing about effects that settle off this ledger',
      strong_reading_conditions: null,
    };
  }
  if (completeness.level !== 'protocol_defined') {
    return {
      ...base,
      outcome: READINGS.WEAK_COMPLETENESS,
      asserted: 'no observation recorded; without a protocol-defined closure the absence is not evidence of non-occurrence',
      strong_reading_conditions: null,
    };
  }
  const expectedMs = Date.parse(meta.expected_settled_at);
  if (Math.abs(expectedMs - finalityBoundaryMs) <= skewBoundMs) {
    return {
      ...base,
      outcome: READINGS.INDETERMINATE_SKEW,
      asserted: 'indeterminate: the expected settlement time sits at the finality boundary within the declared clock-skew bound, so neither reading is taken',
      strong_reading_conditions: null,
    };
  }
  if (expectedMs > finalityBoundaryMs) {
    return {
      ...base,
      outcome: READINGS.IN_FLIGHT,
      asserted: 'in flight: the finality horizon has not passed for this settlement; this is its own outcome and is never collapsed into either reading',
      strong_reading_conditions: null,
    };
  }
  return {
    ...base,
    outcome: READINGS.STRONG,
    asserted: 'effect did not occur: the population is closed by a protocol-defined finality rule, the settlement would land on this ledger, and the finality horizon has passed outside the skew bound',
    strong_reading_conditions: {
      completeness_protocol_defined: true,
      settlement_would_land_on_ledger: true,
      finality_horizon_passed_outside_skew: true,
    },
  };
}

// --- One reconciliation run through the real runner -------------------------

function populationRecord(identity, recordId, classification) {
  return {
    record_id: recordId,
    caid: identity.caid,
    action_digest: identity.action_digest,
    classification,
  };
}

/**
 * Run one closed-population reconciliation: fetch the finalized ledger view
 * through the adapter, build and sign both populations (independent
 * operators), run packages/gate runCoverageReconciliation AS-IS, verify the
 * attestation binding, and post-classify the receipted-without-observation
 * bin under the reading policy.
 */
export function runClosedPopulationReconciliation({
  runId,
  adapter,
  receipts,
  observedAt = OBSERVED_AT,
  period = PERIOD,
}) {
  const ledgerRecordsRaw = adapter.fetchFinalizedSettlements({ window: period, observed_at: observedAt });
  const systemRecords = ledgerRecordsRaw.map((settlement) => populationRecord(
    settlementIdentity(settlement),
    `${adapter.ledger_id}:${settlement.settlement_id}`,
    'effect',
  ));
  const receiptRecords = receipts.map((meta) => populationRecord(
    settlementIdentity(meta.settlement),
    meta.record_id,
    'receipt',
  ));

  const mappingProfile = {
    profile: 'closed-ledger-settlement-mapping:v0.1',
    identity_fields: ['settlement_id', 'rail', 'payee', 'amount', 'currency'],
    caid: 'packages/verify receiptActionCaid over payment.settlement.1',
  };
  const mappingProfileDigest = `sha256:${hashCanonical(mappingProfile)}`;

  const census = {
    ledger_id: adapter.ledger_id,
    window: period,
    observed_at: observedAt,
    completeness: adapter.completeness,
    finality: adapter.finality,
    clock: { ledger: adapter.clock, receipt_side: RECEIPT_SIDE_CLOCK },
  };
  const censusDigest = `sha256:${hashCanonical(census)}`;

  const systemArtifact = signCoverageSourceInventory({
    inventory_id: `inventory:${runId}:ledger`,
    inventory_kind: 'system_of_record',
    source_system_id: adapter.ledger_id,
    source_operator_id: LEDGER_OPERATOR.issuer_id,
    period,
    mapping_profile_digest: mappingProfileDigest,
    issued_at: INVENTORY_ISSUED_AT,
    expires_at: EXPIRES_AT,
  }, systemRecords, LEDGER_OPERATOR);

  const receiptArtifact = signCoverageSourceInventory({
    inventory_id: `inventory:${runId}:receipts`,
    inventory_kind: 'receipt_population',
    source_system_id: 'gate:fixture-01',
    source_operator_id: RECEIPT_OPERATOR.issuer_id,
    period,
    mapping_profile_digest: mappingProfileDigest,
    issued_at: INVENTORY_ISSUED_AT,
    expires_at: EXPIRES_AT,
  }, receiptRecords, RECEIPT_OPERATOR);

  const program = {
    program_id: 'program:closed-ledger-reconciliation:v0.1',
    version: 1,
    source_digest: `sha256:${hashCanonical({ profile: PROFILE, harness: 'conformance/composition/closed-ledger-reconciliation-v0.1' })}`,
    program_digest: `sha256:${hashCanonical(mappingProfile)}`,
  };

  const result = runCoverageReconciliation({
    run_id: `run:${runId}`,
    attestation_id: `attestation:${runId}`,
    relying_party_id: RELYING_PARTY.issuer_id,
    program,
    period,
    census_digest: censusDigest,
    system_of_record: { artifact: systemArtifact, records: systemRecords },
    receipt_population: { artifact: receiptArtifact, records: receiptRecords },
    generated_at: observedAt,
    expires_at: EXPIRES_AT,
    timestamp_anchor: null,
  }, {
    trusted_keys: TRUSTED_KEYS,
    now: observedAt,
    system_of_record_pin: {
      source_system_id: adapter.ledger_id,
      mapping_profile_digest: mappingProfileDigest,
      source_operator_id: LEDGER_OPERATOR.issuer_id,
    },
    receipt_population_pin: {
      source_system_id: 'gate:fixture-01',
      mapping_profile_digest: mappingProfileDigest,
      source_operator_id: RECEIPT_OPERATOR.issuer_id,
    },
  }, RELYING_PARTY);

  const binding = verifyCoverageReconciliationReportBinding(result.report, result.attestation);
  const attestation = verifyCoverageReconciliationAttestation(result.attestation, {
    trusted_keys: TRUSTED_KEYS,
    now: observedAt,
    expected_program: program,
    expected_census_digest: censusDigest,
    expected_relying_party_id: RELYING_PARTY.issuer_id,
    expected_coverage_report_hash: result.report_hash,
  });
  if (!binding.accepted || !attestation.accepted) {
    throw new Error(`reconciliation attestation refused: ${binding.reason ?? attestation.reason}`);
  }

  // The runner names its own bins; use exactly the name the imported runner
  // exports at run time (the receipted-without-observation bin is being
  // renamed from receipt_without_effect upstream; follow whichever name the
  // pinned import carries).
  const joins = result.report.joins;
  const unobservedBin = Object.hasOwn(joins, 'receipted_without_observation')
    ? 'receipted_without_observation'
    : 'receipt_without_effect';
  const unobservedFindings = result.report.findings[unobservedBin] ?? [];

  const finalityBoundaryMs = Date.parse(observedAt) - adapter.finality.finality_horizon_seconds * 1000;
  const skewBoundMs = Math.max(
    adapter.clock.skew_bound_seconds,
    RECEIPT_SIDE_CLOCK.skew_bound_seconds,
  ) * 1000;
  const metaByJoin = new Map(receipts.map((meta) => {
    const identity = settlementIdentity(meta.settlement);
    return [`${identity.caid} ${identity.action_digest}`, meta];
  }));
  const readings = unobservedFindings.map((record) => {
    const meta = metaByJoin.get(`${record.caid} ${record.action_digest}`);
    if (!meta) throw new Error(`no harness metadata for unobserved record ${record.record_id}`);
    return classifyUnobservedReceipt(meta, {
      completeness: adapter.completeness,
      finalityBoundaryMs,
      skewBoundMs,
    });
  });

  return {
    run_id: `run:${runId}`,
    census,
    census_digest: censusDigest,
    mapping_profile: mappingProfile,
    mapping_profile_digest: mappingProfileDigest,
    runner: {
      source: 'packages/gate runCoverageReconciliation (imported as-is, not forked)',
      report_version: result.report['@version'],
      report_claim_boundary: COVERAGE_REPORT_CLAIM_BOUNDARY,
      source_claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
      bin_names: Object.keys(joins),
      unobserved_bin_name: unobservedBin,
    },
    joins,
    attestation_verified: { binding: binding.accepted, attestation: attestation.accepted },
    report_hash: result.report_hash,
    unobserved_receipt_readings: readings,
    reconciliation_report: result.report,
  };
}

// --- Scenarios --------------------------------------------------------------

export function runHarness({ adapter = createFixtureLedgerAdapter() } = {}) {
  const clean = runClosedPopulationReconciliation({
    runId: 'clean-window',
    adapter,
    receipts: RECEIPT_FIXTURES.filter((meta) => meta.record_id === 'receipt:R-001-vendor-acme'),
  });
  const mixed = runClosedPopulationReconciliation({
    runId: 'mixed-window',
    adapter,
    receipts: RECEIPT_FIXTURES,
  });

  const readingsById = Object.fromEntries(
    mixed.unobserved_receipt_readings.map((entry) => [entry.record_id, entry.outcome]),
  );
  const cases = [
    {
      id: 'clean-reconciliation',
      title: 'Every receipt in the window matches a finalized settlement; no unobserved bin entries',
      passed: clean.joins.matched === 1
        && clean.joins[clean.runner.unobserved_bin_name] === 0
        && clean.unobserved_receipt_readings.length === 0,
    },
    {
      id: 'absent-after-finality-strong-reading',
      title: 'A receipt naming a settlement genuinely absent from the finalized ledger after the horizon: strong reading asserted',
      passed: readingsById['receipt:R-002-vendor-nomad'] === READINGS.STRONG,
    },
    {
      id: 'in-flight-own-outcome',
      title: 'A receipt whose settlement is still inside the finality horizon is in flight, its own outcome',
      passed: readingsById['receipt:R-003-vendor-brook'] === READINGS.IN_FLIGHT,
    },
    {
      id: 'skew-boundary-indeterminate',
      title: 'A receipt at the finality boundary within the declared clock-skew bound lands indeterminate',
      passed: readingsById['receipt:R-004-vendor-quill'] === READINGS.INDETERMINATE_SKEW,
    },
    {
      id: 'off-ledger-weak-reading',
      title: 'A receipt for an off-ledger effect gets the weak reading only',
      passed: readingsById['receipt:R-005-offledger-wire'] === READINGS.WEAK_OFF_LEDGER,
    },
    {
      id: 'effect-without-receipt-still-surfaced',
      title: 'The opposite direction still surfaces: a finalized settlement with no receipt',
      passed: mixed.joins.effect_without_receipt === 1,
    },
  ];

  const body = {
    '@version': 'CLOSED-LEDGER-RECONCILIATION-REPORT-v0.1',
    profile: PROFILE,
    context: {
      commitment: 'EMILIA committed on the SCITT list to running coverage reconciliation over a self-closed source population on the draft-hawkins testnet at its own cost; this harness is that run, minus the endpoint.',
      pinned_draft: {
        name: PINNED_DRAFT,
        url: `https://www.ietf.org/archive/id/${PINNED_DRAFT}.txt`,
        sha256: PINNED_DRAFT_SHA256,
      },
    },
    claim_boundary: {
      fixture: 'This run is against a deterministic fixture ledger, NOT the draft author\'s testnet. Nothing here characterizes his rail.',
      strong_reading: 'The strong reading (effect did not occur) is conditional on the declared completeness level and finality rule. The fixture defines both, so they hold here by construction; a real rail must prove its own finality rule before the strong reading transfers.',
      adapter: 'The ledger is isolated behind the fetchFinalizedSettlements adapter interface; the real testnet is an adapter swap.',
    },
    source_population_completeness: {
      ladder: COMPLETENESS_LADDER,
      declared: adapter.completeness,
    },
    clocks: {
      ledger: adapter.clock,
      receipt_side: RECEIPT_SIDE_CLOCK,
      note: 'Each side declares its clock source; the harness applies the larger declared skew bound. Boundary cases within the bound land indeterminate.',
    },
    reading_policy: {
      strong: 'asserted ONLY when completeness is protocol_defined AND the receipt\'s settlement would land on this ledger AND the finality horizon has passed at observation time outside the skew bound',
      in_flight: 'a settlement inside the finality horizon is its own outcome and is never collapsed into either reading',
      indeterminate: 'expected settlement time within the skew bound of the finality boundary takes no reading',
      weak: 'off-ledger effects, or any completeness level below protocol_defined, get at most: no observation recorded, effect status unknown',
    },
    runs: {
      clean: {
        run_id: clean.run_id,
        joins: clean.joins,
        bin_names: clean.runner.bin_names,
        unobserved_bin_name: clean.runner.unobserved_bin_name,
        attestation_verified: clean.attestation_verified,
        report_hash: clean.report_hash,
        unobserved_receipt_readings: clean.unobserved_receipt_readings,
      },
      mixed: {
        run_id: mixed.run_id,
        joins: mixed.joins,
        bin_names: mixed.runner.bin_names,
        unobserved_bin_name: mixed.runner.unobserved_bin_name,
        attestation_verified: mixed.attestation_verified,
        report_hash: mixed.report_hash,
        unobserved_receipt_readings: mixed.unobserved_receipt_readings,
      },
    },
    runner: mixed.runner,
    cases: cases.map((entry) => ({ id: entry.id, title: entry.title, passed: entry.passed })),
    passed: cases.every((entry) => entry.passed),
  };
  // packages/gate canonicalize refuses aliased objects; the body reuses
  // shared frozen fixtures (ladder, clocks, bin-name arrays), so digest and
  // return a plain deep copy.
  const plain = JSON.parse(JSON.stringify(body));
  const reportDigest = `sha256:${crypto.createHash('sha256').update(canonicalize(plain), 'utf8').digest('hex')}`;
  return { ...plain, report_digest: reportDigest, runs_full: { clean, mixed } };
}

function parseArgs(argv) {
  const args = { emit: false };
  for (const arg of argv) {
    if (arg === '--emit') args.emit = true;
    else throw new TypeError(`unknown argument: ${arg}`);
  }
  return args;
}

// No committed reference report for this harness, deliberately: the runner's
// bin names are owned by packages/gate and are mid-rename upstream
// (receipt_without_effect -> receipted_without_observation), so a committed
// byte-exact reference would go stale the moment the rebuilt runner lands.
// Determinism is asserted by the test suite (two runs, identical digest), and
// --emit writes a local report.json for inspection or external reproduction.
function main() {
  const args = parseArgs(process.argv.slice(2));
  const { runs_full, ...report } = runHarness();
  if (args.emit) {
    writeFileSync(resolve(HERE, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
