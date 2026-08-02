// SPDX-License-Identifier: Apache-2.0
/**
 * Derive and reconcile two independently signed, privacy-minimized action
 * populations. The runner proves only what the supplied signed populations
 * contain; it never self-proves source-system completeness.
 */
import {
  RISK_CAID,
  RISK_DIGEST,
  riskClone,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskInstant,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';
import {
  COVERAGE_RECONCILIATION_ATTESTATION_VERSION,
  signCoverageReconciliationAttestation,
} from './coverage-reconciliation-attestation.js';

export const COVERAGE_SOURCE_INVENTORY_VERSION = 'EP-COVERAGE-SOURCE-INVENTORY-v1';
export const COVERAGE_POPULATION_VERSION = 'EP-COVERAGE-POPULATION-v1';
export const COVERAGE_RECONCILIATION_REPORT_VERSION = 'EP-COVERAGE-RECONCILIATION-REPORT-v1';
export const COVERAGE_SOURCE_CLAIM_BOUNDARY = 'signed_root_of_supplied_minimized_records_not_source_completeness';
export const COVERAGE_REPORT_CLAIM_BOUNDARY = 'deterministic_join_of_two_verified_supplied_populations_not_source_completeness';

const MAX_RECORDS = 50_000;
const RECORD_KEYS = ['record_id', 'caid', 'action_digest', 'classification'] as const;
const PERIOD_KEYS = ['start', 'end'] as const;
const SOURCE_BODY_KEYS = [
  '@version', 'inventory_id', 'inventory_kind', 'source_system_id',
  'source_operator_id', 'period', 'record_count', 'population_root',
  'mapping_profile_digest', 'issued_at', 'expires_at', 'claim_boundary',
] as const;
const SYSTEM_CLASSIFICATIONS = new Set(['effect', 'excluded', 'exception']);
const RECEIPT_CLASSIFICATIONS = new Set(['receipt', 'indeterminate']);
const INVENTORY_KINDS = new Set(['system_of_record', 'receipt_population']);

export type CoverageInventoryKind = 'system_of_record' | 'receipt_population';
export type CoverageRecordClassification = 'effect' | 'excluded' | 'exception' | 'receipt' | 'indeterminate';

export interface CoveragePopulationRecord {
  record_id: string;
  caid: string;
  action_digest: string;
  classification: CoverageRecordClassification;
}

export interface CoverageSourceInventoryInput {
  inventory_id: string;
  inventory_kind: CoverageInventoryKind;
  source_system_id: string;
  source_operator_id: string;
  period: { start: string; end: string };
  mapping_profile_digest: string;
  issued_at: string;
  expires_at: string;
}

export interface CoverageSourcePin {
  source_system_id: string;
  mapping_profile_digest: string;
  source_operator_id?: string;
}

export interface CoverageRunnerOptions {
  trusted_keys: TrustedRiskKeys;
  now: string | number;
  system_of_record_pin: CoverageSourcePin;
  receipt_population_pin: CoverageSourcePin;
  require_independent_source_issuers?: boolean;
}

function textOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function period(value: unknown): value is { start: string; end: string } {
  if (!riskExact(value, PERIOD_KEYS)) return false;
  const start = riskInstant(value.start);
  const end = riskInstant(value.end);
  return Number.isFinite(start) && Number.isFinite(end) && end > start;
}

function samePeriod(left: RiskRecord, right: RiskRecord): boolean {
  return left.start === right.start && left.end === right.end;
}

function allowedClassification(kind: CoverageInventoryKind, classification: unknown): classification is CoverageRecordClassification {
  return typeof classification === 'string'
    && (kind === 'system_of_record'
      ? SYSTEM_CLASSIFICATIONS.has(classification)
      : RECEIPT_CLASSIFICATIONS.has(classification));
}

function joinKey(record: CoveragePopulationRecord): string {
  return `${record.caid}\0${record.action_digest}`;
}

function normalizeRecords(
  kind: CoverageInventoryKind,
  records: readonly CoveragePopulationRecord[],
): CoveragePopulationRecord[] {
  if (!Array.isArray(records) || records.length > MAX_RECORDS) {
    throw new TypeError('coverage population exceeds the record limit');
  }
  const normalized = records.map((record) => {
    if (!riskExact(record, RECORD_KEYS)
        || !riskIdentifier(record.record_id)
        || !RISK_CAID.test(record.caid)
        || !RISK_DIGEST.test(record.action_digest)
        || !allowedClassification(kind, record.classification)) {
      throw new TypeError('coverage population record is invalid');
    }
    return riskClone(record) as CoveragePopulationRecord;
  }).sort((left, right) => textOrder(left.record_id, right.record_id));

  const recordIds = new Set<string>();
  const joins = new Set<string>();
  const caidToDigest = new Map<string, string>();
  const digestToCaid = new Map<string, string>();
  for (const record of normalized) {
    if (recordIds.has(record.record_id)) throw new TypeError('coverage population contains a duplicate record id');
    recordIds.add(record.record_id);
    const key = joinKey(record);
    if (joins.has(key)) throw new TypeError('coverage population contains a duplicate action join');
    joins.add(key);
    const digest = caidToDigest.get(record.caid);
    if (digest !== undefined && digest !== record.action_digest) {
      throw new TypeError('one CAID maps to a different action digest');
    }
    caidToDigest.set(record.caid, record.action_digest);
    const caid = digestToCaid.get(record.action_digest);
    if (caid !== undefined && caid !== record.caid) {
      throw new TypeError('one action digest maps to a different CAID');
    }
    digestToCaid.set(record.action_digest, record.caid);
  }
  return normalized;
}

export function coveragePopulationRoot(
  kind: CoverageInventoryKind,
  records: readonly CoveragePopulationRecord[],
): string {
  if (!INVENTORY_KINDS.has(kind)) throw new TypeError('coverage population kind is invalid');
  return riskDigest({
    '@version': COVERAGE_POPULATION_VERSION,
    inventory_kind: kind,
    records: normalizeRecords(kind, records),
  });
}

/**
 * Verify only the digest binding between a report and an attestation envelope.
 * Callers MUST separately verify the attestation signature and relying-party
 * context with `verifyCoverageReconciliationAttestation`.
 */
export function verifyCoverageReconciliationReportBinding(
  report: unknown,
  attestation: unknown,
) {
  if (!riskRecord(report)
      || report['@version'] !== COVERAGE_RECONCILIATION_REPORT_VERSION) {
    return { accepted: false, reason: 'coverage_report_invalid', report_hash: null };
  }
  if (!riskRecord(attestation)
      || attestation['@version'] !== COVERAGE_RECONCILIATION_ATTESTATION_VERSION
      || !RISK_DIGEST.test(attestation.coverage_report_hash)) {
    return { accepted: false, reason: 'coverage_attestation_invalid', report_hash: null };
  }
  let reportHash: string;
  try {
    reportHash = riskDigest(report);
  } catch {
    return { accepted: false, reason: 'coverage_report_invalid', report_hash: null };
  }
  if (reportHash !== attestation.coverage_report_hash) {
    return { accepted: false, reason: 'coverage_report_hash_mismatch', report_hash: reportHash };
  }
  return { accepted: true, reason: null, report_hash: reportHash };
}

function validateSourceBody(value: unknown): asserts value is RiskRecord {
  if (!riskExact(value, SOURCE_BODY_KEYS)
      || value['@version'] !== COVERAGE_SOURCE_INVENTORY_VERSION
      || !riskIdentifier(value.inventory_id)
      || !INVENTORY_KINDS.has(value.inventory_kind)
      || !riskIdentifier(value.source_system_id)
      || !riskIdentifier(value.source_operator_id)
      || !period(value.period)
      || !Number.isSafeInteger(value.record_count)
      || value.record_count < 0
      || value.record_count > MAX_RECORDS
      || !RISK_DIGEST.test(value.population_root)
      || !RISK_DIGEST.test(value.mapping_profile_digest)
      || value.claim_boundary !== COVERAGE_SOURCE_CLAIM_BOUNDARY) {
    throw new TypeError('coverage source inventory shape is invalid');
  }
  const issued = riskInstant(value.issued_at);
  const expires = riskInstant(value.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)
      || issued < riskInstant(value.period.end) || expires <= issued) {
    throw new TypeError('coverage source inventory validity window is invalid');
  }
}

export function signCoverageSourceInventory(
  input: CoverageSourceInventoryInput,
  records: readonly CoveragePopulationRecord[],
  signer: { issuer_id: string; key_id: string; private_key: any },
): RiskRecord {
  const normalized = normalizeRecords(input.inventory_kind, records);
  const body: RiskRecord = {
    '@version': COVERAGE_SOURCE_INVENTORY_VERSION,
    ...riskClone(input),
    record_count: normalized.length,
    population_root: coveragePopulationRoot(input.inventory_kind, normalized),
    claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
  };
  validateSourceBody(body);
  if (signer.issuer_id !== body.source_operator_id) {
    throw new TypeError('coverage source inventory issuer must be the source operator');
  }
  return signRiskBody(COVERAGE_SOURCE_INVENTORY_VERSION, body, signer);
}

export function verifyCoverageSourceInventory(
  artifact: unknown,
  records: readonly CoveragePopulationRecord[],
  options: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_inventory_kind?: CoverageInventoryKind;
    expected_source_system_id?: string;
    expected_mapping_profile_digest?: string;
    expected_source_operator_id?: string;
  } = {},
) {
  const refuse = (reason: string, verified = false, inventoryDigest: string | null = null) => ({
    accepted: false,
    verified,
    reason,
    inventory_digest: inventoryDigest,
    claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
  });
  const signed = verifyRiskBody(artifact, COVERAGE_SOURCE_INVENTORY_VERSION, options.trusted_keys);
  if (!signed.valid || !signed.body) return refuse(signed.reason ?? 'inventory_invalid');
  const { issuer, ...payload } = signed.body;
  if (issuer.id !== payload.source_operator_id) {
    return refuse('source_operator_issuer_mismatch', true, signed.artifact_digest);
  }
  try {
    validateSourceBody(payload);
  } catch {
    return refuse('inventory_schema_invalid', true, signed.artifact_digest);
  }
  if (options.expected_inventory_kind === undefined
      || options.expected_source_system_id === undefined
      || options.expected_mapping_profile_digest === undefined) {
    return refuse('context_binding_required', true, signed.artifact_digest);
  }
  if (payload.inventory_kind !== options.expected_inventory_kind) {
    return refuse('inventory_kind_mismatch', true, signed.artifact_digest);
  }
  if (payload.source_system_id !== options.expected_source_system_id) {
    return refuse('source_system_mismatch', true, signed.artifact_digest);
  }
  if (payload.mapping_profile_digest !== options.expected_mapping_profile_digest) {
    return refuse('mapping_profile_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_source_operator_id !== undefined
      && payload.source_operator_id !== options.expected_source_operator_id) {
    return refuse('source_operator_mismatch', true, signed.artifact_digest);
  }
  const now = options.now === undefined
    ? Date.now()
    : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
  if (!Number.isFinite(now)) return refuse('verification_time_invalid', true, signed.artifact_digest);
  if (now < riskInstant(payload.issued_at)) return refuse('inventory_not_yet_issued', true, signed.artifact_digest);
  if (now >= riskInstant(payload.expires_at)) return refuse('inventory_expired', true, signed.artifact_digest);
  let root: string;
  try {
    root = coveragePopulationRoot(payload.inventory_kind, records);
  } catch {
    return refuse('population_invalid', true, signed.artifact_digest);
  }
  if (records.length !== payload.record_count) {
    return refuse('population_count_mismatch', true, signed.artifact_digest);
  }
  if (root !== payload.population_root) {
    return refuse('population_root_mismatch', true, signed.artifact_digest);
  }
  return {
    accepted: true,
    verified: true,
    reason: null,
    inventory_digest: signed.artifact_digest,
    body: riskFreeze(riskClone(payload)),
    claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
  };
}

function assertCrossPopulationIdentity(
  systemRecords: CoveragePopulationRecord[],
  receiptRecords: CoveragePopulationRecord[],
): void {
  const caids = new Map<string, string>();
  const digests = new Map<string, string>();
  for (const record of [...systemRecords, ...receiptRecords]) {
    const existingDigest = caids.get(record.caid);
    if (existingDigest !== undefined && existingDigest !== record.action_digest) {
      throw new TypeError('one CAID maps to a different action digest across populations');
    }
    caids.set(record.caid, record.action_digest);
    const existingCaid = digests.get(record.action_digest);
    if (existingCaid !== undefined && existingCaid !== record.caid) {
      throw new TypeError('one action digest maps to a different CAID across populations');
    }
    digests.set(record.action_digest, record.caid);
  }
}

function requiredPin(pin: unknown): asserts pin is CoverageSourcePin {
  if (!riskRecord(pin)
      || !riskIdentifier(pin.source_system_id)
      || !RISK_DIGEST.test(pin.mapping_profile_digest)
      || (pin.source_operator_id !== undefined && !riskIdentifier(pin.source_operator_id))) {
    throw new TypeError('coverage source pin is invalid');
  }
}

export function runCoverageReconciliation(
  input: {
    run_id: string;
    attestation_id: string;
    relying_party_id: string;
    program: RiskRecord;
    period: { start: string; end: string };
    census_digest: string;
    system_of_record: { artifact: unknown; records: CoveragePopulationRecord[] };
    receipt_population: { artifact: unknown; records: CoveragePopulationRecord[] };
    generated_at: string;
    expires_at: string;
    timestamp_anchor: RiskRecord | null;
  },
  options: CoverageRunnerOptions,
  signer: { issuer_id: string; key_id: string; private_key: any },
) {
  if (!riskRecord(input)
      || !riskIdentifier(input.run_id)
      || !riskIdentifier(input.attestation_id)
      || !riskIdentifier(input.relying_party_id)
      || !period(input.period)
      || !RISK_DIGEST.test(input.census_digest)
      || !riskRecord(input.system_of_record)
      || !riskRecord(input.receipt_population)) {
    throw new TypeError('coverage reconciliation input is invalid');
  }
  requiredPin(options.system_of_record_pin);
  requiredPin(options.receipt_population_pin);
  const systemVerification = verifyCoverageSourceInventory(
    input.system_of_record.artifact,
    input.system_of_record.records,
    {
      trusted_keys: options.trusted_keys,
      now: options.now,
      expected_inventory_kind: 'system_of_record',
      expected_source_system_id: options.system_of_record_pin.source_system_id,
      expected_mapping_profile_digest: options.system_of_record_pin.mapping_profile_digest,
      expected_source_operator_id: options.system_of_record_pin.source_operator_id,
    },
  );
  if (!systemVerification.accepted || !('body' in systemVerification)) {
    throw new TypeError(`system-of-record inventory refused: ${systemVerification.reason}`);
  }
  const receiptVerification = verifyCoverageSourceInventory(
    input.receipt_population.artifact,
    input.receipt_population.records,
    {
      trusted_keys: options.trusted_keys,
      now: options.now,
      expected_inventory_kind: 'receipt_population',
      expected_source_system_id: options.receipt_population_pin.source_system_id,
      expected_mapping_profile_digest: options.receipt_population_pin.mapping_profile_digest,
      expected_source_operator_id: options.receipt_population_pin.source_operator_id,
    },
  );
  if (!receiptVerification.accepted || !('body' in receiptVerification)) {
    throw new TypeError(`receipt inventory refused: ${receiptVerification.reason}`);
  }
  const systemBody = systemVerification.body as RiskRecord;
  const receiptBody = receiptVerification.body as RiskRecord;
  if (!samePeriod(systemBody.period, input.period)
      || !samePeriod(receiptBody.period, input.period)) {
    throw new TypeError('coverage source inventory period mismatch');
  }
  if (options.require_independent_source_issuers !== false
      && systemBody.source_operator_id === receiptBody.source_operator_id) {
    throw new TypeError('coverage reconciliation requires independent source issuers');
  }

  const systemRecords = normalizeRecords('system_of_record', input.system_of_record.records);
  const receiptRecords = normalizeRecords('receipt_population', input.receipt_population.records);
  assertCrossPopulationIdentity(systemRecords, receiptRecords);

  const availableReceipts = new Map(
    receiptRecords
      .filter((record) => record.classification === 'receipt')
      .map((record) => [joinKey(record), record]),
  );
  const matched: RiskRecord[] = [];
  const effectWithoutReceipt: CoveragePopulationRecord[] = [];
  const excluded: CoveragePopulationRecord[] = [];
  const exception: CoveragePopulationRecord[] = [];
  for (const record of systemRecords) {
    if (record.classification === 'excluded') {
      excluded.push(record);
      continue;
    }
    if (record.classification === 'exception') {
      exception.push(record);
      continue;
    }
    const receipt = availableReceipts.get(joinKey(record));
    if (!receipt) {
      effectWithoutReceipt.push(record);
      continue;
    }
    availableReceipts.delete(joinKey(record));
    matched.push({
      caid: record.caid,
      action_digest: record.action_digest,
      system_record_id: record.record_id,
      receipt_record_id: receipt.record_id,
    });
  }
  const receiptWithoutEffect = [...availableReceipts.values()]
    .sort((left, right) => textOrder(left.record_id, right.record_id));
  const indeterminate = receiptRecords
    .filter((record) => record.classification === 'indeterminate');
  const joins = {
    matched: matched.length,
    effect_without_receipt: effectWithoutReceipt.length,
    receipt_without_effect: receiptWithoutEffect.length,
    indeterminate: indeterminate.length,
    excluded: excluded.length,
    exception: exception.length,
  };

  const generated = riskInstant(input.generated_at);
  const expires = riskInstant(input.expires_at);
  if (!Number.isFinite(generated) || !Number.isFinite(expires)
      || generated < riskInstant(input.period.end) || expires <= generated) {
    throw new TypeError('coverage reconciliation report validity window is invalid');
  }
  const report = riskFreeze({
    '@version': COVERAGE_RECONCILIATION_REPORT_VERSION,
    run_id: input.run_id,
    relying_party_id: input.relying_party_id,
    program: riskClone(input.program),
    period: riskClone(input.period),
    system_of_record: {
      inventory_id: systemBody.inventory_id,
      source_system_id: systemBody.source_system_id,
      source_operator_id: systemBody.source_operator_id,
      inventory_digest: systemVerification.inventory_digest,
      population_root: systemBody.population_root,
      count: systemBody.record_count,
    },
    receipt_population: {
      inventory_id: receiptBody.inventory_id,
      source_system_id: receiptBody.source_system_id,
      source_operator_id: receiptBody.source_operator_id,
      inventory_digest: receiptVerification.inventory_digest,
      population_root: receiptBody.population_root,
      count: receiptBody.record_count,
    },
    joins,
    findings: {
      matched,
      effect_without_receipt: effectWithoutReceipt,
      receipt_without_effect: receiptWithoutEffect,
      indeterminate,
      excluded,
      exception,
    },
    generated_at: input.generated_at,
    claim_boundary: COVERAGE_REPORT_CLAIM_BOUNDARY,
  });
  const reportHash = riskDigest(report);
  const attestation = signCoverageReconciliationAttestation({
    attestation_id: input.attestation_id,
    relying_party_id: input.relying_party_id,
    program: riskClone(input.program),
    period: riskClone(input.period),
    coverage_report_hash: reportHash,
    census_digest: input.census_digest,
    system_of_record: {
      inventory_id: systemBody.inventory_id,
      population_root: systemBody.population_root,
      count: systemBody.record_count,
    },
    receipt_population: {
      inventory_id: receiptBody.inventory_id,
      population_root: receiptBody.population_root,
      count: receiptBody.record_count,
    },
    joins,
    issued_at: input.generated_at,
    expires_at: input.expires_at,
    timestamp_anchor: riskClone(input.timestamp_anchor),
    claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
  }, signer);
  return riskFreeze({ report, report_hash: reportHash, attestation });
}
