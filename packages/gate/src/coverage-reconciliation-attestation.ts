// SPDX-License-Identifier: Apache-2.0
/** Signed period reconciliation of supplied populations; never proof that the supplied population is complete. */
import {
  RISK_DIGEST, riskExact, riskIdentifier, riskInstant,
  riskRecord, signRiskBody, verifyRiskBody, type RiskRecord, type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const COVERAGE_RECONCILIATION_ATTESTATION_VERSION = 'EP-COVERAGE-RECONCILIATION-ATTESTATION-v2';
export const COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION = 'EP-COVERAGE-RECONCILIATION-ATTESTATION-v1';
export const COVERAGE_RECONCILIATION_CLAIM_BOUNDARY = 'signed_reconciliation_of_supplied_populations_not_population_completeness';
const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'] as const;
const PERIOD_KEYS = ['start', 'end'] as const;
const POPULATION_KEYS = ['inventory_id', 'population_root', 'count'] as const;
const JOIN_KEYS = ['matched', 'observed_without_receipt', 'receipted_without_observation', 'indeterminate', 'excluded', 'exception'] as const;
const V1_JOIN_KEYS = ['matched', 'effect_without_receipt', 'receipt_without_effect', 'indeterminate', 'excluded', 'exception'] as const;
const ANCHOR_KEYS = ['method', 'evidence_digest'] as const;
const BODY_KEYS = ['@version', 'attestation_id', 'relying_party_id', 'program', 'period', 'coverage_report_hash', 'census_digest', 'system_of_record', 'receipt_population', 'joins', 'issued_at', 'expires_at', 'timestamp_anchor', 'claim_boundary'] as const;

function count(value: unknown): value is number { return Number.isSafeInteger(value) && Number(value) >= 0; }
function sameProgram(actual: RiskRecord, expected: RiskRecord): boolean {
  return actual.program_id === expected.program_id && actual.version === expected.version
    && actual.source_digest === expected.source_digest && actual.program_digest === expected.program_digest;
}
function validExpectedProgram(value: unknown): value is RiskRecord {
  return riskExact(value, PROGRAM_KEYS) && riskIdentifier(value.program_id)
    && Number.isSafeInteger(value.version) && value.version >= 1
    && RISK_DIGEST.test(value.source_digest) && RISK_DIGEST.test(value.program_digest);
}
function validate(
  value: unknown,
  version: typeof COVERAGE_RECONCILIATION_ATTESTATION_VERSION
    | typeof COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION,
): asserts value is RiskRecord {
  const joinKeys = version === COVERAGE_RECONCILIATION_ATTESTATION_VERSION
    ? JOIN_KEYS
    : V1_JOIN_KEYS;
  if (!riskExact(value, BODY_KEYS) || value['@version'] !== version
      || !riskIdentifier(value.attestation_id) || !riskIdentifier(value.relying_party_id)
      || !riskExact(value.program, PROGRAM_KEYS) || !riskIdentifier(value.program.program_id)
      || !Number.isSafeInteger(value.program.version) || value.program.version < 1
      || !RISK_DIGEST.test(value.program.source_digest) || !RISK_DIGEST.test(value.program.program_digest)
      || !riskExact(value.period, PERIOD_KEYS) || !RISK_DIGEST.test(value.coverage_report_hash)
      || !RISK_DIGEST.test(value.census_digest)
      || !riskExact(value.system_of_record, POPULATION_KEYS) || !riskExact(value.receipt_population, POPULATION_KEYS)
      || !riskExact(value.joins, joinKeys) || value.claim_boundary !== COVERAGE_RECONCILIATION_CLAIM_BOUNDARY) {
    throw new TypeError('coverage reconciliation attestation shape is invalid');
  }
  const start = riskInstant(value.period.start); const end = riskInstant(value.period.end);
  const issued = riskInstant(value.issued_at); const expires = riskInstant(value.expires_at);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || !Number.isFinite(issued)
      || !Number.isFinite(expires) || expires <= issued || issued < end) throw new TypeError('coverage reconciliation period is invalid');
  for (const population of [value.system_of_record, value.receipt_population]) {
    if (!riskIdentifier(population.inventory_id) || !RISK_DIGEST.test(population.population_root) || !count(population.count)) {
      throw new TypeError('coverage reconciliation population is invalid');
    }
  }
  if (!joinKeys.every((key) => count(value.joins[key]))) throw new TypeError('coverage reconciliation counts are invalid');
  const systemUnmatched = version === COVERAGE_RECONCILIATION_ATTESTATION_VERSION
    ? value.joins.observed_without_receipt
    : value.joins.effect_without_receipt;
  const receiptUnmatched = version === COVERAGE_RECONCILIATION_ATTESTATION_VERSION
    ? value.joins.receipted_without_observation
    : value.joins.receipt_without_effect;
  if (value.system_of_record.count !== value.joins.matched + systemUnmatched + value.joins.excluded + value.joins.exception
      || value.receipt_population.count !== value.joins.matched + receiptUnmatched + value.joins.indeterminate) {
    throw new TypeError('coverage reconciliation population conservation failed');
  }
  if (value.timestamp_anchor !== null && (!riskExact(value.timestamp_anchor, ANCHOR_KEYS)
      || !riskIdentifier(value.timestamp_anchor.method) || !RISK_DIGEST.test(value.timestamp_anchor.evidence_digest))) {
    throw new TypeError('coverage timestamp anchor is invalid');
  }
}

export function signCoverageReconciliationAttestation(input: RiskRecord, signer: { issuer_id: string; key_id: string; private_key: any }) {
  const body: RiskRecord = { '@version': COVERAGE_RECONCILIATION_ATTESTATION_VERSION, ...input };
  validate(body, COVERAGE_RECONCILIATION_ATTESTATION_VERSION);
  if (signer.issuer_id !== body.relying_party_id) throw new TypeError('coverage attestation issuer must be relying party');
  return signRiskBody(COVERAGE_RECONCILIATION_ATTESTATION_VERSION, body, signer);
}

export function verifyCoverageReconciliationAttestation(attestation: unknown, options: {
  trusted_keys?: TrustedRiskKeys; now?: string | number; expected_program?: RiskRecord;
  expected_census_digest?: string; expected_relying_party_id?: string;
  expected_coverage_report_hash?: string;
} = {}) {
  const refuse = (reason: string, verified = false, attestationDigest: string | null = null) => ({
    accepted: false,
    verified,
    reason,
    attestation_digest: attestationDigest,
    claim_boundary: COVERAGE_RECONCILIATION_CLAIM_BOUNDARY,
  });
  const version = riskRecord(attestation)
    && attestation['@version'] === COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION
    ? COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION
    : COVERAGE_RECONCILIATION_ATTESTATION_VERSION;
  const signed = verifyRiskBody(attestation, version, options.trusted_keys);
  if (!signed.valid || !signed.body) return refuse(signed.reason ?? 'attestation_invalid');
  const { issuer, ...payload } = signed.body;
  if (issuer.id !== payload.relying_party_id) {
    return refuse('relying_party_issuer_mismatch', true, signed.artifact_digest);
  }
  try { validate(payload, version); } catch {
    return refuse('population_conservation_or_schema_invalid', true, signed.artifact_digest);
  }
  const now = options.now === undefined ? Date.now() : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
  if (!Number.isFinite(now)) return refuse('verification_time_invalid', true, signed.artifact_digest);
  if (now < riskInstant(payload.issued_at)) return refuse('attestation_not_yet_issued', true, signed.artifact_digest);
  if (now >= riskInstant(payload.expires_at)) return refuse('attestation_expired', true, signed.artifact_digest);
  if (options.expected_program === undefined || options.expected_census_digest === undefined
      || options.expected_relying_party_id === undefined) {
    return refuse('context_binding_required', true, signed.artifact_digest);
  }
  if (!validExpectedProgram(options.expected_program)) {
    return refuse('expected_program_invalid', true, signed.artifact_digest);
  }
  if (!sameProgram(payload.program, options.expected_program)) {
    return refuse('program_binding_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_census_digest !== payload.census_digest) {
    return refuse('census_digest_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_relying_party_id !== payload.relying_party_id) {
    return refuse('relying_party_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_coverage_report_hash !== undefined
      && options.expected_coverage_report_hash !== payload.coverage_report_hash) {
    return refuse('coverage_report_hash_mismatch', true, signed.artifact_digest);
  }
  return { accepted: true, verified: true, reason: null, attestation_digest: signed.artifact_digest, claim_boundary: COVERAGE_RECONCILIATION_CLAIM_BOUNDARY };
}
