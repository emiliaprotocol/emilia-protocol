// SPDX-License-Identifier: Apache-2.0
/**
 * Signed, privacy-bounded external loss-experience observations.
 *
 * The feed records what its issuer reports. It deliberately does not establish
 * causation, insurance coverage, legal liability, adjudicated loss, solvency,
 * payment, or authorization.
 */
import {
  RISK_DIGEST,
  riskExact,
  riskIdentifier,
  riskInstant,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const LOSS_EXPERIENCE_FEED_VERSION = 'EP-LOSS-EXPERIENCE-FEED-v1';
export const LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY =
  'externally_reported_observation_not_verified_causation_not_insurance_coverage_not_legal_liability_not_adjudicated_loss_not_solvency_not_payment';

const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'] as const;
const PERIOD_KEYS = ['start', 'end'] as const;
const RECORD_KEYS = [
  'record_id',
  'receipt_digest',
  'action_class',
  'classification',
  'reported_amount_minor',
  'currency',
  'occurred_at',
  'reported_at',
  'source_record_digest',
  'event_type',
  'supersedes_record_digest',
] as const;
const ANCHOR_KEYS = ['method', 'evidence_digest'] as const;
const BODY_KEYS = [
  '@version',
  'feed_id',
  'reporting_party_id',
  'relying_party_id',
  'program',
  'period',
  'census_digest',
  'source_inventory_digest',
  'records',
  'issued_at',
  'expires_at',
  'timestamp_anchor',
  'claim_boundary',
] as const;

const CLASSIFICATIONS = new Set([
  'NO_REPORTED_LOSS',
  'LOSS_REPORTED',
  'NEAR_MISS',
  'DISPUTED',
  'UNKNOWN',
]);
const EVENT_TYPES = new Set(['OBSERVED', 'CORRECTED', 'WITHDRAWN']);

function money(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,39})$/.test(value);
}

function validateRecord(value: unknown, periodStart: number, periodEnd: number, issuedAt: number): asserts value is RiskRecord {
  if (!riskExact(value, RECORD_KEYS)
      || !riskIdentifier(value.record_id)
      || typeof value.receipt_digest !== 'string'
      || !RISK_DIGEST.test(value.receipt_digest)
      || !riskIdentifier(value.action_class)
      || typeof value.classification !== 'string'
      || !CLASSIFICATIONS.has(value.classification)
      || !money(value.reported_amount_minor)
      || typeof value.currency !== 'string'
      || !/^[A-Z]{3}$/.test(value.currency)
      || typeof value.source_record_digest !== 'string'
      || !RISK_DIGEST.test(value.source_record_digest)
      || typeof value.event_type !== 'string'
      || !EVENT_TYPES.has(value.event_type)) {
    throw new TypeError('loss experience record shape or field is invalid');
  }

  const occurredAt = riskInstant(value.occurred_at);
  const reportedAt = riskInstant(value.reported_at);
  if (!Number.isFinite(occurredAt) || occurredAt < periodStart || occurredAt >= periodEnd
      || !Number.isFinite(reportedAt) || reportedAt < occurredAt || reportedAt > issuedAt) {
    throw new TypeError('loss experience occurred/reported time is invalid for the issued period');
  }

  if (value.event_type === 'OBSERVED') {
    if (value.supersedes_record_digest !== null) {
      throw new TypeError('an observed loss record cannot supersede another record');
    }
  } else if (typeof value.supersedes_record_digest !== 'string'
      || !RISK_DIGEST.test(value.supersedes_record_digest)) {
    throw new TypeError('a corrected or withdrawn record requires a supersedes record digest');
  }
}

function validateBody(value: unknown): asserts value is RiskRecord {
  if (!riskExact(value, BODY_KEYS)
      || value['@version'] !== LOSS_EXPERIENCE_FEED_VERSION
      || !riskIdentifier(value.feed_id)
      || !riskIdentifier(value.reporting_party_id)
      || !riskIdentifier(value.relying_party_id)
      || !riskExact(value.program, PROGRAM_KEYS)
      || !riskIdentifier(value.program.program_id)
      || !Number.isSafeInteger(value.program.version)
      || value.program.version < 1
      || typeof value.program.source_digest !== 'string'
      || !RISK_DIGEST.test(value.program.source_digest)
      || typeof value.program.program_digest !== 'string'
      || !RISK_DIGEST.test(value.program.program_digest)
      || !riskExact(value.period, PERIOD_KEYS)
      || typeof value.census_digest !== 'string'
      || !RISK_DIGEST.test(value.census_digest)
      || typeof value.source_inventory_digest !== 'string'
      || !RISK_DIGEST.test(value.source_inventory_digest)
      || !Array.isArray(value.records)
      || value.records.length > 10_000
      || value.claim_boundary !== LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY) {
    throw new TypeError('loss experience feed shape or field is invalid');
  }

  const periodStart = riskInstant(value.period.start);
  const periodEnd = riskInstant(value.period.end);
  const issuedAt = riskInstant(value.issued_at);
  const expiresAt = riskInstant(value.expires_at);
  if (!Number.isFinite(periodStart) || !Number.isFinite(periodEnd) || periodEnd <= periodStart
      || !Number.isFinite(issuedAt) || issuedAt < periodEnd
      || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    throw new TypeError('loss experience feed period or validity is invalid');
  }

  for (const record of value.records) validateRecord(record, periodStart, periodEnd, issuedAt);
  const recordIds = value.records.map((record: RiskRecord) => record.record_id);
  if (new Set(recordIds).size !== recordIds.length) {
    throw new TypeError('loss experience feed contains duplicate record identifiers');
  }

  if (value.timestamp_anchor !== null
      && (!riskExact(value.timestamp_anchor, ANCHOR_KEYS)
        || !riskIdentifier(value.timestamp_anchor.method)
        || typeof value.timestamp_anchor.evidence_digest !== 'string'
        || !RISK_DIGEST.test(value.timestamp_anchor.evidence_digest))) {
    throw new TypeError('loss experience timestamp anchor is invalid');
  }
}

export interface VerifyLossExperienceFeedOptions {
  trusted_keys?: TrustedRiskKeys;
  now?: string | number;
  expected_program_digest?: string;
  expected_census_digest?: string;
  expected_relying_party_id?: string;
}

export function signLossExperienceFeed(
  input: RiskRecord,
  signer: { issuer_id: string; key_id: string; private_key: any },
) {
  const body: RiskRecord = { '@version': LOSS_EXPERIENCE_FEED_VERSION, ...input };
  validateBody(body);
  if (signer.issuer_id !== body.reporting_party_id) {
    throw new TypeError('loss experience feed issuer must be the reporting party');
  }
  return signRiskBody(LOSS_EXPERIENCE_FEED_VERSION, body, signer);
}

export function verifyLossExperienceFeed(
  feed: unknown,
  options: VerifyLossExperienceFeedOptions = {},
) {
  const refuse = (reason: string, verified = false, feedDigest: string | null = null) => ({
    accepted: false,
    verified,
    reason,
    feed_digest: feedDigest,
    claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  });
  const signed = verifyRiskBody(feed, LOSS_EXPERIENCE_FEED_VERSION, options.trusted_keys);
  if (!signed.valid || !signed.body) return refuse(signed.reason ?? 'feed_invalid');

  const { issuer, ...payload } = signed.body;
  if (issuer.id !== payload.reporting_party_id) {
    return refuse('reporting_party_issuer_mismatch', true, signed.artifact_digest);
  }
  try {
    validateBody(payload);
  } catch {
    return refuse('feed_schema_or_period_invalid', true, signed.artifact_digest);
  }

  const now = options.now === undefined
    ? Date.now()
    : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
  if (!Number.isFinite(now)) return refuse('verification_time_invalid', true, signed.artifact_digest);
  if (now >= riskInstant(payload.expires_at)) return refuse('feed_expired', true, signed.artifact_digest);
  if (options.expected_program_digest !== undefined
      && options.expected_program_digest !== payload.program.program_digest) {
    return refuse('program_digest_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_census_digest !== undefined
      && options.expected_census_digest !== payload.census_digest) {
    return refuse('census_digest_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_relying_party_id !== undefined
      && options.expected_relying_party_id !== payload.relying_party_id) {
    return refuse('relying_party_mismatch', true, signed.artifact_digest);
  }

  return {
    accepted: true,
    verified: true,
    reason: null,
    feed_digest: signed.artifact_digest,
    claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  };
}
