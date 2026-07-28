// SPDX-License-Identifier: Apache-2.0
/**
 * Signed external loss-experience observations with governed action classes.
 *
 * The feed records what its issuer reports. It deliberately does not establish
 * causation, insurance coverage, legal liability, adjudicated loss, solvency,
 * payment, or authorization.
 */
import {
  RISK_DIGEST,
  riskDigest,
  riskExact,
  riskIdentifier,
  riskInstant,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const LOSS_EXPERIENCE_FEED_VERSION = 'EP-LOSS-EXPERIENCE-FEED-v1';
export const LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY =
  'externally_reported_observation_not_verified_causation_not_insurance_coverage_not_legal_liability_not_adjudicated_loss_not_solvency_not_payment_not_authorization';

const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'] as const;
const PERIOD_KEYS = ['start', 'end'] as const;
const RECORD_KEYS = [
  'record_id',
  'lineage_digest',
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
  'taxonomy_digest',
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
      || typeof value.lineage_digest !== 'string'
      || !RISK_DIGEST.test(value.lineage_digest)
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
      || typeof value.taxonomy_digest !== 'string'
      || !RISK_DIGEST.test(value.taxonomy_digest)
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
  const superseded = value.records
    .filter((record: RiskRecord) => record.supersedes_record_digest !== null)
    .map((record: RiskRecord) => record.supersedes_record_digest);
  if (new Set(superseded).size !== superseded.length) {
    throw new TypeError('loss experience feed forks one predecessor into multiple current records');
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
  expected_program?: RiskRecord;
  expected_census_digest?: string;
  expected_taxonomy_digest?: string;
  expected_relying_party_id?: string;
  expected_action_classes?: readonly string[];
  commit_lineage_batch?: (
    request: Readonly<LossExperienceLineageCommitRequest>,
  ) => LossExperienceLineageCommitResult;
}

export interface LossExperiencePredecessorResolution {
  current_head: boolean;
  reporting_party_id: string;
  relying_party_id: string;
  program_digest: string;
  record: RiskRecord;
}

export interface LossExperienceLineageTransition {
  lineage_digest: string;
  event_type: 'OBSERVED' | 'CORRECTED' | 'WITHDRAWN';
  predecessor_digest: string | null;
  successor_digest: string;
  reporting_party_id: string;
  relying_party_id: string;
  program_digest: string;
  receipt_digest: string;
  action_class: string;
  currency: string;
  reported_at: string;
  record: Readonly<RiskRecord>;
}

export interface LossExperienceLineageCommitRequest {
  feed_digest: string;
  transitions: readonly LossExperienceLineageTransition[];
  /**
   * The lineage store MUST invoke this callback inside the same transaction
   * after locking/loading the current heads and before making successors
   * visible. A refusal MUST leave every lineage unchanged.
   */
  validate_predecessors: (
    predecessors: Readonly<Record<string, LossExperiencePredecessorResolution>>,
  ) => LossExperienceLineageValidationResult;
}

export type LossExperienceLineageValidationResult =
  | { accepted: true }
  | { accepted: false; reason: string };

export type LossExperienceLineageCommitResult =
  | { accepted: true }
  | { accepted: false; reason: string };

function validExpectedProgram(value: unknown): value is RiskRecord {
  return riskExact(value, PROGRAM_KEYS) && riskIdentifier(value.program_id)
    && Number.isSafeInteger(value.version) && value.version >= 1
    && RISK_DIGEST.test(value.source_digest) && RISK_DIGEST.test(value.program_digest);
}

function sameProgram(actual: RiskRecord, expected: RiskRecord): boolean {
  return actual.program_id === expected.program_id && actual.version === expected.version
    && actual.source_digest === expected.source_digest && actual.program_digest === expected.program_digest;
}

function validateLineage(
  payload: RiskRecord,
  artifactDigest: string,
  options: VerifyLossExperienceFeedOptions,
): string | null {
  if (payload.records.length === 0) return null;
  if (options.commit_lineage_batch === undefined) return 'lineage_store_required';
  const transitions: LossExperienceLineageTransition[] = payload.records.map((record: RiskRecord) => ({
    lineage_digest: record.lineage_digest,
    event_type: record.event_type,
    predecessor_digest: record.supersedes_record_digest,
    successor_digest: riskDigest(record),
    reporting_party_id: payload.reporting_party_id,
    relying_party_id: payload.relying_party_id,
    program_digest: payload.program.program_digest,
    receipt_digest: record.receipt_digest,
    action_class: record.action_class,
    currency: record.currency,
    reported_at: record.reported_at,
    record: Object.freeze(structuredClone(record)),
  }));
  if (new Set(transitions.map((entry) => entry.lineage_digest)).size !== transitions.length) {
    return 'lineage_batch_conflict';
  }
  const validatePredecessors = (
    predecessors: Readonly<Record<string, LossExperiencePredecessorResolution>>,
  ): LossExperienceLineageValidationResult => {
    if (!riskRecord(predecessors)) return { accepted: false, reason: 'lineage_predecessors_invalid' };
    for (const record of payload.records.filter((entry: RiskRecord) => entry.event_type !== 'OBSERVED')) {
      const resolved = predecessors[record.supersedes_record_digest] as LossExperiencePredecessorResolution | undefined;
      if (!resolved) return { accepted: false, reason: 'lineage_predecessor_missing' };
      if (resolved.current_head !== true) return { accepted: false, reason: 'lineage_head_invalid' };
      if (resolved.reporting_party_id !== payload.reporting_party_id
          || resolved.relying_party_id !== payload.relying_party_id
          || resolved.program_digest !== payload.program.program_digest) {
        return { accepted: false, reason: 'lineage_context_mismatch' };
      }
      try {
        validateRecord(resolved.record, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY,
          riskInstant(payload.issued_at));
      } catch {
        return { accepted: false, reason: 'lineage_predecessor_invalid' };
      }
      if (riskDigest(resolved.record) !== record.supersedes_record_digest) {
        return { accepted: false, reason: 'lineage_predecessor_digest_mismatch' };
      }
      if (resolved.record.event_type === 'WITHDRAWN') {
        return { accepted: false, reason: 'lineage_terminal_predecessor' };
      }
      if (resolved.record.lineage_digest !== record.lineage_digest
          || resolved.record.receipt_digest !== record.receipt_digest
          || resolved.record.action_class !== record.action_class
          || resolved.record.currency !== record.currency) {
        return { accepted: false, reason: 'lineage_record_mismatch' };
      }
      if (riskInstant(record.reported_at) <= riskInstant(resolved.record.reported_at)
          || record.source_record_digest === resolved.record.source_record_digest
          || riskDigest(record) === record.supersedes_record_digest) {
        return { accepted: false, reason: 'lineage_order_invalid' };
      }
    }
    return { accepted: true };
  };

  let committed: LossExperienceLineageCommitResult;
  try {
    committed = options.commit_lineage_batch(Object.freeze({
      feed_digest: artifactDigest,
      transitions: Object.freeze(transitions.map((entry) => Object.freeze(entry))),
      validate_predecessors: validatePredecessors,
    }));
  } catch {
    return 'lineage_commit_failed';
  }
  if (!riskRecord(committed) || committed.accepted !== true) {
    return riskRecord(committed) && typeof committed.reason === 'string'
      ? committed.reason
      : 'lineage_commit_refused';
  }
  return null;
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
  if (typeof signed.artifact_digest !== 'string') return refuse('feed_digest_missing', true);

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
  if (now < riskInstant(payload.issued_at)) return refuse('feed_not_yet_issued', true, signed.artifact_digest);
  if (now >= riskInstant(payload.expires_at)) return refuse('feed_expired', true, signed.artifact_digest);
  if (options.expected_program === undefined || options.expected_census_digest === undefined
      || options.expected_taxonomy_digest === undefined
      || options.expected_relying_party_id === undefined
      || options.expected_action_classes === undefined
      || options.expected_action_classes.length < 1
      || !options.expected_action_classes.every(riskIdentifier)) {
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
  if (options.expected_taxonomy_digest !== payload.taxonomy_digest) {
    return refuse('taxonomy_digest_mismatch', true, signed.artifact_digest);
  }
  if (options.expected_relying_party_id !== payload.relying_party_id) {
    return refuse('relying_party_mismatch', true, signed.artifact_digest);
  }
  const actionClasses = new Set(options.expected_action_classes);
  if (!payload.records.every((record: RiskRecord) => actionClasses.has(record.action_class))) {
    return refuse('action_class_taxonomy_mismatch', true, signed.artifact_digest);
  }
  const lineageFailure = validateLineage(payload, signed.artifact_digest, options);
  if (lineageFailure !== null) return refuse(lineageFailure, true, signed.artifact_digest);

  return {
    accepted: true,
    verified: true,
    reason: null,
    feed_digest: signed.artifact_digest,
    claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  };
}
