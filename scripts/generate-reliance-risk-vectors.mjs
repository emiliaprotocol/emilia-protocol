// SPDX-License-Identifier: Apache-2.0
/** Regenerate deterministic, synthetic, PHI-free reliance-risk vectors. */
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  createReceiptCensus,
} from '../packages/gate/dist/receipt-census.js';
import {
  COVERAGE_RECONCILIATION_CLAIM_BOUNDARY,
  signCoverageReconciliationAttestation,
  verifyCoverageReconciliationAttestation,
} from '../packages/gate/dist/coverage-reconciliation-attestation.js';
import {
  LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
  signLossExperienceFeed,
  verifyLossExperienceFeed,
} from '../packages/gate/dist/loss-experience-feed.js';
import {
  LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  createLossAllocationAdmissibilityProfilePin,
  lossAllocationRulesDigest,
  lossAllocationScheduleDigest,
  signLossAllocationSchedule,
  verifyLossAllocationSchedule,
} from '../packages/gate/dist/loss-allocation-schedule.js';

const D = (character) => `sha256:${character.repeat(64)}`;
const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
function signer(seedHex, issuerId, keyId) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  // @types/node omits the KeyObject overload accepted by Node's createPublicKey.
  const publicKey = createPublicKey(/** @type {any} */ (privateKey))
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    signer: { issuer_id: issuerId, key_id: keyId, private_key: privateKey },
    trusted_keys: { [keyId]: { issuer_id: issuerId, public_key: publicKey } },
  };
}

const taxonomy = {
  taxonomy_id: 'payer:synthetic:receipt-census:v1',
  allowed_action_classes: ['health.prior-authorization'],
  allowed_outcomes: ['executed', 'refused'],
};
const program = {
  program_id: 'rp.synthetic-payer.pas.1',
  version: 1,
  source_digest: D('1'),
  program_digest: D('2'),
};

const scheduleSeed = '42'.repeat(32);
const scheduleIdentity = signer(
  scheduleSeed,
  'issuer:conformance-lab',
  'loss-allocation-vector-key-1',
);
const scheduleProgram = {
  program_id: 'rp.conformance.program.1',
  version: 1,
  source_digest: D('1'),
  program_digest: D('2'),
};
const scheduleArtifact = signLossAllocationSchedule({
  schedule_id: 'loss-allocation:conformance-1',
  relying_party_id: 'rp:conformance-lab',
  program: scheduleProgram,
  issued_at: '2026-07-28T12:00:00Z',
  valid_from: '2026-07-28T12:00:00Z',
  expires_at: '2026-07-29T12:00:00Z',
  status_target: { type: 'loss-allocation-schedule', usage: 'reliance' },
  rules: [
    {
      failure_class: 'issuer_artifact_invalid',
      responsible_party_id: 'issuer:conformance-lab',
      allocation: { currency: 'USD', max_amount_minor: '25000000' },
      terms_digest: D('a'),
      dispute_endpoint: 'https://example.test/disputes/issuer-artifact',
    },
    {
      failure_class: 'relying_party_policy_misconfiguration',
      responsible_party_id: 'rp:conformance-lab',
      allocation: { currency: 'USD', max_amount_minor: '10000000' },
      terms_digest: D('b'),
      dispute_endpoint: null,
    },
  ],
  claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
}, scheduleIdentity.signer);
const scheduleStatus = {
  outcome: /** @type {'current_not_revoked'} */ ('current_not_revoked'),
  target_digest: lossAllocationScheduleDigest(scheduleArtifact),
};
const scheduleVerification = {
  trusted_keys: scheduleIdentity.trusted_keys,
  expected_relying_party_id: 'rp:conformance-lab',
  expected_program: scheduleProgram,
  status: scheduleStatus,
  now: '2026-07-28T13:00:00Z',
};
const schedulePin = createLossAllocationAdmissibilityProfilePin(scheduleArtifact, {
  profileId: 'rp:admissibility:loss-allocation-conformance:v1',
  evaluationMaxAgeSec: 300,
}, scheduleVerification);
const scheduleVector = {
  '@version': 'EP-LOSS-ALLOCATION-SCHEDULE-CONFORMANCE-v1',
  description: 'Deterministic shared JCS and Ed25519 proof with digest-bound current, stale, and revoked outcomes.',
  claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  seed_hex: scheduleSeed,
  verification_time: '2026-07-28T13:00:00Z',
  stale_verification_time: '2026-07-29T12:00:00Z',
  profile_id: 'rp:admissibility:loss-allocation-conformance:v1',
  evaluation_max_age_sec: 300,
  expected_relying_party_id: 'rp:conformance-lab',
  expected_program: scheduleProgram,
  trusted_keys: scheduleIdentity.trusted_keys,
  current_status: scheduleStatus,
  artifact: scheduleArtifact,
  expected: {
    valid: verifyLossAllocationSchedule(scheduleArtifact, scheduleVerification).accepted,
    schedule_digest: lossAllocationScheduleDigest(scheduleArtifact),
    rules_digest: lossAllocationRulesDigest(scheduleArtifact),
    profile_hash: schedulePin.profile.profile_hash,
    stale_reason: 'schedule_stale',
    revoked_reason: 'schedule_revoked',
  },
};
function inMemoryLineageCommitter() {
  const heads = new Map();
  return (request) => {
    const staged = new Map(heads);
    const predecessors = {};
    for (const transition of request.transitions) {
      const current = staged.get(transition.lineage_digest);
      if (transition.event_type === 'OBSERVED') {
        if (current !== undefined) return { accepted: false, reason: 'lineage_exists' };
      } else {
        if (current === undefined || current.digest !== transition.predecessor_digest) {
          return { accepted: false, reason: 'predecessor_not_current' };
        }
        predecessors[transition.predecessor_digest] = current.resolution;
      }
      staged.set(transition.lineage_digest, {
        digest: transition.successor_digest,
        resolution: {
          current_head: true,
          reporting_party_id: transition.reporting_party_id,
          relying_party_id: transition.relying_party_id,
          program_digest: transition.program_digest,
          record: structuredClone(transition.record),
        },
      });
    }
    const validation = request.validate_predecessors(predecessors);
    if (validation.accepted !== true) return validation;
    heads.clear();
    for (const [key, value] of staged) heads.set(key, value);
    return { accepted: true };
  };
}
const census = createReceiptCensus({
  census_id: 'census:synthetic:2026-06',
  relying_party_id: 'payer:synthetic',
  period: { start: '2026-06-01T00:00:00Z', end: '2026-07-01T00:00:00Z' },
  program,
  minimum_bucket_count: 5,
  buckets: [
    {
      action_class: 'health.prior-authorization', program_version: 1, outcome: 'executed', count: 95,
      open_exposure_amount_minor: '100000', reported_loss_amount_minor: '12500', currency: 'USD',
    },
    {
      action_class: 'health.prior-authorization', program_version: 1, outcome: 'refused', count: 2,
      open_exposure_amount_minor: '0', reported_loss_amount_minor: '0', currency: 'USD',
    },
  ],
  source_inventory_digest: D('3'),
  generated_at: '2026-07-01T01:00:00Z',
}, taxonomy);

const coverageSeed = '43'.repeat(32);
const coverageIdentity = signer(coverageSeed, 'payer:synthetic', 'coverage-vector-key-1');
const coverageArtifact = signCoverageReconciliationAttestation({
  attestation_id: 'coverage:synthetic:2026-06',
  relying_party_id: 'payer:synthetic',
  program,
  period: { start: '2026-06-01T00:00:00Z', end: '2026-07-01T00:00:00Z' },
  coverage_report_hash: D('4'),
  census_digest: census.census_digest,
  system_of_record: { inventory_id: 'pas:sor:synthetic:2026-06', population_root: D('5'), count: 100 },
  receipt_population: { inventory_id: 'ep:receipts:synthetic:2026-06', population_root: D('6'), count: 98 },
  joins: { matched: 95, effect_without_receipt: 3, receipt_without_effect: 1, indeterminate: 2, excluded: 2, exception: 0 },
  issued_at: '2026-07-01T01:00:00Z', expires_at: '2026-08-01T01:00:00Z',
  timestamp_anchor: null,
  claim_boundary: COVERAGE_RECONCILIATION_CLAIM_BOUNDARY,
}, coverageIdentity.signer);
const coverageVector = {
  '@version': 'EP-COVERAGE-RECONCILIATION-CONFORMANCE-v1',
  description: 'Synthetic PHI-free deterministic vector for supplied-population reconciliation and governed-taxonomy census.',
  seed_hex: coverageSeed,
  taxonomy,
  trusted_keys: coverageIdentity.trusted_keys,
  verification_time: '2026-07-02T00:00:00Z',
  expected_program: program,
  expected_census_digest: census.census_digest,
  expected_relying_party_id: 'payer:synthetic',
  census,
  artifact: coverageArtifact,
  expected: verifyCoverageReconciliationAttestation(coverageArtifact, {
    trusted_keys: coverageIdentity.trusted_keys,
    now: '2026-07-02T00:00:00Z',
    expected_program: program,
    expected_census_digest: census.census_digest,
    expected_relying_party_id: 'payer:synthetic',
  }),
};

const feedSeed = '44'.repeat(32);
const feedIdentity = signer(feedSeed, 'carrier:synthetic', 'loss-feed-vector-key-1');
const feedArtifact = signLossExperienceFeed({
  feed_id: 'loss-feed:synthetic:2026-06',
  reporting_party_id: 'carrier:synthetic', relying_party_id: 'payer:synthetic',
  program,
  period: { start: '2026-06-01T00:00:00Z', end: '2026-07-01T00:00:00Z' },
  census_digest: census.census_digest, taxonomy_digest: census.taxonomy_digest,
  source_inventory_digest: D('3'),
  records: [{
    record_id: 'loss-event:synthetic:001', lineage_digest: D('8'), receipt_digest: D('4'),
    action_class: 'health.prior-authorization', classification: 'LOSS_REPORTED',
    reported_amount_minor: '12500', currency: 'USD',
    occurred_at: '2026-06-15T12:00:00Z', reported_at: '2026-06-20T12:00:00Z',
    source_record_digest: D('5'), event_type: 'OBSERVED', supersedes_record_digest: null,
  }],
  issued_at: '2026-07-01T01:00:00Z', expires_at: '2026-09-01T01:00:00Z',
  timestamp_anchor: null,
  claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
}, feedIdentity.signer);
const feedVector = {
  '@version': 'EP-LOSS-EXPERIENCE-FEED-CONFORMANCE-v1',
  description: 'Synthetic PHI-free deterministic external loss-observation vector.',
  seed_hex: feedSeed,
  trusted_keys: feedIdentity.trusted_keys,
  verification_time: '2026-07-02T00:00:00Z',
  expected_program: program,
  expected_census_digest: census.census_digest,
  expected_taxonomy_digest: census.taxonomy_digest,
  expected_relying_party_id: 'payer:synthetic',
  expected_action_classes: ['health.prior-authorization'],
  artifact: feedArtifact,
  expected: verifyLossExperienceFeed(feedArtifact, {
    trusted_keys: feedIdentity.trusted_keys,
    now: '2026-07-02T00:00:00Z',
    expected_program: program,
    expected_census_digest: census.census_digest,
    expected_taxonomy_digest: census.taxonomy_digest,
    expected_relying_party_id: 'payer:synthetic',
    expected_action_classes: ['health.prior-authorization'],
    commit_lineage_batch: inMemoryLineageCommitter(),
  }),
};

await Promise.all([
  writeFile(resolve('conformance/vectors/loss-allocation-schedule.v1.json'), `${JSON.stringify(scheduleVector, null, 2)}\n`),
  writeFile(resolve('conformance/vectors/coverage-reconciliation.v1.json'), `${JSON.stringify(coverageVector, null, 2)}\n`),
  writeFile(resolve('conformance/vectors/loss-experience-feed.v1.json'), `${JSON.stringify(feedVector, null, 2)}\n`),
]);
