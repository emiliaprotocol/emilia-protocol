// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY,
  BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION,
  BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION,
  buildBoundedExecutionEvidencePack,
  evaluateBoundedExecutionAcceptance,
  signBoundedExecutionAcceptanceProfile,
  verifyBoundedExecutionAcceptanceProfile,
  verifyBoundedExecutionEvidencePack,
} from './bounded-execution-acceptance.js';
import { BOUNDED_EXECUTION_REPORT_VERSION } from './bounded-execution-report.js';
import { signRiskBody } from './dist/reliance-risk-crypto.js';

const VECTOR_PATH = fileURLToPath(new URL(
  '../../conformance/vectors/bounded-execution-report.v1.json',
  import.meta.url,
));
const vectors = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const known = vectors.known_answer;
const ACCEPTANCE_VECTOR_PATH = fileURLToPath(new URL(
  '../../conformance/vectors/bounded-execution-acceptance.v1.json',
  import.meta.url,
));
const acceptanceVectors = JSON.parse(readFileSync(ACCEPTANCE_VECTOR_PATH, 'utf8'));

function reportHarness(mutate: (body: Record<string, any>) => void) {
  const keys = generateKeyPairSync('ed25519');
  const keyId = 'key:acceptance-test-report';
  const body = structuredClone(known.report_artifact);
  delete body.proof;
  mutate(body);
  const artifact = signRiskBody(BOUNDED_EXECUTION_REPORT_VERSION, body, {
    issuer_id: body.relying_party_id,
    key_id: keyId,
    private_key: keys.privateKey,
  });
  const context = {
    ...known.report_verification_context,
    trusted_keys: {
      [keyId]: {
        issuer_id: body.relying_party_id,
        public_key: keys.publicKey.export({
          type: 'spki', format: 'der',
        }).toString('base64url'),
      },
    },
  };
  return { artifact, context };
}

function profileHarness(overrides: Record<string, unknown> = {}) {
  const keys = generateKeyPairSync('ed25519');
  const relyingPartyId = known.report_artifact.relying_party_id;
  const keyId = 'key:process-acceptance';
  const input = {
    profile_id: 'profile:reference-process-completion:01',
    relying_party_id: relyingPartyId,
    program_id: known.report_artifact.program_id,
    program_version: known.report_artifact.program_version,
    program_digest: known.report_artifact.program_digest,
    valid_from: '2026-07-30T20:00:00.000Z',
    expires_at: '2026-07-31T20:00:00.000Z',
    accepted_program_statuses: ['ACTIVE'],
    max_total_unresolved: 0,
    max_total_reserved: 0,
    required_nodes: [{
      node_id: 'inspect',
      min_terminal_occurrences: 1,
      accepted_outcomes: ['COMMITTED'],
      allow_additional_terminal_outcomes: false,
    }],
    ...overrides,
  };
  const artifact = signBoundedExecutionAcceptanceProfile(input, {
    issuer_id: relyingPartyId,
    key_id: keyId,
    private_key: keys.privateKey,
  });
  const context = {
    trusted_keys: {
      [keyId]: {
        issuer_id: relyingPartyId,
        public_key: keys.publicKey.export({
          type: 'spki', format: 'der',
        }).toString('base64url'),
      },
    },
    expected_profile_id: input.profile_id,
    expected_relying_party_id: relyingPartyId,
    expected_program_id: input.program_id,
    expected_program_version: input.program_version,
    expected_program_digest: input.program_digest,
    now: '2026-07-30T21:00:00.000Z',
  };
  return { artifact, context };
}

test('signs and verifies a closed relying-party process acceptance profile', () => {
  const run = profileHarness();
  assert.equal(run.artifact['@version'], BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION);
  assert.equal(run.artifact.claim_boundary, BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY);
  assert.equal(Object.hasOwn(run.artifact, 'compliant'), false);

  const verified = verifyBoundedExecutionAcceptanceProfile(run.artifact, run.context);
  assert.equal(verified.accepted, true);
  assert.equal(verified.verified, true);
  assert.equal(verified.profile.required_nodes[0].node_id, 'inspect');
});

test('accepts the recorded process only when the RP-required terminal outcome exists', () => {
  const run = profileHarness();
  const result = evaluateBoundedExecutionAcceptance(
    run.artifact,
    run.context,
    known.report_artifact,
    known.report_verification_context,
  );
  assert.equal(result.valid, true);
  assert.equal(result.verdict, 'RECORDED_PROCESS_ACCEPTED');
  assert.deepEqual(result.reasons, []);
  assert.equal(Object.hasOwn(result, 'compliant'), false);
});

test('reports a completed but insufficient process as not accepted', () => {
  const run = profileHarness({
    required_nodes: [{
      node_id: 'inspect',
      min_terminal_occurrences: 2,
      accepted_outcomes: ['COMMITTED'],
      allow_additional_terminal_outcomes: false,
    }],
  });
  const result = evaluateBoundedExecutionAcceptance(
    run.artifact,
    run.context,
    known.report_artifact,
    known.report_verification_context,
  );
  assert.equal(result.valid, true);
  assert.equal(result.verdict, 'RECORDED_PROCESS_NOT_ACCEPTED');
  assert.deepEqual(result.reasons, ['required_terminal_count_unsatisfied:inspect']);
});

test('preserves unresolved or reserved work as indeterminate', () => {
  const run = profileHarness();
  const unresolved = reportHarness((body) => {
    body.node_buckets[0].terminal_recorded_outcomes = [];
    body.node_buckets[0].unresolved_post_entry = [{
      occurrence_id: 'occurrence:inspect:pending',
      recorded_state: 'INDETERMINATE',
    }];
  });
  const unresolvedResult = evaluateBoundedExecutionAcceptance(
    run.artifact,
    run.context,
    unresolved.artifact,
    unresolved.context,
  );
  assert.equal(unresolvedResult.verdict, 'INDETERMINATE');
  assert.deepEqual(unresolvedResult.reasons, ['unresolved_occurrence_limit_exceeded']);

  const reserved = reportHarness((body) => {
    body.node_buckets[0].terminal_recorded_outcomes = [];
    body.node_buckets[0].never_attempted.reserved_occurrence_ids = [
      'occurrence:inspect:reserved',
    ];
  });
  const reservedResult = evaluateBoundedExecutionAcceptance(
    run.artifact,
    run.context,
    reserved.artifact,
    reserved.context,
  );
  assert.equal(reservedResult.verdict, 'INDETERMINATE');
  assert.deepEqual(reservedResult.reasons, ['reserved_occurrence_limit_exceeded']);
});

test('a disallowed terminal outcome cannot be hidden by an accepted one', () => {
  const run = profileHarness();
  const report = reportHarness((body) => {
    body.node_buckets[0].max_occurrences = 2;
    body.node_buckets[0].terminal_recorded_outcomes.push({
      occurrence_id: 'occurrence:inspect:not-committed',
      outcome: 'PROVEN_NOT_COMMITTED',
    });
  });
  const result = evaluateBoundedExecutionAcceptance(
    run.artifact,
    run.context,
    report.artifact,
    report.context,
  );
  assert.equal(result.verdict, 'RECORDED_PROCESS_NOT_ACCEPTED');
  assert.deepEqual(result.reasons, ['disallowed_terminal_outcome:inspect']);
});

test('builds one portable pack and independently re-evaluates both signed objects', () => {
  const run = profileHarness();
  const pack = buildBoundedExecutionEvidencePack({
    profile_artifact: run.artifact,
    profile_context: run.context,
    report_artifact: known.report_artifact,
    report_context: known.report_verification_context,
  });
  assert.equal(pack['@version'], BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION);
  assert.equal(pack.evaluation.verdict, 'RECORDED_PROCESS_ACCEPTED');
  assert.equal(Object.hasOwn(pack, 'compliant'), false);

  const checked = verifyBoundedExecutionEvidencePack(pack, {
    profile_context: run.context,
    report_context: known.report_verification_context,
  });
  assert.equal(checked.valid, true);
  assert.equal(checked.verdict, 'RECORDED_PROCESS_ACCEPTED');
  assert.equal(checked.package_digest, pack.package_digest);
});

test('pack verification refuses tampering, substituted programs, and untrusted profile keys', () => {
  const run = profileHarness();
  const pack = buildBoundedExecutionEvidencePack({
    profile_artifact: run.artifact,
    profile_context: run.context,
    report_artifact: known.report_artifact,
    report_context: known.report_verification_context,
  });

  const tampered = structuredClone(pack);
  tampered.evaluation.verdict = 'RECORDED_PROCESS_NOT_ACCEPTED';
  assert.equal(verifyBoundedExecutionEvidencePack(tampered, {
    profile_context: run.context,
    report_context: known.report_verification_context,
  }).reason, 'package_digest_mismatch');

  const substituted = profileHarness({ program_digest: `sha256:${'9'.repeat(64)}` });
  const mismatch = evaluateBoundedExecutionAcceptance(
    substituted.artifact,
    substituted.context,
    known.report_artifact,
    known.report_verification_context,
  );
  assert.equal(mismatch.valid, false);
  assert.equal(mismatch.reason, 'program_digest_mismatch');

  const other = generateKeyPairSync('ed25519');
  assert.equal(verifyBoundedExecutionAcceptanceProfile(run.artifact, {
    ...run.context,
    trusted_keys: {
      'key:other': {
        issuer_id: run.context.expected_relying_party_id,
        public_key: other.publicKey.export({
          type: 'spki', format: 'der',
        }).toString('base64url'),
      },
    },
  }).reason, 'issuer_untrusted');
});

test('profile construction refuses accessor-bearing arrays without invoking them', () => {
  const base = profileHarness();
  let invoked = false;
  const hostile: unknown[] = [];
  Object.defineProperty(hostile, '0', {
    enumerable: true,
    get() {
      invoked = true;
      return base.artifact.required_nodes[0];
    },
  });
  hostile.length = 1;
  assert.throws(() => signBoundedExecutionAcceptanceProfile({
    profile_id: base.artifact.profile_id,
    relying_party_id: base.artifact.relying_party_id,
    program_id: base.artifact.program_id,
    program_version: base.artifact.program_version,
    program_digest: base.artifact.program_digest,
    valid_from: base.artifact.valid_from,
    expires_at: base.artifact.expires_at,
    accepted_program_statuses: base.artifact.accepted_program_statuses,
    max_total_unresolved: 0,
    max_total_reserved: 0,
    required_nodes: hostile,
  }, {
    issuer_id: base.artifact.relying_party_id,
    key_id: 'key:hostile',
    private_key: generateKeyPairSync('ed25519').privateKey,
  }));
  assert.equal(invoked, false);
});

test('profile construction refuses duplicate nodes and unsafe signer authority', () => {
  const base = profileHarness();
  assert.throws(() => signBoundedExecutionAcceptanceProfile({
    profile_id: base.artifact.profile_id,
    relying_party_id: base.artifact.relying_party_id,
    program_id: base.artifact.program_id,
    program_version: base.artifact.program_version,
    program_digest: base.artifact.program_digest,
    valid_from: base.artifact.valid_from,
    expires_at: base.artifact.expires_at,
    accepted_program_statuses: base.artifact.accepted_program_statuses,
    max_total_unresolved: 0,
    max_total_reserved: 0,
    required_nodes: [
      base.artifact.required_nodes[0],
      base.artifact.required_nodes[0],
    ],
  }, {
    issuer_id: 'rp:attacker',
    key_id: 'key:attacker',
    private_key: generateKeyPairSync('ed25519').privateKey,
  }), /relying party|duplicated/i);
});

test('replays the deterministic portable evidence-pack known answer', () => {
  const vector = acceptanceVectors.known_answer;
  const verified = verifyBoundedExecutionAcceptanceProfile(
    vector.profile_artifact,
    vector.profile_verification_context,
  );
  assert.equal(verified.accepted, true);
  assert.equal(verified.profile_digest, vector.profile_digest);
  const evaluation = evaluateBoundedExecutionAcceptance(
    vector.profile_artifact,
    vector.profile_verification_context,
    vector.report_artifact,
    vector.report_verification_context,
  );
  assert.deepEqual(evaluation, vector.evaluation);
  const pack = verifyBoundedExecutionEvidencePack(vector.evidence_pack, {
    profile_context: vector.profile_verification_context,
    report_context: vector.report_verification_context,
  });
  assert.equal(pack.valid, true);
  assert.equal(pack.package_digest, vector.package_digest);
});
