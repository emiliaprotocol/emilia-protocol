// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  LOSS_ALLOCATION_SCHEDULE_VERSION,
  LossAllocationScheduleValidationError,
  createLossAllocationAdmissibilityProfilePin,
  lossAllocationRulesDigest,
  lossAllocationScheduleDigest,
  lossAllocationScheduleProfileReference,
  signLossAllocationSchedule,
  verifyLossAllocationSchedule,
} from './loss-allocation-schedule.js';
import { hashCanonical } from './execution-binding.js';
import {
  RELIANCE_PROGRAM_SOURCE_VERSION,
  compileRelianceProgram,
  signRelianceProgram,
} from './reliance-program.js';

const D = (character: string) => `sha256:${character.repeat(64)}`;
const NOW = '2026-07-28T13:00:00Z';

function program(sourceDigest = D('1'), programDigest = D('2')) {
  return {
    program_id: 'rp.payer.pas-adverse-determination.1',
    version: 1,
    source_digest: sourceDigest,
    program_digest: programDigest,
  };
}

function schedule(): any {
  return {
    schedule_id: 'loss-allocation:payer-program-1',
    relying_party_id: 'payer:example-health-plan',
    program: program(),
    issued_at: '2026-07-28T12:00:00Z',
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    status_target: {
      type: 'loss-allocation-schedule',
      usage: 'reliance',
    },
    rules: [
      {
        failure_class: 'issuer_artifact_invalid',
        responsible_party_id: 'issuer:allocation-committee',
        allocation: { currency: 'USD', max_amount_minor: '25000000' },
        terms_digest: D('a'),
        dispute_endpoint: 'https://example.test/disputes/issuer-artifact',
      },
      {
        failure_class: 'relying_party_policy_misconfiguration',
        responsible_party_id: 'payer:example-health-plan',
        allocation: { currency: 'USD', max_amount_minor: '10000000' },
        terms_digest: D('b'),
        dispute_endpoint: null,
      },
    ],
    claim_boundary: LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY,
  };
}

function harness() {
  const keys = generateKeyPairSync('ed25519');
  const signer = {
    issuer_id: 'issuer:allocation-committee',
    key_id: 'loss-allocation-key-1',
    private_key: keys.privateKey,
  };
  const artifact = signLossAllocationSchedule(schedule(), signer);
  const trusted_keys = {
    'loss-allocation-key-1': {
      issuer_id: signer.issuer_id,
      public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
  };
  const status = {
    outcome: 'current_not_revoked',
    target_digest: lossAllocationScheduleDigest(artifact),
  };
  return { artifact, keys, signer, status, trusted_keys };
}

function validationCode(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    assert.ok(error instanceof LossAllocationScheduleValidationError);
    return error.code;
  }
}

test('signs and verifies a JCS-canonical schedule under the shared risk-artifact proof', () => {
  const { artifact, status, trusted_keys } = harness();
  const verified = verifyLossAllocationSchedule(artifact, {
    trusted_keys,
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: program(),
    status,
    now: NOW,
  });

  assert.equal(artifact['@version'], LOSS_ALLOCATION_SCHEDULE_VERSION);
  assert.equal(artifact.proof.algorithm, 'Ed25519');
  assert.equal(artifact.proof.body_digest, `sha256:${hashCanonical((({ proof: _, ...body }) => body)(artifact))}`);
  assert.equal(Object.isFrozen(artifact.rules[0]), true);
  assert.equal(verified.accepted, true);
  assert.equal(verified.verified, true);
  assert.equal(verified.schedule_digest, lossAllocationScheduleDigest(artifact));
  assert.equal(verified.rules_digest, lossAllocationRulesDigest(artifact));
  assert.equal(verified.claim_boundary, LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY);

  const reordered = schedule();
  reordered.program = {
    program_digest: D('2'), source_digest: D('1'), version: 1,
    program_id: 'rp.payer.pas-adverse-determination.1',
  };
  const resigned = signLossAllocationSchedule(reordered, harness().signer);
  assert.equal(resigned.proof.body_digest, artifact.proof.body_digest);
});

test('refuses tampering, untrusted issuers, and missing or substituted relying-party/program pins', () => {
  const { artifact, status, trusted_keys } = harness();
  const options = { trusted_keys, status, now: NOW };

  const tampered = structuredClone(artifact);
  tampered.rules[0].allocation.max_amount_minor = '99999999';
  assert.equal(verifyLossAllocationSchedule(tampered, options).reason, 'digest_mismatch');
  assert.equal(verifyLossAllocationSchedule(artifact, { ...options, trusted_keys: {} }).reason,
    'issuer_untrusted');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...options,
    expected_relying_party_id: 'payer:example-health-plan',
  }).reason, 'program_binding_required');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...options,
    expected_relying_party_id: 'payer:other',
    expected_program: program(),
  }).reason, 'relying_party_binding_mismatch');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...options,
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: program(D('1'), D('9')),
  }).reason, 'reliance_program_binding_mismatch');
});

test('refuses duplicate and conflicting rules keyed by one failure class', () => {
  const { signer } = harness();
  const duplicate = schedule();
  duplicate.rules.push(structuredClone(duplicate.rules[0]));
  assert.equal(validationCode(() => signLossAllocationSchedule(duplicate, signer)),
    'duplicate_failure_rule');

  const conflict = schedule();
  conflict.rules.push({ ...structuredClone(conflict.rules[0]), terms_digest: D('f') });
  assert.equal(validationCode(() => signLossAllocationSchedule(conflict, signer)),
    'conflicting_failure_rule');
});

test('requires a digest-bound current status and refuses not-yet-valid, stale, and revoked schedules', () => {
  const { artifact, status, trusted_keys } = harness();
  const base = {
    trusted_keys,
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: program(),
  };
  assert.equal(verifyLossAllocationSchedule(artifact, { ...base, now: NOW }).reason,
    'schedule_status_required');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...base, now: NOW, status: { ...status, target_digest: D('9') },
  }).reason, 'status_target_mismatch');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...base, now: NOW, status: { ...status, outcome: 'revoked' },
  }).reason, 'schedule_revoked');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...base, status, now: '2026-07-28T11:59:59Z',
  }).reason, 'schedule_not_yet_valid');
  assert.equal(verifyLossAllocationSchedule(artifact, {
    ...base, status, now: '2026-07-29T12:00:00Z',
  }).reason, 'schedule_stale');
});

test('produces compact and non-circular Admissibility Profile digest pins', () => {
  const { artifact, signer } = harness();
  assert.deepEqual(lossAllocationScheduleProfileReference(artifact), {
    artifact_type: LOSS_ALLOCATION_SCHEDULE_VERSION,
    artifact_digest: lossAllocationScheduleDigest(artifact),
    required_status: true,
  });

  const pin = createLossAllocationAdmissibilityProfilePin(artifact, {
    profileId: 'rp:admissibility:loss-allocation:v1',
    evaluationMaxAgeSec: 300,
  });
  assert.deepEqual(Object.keys(pin.reference).sort(), [
    'evaluation_max_age_sec', 'profile_hash', 'profile_id', 'revocation_required',
  ]);
  assert.equal(pin.reference.profile_hash, pin.profile.profile_hash);
  assert.equal(pin.profile.loss_allocation_schedule.rules_digest, lossAllocationRulesDigest(artifact));
  assert.equal(Object.hasOwn(pin.profile.loss_allocation_schedule, 'program_digest'), false);
  assert.equal(Object.hasOwn(pin.profile.loss_allocation_schedule, 'source_digest'), false);
  const { profile_hash: profileHash, ...profileBody } = pin.profile;
  assert.equal(profileHash, `sha256:${hashCanonical(profileBody)}`);

  const rebound = signLossAllocationSchedule({
    ...schedule(),
    program: program(D('7'), D('8')),
  }, signer);
  assert.equal(createLossAllocationAdmissibilityProfilePin(rebound, {
    profileId: pin.profile.id,
    evaluationMaxAgeSec: 300,
  }).profile.profile_hash, profileHash, 'final program digests must not create a profile-pin cycle');

  const changed = schedule();
  changed.rules[0].responsible_party_id = 'issuer:different';
  const changedArtifact = signLossAllocationSchedule(changed, signer);
  assert.notEqual(createLossAllocationAdmissibilityProfilePin(changedArtifact, {
    profileId: pin.profile.id,
    evaluationMaxAgeSec: 300,
  }).profile.profile_hash, profileHash);
});

test('the generated pin compiles through unchanged Reliance Program v1 before final digest binding', () => {
  const { artifact: draftArtifact, signer, trusted_keys } = harness();
  const pin = createLossAllocationAdmissibilityProfilePin(draftArtifact, {
    profileId: 'rp:admissibility:loss-allocation:v1',
    evaluationMaxAgeSec: 300,
  });
  const rpKeys = generateKeyPairSync('ed25519');
  const source = {
    '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
    program_id: program().program_id,
    version: program().version,
    relying_party: { id: 'payer:example-health-plan', key_id: 'rp-key-1' },
    root_caid: `caid:1:health.prior-authorization-determination.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: D('c'),
    valid_from: '2026-07-28T12:00:00Z',
    expires_at: '2026-07-29T12:00:00Z',
    stages: [{
      stage_id: 'loss-allocation',
      depends_on: [],
      rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
      profiles: [pin.reference],
    }],
    execution: {
      depends_on: ['loss-allocation'],
      consequence_mode: 'action-escrow',
      capability_template_digest: null,
      escrow_profile_digest: D('e'),
    },
  };
  const signedProgram = signRelianceProgram(source, rpKeys.privateKey);
  const compiled = compileRelianceProgram(signedProgram, {
    trustedKeys: {
      'rp-key-1': {
        relying_party_id: source.relying_party.id,
        public_key: rpKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    profiles: [pin.profile],
  });
  assert.equal(compiled.program.stages[0].requirements[0].policy_digest, pin.profile.profile_hash);

  const finalProgram = program(signedProgram.source_digest, compiled.program_digest);
  const finalArtifact = signLossAllocationSchedule({
    ...schedule(),
    program: finalProgram,
  }, signer);
  assert.equal(createLossAllocationAdmissibilityProfilePin(finalArtifact, {
    profileId: pin.profile.id,
    evaluationMaxAgeSec: 300,
  }).profile.profile_hash, pin.profile.profile_hash);
  assert.equal(verifyLossAllocationSchedule(finalArtifact, {
    trusted_keys,
    expected_relying_party_id: 'payer:example-health-plan',
    expected_program: finalProgram,
    status: {
      outcome: 'current_not_revoked',
      target_digest: lossAllocationScheduleDigest(finalArtifact),
    },
    now: NOW,
  }).accepted, true);
});

test('closed schemas, decimal monetary caps, timestamps, and claim boundary fail before signing', () => {
  const { signer } = harness();
  const extra = schedule();
  extra.legal_enforceability = true;
  assert.equal(validationCode(() => signLossAllocationSchedule(extra, signer)),
    'schedule_schema_invalid');

  const numericMoney = schedule();
  numericMoney.rules[0].allocation.max_amount_minor = 25_000_000;
  assert.equal(validationCode(() => signLossAllocationSchedule(numericMoney, signer)),
    'failure_rule_invalid');

  const impossibleTime = schedule();
  impossibleTime.expires_at = '2026-02-30T12:00:00.1Z';
  assert.equal(validationCode(() => signLossAllocationSchedule(impossibleTime, signer)),
    'schedule_validity_invalid');

  const overstated = schedule();
  overstated.claim_boundary = 'this_moves_money';
  assert.equal(validationCode(() => signLossAllocationSchedule(overstated, signer)),
    'claim_boundary_invalid');
});

test('checked-in vector verifies deterministic Ed25519 bytes and named status refusals', () => {
  const vector = JSON.parse(readFileSync(fileURLToPath(new URL(
    '../../conformance/vectors/loss-allocation-schedule.v1.json', import.meta.url,
  )), 'utf8'));
  assert.equal(vector['@version'], 'EP-LOSS-ALLOCATION-SCHEDULE-CONFORMANCE-v1');
  assert.equal(vector.claim_boundary, LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY);

  const accepted = verifyLossAllocationSchedule(vector.artifact, {
    trusted_keys: vector.trusted_keys,
    expected_relying_party_id: vector.expected_relying_party_id,
    expected_program: vector.expected_program,
    status: vector.current_status,
    now: vector.verification_time,
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.schedule_digest, vector.expected.schedule_digest);
  assert.equal(accepted.rules_digest, vector.expected.rules_digest);
  assert.equal(createLossAllocationAdmissibilityProfilePin(vector.artifact, {
    profileId: vector.profile_id,
    evaluationMaxAgeSec: vector.evaluation_max_age_sec,
  }).profile.profile_hash, vector.expected.profile_hash);
  assert.equal(verifyLossAllocationSchedule(vector.artifact, {
    trusted_keys: vector.trusted_keys,
    expected_relying_party_id: vector.expected_relying_party_id,
    expected_program: vector.expected_program,
    status: vector.current_status,
    now: vector.stale_verification_time,
  }).reason, 'schedule_stale');
  assert.equal(verifyLossAllocationSchedule(vector.artifact, {
    trusted_keys: vector.trusted_keys,
    expected_relying_party_id: vector.expected_relying_party_id,
    expected_program: vector.expected_program,
    status: { ...vector.current_status, outcome: 'revoked' },
    now: vector.verification_time,
  }).reason, 'schedule_revoked');
});
