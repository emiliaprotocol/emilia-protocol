#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Same-team experimental reference vectors for process acceptance over one
// signed EP-BOUNDED-EXECUTION-REPORT-v1 artifact.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION,
  BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION,
  buildBoundedExecutionEvidencePack,
  evaluateBoundedExecutionAcceptance,
  signBoundedExecutionAcceptanceProfile,
  verifyBoundedExecutionAcceptanceProfile,
  verifyBoundedExecutionEvidencePack,
} from '../../packages/gate/src/bounded-execution-acceptance.ts';
import { canonicalize } from '../../packages/gate/src/execution-binding.ts';
import { riskDigest } from '../../packages/gate/src/reliance-risk-crypto.ts';

const OUTPUT = fileURLToPath(new URL('./bounded-execution-acceptance.v1.json', import.meta.url));
const REPORT_VECTORS = fileURLToPath(new URL('./bounded-execution-report.v1.json', import.meta.url));
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const clone = (value) => structuredClone(value);

function deterministicEd25519(label) {
  const seed = crypto.createHash('sha256')
    .update(`EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1 same-team reference key\0${label}`)
    .digest();
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

function publicKey(privateKey) {
  return crypto.createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
}

const reportSuite = JSON.parse(readFileSync(REPORT_VECTORS, 'utf8'));
const reportArtifact = reportSuite.known_answer.report_artifact;
const reportContext = reportSuite.known_answer.report_verification_context;
const privateKey = deterministicEd25519('relying-party-acceptance');
const signer = {
  issuer_id: reportArtifact.relying_party_id,
  key_id: 'key:reference-process-acceptance',
  private_key: privateKey,
};
const profileInput = {
  profile_id: 'profile:reference-remediation-acceptance:01',
  relying_party_id: reportArtifact.relying_party_id,
  program_id: reportArtifact.program_id,
  program_version: reportArtifact.program_version,
  program_digest: reportArtifact.program_digest,
  valid_from: '2026-07-30T20:00:00.000Z',
  expires_at: '2026-07-30T21:00:00.000Z',
  accepted_program_statuses: ['ACTIVE'],
  max_total_unresolved: 0,
  max_total_reserved: 0,
  required_nodes: [{
    node_id: 'inspect',
    min_terminal_occurrences: 1,
    accepted_outcomes: ['COMMITTED'],
    allow_additional_terminal_outcomes: false,
  }],
};
const profileArtifact = signBoundedExecutionAcceptanceProfile(profileInput, signer);
const profileContext = {
  trusted_keys: {
    [signer.key_id]: {
      issuer_id: signer.issuer_id,
      public_key: publicKey(privateKey),
    },
  },
  expected_profile_id: profileInput.profile_id,
  expected_relying_party_id: profileInput.relying_party_id,
  expected_program_id: profileInput.program_id,
  expected_program_version: profileInput.program_version,
  expected_program_digest: profileInput.program_digest,
  now: reportArtifact.generated_at,
};
const evaluation = evaluateBoundedExecutionAcceptance(
  profileArtifact,
  profileContext,
  reportArtifact,
  reportContext,
);
assert.equal(evaluation.verdict, 'RECORDED_PROCESS_ACCEPTED');
const pack = buildBoundedExecutionEvidencePack({
  profile_artifact: profileArtifact,
  profile_context: profileContext,
  report_artifact: reportArtifact,
  report_context: reportContext,
});

const tamperedProfile = clone(profileArtifact);
tamperedProfile.required_nodes[0].min_terminal_occurrences = 2;
const forgedEvaluationPack = clone(pack);
forgedEvaluationPack.evaluation.verdict = 'RECORDED_PROCESS_NOT_ACCEPTED';
const { package_digest: _oldDigest, ...forgedBody } = forgedEvaluationPack;
forgedEvaluationPack.package_digest = riskDigest(forgedBody);
const substitutedContext = {
  ...profileContext,
  expected_program_digest: `sha256:${'9'.repeat(64)}`,
};
const { proof: _proof, ...profileBody } = profileArtifact;
const profileBodyJcs = canonicalize(profileBody);

const SUITE = {
  '@version': 'EP-BOUNDED-EXECUTION-ACCEPTANCE-REFERENCE-VECTORS-v1',
  status: 'same-team-experimental-reference-vectors',
  vectors_version: '1.0.0',
  claim_boundary: {
    establishes: [
      'deterministic profile signature, report composition, tri-state evaluation, package digest, and hostile outcomes against this repository reference implementation',
      'one relying party accepted one Gate-recorded process result under an exact signed profile',
    ],
    does_not_establish: [
      'independent or cross-language conformance, interoperability, standardization, certification, deployment, or production durability',
      'legal compliance, external effect truth, event chronology, program safety, complete mediation, or the absence of outside-Gate actions',
    ],
  },
  known_answer: {
    profile_input: profileInput,
    profile_artifact: profileArtifact,
    profile_verification_context: profileContext,
    report_artifact: reportArtifact,
    report_verification_context: reportContext,
    evaluation,
    evidence_pack: pack,
    canonical_profile_body_utf8: profileBodyJcs,
    canonical_profile_body_b64u: Buffer.from(profileBodyJcs, 'utf8').toString('base64url'),
    signature_input_b64u: Buffer.from(
      `${BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION}\0${profileBodyJcs}`,
      'utf8',
    ).toString('base64url'),
    signature_b64u: profileArtifact.proof.signature_b64u,
    profile_digest: riskDigest(profileArtifact),
    package_digest: pack.package_digest,
  },
  hostile_mutations: [
    {
      id: 'profile_requirement_tampered_after_signature',
      target: 'profile',
      artifact: tamperedProfile,
      expected_reason: 'digest_mismatch',
    },
    {
      id: 'evaluation_forged_and_package_digest_recomputed',
      target: 'pack',
      artifact: forgedEvaluationPack,
      expected_reason: 'package_evaluation_mismatch',
    },
    {
      id: 'caller_substitutes_expected_program_digest',
      target: 'profile_context',
      context: substitutedContext,
      expected_reason: 'program_digest_mismatch',
    },
  ],
};

function validateSuite(suite) {
  const known = suite.known_answer;
  const verifiedProfile = verifyBoundedExecutionAcceptanceProfile(
    known.profile_artifact,
    known.profile_verification_context,
  );
  assert.equal(verifiedProfile.accepted, true);
  assert.equal(verifiedProfile.profile_digest, known.profile_digest);
  const checkedEvaluation = evaluateBoundedExecutionAcceptance(
    known.profile_artifact,
    known.profile_verification_context,
    known.report_artifact,
    known.report_verification_context,
  );
  assert.deepEqual(checkedEvaluation, known.evaluation);
  const checkedPack = verifyBoundedExecutionEvidencePack(known.evidence_pack, {
    profile_context: known.profile_verification_context,
    report_context: known.report_verification_context,
  });
  assert.equal(checkedPack.valid, true);
  assert.equal(checkedPack.verdict, 'RECORDED_PROCESS_ACCEPTED');
  assert.equal(checkedPack.package_digest, known.package_digest);
  const { proof, ...body } = known.profile_artifact;
  assert.equal(canonicalize(body), known.canonical_profile_body_utf8);
  assert.equal(proof.signature_b64u, known.signature_b64u);
  assert.equal(known.profile_artifact['@version'], BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION);
  assert.equal(known.evidence_pack['@version'], BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION);

  for (const mutation of suite.hostile_mutations) {
    let reason;
    if (mutation.target === 'profile') {
      reason = verifyBoundedExecutionAcceptanceProfile(
        mutation.artifact,
        known.profile_verification_context,
      ).reason;
    } else if (mutation.target === 'pack') {
      reason = verifyBoundedExecutionEvidencePack(mutation.artifact, {
        profile_context: known.profile_verification_context,
        report_context: known.report_verification_context,
      }).reason;
    } else {
      reason = verifyBoundedExecutionAcceptanceProfile(
        known.profile_artifact,
        mutation.context,
      ).reason;
    }
    assert.equal(reason, mutation.expected_reason, mutation.id);
  }
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  throw new Error('usage: generate-bounded-execution-acceptance.mjs [--check]');
}

validateSuite(SUITE);
const serialized = `${JSON.stringify(SUITE, null, 2)}\n`;
if (args[0] === '--check') {
  const checkedIn = readFileSync(OUTPUT, 'utf8');
  if (checkedIn !== serialized) {
    console.error('bounded-execution-acceptance.v1.json is stale; regenerate it');
    process.exitCode = 1;
  } else {
    validateSuite(JSON.parse(checkedIn));
    console.log('checked bounded-execution-acceptance.v1.json — known answer and 3 hostile cases');
  }
} else {
  writeFileSync(OUTPUT, serialized);
  console.log('wrote bounded-execution-acceptance.v1.json — known answer and 3 hostile cases');
}
