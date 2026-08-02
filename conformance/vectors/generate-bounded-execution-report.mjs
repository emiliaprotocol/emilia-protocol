#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Same-team experimental reference vectors for EP-BOUNDED-EXECUTION-REPORT-v1.
// Run with: node --import ./scripts/ts-loader/register.mjs \
//   conformance/vectors/generate-bounded-execution-report.mjs [--check]

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  EXECUTION_PROGRAM_RUNTIME_VERSION,
  executionProgramReportSnapshotMarker,
} from '../../packages/gate/src/admission-store.ts';
import {
  executionProgramDigest,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
} from '../../packages/gate/src/bounded-execution-program.ts';
import {
  BOUNDED_EXECUTION_REPORT_VERSION,
  boundedExecutionOccurrenceInventoryDigest,
  boundedExecutionReportDigest,
  boundedExecutionRuntimeStateDigest,
  signBoundedExecutionReport,
  verifyBoundedExecutionReport,
} from '../../packages/gate/src/bounded-execution-report.ts';
import { canonicalize } from '../../packages/gate/src/execution-binding.ts';
import { signRiskBody } from '../../packages/gate/src/reliance-risk-crypto.ts';

const OUTPUT = fileURLToPath(new URL('./bounded-execution-report.v1.json', import.meta.url));
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const REPORT_START = '2026-07-30T20:00:00.000Z';
const REPORT_END = '2026-07-30T20:30:00.000Z';
const GENERATED_AT = '2026-07-30T20:31:00.000Z';

const clone = (value) => structuredClone(value);
/**
 * @param {string} label
 * @returns {import('../../packages/gate/src/admission-store.ts').AdmissionDigest}
 */
const digest = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const caid = (label) => (
  `caid:1:reference.synthetic-action.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`
);

function deterministicEd25519(label) {
  const seed = crypto.createHash('sha256')
    .update(`EP-BOUNDED-EXECUTION-REPORT-v1 same-team reference key\0${label}`)
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

const PROGRAM_PRIVATE_KEY = deterministicEd25519('program-authorizer');
const PROGRAM_SIGNER = {
  issuer_id: 'customer:reference-security',
  key_id: 'key:reference-program-authorizer',
  private_key: PROGRAM_PRIVATE_KEY,
};
const REPORT_PRIVATE_KEY = deterministicEd25519('report-signer');
const REPORT_SIGNER = {
  relying_party_id: 'rp:reference-operations',
  key_id: 'key:reference-report-signer',
  private_key: REPORT_PRIVATE_KEY,
};

const PROGRAM_INPUT = {
  program_id: 'program:reference-remediation:01',
  tenant_id: 'tenant:reference',
  version: 1,
  subject_id: 'agent:reference-operator:01',
  audience: 'gate:reference:01',
  objective_digest: digest('reference-objective'),
  authorization_digest: digest('reference-authorization'),
  presentation_digest: digest('reference-presentation'),
  supersedes_program_digest: null,
  issued_at: '2026-07-30T19:55:00.000Z',
  valid_from: REPORT_START,
  expires_at: '2026-07-30T21:00:00.000Z',
  max_total_occurrences: 2,
  max_concurrent_effects: 1,
  budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 1 }],
  nodes: [{
    node_id: 'inspect',
    action: {
      mode: 'exact',
      caid: caid('inspect'),
      action_digest: digest('action:inspect'),
    },
    trust_program_digest: digest('trust:inspect'),
    depends_on: [],
    max_occurrences: 1,
    charges: [{ budget_id: 'attempts', amount: 1 }],
  }],
};

const PROGRAM_ARTIFACT = signBoundedExecutionProgram(PROGRAM_INPUT, PROGRAM_SIGNER);
const PROGRAM_DIGEST = executionProgramDigest(PROGRAM_ARTIFACT);
const PROGRAM_VERIFICATION_CONTEXT = {
  trusted_keys: {
    [PROGRAM_SIGNER.key_id]: {
      issuer_id: PROGRAM_SIGNER.issuer_id,
      public_key: publicKey(PROGRAM_PRIVATE_KEY),
    },
  },
  now: REPORT_START,
  expected_program_id: PROGRAM_INPUT.program_id,
  expected_tenant_id: PROGRAM_INPUT.tenant_id,
  expected_authorizer_id: PROGRAM_SIGNER.issuer_id,
  expected_authorization_digest: PROGRAM_INPUT.authorization_digest,
  expected_audience: PROGRAM_INPUT.audience,
};
const VERIFIED_PROGRAM = verifyBoundedExecutionProgram(
  PROGRAM_ARTIFACT,
  PROGRAM_VERIFICATION_CONTEXT,
);
assert.equal(VERIFIED_PROGRAM.accepted, true);
if (!VERIFIED_PROGRAM.accepted || VERIFIED_PROGRAM.program === null) {
  throw new Error('reference program verification failed');
}
const VERIFIED_PROGRAM_BODY = VERIFIED_PROGRAM.program;

/** @type {import('../../packages/gate/src/admission-store.ts').ExecutionProgramRuntimeState} */
const RUNTIME_STATE = {
  '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
  tenant_id: PROGRAM_INPUT.tenant_id,
  program_id: PROGRAM_INPUT.program_id,
  program_digest: PROGRAM_DIGEST,
  version: 1,
  status: 'ACTIVE',
  status_sequence: 0,
  status_observed_at: REPORT_START,
  status_expires_at: '2026-07-30T20:45:00.000Z',
  authorizer_id: PROGRAM_SIGNER.issuer_id,
  registered_at: REPORT_START,
  superseded_by_program_digest: null,
  total_occurrences: 2,
  budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 1, reserved: 0, consumed: 1 }],
  program: VERIFIED_PROGRAM_BODY,
};

/**
 * @param {string} occurrenceId
 * @param {string} admissionId
 * @param {import('../../packages/gate/src/admission-store.ts').ExecutionProgramOccurrenceState} state
 * @param {number} minute
 * @returns {import('../../packages/gate/src/admission-store.ts').ExecutionProgramOccurrence}
 */
function occurrence(occurrenceId, admissionId, state, minute) {
  const timestamp = `2026-07-30T20:${String(minute).padStart(2, '0')}:00.000Z`;
  return {
    tenant_id: PROGRAM_INPUT.tenant_id,
    program_digest: PROGRAM_DIGEST,
    node_id: 'inspect',
    occurrence_id: occurrenceId,
    admission_id: admissionId,
    snapshot_digest: digest(`snapshot:${occurrenceId}`),
    state,
    charges: [{ budget_id: 'attempts', amount: 1 }],
    created_at: timestamp,
    updated_at: timestamp,
  };
}

const OCCURRENCES = [
  occurrence('occurrence:inspect:01-released', 'admission:inspect:01', 'RELEASED', 5),
  occurrence('occurrence:inspect:02-committed', 'admission:inspect:02', 'COMMITTED', 10),
];
/** @type {import('../../packages/gate/src/admission-store.ts').ExecutionProgramReportSnapshotBody} */
const SNAPSHOT_BODY = {
  '@version': EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  tenant_id: PROGRAM_INPUT.tenant_id,
  program_digest: PROGRAM_DIGEST,
  runtime_state: RUNTIME_STATE,
  occurrences: OCCURRENCES,
};
const REPORT_SNAPSHOT = {
  ...SNAPSHOT_BODY,
  snapshot_marker: executionProgramReportSnapshotMarker(SNAPSHOT_BODY),
};
const REPORT_INPUT = {
  report_id: 'report:reference-remediation:01',
  relying_party_id: REPORT_SIGNER.relying_party_id,
  report_interval: { start: REPORT_START, end: REPORT_END },
  generated_at: GENERATED_AT,
  verified_program: VERIFIED_PROGRAM,
  report_snapshot: REPORT_SNAPSHOT,
};
const REPORT_ARTIFACT = signBoundedExecutionReport(REPORT_INPUT, REPORT_SIGNER);
const REPORT_VERIFICATION_CONTEXT = {
  trusted_keys: {
    [REPORT_SIGNER.key_id]: {
      issuer_id: REPORT_SIGNER.relying_party_id,
      public_key: publicKey(REPORT_PRIVATE_KEY),
    },
  },
  expected_report_id: REPORT_INPUT.report_id,
  expected_relying_party_id: REPORT_INPUT.relying_party_id,
  expected_tenant_id: PROGRAM_INPUT.tenant_id,
  expected_program_id: PROGRAM_INPUT.program_id,
  expected_program_version: 1,
  expected_program_digest: PROGRAM_DIGEST,
  expected_subject_id: PROGRAM_INPUT.subject_id,
  expected_audience: PROGRAM_INPUT.audience,
  expected_report_interval: REPORT_INPUT.report_interval,
  expected_runtime_state_digest: boundedExecutionRuntimeStateDigest(RUNTIME_STATE),
  expected_occurrence_inventory_digest: boundedExecutionOccurrenceInventoryDigest(OCCURRENCES),
  expected_report_snapshot_marker: REPORT_SNAPSHOT.snapshot_marker,
  now: GENERATED_AT,
  max_report_age_ms: 60_000,
};

const { proof: _proof, ...REPORT_BODY } = clone(REPORT_ARTIFACT);
const REPORT_BODY_JCS = canonicalize(REPORT_BODY);
const SIGNATURE_INPUT = Buffer.from(
  `${BOUNDED_EXECUTION_REPORT_VERSION}\0${REPORT_BODY_JCS}`,
  'utf8',
);

function signRawReportBody(body) {
  return signRiskBody(BOUNDED_EXECUTION_REPORT_VERSION, body, {
    issuer_id: REPORT_SIGNER.relying_party_id,
    key_id: REPORT_SIGNER.key_id,
    private_key: REPORT_PRIVATE_KEY,
  });
}

const tamperedBudget = clone(REPORT_ARTIFACT);
tamperedBudget.budget_usage[0].consumed = 0;
tamperedBudget.budget_usage[0].remaining = 1;
const signedUnknownField = signRawReportBody({ ...REPORT_BODY, complete_mediation: true });
const badSignature = clone(REPORT_ARTIFACT);
badSignature.proof.signature_b64u = `${'A'.repeat(85)}A`;
const badSnapshot = clone(REPORT_SNAPSHOT);
badSnapshot.snapshot_marker = digest('substituted-snapshot-marker');

const SUITE = {
  '@version': 'EP-BOUNDED-EXECUTION-REPORT-REFERENCE-VECTORS-v1',
  status: 'same-team-experimental-reference-vectors',
  vectors_version: '1.0.0',
  claim_boundary: {
    establishes: [
      'deterministic canonical bytes, Ed25519 signature, digest, verifier projection, and hostile outcomes against this repository reference implementation',
      'retained RELEASED history alongside one replacement occurrence under a node max_occurrences of one',
    ],
    does_not_establish: [
      'independent or cross-language conformance, interoperability, standardization, certification, deployment, or production durability',
      'external effect truth, event chronology, program safety, complete mediation, or the absence of outside-Gate actions',
    ],
  },
  known_answer: {
    program_artifact: PROGRAM_ARTIFACT,
    program_verification_context: PROGRAM_VERIFICATION_CONTEXT,
    report_input: REPORT_INPUT,
    report_artifact: REPORT_ARTIFACT,
    report_verification_context: REPORT_VERIFICATION_CONTEXT,
    canonical_signed_body_utf8: REPORT_BODY_JCS,
    canonical_signed_body_b64u: Buffer.from(REPORT_BODY_JCS, 'utf8').toString('base64url'),
    signature_input_b64u: SIGNATURE_INPUT.toString('base64url'),
    signature_b64u: REPORT_ARTIFACT.proof.signature_b64u,
    report_digest: boundedExecutionReportDigest(REPORT_ARTIFACT),
  },
  hostile_mutations: {
    artifact_cases: [
      { id: 'tampered_budget_after_signature', artifact: tamperedBudget, expected_reason: 'digest_mismatch' },
      { id: 'validly_signed_unknown_complete_mediation_field', artifact: signedUnknownField, expected_reason: 'report_schema_invalid' },
      { id: 'malformed_signature', artifact: badSignature, expected_reason: 'signature_invalid' },
    ],
    context_cases: [{
      id: 'snapshot_marker_substitution',
      context_override: { expected_report_snapshot_marker: digest('wrong-context-marker') },
      expected_reason: 'report_snapshot_marker_mismatch',
    }],
    construction_cases: [{
      id: 'snapshot_body_marker_substitution',
      report_snapshot: badSnapshot,
      expected_error_code: 'report_snapshot_marker_invalid',
    }],
  },
};

function validateSuite(suite) {
  const known = suite.known_answer;
  const verifiedProgram = verifyBoundedExecutionProgram(
    known.program_artifact,
    known.program_verification_context,
  );
  assert.equal(verifiedProgram.accepted, true);
  assert.deepEqual(known.report_input.verified_program, verifiedProgram);
  const verifiedReport = verifyBoundedExecutionReport(
    known.report_artifact,
    known.report_verification_context,
  );
  assert.equal(verifiedReport.accepted, true);
  assert.equal(verifiedReport.report_digest, known.report_digest);
  const { proof, ...body } = known.report_artifact;
  assert.equal(canonicalize(body), known.canonical_signed_body_utf8);
  assert.equal(
    Buffer.from(known.canonical_signed_body_utf8, 'utf8').toString('base64url'),
    known.canonical_signed_body_b64u,
  );
  assert.equal(
    Buffer.from(`${BOUNDED_EXECUTION_REPORT_VERSION}\0${known.canonical_signed_body_utf8}`, 'utf8')
      .toString('base64url'),
    known.signature_input_b64u,
  );
  assert.equal(proof.signature_b64u, known.signature_b64u);
  for (const entry of suite.hostile_mutations.artifact_cases) {
    assert.equal(
      verifyBoundedExecutionReport(entry.artifact, known.report_verification_context).reason,
      entry.expected_reason,
      entry.id,
    );
  }
  for (const entry of suite.hostile_mutations.context_cases) {
    assert.equal(verifyBoundedExecutionReport(known.report_artifact, {
      ...known.report_verification_context,
      ...entry.context_override,
    }).reason, entry.expected_reason, entry.id);
  }
  for (const entry of suite.hostile_mutations.construction_cases) {
    assert.throws(() => signBoundedExecutionReport({
      ...known.report_input,
      report_snapshot: entry.report_snapshot,
    }, REPORT_SIGNER), (error) => (
      typeof error === 'object'
      && error !== null
      && 'code' in error
      && error.code === entry.expected_error_code
    ), entry.id);
  }
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
  throw new Error('usage: generate-bounded-execution-report.mjs [--check]');
}

validateSuite(SUITE);
const serialized = `${JSON.stringify(SUITE, null, 2)}\n`;
if (args[0] === '--check') {
  const checkedIn = readFileSync(OUTPUT, 'utf8');
  if (checkedIn !== serialized) {
    console.error('bounded-execution-report.v1.json is stale; regenerate it');
    process.exitCode = 1;
  } else {
    validateSuite(JSON.parse(checkedIn));
    console.log('checked bounded-execution-report.v1.json — known answer and 5 hostile cases');
  }
} else {
  writeFileSync(OUTPUT, serialized);
  console.log('wrote bounded-execution-report.v1.json — known answer and 5 hostile cases');
}
