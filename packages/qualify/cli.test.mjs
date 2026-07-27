// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AGENT_EVALUATION_EVIDENCE_PREDICATE,
  CANDIDATE_MANIFEST_VERSION,
  EVALUATION_CAMPAIGN_PREDICATE,
  IN_TOTO_PAYLOAD_TYPE,
  IN_TOTO_STATEMENT_V1,
  QUALIFICATION_PROPERTY,
  QUALIFICATION_STATEMENT_PREDICATE,
  QUALIFICATION_STATUS_PAYLOAD_TYPE,
  QUALIFICATION_STATUS_VERSION,
  RUNTIME_CANDIDATE_MEASUREMENT_VERSION,
  RUNTIME_MEASUREMENT_PAYLOAD_TYPE,
  TEST_RESULT_PREDICATE,
  canonicalizeQualification,
  dsseSigningBytes,
  qualificationGraphDigest,
  qualificationPayloadDigest,
  terminalOutcomesRoot,
} from '../verify/src/gate-qualification.ts';

const CLI = join(dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const NOW = '2026-07-26T12:00:00Z';

function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function descriptor(name, value) {
  return { name, digest: { sha256: value.slice('sha256:'.length) } };
}

function signer(keyid) {
  return { keyid, ...crypto.generateKeyPairSync('ed25519') };
}

const SIGNERS = {
  campaign: signer('key:campaign'),
  test_result: signer('key:test-result'),
  agent_evidence: signer('key:agent-evidence'),
  qualification_statement: signer('key:qualifier'),
  qualification_status: signer('key:status'),
  runtime_measurement: signer('key:runtime-measurement'),
};

function publicKey(value) {
  return value.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function envelope(body, value, payloadType = IN_TOTO_PAYLOAD_TYPE) {
  const bytes = Buffer.from(canonicalizeQualification(body), 'utf8');
  return {
    payloadType,
    payload: bytes.toString('base64'),
    signatures: [{
      keyid: value.keyid,
      sig: crypto.sign(null, dsseSigningBytes(payloadType, bytes), value.privateKey).toString('base64'),
    }],
  };
}

function payload(value) {
  return JSON.parse(Buffer.from(value.payload, 'base64').toString('utf8'));
}

function resign(value, role, mutate) {
  const body = structuredClone(payload(value));
  mutate(body);
  return envelope(body, SIGNERS[role], value.payloadType);
}

function trust(value) {
  return {
    keys: { [value.keyid]: publicKey(value) },
    accepted_keyids: [value.keyid],
    threshold: 1,
  };
}

function nativeTestResult(manifestDigest, campaign, result, name) {
  return {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [descriptor('candidate-manifest', manifestDigest)],
    predicateType: TEST_RESULT_PREDICATE,
    predicate: {
      result,
      configuration: [
        descriptor('environment', campaign.environment_digest),
        descriptor('evaluator-configuration', campaign.evaluator_configuration_digest),
        descriptor('harness', campaign.harness_digest),
      ],
      ...(result === 'PASSED' ? { passedTests: [name] } : { failedTests: [name] }),
    },
  };
}

function makeFixture() {
  const staticCandidate = {
    code_digests: [digest('code')],
    dependency_digests: [digest('dependency')],
    prompt_template_digests: [digest('prompt')],
    tool_definition_digests: [digest('tool')],
    effective_permissions_digest: digest('permissions'),
    model: {
      provider: 'example.ai',
      identity: 'model-1',
      version: '2026-07-01',
      artifact_digest: digest('model-weights'),
      pinning_strength: 'IMMUTABLE_DIGEST',
    },
    retrieval_configuration_digest: digest('retrieval-config'),
    builder_orchestrator_digest: digest('builder'),
  };
  const manifest = {
    profile: CANDIDATE_MANIFEST_VERSION,
    candidate_id: 'candidate:checkout-agent:v2',
    static: staticCandidate,
  };
  const manifestDigest = qualificationPayloadDigest(manifest);
  const assignmentDigest = digest('assignment');
  const policyDigest = digest('qualification-policy');
  const commitments = [
    digest('hidden-0'),
    digest('hidden-1'),
    digest('hidden-2'),
    digest('hidden-3'),
  ].sort();
  const campaignPredicate = {
    campaign_id: 'campaign:2026-07-26:001',
    candidate_manifest_digest: manifestDigest,
    assignment_digest: assignmentDigest,
    qualification_policy_digest: policyDigest,
    harness_digest: digest('harness'),
    evaluator_configuration_digest: digest('evaluator-config'),
    environment_digest: digest('environment'),
    hidden_challenges: { scheme: 'SALTED_SHA256_SET', commitments },
    scenario_selection_commitment_digest: digest('scenario-selection'),
    planned_batches: 1,
    maximum_batches: 2,
    attempt_ceiling: 2,
    not_before: '2026-07-26T10:00:00Z',
    not_after: '2026-07-26T11:00:00Z',
    predecessor_campaign_payload_digest: null,
  };
  const campaignStatement = {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [descriptor('candidate-manifest', manifestDigest)],
    predicateType: EVALUATION_CAMPAIGN_PREDICATE,
    predicate: campaignPredicate,
  };
  const campaignEnvelope = envelope(campaignStatement, SIGNERS.campaign);
  const campaignDigest = qualificationPayloadDigest(campaignStatement);
  const passStatement = nativeTestResult(manifestDigest, campaignPredicate, 'PASSED', 'challenge-0');
  const failStatement = nativeTestResult(manifestDigest, campaignPredicate, 'FAILED', 'challenge-1');
  const passEnvelope = envelope(passStatement, SIGNERS.test_result);
  const failEnvelope = envelope(failStatement, SIGNERS.test_result);
  const resultDigests = [
    qualificationPayloadDigest(passStatement),
    qualificationPayloadDigest(failStatement),
  ];
  const outcomes = ['PASS', 'FAIL', 'ABORTED', 'EXPIRED'];
  const terminalOutcomes = outcomes.map((outcome, index) => ({
    batch: 1,
    challenge_index: index,
    attempt: 1,
    challenge_commitment: commitments[index],
    challenge_proof: [],
    scenario_selection_commitment_digest: campaignPredicate.scenario_selection_commitment_digest,
    outcome,
    test_result_payload_digest: index < 2 ? resultDigests[index] : null,
    terminal_evidence_payload_digest: index < 2 ? resultDigests[index] : digest(`terminal-${outcome}`),
    started_at: `2026-07-26T10:0${index}:00Z`,
    finished_at: `2026-07-26T10:0${index}:30Z`,
  }));
  const evidencePredicate = {
    campaign_payload_digest: campaignDigest,
    candidate_manifest_digest: manifestDigest,
    assignment_digest: assignmentDigest,
    qualification_policy_digest: policyDigest,
    completed_batches: 1,
    issued_challenges: terminalOutcomes.length,
    terminal_outcomes: terminalOutcomes,
    outcome_counts: { PASS: 1, FAIL: 1, ABORTED: 1, EXPIRED: 1 },
    terminal_outcomes_root: terminalOutcomesRoot(terminalOutcomes),
    measurements: [
      { name: 'latency-p95', value: '740', unit: 'ms' },
      { name: 'policy-score', value: '0.98', unit: null },
    ],
    started_at: '2026-07-26T10:00:00Z',
    completed_at: '2026-07-26T10:10:00Z',
  };
  const evidenceStatement = {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [descriptor('candidate-manifest', manifestDigest)],
    predicateType: AGENT_EVALUATION_EVIDENCE_PREDICATE,
    predicate: evidencePredicate,
  };
  const evidenceEnvelope = envelope(evidenceStatement, SIGNERS.agent_evidence);
  const evidenceDigest = qualificationPayloadDigest(evidenceStatement);
  const graphDigest = qualificationGraphDigest({
    campaign_payload_digests: [campaignDigest],
    test_result_payload_digests: [...resultDigests].sort(),
    agent_evaluation_evidence_payload_digests: [evidenceDigest],
  });
  const qualificationStatement = {
    _type: IN_TOTO_STATEMENT_V1,
    subject: [
      descriptor('candidate-manifest', manifestDigest),
      descriptor('evaluation-campaign', campaignDigest),
      descriptor('qualification-graph', graphDigest),
    ],
    predicateType: QUALIFICATION_STATEMENT_PREDICATE,
    predicate: {
      verifier: {
        id: 'https://qualifier.example/v2',
        policies: [
          descriptor('assignment', assignmentDigest),
          descriptor('qualification-policy', policyDigest),
        ],
      },
      timeCreated: '2026-07-26T10:15:00Z',
      properties: [QUALIFICATION_PROPERTY],
    },
  };
  const qualificationEnvelope = envelope(qualificationStatement, SIGNERS.qualification_statement);
  const qualificationDigest = qualificationPayloadDigest(qualificationStatement);
  const status = {
    profile: QUALIFICATION_STATUS_VERSION,
    authority_id: 'authority:qualification:primary',
    qualification_statement_payload_digest: qualificationDigest,
    candidate_manifest_digest: manifestDigest,
    assignment_digest: assignmentDigest,
    qualification_policy_digest: policyDigest,
    status: 'QUALIFIED',
    sequence: 0,
    previous_status_payload_digest: null,
    issued_at: '2026-07-26T10:16:00Z',
    next_update: '2026-07-26T12:05:00Z',
    valid_until: '2026-07-27T00:00:00Z',
  };
  const statusEnvelope = envelope(
    status,
    SIGNERS.qualification_status,
    QUALIFICATION_STATUS_PAYLOAD_TYPE,
  );
  const runtime = {
    profile: RUNTIME_CANDIDATE_MEASUREMENT_VERSION,
    measurement_id: 'measurement:runtime:001',
    authority_id: 'authority:runtime-measurement:primary',
    measurement_mechanism_digest: digest('runtime-measurement-mechanism'),
    candidate_manifest_digest: manifestDigest,
    assignment_digest: assignmentDigest,
    measured_at: '2026-07-26T11:59:30Z',
    candidate_influence_cutoff: '2026-07-26T11:59:45Z',
    remains_in_execution_path: true,
    static: structuredClone(staticCandidate),
    dynamic_retrieval_root: digest('dynamic-retrieval'),
    memory_state_snapshot_digest: digest('memory'),
    user_input_digest: digest('user-input'),
    protected_request_digest: digest('protected-request'),
  };
  const bundle = {
    candidate_manifest: manifest,
    campaigns: [campaignEnvelope],
    test_results: [passEnvelope, failEnvelope],
    agent_evaluation_evidence: [evidenceEnvelope],
    qualification_statement: qualificationEnvelope,
    qualification_status_chain: [statusEnvelope],
    qualification_status_observation: {
      authority_id: status.authority_id,
      head_payload_digest: qualificationPayloadDigest(status),
      sequence: 0,
      observed_at: '2026-07-26T11:59:50Z',
    },
    runtime_measurement: envelope(
      runtime,
      SIGNERS.runtime_measurement,
      RUNTIME_MEASUREMENT_PAYLOAD_TYPE,
    ),
  };
  const context = {
    now: NOW,
    expected_candidate_manifest_digest: manifestDigest,
    expected_assignment_digest: assignmentDigest,
    expected_qualification_policy_digest: policyDigest,
    expected_protected_request_digest: runtime.protected_request_digest,
    expected_runtime_measurement_authority_id: runtime.authority_id,
    expected_runtime_measurement_mechanism_digest: runtime.measurement_mechanism_digest,
    expected_status_authority_id: status.authority_id,
    minimum_status_sequence: 0,
    max_status_observation_age_seconds: 60,
    max_runtime_measurement_age_seconds: 60,
    minimum_model_pinning_strength: 'VERSION_PINNED',
    trust: {
      campaign: trust(SIGNERS.campaign),
      test_result: trust(SIGNERS.test_result),
      agent_evidence: trust(SIGNERS.agent_evidence),
      qualification_statement: trust(SIGNERS.qualification_statement),
      qualification_status: trust(SIGNERS.qualification_status),
      runtime_measurement: trust(SIGNERS.runtime_measurement),
    },
  };
  return { bundle, context };
}

function replaceStatus(fixture, status) {
  fixture.bundle.qualification_status_chain[0] = resign(
    fixture.bundle.qualification_status_chain[0],
    'qualification_status',
    (body) => { body.status = status; },
  );
  fixture.bundle.qualification_status_observation.head_payload_digest = qualificationPayloadDigest(
    payload(fixture.bundle.qualification_status_chain[0]),
  );
}

function tempPath(name) {
  return join(mkdtempSync(join(tmpdir(), 'ep-qualify-')), name);
}

function runPath(path) {
  const result = spawnSync(process.execPath, [CLI, path], { encoding: 'utf8' });
  const lines = result.stdout.trimEnd().split('\n');
  let detail = null;
  try { detail = JSON.parse(lines[1]); } catch { /* asserted by each test */ }
  return {
    code: result.status,
    lines,
    detail,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function runDocument(document) {
  const path = tempPath('qualification.json');
  writeFileSync(path, JSON.stringify(document));
  return { path, output: runPath(path) };
}

function runRaw(raw) {
  const path = tempPath('qualification.json');
  writeFileSync(path, raw);
  return runPath(path);
}

function assertDecision(output, decision, reason, code) {
  assert.equal(output.code, code, output.stdout + output.stderr);
  assert.equal(output.stderr, '');
  assert.equal(output.lines.length, 2, output.stdout);
  assert.equal(output.lines[0], decision);
  assert.equal(output.detail?.decision, decision);
  assert.equal(output.detail?.reason, reason);
}

test('valid fixture -> QUALIFIED, exact two-line output, exit 0, and no input mutation', () => {
  const fixture = makeFixture();
  const path = tempPath('qualification.json');
  const raw = JSON.stringify(fixture);
  writeFileSync(path, raw);

  const output = runPath(path);

  assertDecision(output, 'QUALIFIED', 'qualified', 0);
  assert.equal(output.detail.verification, 'VERIFIED');
  assert.equal(output.detail.acceptance, 'ACCEPTED');
  assert.equal(readFileSync(path, 'utf8'), raw);
});

test('tampered signed artifact fails closed and never exits 0', () => {
  const fixture = makeFixture();
  const signature = fixture.bundle.campaigns[0].signatures[0].sig;
  fixture.bundle.campaigns[0].signatures[0].sig = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;

  const { output } = runDocument(fixture);

  assertDecision(output, 'INDETERMINATE', 'invalid_artifact_signature', 1);
  assert.equal(output.detail.verification, 'NOT_VERIFIED');
});

test('stale and revoked status are distinguishable but both fail closed', () => {
  const stale = makeFixture();
  stale.bundle.qualification_status_observation.observed_at = '2026-07-26T11:00:00Z';
  assertDecision(
    runDocument(stale).output,
    'INDETERMINATE',
    'qualification_status_stale',
    1,
  );

  const revoked = makeFixture();
  replaceStatus(revoked, 'REVOKED');
  const output = runDocument(revoked).output;
  assertDecision(output, 'NOT_QUALIFIED', 'qualification_revoked', 1);
  assert.equal(output.detail.currentness, 'REVOKED');
});

test('well-formed but invalid evaluation input remains INDETERMINATE', () => {
  const { output } = runDocument({ bundle: {}, context: {} });
  assertDecision(output, 'INDETERMINATE', 'invalid_evaluation_context', 1);
});

test('malformed and duplicate-member JSON are rejected before interpretation', () => {
  assertDecision(runRaw('{"bundle":'), 'INDETERMINATE', 'malformed_json', 1);

  const duplicate = runRaw('{"bundle":{},"bundle":{"candidate_manifest":"attacker"},"context":{}}');
  assertDecision(duplicate, 'INDETERMINATE', 'malformed_json', 1);
  assert.match(duplicate.detail.error, /duplicate object member/i);
});

test('top-level input is exactly {bundle, context}', () => {
  const fixture = makeFixture();
  const output = runDocument({ ...fixture, authorize: true }).output;
  assertDecision(output, 'INDETERMINATE', 'invalid_cli_input', 1);
});

test('input larger than 8 MiB is refused before JSON parsing', () => {
  const path = tempPath('oversized.json');
  writeFileSync(path, '');
  truncateSync(path, MAX_INPUT_BYTES + 1);

  const output = runPath(path);

  assertDecision(output, 'INDETERMINATE', 'input_too_large', 1);
});

test('trust is never inferred when context.trust is absent', () => {
  const fixture = makeFixture();
  delete fixture.context.trust;
  const { output } = runDocument(fixture);

  assertDecision(output, 'INDETERMINATE', 'invalid_evaluation_context', 1);
  assert.equal(output.detail.acceptance, 'NOT_ACCEPTED');
});
