// SPDX-License-Identifier: Apache-2.0
//
// EP-BOUNDED-EXECUTION-REPORT-v2 hybrid profile test. Builds a REAL Ed25519 +
// ML-DSA-65 signed bounded-execution report over a fully verified program and
// runs the hostile matrix (leg stripping both ways, set narrowing structural +
// independent crypto.verify, widening, duplicate alg, Ed448 masquerade,
// relabelling, swapped legs, PQ key substitution, tamper after signing), plus
// domain refusals (expected-tuple / freshness), the v1-refuses-v2 capture, and
// a v1 byte-identity regression.
//
// The PQ leg runs for real; this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';

import {
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  EXECUTION_PROGRAM_RUNTIME_VERSION,
  executionProgramReportSnapshotMarker,
  type ExecutionProgramOccurrence,
  type ExecutionProgramReportSnapshot,
  type ExecutionProgramRuntimeState,
} from './admission-store.js';
import {
  executionProgramDigest,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
} from './bounded-execution-program.js';
import {
  BOUNDED_EXECUTION_REPORT_V2_VERSION,
  boundedExecutionOccurrenceInventoryDigest,
  boundedExecutionRuntimeStateDigest,
  signBoundedExecutionReport,
  signBoundedExecutionReportV2,
  verifyBoundedExecutionReport,
  verifyBoundedExecutionReportV2,
} from './bounded-execution-report.js';
import { canonicalize } from './execution-binding.js';
import { RISK_HYBRID_PROFILE } from './reliance-risk-crypto.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => `caid:1:devops.infrastructure-change.1:jcs-sha256:${character.repeat(43)}`;
const PROGRAM_NOW = '2026-07-29T20:00:00.000Z';
const REPORT_END = '2026-07-29T20:30:00.000Z';
const GENERATED_AT = '2026-07-29T20:35:00.000Z';
const mutable = (x: unknown): any => JSON.parse(JSON.stringify(x));

function keyMaterial(issuerId: string, keyId: string) {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    pair, publicKey,
    signer: { issuer_id: issuerId, key_id: keyId, private_key: pair.privateKey },
    trusted_keys: { [keyId]: { issuer_id: issuerId, public_key: publicKey } },
  };
}

function reporterMaterial(issuerId: string, keyId: string) {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pqPub = Buffer.from(pq.publicKey).toString('base64url');
  return {
    pair, pq, publicKey, pqPub,
    signerV1: { relying_party_id: issuerId, key_id: keyId, private_key: pair.privateKey },
    signerV2: { relying_party_id: issuerId, key_id: keyId, private_key: pair.privateKey, pq_private_key: Buffer.from(pq.secretKey).toString('base64url') },
    trusted_keys_v1: { [keyId]: { issuer_id: issuerId, public_key: publicKey } },
    trusted_keys_v2: { [keyId]: { issuer_id: issuerId, public_key: publicKey, pq_public_key: pqPub } },
  };
}

function programInput() {
  return {
    program_id: 'program:production-remediation:01',
    tenant_id: 'tenant:example',
    version: 1,
    subject_id: 'agent:operations:01',
    audience: 'gate:production:01',
    objective_digest: D('1'),
    authorization_digest: D('2'),
    presentation_digest: D('3'),
    supersedes_program_digest: null,
    issued_at: '2026-07-29T19:55:00.000Z',
    valid_from: PROGRAM_NOW,
    expires_at: '2026-07-29T21:00:00.000Z',
    max_total_occurrences: 7,
    max_concurrent_effects: 2,
    budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 10 }],
    nodes: [
      { node_id: 'inspect', action: { mode: 'exact', caid: C('A'), action_digest: D('a') }, trust_program_digest: D('4'), depends_on: [], max_occurrences: 3, charges: [{ budget_id: 'attempts', amount: 1 }] },
      { node_id: 'notify', action: { mode: 'exact', caid: C('D'), action_digest: D('d') }, trust_program_digest: D('7'), depends_on: [{ node_id: 'verify', outcomes: ['COMMITTED'] as const }], max_occurrences: 1, charges: [{ budget_id: 'attempts', amount: 1 }] },
      { node_id: 'remediate', action: { mode: 'exact', caid: C('B'), action_digest: D('b') }, trust_program_digest: D('5'), depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] as const }], max_occurrences: 2, charges: [{ budget_id: 'attempts', amount: 1 }] },
      { node_id: 'verify', action: { mode: 'exact', caid: C('C'), action_digest: D('c') }, trust_program_digest: D('6'), depends_on: [{ node_id: 'remediate', outcomes: ['COMMITTED'] as const }], max_occurrences: 2, charges: [{ budget_id: 'attempts', amount: 1 }] },
    ],
  };
}

function occurrence(nodeId: string, occurrenceId: string, state: ExecutionProgramOccurrence['state'], minute: number): ExecutionProgramOccurrence {
  const timestamp = `2026-07-29T20:${String(minute).padStart(2, '0')}:00.000Z`;
  return {
    tenant_id: 'tenant:example', program_digest: D('0'), node_id: nodeId, occurrence_id: occurrenceId,
    admission_id: `admission:${occurrenceId}`, snapshot_digest: D(String((minute % 9) + 1)), state,
    charges: [{ budget_id: 'attempts', amount: 1 }], created_at: timestamp, updated_at: timestamp,
  };
}

function reportSnapshot(runtimeState: ExecutionProgramRuntimeState, occurrences: ExecutionProgramOccurrence[]): ExecutionProgramReportSnapshot {
  const ordered = [...occurrences].sort((left, right) => (
    Buffer.compare(Buffer.from(left.node_id), Buffer.from(right.node_id))
      || Buffer.compare(Buffer.from(left.occurrence_id), Buffer.from(right.occurrence_id))
  ));
  const body = {
    '@version': EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
    tenant_id: runtimeState.tenant_id, program_digest: runtimeState.program_digest,
    runtime_state: runtimeState, occurrences: ordered,
  } as const;
  return { ...body, snapshot_marker: executionProgramReportSnapshotMarker(body) };
}

function baseHarness() {
  const authorizer = keyMaterial('customer:example-security', 'key:customer-program-authorizer');
  const programArtifact = signBoundedExecutionProgram(programInput(), authorizer.signer);
  const programDigest = executionProgramDigest(programArtifact);
  const verifiedProgram = verifyBoundedExecutionProgram(programArtifact, {
    trusted_keys: authorizer.trusted_keys, now: PROGRAM_NOW,
    expected_program_id: programInput().program_id, expected_tenant_id: programInput().tenant_id,
    expected_authorizer_id: authorizer.signer.issuer_id, expected_authorization_digest: programInput().authorization_digest,
    expected_audience: programInput().audience,
  });
  assert.equal(verifiedProgram.accepted, true);
  const runtimeState: ExecutionProgramRuntimeState = {
    '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
    tenant_id: verifiedProgram.program.tenant_id, program_id: verifiedProgram.program.program_id,
    program_digest: programDigest, version: verifiedProgram.program.version, status: 'ACTIVE',
    status_sequence: 0, status_observed_at: PROGRAM_NOW, status_expires_at: '2026-07-29T20:45:00.000Z',
    authorizer_id: verifiedProgram.authorizer_id, registered_at: PROGRAM_NOW,
    superseded_by_program_digest: null, total_occurrences: 6,
    budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 10, reserved: 1, consumed: 4 }],
    program: verifiedProgram.program,
  };
  const occurrences: ExecutionProgramOccurrence[] = [
    occurrence('remediate', 'occurrence:remediate:indeterminate', 'INDETERMINATE', 14),
    occurrence('inspect', 'occurrence:inspect:released', 'RELEASED', 8),
    occurrence('verify', 'occurrence:verify:reserved', 'RESERVED', 18),
    occurrence('inspect', 'occurrence:inspect:proven-not-committed', 'PROVEN_NOT_COMMITTED', 6),
    occurrence('remediate', 'occurrence:remediate:invoking', 'INVOKING', 12),
    occurrence('inspect', 'occurrence:inspect:committed', 'COMMITTED', 4),
  ].map((entry) => ({ ...entry, program_digest: programDigest }));
  const reporter = reporterMaterial('rp:example-operations', 'key:rp:bounded-report:v2');
  const input = {
    report_id: 'report:bounded-execution:2026-07-29:01',
    relying_party_id: reporter.signerV2.relying_party_id,
    report_interval: { start: PROGRAM_NOW, end: REPORT_END },
    generated_at: GENERATED_AT,
    verified_program: verifiedProgram,
    report_snapshot: reportSnapshot(runtimeState, occurrences),
  };
  const contextCommon = {
    expected_report_id: input.report_id,
    expected_relying_party_id: input.relying_party_id,
    expected_tenant_id: runtimeState.tenant_id,
    expected_program_id: runtimeState.program_id,
    expected_program_version: runtimeState.version,
    expected_program_digest: runtimeState.program_digest,
    expected_subject_id: verifiedProgram.program.subject_id,
    expected_audience: verifiedProgram.program.audience,
    expected_report_interval: input.report_interval,
    expected_runtime_state_digest: boundedExecutionRuntimeStateDigest(runtimeState),
    expected_occurrence_inventory_digest: boundedExecutionOccurrenceInventoryDigest(occurrences),
    expected_report_snapshot_marker: input.report_snapshot.snapshot_marker,
    now: '2026-07-29T20:36:00.000Z',
    max_report_age_ms: 10 * 60 * 1000,
  };
  return {
    reporter, input,
    v2Context: { trusted_keys: reporter.trusted_keys_v2, ...contextCommon },
    v1Context: { trusted_keys: reporter.trusted_keys_v1, ...contextCommon },
  };
}

async function harnessV2() {
  const h = baseHarness();
  const artifact = await signBoundedExecutionReportV2(h.input, h.reporter.signerV2);
  return { ...h, artifact };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

// --- happy path ---------------------------------------------------------------

test('a real hybrid report verifies under both pinned keys', async () => {
  const { artifact, v2Context } = await harnessV2();
  const res: any = await verifyBoundedExecutionReportV2(artifact, v2Context as any);
  assert.equal(res.accepted, true, res.reason ?? '');
  assert.equal(res.verified, true);
});

test('the proof carries the set shape and committed set', async () => {
  const { artifact } = await harnessV2();
  const a = artifact as any;
  assert.equal(a['@version'], BOUNDED_EXECUTION_REPORT_V2_VERSION);
  assert.equal(a.proof.profile, RISK_HYBRID_PROFILE);
  assert.deepEqual(a.proof.signatures.map((s: any) => s.alg), ['Ed25519', 'ML-DSA-65']);
});

// --- v1 / v2 compatibility ----------------------------------------------------

test('the v1 verifier refuses a v2 report (version/envelope marker)', async () => {
  const { artifact, v1Context } = await harnessV2();
  const res: any = verifyBoundedExecutionReport(artifact, v1Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'artifact_signature_envelope_invalid');
});

test('v1 signing is byte-identical and still verifies (regression)', () => {
  const h = baseHarness();
  const v1Signer = { relying_party_id: h.reporter.signerV1.relying_party_id, key_id: h.reporter.signerV1.key_id, private_key: h.reporter.signerV1.private_key };
  const a: any = signBoundedExecutionReport(h.input, v1Signer);
  const b: any = signBoundedExecutionReport(h.input, v1Signer);
  assert.equal(a.proof.algorithm, 'Ed25519');
  assert.equal(a.proof.signature_b64u, b.proof.signature_b64u);
  const res: any = verifyBoundedExecutionReport(a, h.v1Context as any);
  assert.equal(res.accepted, true, res.reason ?? '');
});

// --- anti-stripping -----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  a.proof.signatures = a.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_set_incomplete');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  a.proof.signatures = a.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_set_incomplete');
});

test('SET NARROWING fails structurally AND cryptographically', async () => {
  const { artifact, v2Context, reporter } = await harnessV2();
  const a = mutable(artifact);
  a.proof.required_algorithms = ['Ed25519'];
  const survivingEd = a.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  a.proof.signatures = [survivingEd];
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'algorithm_set_invalid');

  const { proof: _p, ...body } = a;
  const narrowedBytes = Buffer.from(canonicalize({ profile: RISK_HYBRID_PROFILE, required_algorithms: ['Ed25519'], version: BOUNDED_EXECUTION_REPORT_V2_VERSION, body }), 'utf8');
  assert.equal(crypto.verify(null, narrowedBytes, reporter.pair.publicKey, Buffer.from(survivingEd.sig, 'base64url')), false);
});

test('SET WIDENING refuses', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  a.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'algorithm_set_invalid');
});

test('DUPLICATE ALGORITHM refuses', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  const edLeg = a.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  a.proof.signatures = [edLeg, edLeg];
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_set_invalid');
});

// --- masquerade ---------------------------------------------------------------

test('ED448 MASQUERADE refuses', async () => {
  const { artifact, v2Context } = await harnessV2();
  const ed448 = generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const kid = Object.keys(v2Context.trusted_keys)[0];
  const ctx = mutable(v2Context);
  ctx.trusted_keys[kid].public_key = ed448Pub;
  const res: any = await verifyBoundedExecutionReportV2(artifact, ctx);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'pinned_key_invalid');
});

test('ALGORITHM RELABELLING refuses (closed registry)', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  a.proof.signatures = a.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_set_invalid');
});

test('SWAPPED LEGS refuse', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  const pqLeg = a.proof.signatures.find((s: any) => s.alg === 'ML-DSA-65');
  a.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_invalid');
});

// --- pinning ------------------------------------------------------------------

test('PQ KEY SUBSTITUTION refuses', async () => {
  const { artifact, v2Context } = await harnessV2();
  const other = ml_dsa65.keygen(crypto.randomBytes(32));
  const kid = Object.keys(v2Context.trusted_keys)[0];
  const ctx = mutable(v2Context);
  ctx.trusted_keys[kid].pq_public_key = Buffer.from(other.publicKey).toString('base64url');
  const res: any = await verifyBoundedExecutionReportV2(artifact, ctx);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'signature_invalid');
});

test('unpinned relying party is untrusted', async () => {
  const { artifact, v2Context } = await harnessV2();
  const ctx = mutable(v2Context);
  ctx.trusted_keys = { 'key:other': { issuer_id: 'rp:other', public_key: v2Context.trusted_keys[Object.keys(v2Context.trusted_keys)[0]].public_key, pq_public_key: v2Context.trusted_keys[Object.keys(v2Context.trusted_keys)[0]].pq_public_key } };
  const res: any = await verifyBoundedExecutionReportV2(artifact, ctx);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'issuer_untrusted');
});

// --- binding + domain refusals ------------------------------------------------

test('TAMPERED AFTER SIGNING breaks the binding', async () => {
  const { artifact, v2Context } = await harnessV2();
  const a = mutable(artifact);
  a.status = a.status === 'ACTIVE' ? 'REVOKED' : 'ACTIVE';
  const res: any = await verifyBoundedExecutionReportV2(a, v2Context as any);
  assert.equal(res.accepted, false);
});

test('expected report-id mismatch refuses on context', async () => {
  const { artifact, v2Context } = await harnessV2();
  const res: any = await verifyBoundedExecutionReportV2(artifact, { ...v2Context, expected_report_id: 'report:other' } as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'report_id_mismatch');
});

test('stale report refuses', async () => {
  const { artifact, v2Context } = await harnessV2();
  const res: any = await verifyBoundedExecutionReportV2(artifact, { ...v2Context, now: '2026-07-29T21:30:00.000Z' } as any);
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'report_stale');
});

// --- fail-closed backend ------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const { artifact, v2Context } = await harnessV2();
  const res: any = await verifyBoundedExecutionReportV2(artifact, v2Context as any, { mldsaBackendLoader: async () => null });
  assert.equal(res.accepted, false);
  assert.equal(res.reason, 'pq_backend_unavailable');
});

// --- fail-closed on junk ------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  const { v2Context } = await harnessV2();
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res: any = await verifyBoundedExecutionReportV2(junk, v2Context as any);
    assert.equal(res.accepted, false);
  }
});
