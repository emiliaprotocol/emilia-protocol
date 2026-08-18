// SPDX-License-Identifier: Apache-2.0
//
// EP-AUTHORITY-PROGRAM-v2 / EP-AUTHORITY-STAGE-RECEIPT-v2 hybrid verifier
// test. Copies the hostile matrix of the reference migration
// (revocation-v2.test.ts): leg stripping both directions, set narrowing
// (structural + independent crypto.verify over the narrowed bytes), duplicate
// algorithm, an Ed448 SPKI masquerading as the Ed25519 half, wrong-length
// signatures, plus the old-verifier-refuses-new capture and a valid hybrid
// roundtrip over a single-stage program.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { canonicalize } from './index.js';
import {
  AUTHORITY_PROGRAM_VERSION,
  authorityProgramDigest,
  verifyAuthorityProgram,
} from './authority-program.js';
import {
  AUTHORITY_PROGRAM_V2_VERSION,
  AUTHORITY_STAGE_RECEIPT_V2_VERSION,
  AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS,
  authorityProgramDigestV2,
  authorityStageReceiptDigestV2,
  signAuthorityProgramV2,
  signAuthorityStageReceiptV2,
  verifyAuthorityProgramV2,
  verifyAuthorityProgramAny,
} from './authority-program.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const digest = (label: string): string => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;

const rootAction = {
  action_type: 'payment.release.1',
  amount: '250.00',
  currency: 'EUR',
  beneficiary_account: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  payment_instruction_id: 'pi-authority-program-v2-0001',
};
function rootActionBinding() {
  const hash = crypto.createHash('sha256').update(canonicalize(rootAction), 'utf8').digest();
  return {
    valid: true,
    root_caid: `caid:1:${rootAction.action_type}:jcs-sha256:${hash.toString('base64url')}`,
    root_action_digest: `sha256:${hash.toString('hex')}`,
  };
}

const programEd = crypto.generateKeyPairSync('ed25519');
const programPq = ml_dsa65.keygen(crypto.randomBytes(32));
const stageEd = crypto.generateKeyPairSync('ed25519');
const stagePq = ml_dsa65.keygen(crypto.randomBytes(32));

function b64u(k: crypto.KeyPairKeyObjectResult['publicKey']): string {
  return k.export({ type: 'spki', format: 'der' }).toString('base64url');
}
const pqB64u = (pk: Uint8Array) => Buffer.from(pk).toString('base64url');
const pqSecretB64u = (sk: Uint8Array) => Buffer.from(sk).toString('base64url');

function programSigners() {
  return [
    { alg: 'Ed25519', private_key: programEd.privateKey, key_id: 'key:program' },
    { alg: 'ML-DSA-65', private_key: pqSecretB64u(programPq.secretKey), key_id: 'key:program' },
  ];
}
function stageSigners() {
  return [
    { alg: 'Ed25519', private_key: stageEd.privateKey, key_id: 'key:alpha' },
    { alg: 'ML-DSA-65', private_key: pqSecretB64u(stagePq.secretKey), key_id: 'key:alpha' },
  ];
}

function stageNode() {
  return {
    type: 'stage',
    stage_id: 'stage-a',
    authority: { organization_id: 'org:alpha', key_id: 'key:alpha' },
    aec_requirement_digest: digest('stage-a:aec:requirement'),
    aom_requirement_digest: digest('stage-a:aom:requirement'),
    capability_requirement_digest: digest('stage-a:capability:requirement'),
  };
}

async function buildProgramV2() {
  const root = rootActionBinding();
  return signAuthorityProgramV2({
    program_id: 'authority-program:purchase-release:v2',
    root_caid: root.root_caid,
    root_action_digest: root.root_action_digest,
    expression: stageNode(),
  }, 'org:governance', 'key:program', programSigners());
}

async function buildReceiptV2(program: any) {
  return signAuthorityStageReceiptV2({
    receipt_id: 'authority-stage-receipt:stage-a:v2',
    program_digest: authorityProgramDigestV2(program),
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
    stage_id: 'stage-a',
    issuer: { organization_id: 'org:alpha', key_id: 'key:alpha' },
    predecessor_receipt_digests: [],
    aec: { requirement_digest: digest('stage-a:aec:requirement'), result_digest: digest('stage-a:aec:result') },
    aom: { requirement_digest: digest('stage-a:aom:requirement'), result_digest: digest('stage-a:aom:result') },
    capability: {
      requirement_digest: digest('stage-a:capability:requirement'),
      input_digest: digest('stage-a:capability:input'),
      output_digest: digest('stage-a:capability:output'),
    },
  }, 'key:alpha', stageSigners());
}

function optionsFor(program: any) {
  return {
    programPin: {
      digest: authorityProgramDigestV2(program),
      organization_id: 'org:governance',
      key_id: 'key:program',
      public_key: b64u(programEd.publicKey),
      pq_public_key: pqB64u(programPq.publicKey),
    },
    stageKeys: {
      'org:alpha': { 'key:alpha': { public_key: b64u(stageEd.publicKey), pq_public_key: pqB64u(stagePq.publicKey) } },
    },
    verifyAec: ({ stage_id }: any) => ({
      valid: true, requirement_digest: digest(`${stage_id}:aec:requirement`), result_digest: digest(`${stage_id}:aec:result`),
    }),
    verifyAom: ({ stage_id }: any) => ({
      valid: true, requirement_digest: digest(`${stage_id}:aom:requirement`), result_digest: digest(`${stage_id}:aom:result`),
    }),
    verifyCapabilityNarrowing: ({ stage_id }: any) => ({
      valid: true, narrowed: true,
      requirement_digest: digest(`${stage_id}:capability:requirement`),
      input_digest: digest(`${stage_id}:capability:input`),
      output_digest: digest(`${stage_id}:capability:output`),
    }),
    verifyRootActionBinding: rootActionBinding,
  };
}

async function build() {
  const program = await buildProgramV2();
  const receipt = await buildReceiptV2(program);
  return { program, receipt };
}

// --- honesty gate --------------------------------------------------------

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});

// --- happy path ------------------------------------------------------------

test('a real hybrid program + stage receipt verifies under both pinned keys (valid roundtrip)', async () => {
  const { program, receipt } = await build();
  assert.equal(program['@version'], AUTHORITY_PROGRAM_V2_VERSION);
  assert.equal(receipt['@version'], AUTHORITY_STAGE_RECEIPT_V2_VERSION);
  const res = await verifyAuthorityProgramV2(program, [receipt], optionsFor(program));
  assert.equal(res.valid, true, res.reason);
});

// --- old-verifier-refuses-new -----------------------------------------------

test('the v1 (classical) verifier refuses a v2 hybrid program cleanly on the version marker', async () => {
  const { program, receipt } = await build();
  const res = verifyAuthorityProgram(program, [receipt], {} as any);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_envelope');
});

test('the v2 verifier refuses a v1 (classical) program on the version marker', async () => {
  const v1Body = {
    '@version': AUTHORITY_PROGRAM_VERSION,
    program_id: 'authority-program:v1',
    root_caid: rootActionBinding().root_caid,
    root_action_digest: rootActionBinding().root_action_digest,
    expression: stageNode(),
    proof: { algorithm: 'Ed25519', organization_id: 'org:governance', key_id: 'key:program', signature_b64u: 'A'.repeat(86) + '==' },
  };
  const res = await verifyAuthorityProgramV2(v1Body, [], optionsFor(v1Body));
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_envelope');
});

test('verifyAuthorityProgramAny routes on the program version', async () => {
  const { program, receipt } = await build();
  assert.equal((await verifyAuthorityProgramAny(program, [receipt], optionsFor(program) as any)).valid, true);
});

// --- anti-stripping ----------------------------------------------------------

test('LEG STRIPPING: removing the ML-DSA leg from the program proof refuses (structural: the closed set shape requires both legs present)', async () => {
  const { program, receipt } = await build();
  const stripped: any = structuredClone(program);
  stripped.proof.signatures = stripped.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyAuthorityProgramV2(stripped, [receipt], optionsFor(program));
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_envelope');
});

test('LEG STRIPPING: removing the ML-DSA leg from the stage receipt proof refuses (structural)', async () => {
  const { program, receipt } = await build();
  const stripped: any = structuredClone(receipt);
  stripped.proof.signatures = stripped.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const res = await verifyAuthorityProgramV2(program, [stripped], optionsFor(program));
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_stage_receipt');
});

test('SET NARROWING: narrowing the program required_algorithms to Ed25519-only refuses structurally and cryptographically', async () => {
  const { program, receipt } = await build();
  const narrowed: any = structuredClone(program);
  narrowed.proof.required_algorithms = ['Ed25519'];
  const res = await verifyAuthorityProgramV2(narrowed, [receipt], optionsFor(program));
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_envelope');

  // Independent cryptographic half: the surviving Ed25519 signature was made
  // over bytes committing to the FULL set.
  const { proof, ...unsigned } = program as any;
  const narrowedBytes = Buffer.from(
    `${AUTHORITY_PROGRAM_V2_VERSION}\0${canonicalize({ ...unsigned, required_algorithms: ['Ed25519'] })}`,
    'utf8',
  );
  const survivingSig = Buffer.from(proof.signatures.find((s: any) => s.alg === 'Ed25519').sig, 'base64url');
  assert.equal(crypto.verify(null, narrowedBytes, programEd.publicKey, survivingSig), false);
});

test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
  const { program, receipt } = await build();
  const dup: any = structuredClone(program);
  dup.proof.signatures = [dup.proof.signatures[0], dup.proof.signatures[0]];
  const res = await verifyAuthorityProgramV2(dup, [receipt], optionsFor(program));
  assert.equal(res.valid, false);
});

// --- wrong-length signature ---------------------------------------------------

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg on the program refuses', async () => {
  const { program, receipt } = await build();
  const truncated: any = structuredClone(program);
  const leg = truncated.proof.signatures.find((s: any) => s.alg === 'Ed25519');
  leg.sig = Buffer.from(leg.sig, 'base64url').subarray(0, 10).toString('base64url');
  const res = await verifyAuthorityProgramV2(truncated, [receipt], optionsFor(program));
  assert.equal(res.valid, false);
});

// --- masquerade ----------------------------------------------------------------

test('ED448 MASQUERADE: an Ed448 SPKI pinned as the program Ed25519 half refuses', async () => {
  const { program, receipt } = await build();
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const options = optionsFor(program);
  (options.programPin as any).public_key = ed448Pub;
  const res = await verifyAuthorityProgramV2(program, [receipt], options);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_signature');
});

// --- pinning ---------------------------------------------------------------

test('pinning the program Ed25519 half but omitting pq_public_key refuses (both halves required)', async () => {
  const { program, receipt } = await build();
  const options = optionsFor(program) as any;
  delete options.programPin.pq_public_key;
  const res = await verifyAuthorityProgramV2(program, [receipt], options);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_pin');
});

test('an unpinned stage authority confers nothing', async () => {
  const { program, receipt } = await build();
  const options = optionsFor(program);
  options.stageKeys = {};
  const res = await verifyAuthorityProgramV2(program, [receipt], options);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_stage_signature');
});

// --- fail-closed backend --------------------------------------------------------

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const { program, receipt } = await build();
  const options: any = optionsFor(program);
  options.mldsaBackendLoader = async () => null;
  const res = await verifyAuthorityProgramV2(program, [receipt], options);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'invalid_program_signature');
});

// --- fail-closed on junk -------------------------------------------------------

test('malformed input refuses without throwing', async () => {
  for (const junk of [null, undefined, 'x', 42, [], {}]) {
    const res = await verifyAuthorityProgramV2(junk, [], {} as any);
    assert.equal(res.valid, false);
  }
});

// authorityStageReceiptDigestV2 / AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS /
// authorityProgramDigest are exercised indirectly above; reference them so an
// unused-import checker stays quiet.
void authorityStageReceiptDigestV2;
void AUTHORITY_PROGRAM_V2_REQUIRED_ALGORITHMS;
void authorityProgramDigest;
