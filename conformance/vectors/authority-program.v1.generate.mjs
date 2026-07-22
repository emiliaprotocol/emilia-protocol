#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Public deterministic vector generator. Test keys have no operational value.
import crypto from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../packages/verify/index.js';
import {
  AUTHORITY_PROGRAM_DOMAIN,
  AUTHORITY_PROGRAM_VERSION,
  AUTHORITY_STAGE_RECEIPT_DOMAIN,
  AUTHORITY_STAGE_RECEIPT_VERSION,
  authorityProgramDigest,
  authorityStageReceiptDigest,
} from '../../packages/verify/authority-program.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUTPUT = resolve(HERE, 'authority-program.v1.json');
const digest = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const clone = (value) => structuredClone(value);
const rootAction = {
  action_type: 'payment.release.1',
  amount: '250.00',
  currency: 'EUR',
  beneficiary_account: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  payment_instruction_id: 'pi-authority-program-0001',
};
const rootActionHash = crypto.createHash('sha256').update(canonicalize(rootAction), 'utf8').digest();
const rootActionBinding = {
  root_caid: `caid:1:${rootAction.action_type}:jcs-sha256:${rootActionHash.toString('base64url')}`,
  root_action_digest: `sha256:${rootActionHash.toString('hex')}`,
};
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function deterministicTestKey(name) {
  const seed = crypto.createHash('sha256')
    .update(`EP-AUTHORITY-PROGRAM-v1 public experimental conformance test key\0${name}`)
    .digest();
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}
const keys = Object.fromEntries(
  ['program', 'alpha', 'beta', 'gamma', 'delta'].map((name) => [name, deterministicTestKey(name)]),
);
const publicKey = (key) => crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');

function sign(body, domain, key) {
  return crypto.sign(null, Buffer.from(`${domain}${canonicalize(body)}`, 'utf8'), key).toString('base64url');
}

function signProgram(body) {
  const unsigned = clone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      organization_id: 'org:governance',
      key_id: 'key:program',
      signature_b64u: sign(unsigned, AUTHORITY_PROGRAM_DOMAIN, keys.program),
    },
  };
}

const stageKey = (organizationId) => keys[organizationId.slice(4)];
function signStage(body) {
  const unsigned = clone(body);
  delete unsigned.proof;
  return {
    ...unsigned,
    proof: {
      algorithm: 'Ed25519',
      key_id: unsigned.issuer.key_id,
      signature_b64u: sign(unsigned, AUTHORITY_STAGE_RECEIPT_DOMAIN, stageKey(unsigned.issuer.organization_id)),
    },
  };
}

const stage = (stage_id, organization_id, key_id) => ({
  type: 'stage',
  stage_id,
  authority: { organization_id, key_id },
  aec_requirement_digest: digest(`${stage_id}:aec:requirement`),
  aom_requirement_digest: digest(`${stage_id}:aom:requirement`),
  capability_requirement_digest: digest(`${stage_id}:capability:requirement`),
});

const program = signProgram({
  '@version': AUTHORITY_PROGRAM_VERSION,
  program_id: 'authority-program:conformance:v1',
  root_caid: rootActionBinding.root_caid,
  root_action_digest: rootActionBinding.root_action_digest,
  expression: {
    type: 'sequence',
    children: [
      stage('stage-a', 'org:alpha', 'key:alpha'),
      {
        type: 'parallel',
        parallel_id: 'parallel-bc',
        allocation_requirement_digest: digest('parallel-bc:allocation:requirement'),
        allocation_proof_digest: digest('parallel-bc:allocation:proof'),
        branches: [
          stage('stage-b', 'org:beta', 'key:beta'),
          stage('stage-c', 'org:gamma', 'key:gamma'),
        ],
      },
      stage('stage-d', 'org:delta', 'key:delta'),
    ],
  },
});

const descriptions = {
  'stage-a': program.expression.children[0],
  'stage-b': program.expression.children[1].branches[0],
  'stage-c': program.expression.children[1].branches[1],
  'stage-d': program.expression.children[2],
};
function receipt(stageId, predecessors) {
  const description = descriptions[stageId];
  return signStage({
    '@version': AUTHORITY_STAGE_RECEIPT_VERSION,
    receipt_id: `authority-stage-receipt:${stageId}:conformance`,
    program_digest: authorityProgramDigest(program),
    root_caid: program.root_caid,
    root_action_digest: program.root_action_digest,
    stage_id: stageId,
    issuer: description.authority,
    predecessor_receipt_digests: [...predecessors].sort(),
    aec: {
      requirement_digest: description.aec_requirement_digest,
      result_digest: digest(`${stageId}:aec:result`),
    },
    aom: {
      requirement_digest: description.aom_requirement_digest,
      result_digest: digest(`${stageId}:aom:result`),
    },
    capability: {
      requirement_digest: description.capability_requirement_digest,
      input_digest: digest(`${stageId}:capability:input`),
      output_digest: digest(`${stageId}:capability:output`),
    },
  });
}

const a = receipt('stage-a', []);
const b = receipt('stage-b', [authorityStageReceiptDigest(a)]);
const c = receipt('stage-c', [authorityStageReceiptDigest(a)]);
const d = receipt('stage-d', [authorityStageReceiptDigest(b), authorityStageReceiptDigest(c)]);
const receipts = [a, b, c, d];

const replace = (stageId, mutate) => {
  const original = clone(receipts.find((candidate) => candidate.stage_id === stageId));
  delete original.proof;
  mutate(original);
  return signStage(original);
};

const vector = {
  '@version': 'EP-AUTHORITY-PROGRAM-CONFORMANCE-v1',
  status: 'public-experimental-test-vector',
  note: 'Deterministic test keys only. This vector is not an adopted standard or independent implementation.',
  root_action: rootAction,
  program,
  program_pin: {
    digest: authorityProgramDigest(program),
    organization_id: 'org:governance',
    key_id: 'key:program',
    public_key: publicKey(keys.program),
  },
  stage_keys: {
    'org:alpha': { 'key:alpha': publicKey(keys.alpha) },
    'org:beta': { 'key:beta': publicKey(keys.beta) },
    'org:gamma': { 'key:gamma': publicKey(keys.gamma) },
    'org:delta': { 'key:delta': publicKey(keys.delta) },
  },
  stage_receipts: receipts,
  native_results: {
    stages: Object.fromEntries(receipts.map((item) => [item.stage_id, {
      aec: { valid: true, ...item.aec },
      aom: { valid: true, ...item.aom },
      capability: { valid: true, narrowed: true, ...item.capability },
    }])),
    parallel_allocations: {
      'parallel-bc': {
        valid: true,
        authoritative: true,
        parallel_id: 'parallel-bc',
        requirement_digest: digest('parallel-bc:allocation:requirement'),
        proof_digest: digest('parallel-bc:allocation:proof'),
      },
    },
  },
  vectors: [
    {
      id: 'accept-exact-authority-program',
      expect: { valid: true, reason: null },
    },
    {
      id: 'reject-missing-root-action-binding',
      expect: { valid: false, reason: 'root_action_binding_unproven' },
    },
  ],
  invalid_cases: [
    {
      name: 'missing-predecessor',
      replace_stage_id: 'stage-d',
      replacement_receipt: replace('stage-d', (item) => { item.predecessor_receipt_digests.pop(); }),
      expected_reason: 'predecessor_receipt_digest_mismatch',
    },
    {
      name: 'wrong-aec-result',
      replace_stage_id: 'stage-b',
      replacement_receipt: replace('stage-b', (item) => { item.aec.result_digest = digest('wrong-aec-result'); }),
      expected_reason: 'aec_verification_mismatch',
    },
    {
      name: 'wrong-aom-requirement',
      replace_stage_id: 'stage-c',
      replacement_receipt: replace('stage-c', (item) => { item.aom.requirement_digest = digest('wrong-aom-requirement'); }),
      expected_reason: 'aom_requirement_mismatch',
    },
  ],
};

await writeFile(OUTPUT, `${JSON.stringify(vector, null, 2)}\n`, 'utf8');
process.stdout.write(`wrote ${OUTPUT}\n`);
