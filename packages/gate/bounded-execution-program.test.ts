// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  BOUNDED_EXECUTION_PROGRAM_VERSION,
  EXECUTION_PROGRAM_CLAIM_BOUNDARY,
  executionProgramDigest,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
} from './bounded-execution-program.js';

const D = (character: string) => `sha256:${character.repeat(64)}`;
const C = (character: string) => (
  `caid:1:devops.infrastructure-change.1:jcs-sha256:${character.repeat(43)}`
);
const NOW = '2026-07-29T20:00:00.000Z';

function keyMaterial() {
  const pair = generateKeyPairSync('ed25519');
  return {
    pair,
    signer: {
      issuer_id: 'customer:example-security',
      key_id: 'key:customer-program-authorizer',
      private_key: pair.privateKey,
    },
    trusted_keys: {
      'key:customer-program-authorizer': {
        issuer_id: 'customer:example-security',
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
  };
}

function program() {
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
    valid_from: '2026-07-29T20:00:00.000Z',
    expires_at: '2026-07-29T21:00:00.000Z',
    max_total_occurrences: 3,
    max_concurrent_effects: 2,
    budgets: [
      { budget_id: 'attempts', unit: 'attempt', limit: 3 },
      { budget_id: 'change-risk', unit: 'risk-point', limit: 5 },
    ],
    nodes: [
      {
        node_id: 'inspect',
        action: { mode: 'exact', caid: C('A'), action_digest: D('a') },
        trust_program_digest: D('4'),
        depends_on: [],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 1 },
        ],
      },
      {
        node_id: 'remediate',
        action: {
          mode: 'profile',
          profile_id: 'profile:terraform-reviewed-plan',
          profile_digest: D('5'),
        },
        trust_program_digest: D('6'),
        depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 3 },
        ],
      },
      {
        node_id: 'verify',
        action: { mode: 'exact', caid: C('B'), action_digest: D('b') },
        trust_program_digest: D('7'),
        depends_on: [{ node_id: 'remediate', outcomes: ['COMMITTED'] }],
        max_occurrences: 1,
        charges: [
          { budget_id: 'attempts', amount: 1 },
          { budget_id: 'change-risk', amount: 1 },
        ],
      },
    ],
  };
}

function verificationOptions(material: ReturnType<typeof keyMaterial>) {
  return {
    trusted_keys: material.trusted_keys,
    now: NOW,
    expected_program_id: 'program:production-remediation:01',
    expected_tenant_id: 'tenant:example',
    expected_authorizer_id: 'customer:example-security',
    expected_authorization_digest: D('2'),
    expected_audience: 'gate:production:01',
  };
}

test('signs and verifies one closed, pinned execution-program DAG', () => {
  const material = keyMaterial();
  const artifact = signBoundedExecutionProgram(program(), material.signer);

  assert.equal(artifact['@version'], BOUNDED_EXECUTION_PROGRAM_VERSION);
  assert.equal(artifact.claim_boundary, EXECUTION_PROGRAM_CLAIM_BOUNDARY);
  const verified = verifyBoundedExecutionProgram(artifact, verificationOptions(material));
  assert.equal(verified.accepted, true);
  assert.equal(verified.verified, true);
  assert.equal(verified.program_digest, executionProgramDigest(artifact));
  assert.equal(verified.program?.nodes[1].node_id, 'remediate');
  assert.equal(Object.isFrozen(verified.program), true);
});

test('verification refuses an unpinned context and a substituted authorizer', () => {
  const material = keyMaterial();
  const artifact = signBoundedExecutionProgram(program(), material.signer);
  assert.equal(verifyBoundedExecutionProgram(artifact, {
    trusted_keys: material.trusted_keys,
    now: NOW,
  }).reason, 'context_binding_required');
  assert.equal(verifyBoundedExecutionProgram(artifact, {
    ...verificationOptions(material),
    expected_authorizer_id: 'customer:attacker',
  }).reason, 'authorizer_mismatch');
});

test('signed bytes are immutable and the program validity window is enforced', () => {
  const material = keyMaterial();
  const artifact = signBoundedExecutionProgram(program(), material.signer);
  const altered = structuredClone(artifact);
  altered.nodes[1].charges[1].amount = 1;
  assert.equal(
    verifyBoundedExecutionProgram(altered, verificationOptions(material)).reason,
    'program_signature_invalid',
  );
  assert.equal(verifyBoundedExecutionProgram(artifact, {
    ...verificationOptions(material),
    now: '2026-07-29T19:59:59.999Z',
  }).reason, 'program_not_active');
  assert.equal(verifyBoundedExecutionProgram(artifact, {
    ...verificationOptions(material),
    now: '2026-07-29T21:00:00.000Z',
  }).reason, 'program_expired');
});

test('program construction rejects unknown fields, cycles, and invalid budgets', () => {
  const material = keyMaterial();
  assert.throws(() => signBoundedExecutionProgram({
    ...program(),
    surprise: true,
  }, material.signer), /program shape is invalid/);

  const cyclic = program();
  cyclic.nodes[0].depends_on = [{ node_id: 'verify', outcomes: ['COMMITTED'] }];
  assert.throws(
    () => signBoundedExecutionProgram(cyclic, material.signer),
    /program graph contains a cycle/,
  );

  const overBudget = program();
  overBudget.budgets[1].limit = 2;
  assert.throws(
    () => signBoundedExecutionProgram(overBudget, material.signer),
    /node charge exceeds its program budget/,
  );

  const unbounded = program();
  delete (unbounded as any).max_total_occurrences;
  assert.throws(
    () => signBoundedExecutionProgram(unbounded, material.signer),
    /program occurrence ceiling is invalid/,
  );

  const excessive = program();
  excessive.max_total_occurrences = 1_000_001;
  assert.throws(
    () => signBoundedExecutionProgram(excessive, material.signer),
    /program occurrence ceiling is invalid/,
  );

  const missingConcurrency = program();
  delete (missingConcurrency as any).max_concurrent_effects;
  assert.throws(
    () => signBoundedExecutionProgram(missingConcurrency, material.signer),
    /program concurrent-effect ceiling is invalid/,
  );

  const excessiveConcurrency = program();
  excessiveConcurrency.max_concurrent_effects = 1_000_001;
  assert.throws(
    () => signBoundedExecutionProgram(excessiveConcurrency, material.signer),
    /program concurrent-effect ceiling is invalid/,
  );
});

test('profile actions require a pinned profile and exact actions require both identifiers', () => {
  const material = keyMaterial();
  const missingProfile = program();
  missingProfile.nodes[1].action = {
    mode: 'profile',
    profile_id: 'profile:terraform-reviewed-plan',
  } as any;
  assert.throws(
    () => signBoundedExecutionProgram(missingProfile, material.signer),
    /program action is invalid/,
  );

  const partialExact = program();
  partialExact.nodes[0].action = { mode: 'exact', caid: C('A') } as any;
  assert.throws(
    () => signBoundedExecutionProgram(partialExact, material.signer),
    /program action is invalid/,
  );
});

test('budget_id is the independent dimension while duplicate unit labels remain valid', () => {
  const material = keyMaterial();
  const source = program();
  source.budgets = [
    { budget_id: 'attempts+foreground', unit: 'attempt', limit: 3 },
    { budget_id: 'attempts+background', unit: 'attempt', limit: 5 },
  ];
  source.nodes = source.nodes.map((node, index) => ({
    ...node,
    node_id: `${node.node_id}+v1`,
    depends_on: index === 0
      ? []
      : [{ node_id: `${source.nodes[index - 1].node_id}+v1`, outcomes: ['COMMITTED'] as const }],
    charges: [
      { budget_id: index % 2 === 0 ? 'attempts+foreground' : 'attempts+background', amount: 1 },
    ],
  }));

  const artifact = signBoundedExecutionProgram(source, material.signer);
  const verified = verifyBoundedExecutionProgram(artifact, verificationOptions(material));
  assert.equal(verified.accepted, true);
  assert.deepEqual(verified.program?.budgets.map(({ budget_id, unit }) => ({ budget_id, unit })), [
    { budget_id: 'attempts+background', unit: 'attempt' },
    { budget_id: 'attempts+foreground', unit: 'attempt' },
  ]);
});
