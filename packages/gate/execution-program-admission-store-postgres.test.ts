// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ADMISSION_POSTGRES_SQL,
  createAdmissionPostgresStore,
  type AdmissionPostgresQuery,
} from './admission-store-postgres.js';
import {
  executionProgramDigest,
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
  type BoundedExecutionProgramInput,
} from './bounded-execution-program.js';
import {
  EXECUTION_PROGRAM_RUNTIME_VERSION,
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  createAdmissionSnapshot,
  createExecutionProgramAdmissionBinding,
  executionProgramReportSnapshotMarker,
  type AdmissionSnapshotInput,
} from './admission-store.js';

const SQL_PATH = fileURLToPath(new URL('./sql/gate-qualification-v2.sql', import.meta.url));
const README_PATH = fileURLToPath(new URL('./README.md', import.meta.url));
const DIGEST = `sha256:${'a'.repeat(64)}`;
const NOW = '2026-07-29T20:00:00.000Z';
const require = createRequire(import.meta.url);

function digestOf(label: string): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function caidOf(label: string): string {
  return `caid:1:devops.infrastructure-change.1:jcs-sha256:${crypto.createHash('sha256').update(label).digest('base64url')}`;
}

function ownerDigest(token: string): `sha256:${string}` {
  return `sha256:${crypto.createHash('sha256')
    .update('EP-GATE-ADMISSION-RECORD-v2:TOKEN')
    .update('\0')
    .update(JSON.stringify(token))
    .digest('hex')}`;
}

function signedProgram() {
  const pair = generateKeyPairSync('ed25519');
  const signer = {
    issuer_id: 'customer:security',
    key_id: 'key:program-authorizer',
    private_key: pair.privateKey,
  };
  const policy = {
    trusted_keys: {
      'key:program-authorizer': {
        issuer_id: signer.issuer_id,
        public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        role: 'program_authorizer' as const,
        status: 'ACTIVE' as const,
      },
    },
  };
  const context = {
    expected_program_id: 'program:postgres:01',
    expected_tenant_id: 'tenant:gate-v2',
    expected_authorization_digest: DIGEST,
    expected_audience: 'gate:production:01',
  };
  const artifact = signBoundedExecutionProgram({
    program_id: context.expected_program_id,
    tenant_id: context.expected_tenant_id,
    version: 1,
    subject_id: 'agent:operations:01',
    audience: context.expected_audience,
    objective_digest: DIGEST,
    authorization_digest: context.expected_authorization_digest,
    presentation_digest: DIGEST,
    supersedes_program_digest: null,
    issued_at: '2026-07-29T19:55:00.000Z',
    valid_from: NOW,
    expires_at: '2026-07-29T21:00:00.000Z',
    max_total_occurrences: 1,
    max_concurrent_effects: 1,
    budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 1 }],
    nodes: [{
      node_id: 'inspect',
      action: {
        mode: 'exact',
        caid: 'caid:1:devops.infrastructure-change.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        action_digest: DIGEST,
      },
      trust_program_digest: DIGEST,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    }],
  }, signer);
  return { artifact, context, policy };
}

function iso(milliseconds: number): string {
  return new Date(milliseconds).toISOString();
}

function admissionInput(
  admissionId: string,
  operationId: string,
  now: number,
  node: BoundedExecutionProgramInput['nodes'][number],
  authorizationDigest: `sha256:${string}`,
  subjectId: string,
  expiresAt = iso(now + 5 * 60_000),
): AdmissionSnapshotInput {
  const admittedAt = iso(now - 5_000);
  const validUntil = iso(now + 10 * 60_000);
  const role = (
    name: AdmissionSnapshotInput['inputs'][number]['role'],
    index: number,
  ): AdmissionSnapshotInput['inputs'][number] => ({
    role: name,
    artifact_type: `artifact:${name}`,
    subject: name === 'candidate_manifest' ? subjectId : `subject:${name}`,
    payload_digest: digestOf(`${operationId}:input:${index}`),
    profile_digest: digestOf(`${name}:profile`),
    verifier_id: `verifier:${name}`,
    trust_configuration_digest: digestOf('trust-configuration'),
    valid_until: validUntil,
  });
  const inputs = [
    { ...role('candidate_manifest', 0), payload_digest: digestOf('candidate-manifest') },
    { ...role('runtime_measurement', 1), payload_digest: digestOf('runtime-measurement') },
    { ...role('test_result', 2), payload_digest: digestOf('test-result') },
    { ...role('agent_evaluation_evidence', 3), payload_digest: digestOf('agent-evaluation') },
    { ...role('qualification_statement', 4), payload_digest: digestOf('qualification-statement') },
    { ...role('qualification_status', 5), payload_digest: digestOf('qualification-status') },
    role('aeb', 6),
    role('aec', 7),
    role('local_policy', 8),
    { ...role('authorization', 9), payload_digest: authorizationDigest },
  ];
  assert.equal(node.action.mode, 'exact');
  return {
    tenant_id: 'tenant:gate-v2',
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: digestOf('candidate-manifest'),
    runtime_measurement_digest: digestOf('runtime-measurement'),
    candidate_custody: {
      request_construction: 'EXECUTOR_ADAPTER',
      mutation_credential_custody: 'EXECUTOR_ADAPTER',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: digestOf('candidate-custody'),
    },
    assignment_digest: digestOf('assignment'),
    qualification_policy_digest: digestOf('qualification-policy'),
    test_result_payload_digests: [digestOf('test-result')],
    agent_evaluation_evidence_payload_digests: [digestOf('agent-evaluation')],
    qualification_statement_payload_digest: digestOf('qualification-statement'),
    qualification_status: {
      authority_id: 'authority:qualification',
      sequence: 7,
      head_payload_digest: digestOf('qualification-status'),
      observed_at: admittedAt,
      expires_at: validUntil,
    },
    caid: node.action.caid,
    action_digest: node.action.action_digest as `sha256:${string}`,
    effect_request_digest: digestOf(`${operationId}:effect`),
    provider: {
      provider_id: 'provider:infrastructure',
      account_id: 'account:production',
      environment: 'production',
    },
    executor_adapter_digest: digestOf('executor-adapter'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: node.trust_program_digest as `sha256:${string}`,
    trust_epoch: 11,
    trust_configuration_digest: digestOf('trust-configuration'),
    configuration_epoch: 13,
    configuration_digest: digestOf('configuration'),
    inputs,
    resource_reservations: [{
      kind: 'provider_operation',
      resource_id: operationId,
      reservation_id: `provider-reservation:${admissionId}`,
      digest: digestOf(`${operationId}:provider-reservation`),
      expires_at: expiresAt,
    }],
    admitted_at: admittedAt,
    expires_at: expiresAt,
    supersedes_admission_id: null,
    remedy_for: null,
  };
}

test('PostgreSQL adapter exposes the complete durable execution-program surface', async () => {
  const runtimeCalls: Array<{ text: string; params: readonly unknown[] }> = [];
  const verifierCalls: Array<{ text: string; params: readonly unknown[] }> = [];
  const query: AdmissionPostgresQuery = async (text, params) => {
    runtimeCalls.push({ text, params });
    return { rowCount: 1, rows: [{ result: { ok: false, reason: 'program_not_found' } }] };
  };
  const executionProgramVerifierQuery: AdmissionPostgresQuery = async (text, params) => {
    verifierCalls.push({ text, params });
    return { rowCount: 1, rows: [{ result: { ok: false, reason: 'program_not_found' } }] };
  };
  const { artifact, context, policy } = signedProgram();
  const store = createAdmissionPostgresStore({
    query,
    executionProgramVerifierQuery,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
    now: NOW,
    executionProgramVerificationPolicy: policy,
  });
  for (const method of [
    'registerExecutionProgram',
    'reserveExecutionProgramAdmission',
    'reserveExecutionProgramAdmissionWithPreparedOwnerToken',
    'beginExecutionProgramInvocation',
    'beginExecutionProgramInvocationWithPreparedToken',
    'releaseExecutionProgramAdmission',
    'expireExecutionProgramAdmission',
    'supersedeExecutionProgram',
    'readExecutionProgram',
    'readExecutionProgramReportSnapshot',
    'readExecutionProgramOccurrence',
  ] as const) {
    assert.equal(typeof store[method], 'function', method);
  }

  assert.deepEqual(await store.registerExecutionProgram(artifact, context), {
    ok: false,
    reason: 'program_not_found',
  });
  assert.equal(runtimeCalls.length, 0);
  assert.equal(verifierCalls.length, 1);
  assert.equal(verifierCalls[0].text, ADMISSION_POSTGRES_SQL.registerExecutionProgram);
  assert.equal(verifierCalls[0].params[0], 'deployment:gate-v2');
  assert.equal(verifierCalls[0].params[1], 'tenant:gate-v2');
  assert.equal(verifierCalls[0].params.length, 6, 'database clock is not caller supplied');
});

test('execution-program registration uses only store-owned trust roots and clock', async () => {
  let queryCount = 0;
  const { artifact, context, policy } = signedProgram();
  const store = createAdmissionPostgresStore({
    query: async () => {
      queryCount += 1;
      return { rowCount: 1, rows: [{ result: null }] };
    },
    executionProgramVerifierQuery: async () => {
      queryCount += 1;
      return { rowCount: 1, rows: [{ result: null }] };
    },
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
    now: NOW,
    executionProgramVerificationPolicy: policy,
  });
  assert.deepEqual(await store.registerExecutionProgram(artifact, {
    ...context,
    trusted_keys: {},
    now: '2000-01-01T00:00:00.000Z',
  } as any), { ok: false, reason: 'context_binding_required' });
  assert.equal(queryCount, 0);
});

test('prepared reservation snapshots the exact owner token before any awaited verifier work', async () => {
  const { artifact, context, policy } = signedProgram();
  const verified = verifyBoundedExecutionProgram(artifact, {
    trusted_keys: Object.fromEntries(Object.entries(policy.trusted_keys).map(([key, value]) => [
      key,
      { issuer_id: value.issuer_id, public_key: value.public_key },
    ])),
    expected_program_id: context.expected_program_id,
    expected_tenant_id: context.expected_tenant_id,
    expected_authorizer_id: 'customer:security',
    expected_authorization_digest: context.expected_authorization_digest,
    expected_audience: context.expected_audience,
    now: NOW,
  });
  assert.equal(verified.accepted, true);
  if (!verified.accepted || !verified.program || !verified.program_digest) {
    assert.fail(verified.reason);
  }
  const runtime = {
    '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
    tenant_id: context.expected_tenant_id,
    program_id: context.expected_program_id,
    program_digest: verified.program_digest,
    version: verified.program.version,
    status: 'ACTIVE',
    status_sequence: 0,
    status_observed_at: NOW,
    status_expires_at: '2026-07-29T21:00:00.000Z',
    authorizer_id: 'customer:security',
    registered_at: NOW,
    superseded_by_program_digest: null,
    total_occurrences: 0,
    budgets: verified.program.budgets.map((budget) => ({
      ...budget,
      reserved: 0,
      consumed: 0,
    })),
    program: verified.program,
  };
  const verifierCalls: Array<{ text: string; params: readonly unknown[] }> = [];
  const query: AdmissionPostgresQuery = async (text) => {
    assert.equal(text, ADMISSION_POSTGRES_SQL.readExecutionProgram);
    await Promise.resolve();
    return { rowCount: 1, rows: [{ result: runtime }] };
  };
  const executionProgramVerifierQuery: AdmissionPostgresQuery = async (text, params) => {
    verifierCalls.push({ text, params });
    return { rowCount: 1, rows: [{ result: { ok: false, reason: 'state_conflict' } }] };
  };
  const store = createAdmissionPostgresStore({
    query,
    executionProgramVerifierQuery,
    deploymentId: 'deployment:gate-v2',
    tenantId: context.expected_tenant_id,
    now: NOW,
    executionProgramVerificationPolicy: policy,
  });
  const preparedA = `admission-owner:v2:${Buffer.alloc(32, 7).toString('base64url')}`;
  const substitutedB = `admission-owner:v2:${Buffer.alloc(32, 8).toString('base64url')}`;
  const input = {
    program_digest: verified.program_digest,
    node_id: verified.program.nodes[0].node_id,
    occurrence_id: 'occurrence:prepared-owner-token',
    admission: admissionInput(
      'admission:prepared-owner-token',
      'operation:prepared-owner-token',
      Date.parse(NOW),
      verified.program.nodes[0],
      context.expected_authorization_digest as `sha256:${string}`,
      verified.program.subject_id,
    ),
    owner_token: preparedA,
  };

  const pending = store.reserveExecutionProgramAdmissionWithPreparedOwnerToken(input);
  input.owner_token = substitutedB;
  assert.deepEqual(await pending, { ok: false, reason: 'state_conflict' });
  assert.equal(verifierCalls.length, 1);
  assert.equal(verifierCalls[0].text, ADMISSION_POSTGRES_SQL.reserveExecutionProgramAdmission);
  assert.equal(verifierCalls[0].params[7], ownerDigest(preparedA));
  assert.notEqual(verifierCalls[0].params[7], ownerDigest(substitutedB));
});

test('execution-program assertion RPCs require a distinct verifier-service query', async () => {
  const { artifact, context, policy } = signedProgram();
  const runtimeQuery: AdmissionPostgresQuery = async () => ({
    rowCount: 1,
    rows: [{ result: null }],
  });
  assert.throws(() => createAdmissionPostgresStore({
    query: runtimeQuery,
    executionProgramVerifierQuery: runtimeQuery,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
    executionProgramVerificationPolicy: policy,
  }), /distinct verifier-service query/);

  const store = createAdmissionPostgresStore({
    query: runtimeQuery,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
    now: NOW,
    executionProgramVerificationPolicy: policy,
  });
  await assert.rejects(
    store.registerExecutionProgram(artifact, context),
    /executionProgramVerifierQuery is required/,
  );
});

test('execution-program SQL seals associations, budgets, transitions, and tenant isolation', async () => {
  const sql = await readFile(SQL_PATH, 'utf8');
  const readme = await readFile(README_PATH, 'utf8');
  for (const table of [
    'ep_gate_execution_programs',
    'ep_gate_execution_program_heads',
    'ep_gate_execution_program_authorizations',
    'ep_gate_execution_program_occurrences',
  ]) assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS public\\.${table}`));
  for (const rpc of [
    'ep_gate_execution_program_register',
    'ep_gate_execution_program_reserve_admission',
    'ep_gate_execution_program_begin_invocation',
    'ep_gate_execution_program_release_admission',
    'ep_gate_execution_program_expire_admission',
    'ep_gate_execution_program_supersede',
    'ep_gate_execution_program_read',
    'ep_gate_execution_program_read_report_snapshot',
    'ep_gate_execution_program_read_occurrence',
  ]) {
    assert.match(sql, new RegExp(`CREATE OR REPLACE FUNCTION public\\.${rpc}`));
    assert.match(sql, new RegExp(`REVOKE ALL ON FUNCTION public\\.${rpc}\\(`));
  }
  assert.match(sql, /'execution_program'/);
  assert.match(sql, /program_required/);
  assert.match(sql, /program_occurrence_exhausted/);
  assert.match(sql, /program_total_occurrence_exhausted/);
  assert.match(sql, /program_budget_exhausted/);
  assert.match(sql, /program_node_unreachable/);
  assert.match(sql, /program_reserved_work_exists/);
  assert.match(sql, /program_status_indeterminate/);
  assert.match(sql, /One statement reads the runtime row and the complete retained occurrence/);
  assert.match(sql, /max_total_occurrences'\)::bigint \+ 1/);
  assert.match(sql, /EP-BOUNDED-EXECUTION-PROGRAM-REPORT-SNAPSHOT-v1:MARKER/);
  assert.match(sql, /EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:IDENTITY/);
  assert.match(sql, /INDETERMINATE/);
  assert.match(sql, /SECURITY DEFINER/);
  assert.match(sql, /ep_gate_assert_binding\(p_deployment_id, p_tenant_id\)/);
  assert.match(sql, /v_now timestamptz := clock_timestamp\(\)/);
  assert.match(sql, /v_observed_at < v_now - v_maximum_observation_age/);
  assert.match(sql, /IF p_observation IS NULL THEN\s+RETURN 'program_status_indeterminate'/);
  assert.doesNotMatch(sql, /p_program_now/);

  for (const rpc of [
    'ep_gate_execution_program_register',
    'ep_gate_execution_program_reserve_admission',
    'ep_gate_execution_program_begin_invocation',
    'ep_gate_execution_program_supersede',
  ]) {
    assert.match(readme, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${rpc}\\([^;]+TO emilia_gate_verifier_service;`));
    assert.doesNotMatch(readme, new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${rpc}\\([^;]+TO emilia_gate_runtime;`));
  }
  assert.match(readme, /executionProgramVerifierQuery/);
  assert.match(readme, /does not verify Ed25519 inside PostgreSQL/);
});

const postgresUrl = process.env.ADMISSION_STORE_POSTGRES_TEST_URL;

test('real PostgreSQL proves the complete execution-program lifecycle atomically', {
  skip: postgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
  const { Pool } = require('pg') as {
    Pool: new (options: { connectionString: string | undefined; max: number }) => {
      query: (text: string, params?: unknown[]) => Promise<{
        rowCount: number | null;
        rows: Array<Record<string, any>>;
      }>;
      connect: () => Promise<{
        query: (text: string, params?: unknown[]) => Promise<{
          rowCount: number | null;
          rows: Array<Record<string, any>>;
        }>;
        release: () => void;
      }>;
      end: () => Promise<void>;
    };
  };
  const pool = new Pool({ connectionString: postgresUrl, max: 16 });
  const ownerQuery: AdmissionPostgresQuery = async (text, params) => {
    const result = await pool.query(text, [...params]);
    return { rowCount: result.rowCount ?? 0, rows: result.rows };
  };
  const queryAs = (role: 'gate_program_runtime' | 'gate_program_verifier'): AdmissionPostgresQuery => (
    async (text, params) => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL ROLE ${role}`);
        const result = await client.query(text, [...params]);
        await client.query('COMMIT');
        return { rowCount: result.rowCount ?? 0, rows: result.rows };
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
  );
  const runtimeQuery = queryAs('gate_program_runtime');
  const verifierRoleQuery = queryAs('gate_program_verifier');
  let verifierDelayMs = 0;
  const executionProgramVerifierQuery: AdmissionPostgresQuery = async (text, params) => {
    const delay = verifierDelayMs;
    verifierDelayMs = 0;
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    return verifierRoleQuery(text, params);
  };
  const signerKeys = generateKeyPairSync('ed25519');
  const signer = {
    issuer_id: 'customer:program-authorizer',
    key_id: 'key:postgres-program-authorizer',
    private_key: signerKeys.privateKey,
  };
  const trustedKeys = {
    [signer.key_id]: {
      issuer_id: signer.issuer_id,
      public_key: signerKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      role: 'program_authorizer' as const,
      status: 'ACTIVE' as const,
    },
  };
  const now = Date.now();
  const programId = 'program:postgres:lifecycle';
  const subjectId = 'agent:postgres:lifecycle';
  const audience = 'gate:production:01';
  const authorizationDigest = digestOf('program-authorization-v1');
  const successorAuthorizationDigest = digestOf('program-authorization-v2');
  const trustProgramDigest = digestOf('program-trust-policy');
  const nodes: BoundedExecutionProgramInput['nodes'] = [
    {
      node_id: 'inspect',
      action: { mode: 'exact', caid: caidOf('inspect'), action_digest: digestOf('inspect-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'remediate',
      action: { mode: 'exact', caid: caidOf('remediate'), action_digest: digestOf('remediate-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [{ node_id: 'inspect', outcomes: ['COMMITTED'] }],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'releaseable',
      action: { mode: 'exact', caid: caidOf('releaseable'), action_digest: digestOf('releaseable-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 3,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'expirable',
      action: { mode: 'exact', caid: caidOf('expirable'), action_digest: digestOf('expirable-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'race',
      action: { mode: 'exact', caid: caidOf('race'), action_digest: digestOf('race-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'rollback',
      action: { mode: 'exact', caid: caidOf('rollback'), action_digest: digestOf('rollback-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 1 }],
    },
    {
      node_id: 'heavy',
      action: { mode: 'exact', caid: caidOf('heavy'), action_digest: digestOf('heavy-action') },
      trust_program_digest: trustProgramDigest,
      depends_on: [],
      max_occurrences: 1,
      charges: [{ budget_id: 'attempts', amount: 6 }],
    },
  ];
  const baseProgram = {
    program_id: programId,
    tenant_id: 'tenant:gate-v2',
    version: 1,
    subject_id: subjectId,
    audience,
    objective_digest: digestOf('program-objective'),
    authorization_digest: authorizationDigest,
    presentation_digest: digestOf('program-presentation'),
    supersedes_program_digest: null,
    issued_at: iso(now - 120_000),
    valid_from: iso(now - 60_000),
    expires_at: iso(now + 15 * 60_000),
    max_total_occurrences: 7,
    max_concurrent_effects: 2,
    budgets: [{ budget_id: 'attempts', unit: 'attempt', limit: 6 }],
    nodes,
  } satisfies BoundedExecutionProgramInput;
  const artifact = signBoundedExecutionProgram(baseProgram, signer);
  const programDigest = executionProgramDigest(artifact);
  const context = {
    expected_program_id: programId,
    expected_tenant_id: 'tenant:gate-v2',
    expected_authorization_digest: authorizationDigest,
    expected_audience: audience,
  };
  let programStatus: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' = 'ACTIVE';
  let programStatusSequence = 1;
  let programStatusObservedAt = iso(now);
  let programStatusExpiresAt = iso(now + 14 * 60_000);
  const setProgramStatus = (status: typeof programStatus) => {
    programStatus = status;
    programStatusSequence += 1;
    programStatusObservedAt = iso(Date.now());
    programStatusExpiresAt = iso(Date.now() + 14 * 60_000);
  };
  const store = createAdmissionPostgresStore({
    query: runtimeQuery,
    executionProgramVerifierQuery,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
    executionProgramVerificationPolicy: { trusted_keys: trustedKeys },
    maxExecutionProgramStatusAgeMs: 300_000,
    executionProgramStatusOracle: {
      read: async (reference) => ({
        '@version': 'EP-BOUNDED-EXECUTION-PROGRAM-STATUS-v1',
        ...reference,
        status: programStatus,
        sequence: programStatusSequence,
        observed_at: programStatusObservedAt,
        expires_at: programStatusExpiresAt,
      }),
    },
  });

  const node = (nodeId: string) => {
    const selected = nodes.find((entry) => entry.node_id === nodeId);
    assert.ok(selected, `missing program node ${nodeId}`);
    return selected;
  };
  const inputFor = (
    suffix: string,
    nodeId: string,
    authorization = authorizationDigest,
    expiry?: string,
  ) => admissionInput(
    `admission:program:${suffix}`,
    `operation:program:${suffix}`,
    Date.now(),
    node(nodeId),
    authorization,
    subjectId,
    expiry,
  );
  const cas = (reserved: Extract<Awaited<ReturnType<typeof store.reserve>>, { ok: true }>) => ({
    tenant_id: 'tenant:gate-v2',
    admission_id: reserved.record.admission_id,
    expected_revision: reserved.record.revision,
    owner_token: reserved.owner_token,
  });

  async function seedCurrentness(value: AdmissionSnapshotInput): Promise<void> {
    await pool.query(`UPDATE public.ep_gate_deployment_binding SET
      trust_epoch = $2,
      trust_configuration_digest = $3,
      configuration_epoch = $4,
      configuration_digest = $5,
      runtime_measurement_digest = $6,
      candidate_match = 'EXACT_MATCH',
      currentness_observed_at = clock_timestamp()
    WHERE deployment_id = $1`, [
      'deployment:gate-v2', value.trust_epoch, value.trust_configuration_digest,
      value.configuration_epoch, value.configuration_digest, value.runtime_measurement_digest,
    ]);
    await pool.query(`INSERT INTO public.ep_gate_candidate_runtime_heads (
      deployment_id, candidate_manifest_digest, runtime_measurement_digest,
      candidate_match, observed_at, expires_at
    ) VALUES ($1, $2, $3, 'EXACT_MATCH', clock_timestamp(), clock_timestamp() + interval '20 minutes')
    ON CONFLICT (deployment_id) DO UPDATE SET
      candidate_manifest_digest = EXCLUDED.candidate_manifest_digest,
      runtime_measurement_digest = EXCLUDED.runtime_measurement_digest,
      candidate_match = EXCLUDED.candidate_match,
      observed_at = EXCLUDED.observed_at,
      expires_at = EXCLUDED.expires_at`, [
      'deployment:gate-v2', value.candidate_manifest_digest, value.runtime_measurement_digest,
    ]);
    await pool.query(`INSERT INTO public.ep_gate_protected_request_heads (
      deployment_id, operation_id, caid, action_digest, effect_request_digest,
      provider_id, provider_account_id, provider_environment,
      executor_adapter_digest, idempotency_key, observed_at, expires_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
      clock_timestamp(), clock_timestamp() + interval '20 minutes')
    ON CONFLICT (deployment_id, operation_id) DO UPDATE SET
      caid = EXCLUDED.caid,
      action_digest = EXCLUDED.action_digest,
      effect_request_digest = EXCLUDED.effect_request_digest,
      provider_id = EXCLUDED.provider_id,
      provider_account_id = EXCLUDED.provider_account_id,
      provider_environment = EXCLUDED.provider_environment,
      executor_adapter_digest = EXCLUDED.executor_adapter_digest,
      idempotency_key = EXCLUDED.idempotency_key,
      observed_at = EXCLUDED.observed_at,
      expires_at = EXCLUDED.expires_at`, [
      'deployment:gate-v2', value.operation_id, value.caid, value.action_digest,
      value.effect_request_digest, value.provider.provider_id, value.provider.account_id,
      value.provider.environment, value.executor_adapter_digest, value.idempotency_key,
    ]);
    await pool.query(`INSERT INTO public.ep_gate_evidence_heads (
      deployment_id, role, subject, verifier_id, artifact_type, payload_digest,
      profile_digest, trust_configuration_digest, observed_at, expires_at
    )
    SELECT $1, input->>'role', input->>'subject', input->>'verifier_id',
      input->>'artifact_type', input->>'payload_digest', input->>'profile_digest',
      input->>'trust_configuration_digest', clock_timestamp(),
      clock_timestamp() + interval '20 minutes'
    FROM jsonb_array_elements($2::jsonb) AS values_(input)
    WHERE input->>'role' IN ('aeb', 'aec', 'local_policy', 'authorization')
    ON CONFLICT (deployment_id, role, subject, verifier_id) DO UPDATE SET
      artifact_type = EXCLUDED.artifact_type,
      payload_digest = EXCLUDED.payload_digest,
      profile_digest = EXCLUDED.profile_digest,
      trust_configuration_digest = EXCLUDED.trust_configuration_digest,
      observed_at = EXCLUDED.observed_at,
      expires_at = EXCLUDED.expires_at`, [
      'deployment:gate-v2', JSON.stringify(value.inputs),
    ]);
    await pool.query(`INSERT INTO public.ep_gate_qualification_status_heads (
      deployment_id, authority_id, sequence, head_payload_digest, observed_at, expires_at
    ) VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '20 minutes')
    ON CONFLICT (deployment_id, authority_id) DO UPDATE SET
      sequence = EXCLUDED.sequence,
      head_payload_digest = EXCLUDED.head_payload_digest,
      observed_at = EXCLUDED.observed_at,
      expires_at = EXCLUDED.expires_at`, [
      'deployment:gate-v2', value.qualification_status.authority_id,
      value.qualification_status.sequence, value.qualification_status.head_payload_digest,
    ]);
  }

  async function reserveProgram(suffix: string, nodeId: string, expiry?: string) {
    const admission = inputFor(suffix, nodeId, authorizationDigest, expiry);
    await seedCurrentness(admission);
    return store.reserveExecutionProgramAdmission({
      program_digest: programDigest,
      node_id: nodeId,
      occurrence_id: `occurrence:${suffix}`,
      admission,
    });
  }

  try {
    await pool.query(await readFile(SQL_PATH, 'utf8'));
    await pool.query(`DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gate_program_runtime') THEN
        DROP OWNED BY gate_program_runtime;
        DROP ROLE gate_program_runtime;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gate_program_verifier') THEN
        DROP OWNED BY gate_program_verifier;
        DROP ROLE gate_program_verifier;
      END IF;
    END $$`);
    await pool.query('CREATE ROLE gate_program_runtime NOLOGIN');
    await pool.query('CREATE ROLE gate_program_verifier NOLOGIN');
    await pool.query('GRANT USAGE ON SCHEMA public TO gate_program_runtime, gate_program_verifier');
    for (const signature of [
      'public.ep_gate_admission_reserve(text,text,jsonb,text)',
      'public.ep_gate_admission_release(text,text,text,bigint,text,text)',
      'public.ep_gate_admission_expire(text,text,text,bigint,text)',
      'public.ep_gate_admission_supersede(text,text,text,bigint,text,jsonb,text)',
      'public.ep_gate_admission_begin_invocation(text,text,text,bigint,text,text)',
      'public.ep_gate_admission_recover_indeterminate(text,text,text,text,text)',
      'public.ep_gate_admission_record_provider_outcome(text,text,text,bigint,text,text,text,text,text)',
      'public.ep_gate_admission_record_effect_relation(text,text,text,bigint,text,text,text,text,text)',
      'public.ep_gate_admission_read(text,text,text)',
      'public.ep_gate_admission_read_by_operation(text,text,text)',
      'public.ep_gate_admission_read_snapshot(text,text,text)',
      'public.ep_gate_admission_journal(text,text,text)',
      'public.ep_gate_admission_check_invariants(text,text)',
      'public.ep_gate_execution_program_release_admission(text,text,text,bigint,text,text)',
      'public.ep_gate_execution_program_expire_admission(text,text,text,bigint,text)',
      'public.ep_gate_execution_program_read(text,text,text)',
      'public.ep_gate_execution_program_read_by_admission(text,text,text)',
      'public.ep_gate_execution_program_read_report_snapshot(text,text,text)',
      'public.ep_gate_execution_program_read_occurrence(text,text,text,text)',
    ]) await pool.query(`GRANT EXECUTE ON FUNCTION ${signature} TO gate_program_runtime`);
    const assertionSignatures = [
      'public.ep_gate_execution_program_register(text,text,text,jsonb,jsonb,text)',
      'public.ep_gate_execution_program_reserve_admission(text,text,text,text,text,jsonb,jsonb,text,jsonb)',
      'public.ep_gate_execution_program_begin_invocation(text,text,text,bigint,text,text,jsonb)',
      'public.ep_gate_execution_program_supersede(text,text,text,jsonb,jsonb,text)',
    ];
    for (const signature of assertionSignatures) {
      await pool.query(`GRANT EXECUTE ON FUNCTION ${signature} TO gate_program_verifier`);
      const privilege = await pool.query(
        `SELECT has_function_privilege('gate_program_runtime', $1, 'EXECUTE') AS runtime,
          has_function_privilege('gate_program_verifier', $1, 'EXECUTE') AS verifier`,
        [signature],
      );
      assert.equal(privilege.rows[0].runtime, false, `${signature}: runtime must be denied`);
      assert.equal(privilege.rows[0].verifier, true, `${signature}: verifier must be allowed`);
    }
    await assert.rejects(runtimeQuery(ADMISSION_POSTGRES_SQL.registerExecutionProgram, [
      'deployment:gate-v2', 'tenant:gate-v2', programDigest,
      JSON.stringify(artifact), JSON.stringify(baseProgram), signer.key_id,
    ]), /permission denied for function ep_gate_execution_program_register/);
    await pool.query('DROP ROLE IF EXISTS gate_program_untrusted');
    await pool.query('CREATE ROLE gate_program_untrusted NOLOGIN');
    const publicExecutors = await pool.query(`SELECT p.oid::regprocedure::text AS function_name
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname LIKE 'ep_gate_%'
        AND has_function_privilege('gate_program_untrusted', p.oid, 'EXECUTE')
      ORDER BY p.oid::regprocedure::text`);
    assert.deepEqual(publicExecutors.rows, [], 'PUBLIC must not execute any Gate helper or RPC');

    await pool.query(`TRUNCATE
      public.ep_gate_execution_program_occurrences,
      public.ep_gate_execution_program_heads,
      public.ep_gate_execution_program_authorizations,
      public.ep_gate_execution_programs,
      public.ep_gate_admission_journal,
      public.ep_gate_resource_fences,
      public.ep_gate_operation_heads,
      public.ep_gate_admission_records,
      public.ep_gate_admission_snapshots,
      public.ep_gate_evidence_heads,
      public.ep_gate_protected_request_heads,
      public.ep_gate_candidate_runtime_heads,
      public.ep_gate_external_leases,
      public.ep_gate_qualification_status_heads,
      public.ep_gate_deployment_binding CASCADE`);
    await pool.query(`INSERT INTO public.ep_gate_deployment_binding (
      singleton, deployment_id, tenant_id, trust_epoch, trust_configuration_digest,
      configuration_epoch, configuration_digest, runtime_measurement_digest,
      candidate_match, currentness_observed_at
    ) VALUES (true, $1, $2, 11, $3, 13, $4, $5, 'EXACT_MATCH', clock_timestamp())`, [
      'deployment:gate-v2', 'tenant:gate-v2', digestOf('trust-configuration'),
      digestOf('configuration'), digestOf('runtime-measurement'),
    ]);

    const ordinaryBefore = inputFor('ordinary-before-register', 'inspect');
    await seedCurrentness(ordinaryBefore);
    const ordinaryReserved = await store.reserve(ordinaryBefore);
    assert.equal(ordinaryReserved.ok, true);
    assert.deepEqual(await store.registerExecutionProgram(artifact, context), {
      ok: false,
      reason: 'program_binding_mismatch',
    });
    assert.equal(ordinaryReserved.ok, true);
    assert.equal((await store.release(cas(ordinaryReserved))).ok, true);

    const registered = await store.registerExecutionProgram(artifact, context);
    assert.equal(registered.ok, true);
    if (!registered.ok) assert.fail(registered.reason);
    assert.equal(registered.program.program_digest, programDigest);
    assert.deepEqual(registered.program.budgets, [{
      budget_id: 'attempts', unit: 'attempt', limit: 6, reserved: 0, consumed: 0,
    }]);

    const noStatusStore = createAdmissionPostgresStore({
      query: runtimeQuery,
      executionProgramVerifierQuery,
      deploymentId: 'deployment:gate-v2',
      tenantId: 'tenant:gate-v2',
      executionProgramVerificationPolicy: { trusted_keys: trustedKeys },
    });
    const missingStatusAdmission = inputFor('missing-status', 'releaseable');
    await seedCurrentness(missingStatusAdmission);
    assert.deepEqual(await noStatusStore.reserveExecutionProgramAdmission({
      program_digest: programDigest,
      node_id: 'releaseable',
      occurrence_id: 'occurrence:missing-status',
      admission: missingStatusAdmission,
    }), { ok: false, reason: 'program_status_indeterminate' });

    programStatusObservedAt = iso(Date.now());
    programStatusExpiresAt = iso(Date.now() + 100);
    verifierDelayMs = 180;
    assert.deepEqual(await reserveProgram('status-expired-in-handoff', 'releaseable'), {
      ok: false,
      reason: 'program_status_indeterminate',
    });

    await pool.query(`UPDATE public.ep_gate_deployment_binding
      SET maximum_observation_age_ms = 50 WHERE deployment_id = $1`, ['deployment:gate-v2']);
    programStatusObservedAt = iso(Date.now() - 100);
    programStatusExpiresAt = iso(Date.now() + 14 * 60_000);
    assert.deepEqual(await reserveProgram('status-too-old-for-database', 'releaseable'), {
      ok: false,
      reason: 'program_status_indeterminate',
    });
    await pool.query(`UPDATE public.ep_gate_deployment_binding
      SET maximum_observation_age_ms = 300000 WHERE deployment_id = $1`, ['deployment:gate-v2']);
    programStatusObservedAt = iso(Date.now());
    programStatusExpiresAt = iso(Date.now() + 14 * 60_000);

    const ordinaryAfter = inputFor('ordinary-after-register', 'inspect');
    await seedCurrentness(ordinaryAfter);
    assert.deepEqual(await store.reserve(ordinaryAfter), { ok: false, reason: 'program_required' });
    const unrelatedOrdinary = inputFor(
      'ordinary-unrelated', 'inspect', digestOf('unrelated-ordinary-authorization'),
    );
    await seedCurrentness(unrelatedOrdinary);
    const unrelatedReserved = await store.reserve(unrelatedOrdinary);
    assert.equal(unrelatedReserved.ok, true);
    if (!unrelatedReserved.ok) assert.fail(unrelatedReserved.reason);
    assert.equal((await store.release(cas(unrelatedReserved))).ok, true);

    const prebuiltInput = inputFor('prebuilt-without-binding', 'inspect');
    await seedCurrentness(prebuiltInput);
    assert.deepEqual(await store.reserveExecutionProgramAdmission({
      program_digest: programDigest,
      node_id: 'inspect',
      occurrence_id: 'occurrence:prebuilt-without-binding',
      admission: createAdmissionSnapshot(prebuiltInput),
    }), { ok: false, reason: 'program_binding_mismatch' });

    const prematureInput = inputFor('premature-remediate', 'remediate');
    await seedCurrentness(prematureInput);
    const prematureBinding = createExecutionProgramAdmissionBinding({
      tenant_id: 'tenant:gate-v2',
      program_digest: programDigest,
      node_id: 'remediate',
      occurrence_id: 'occurrence:premature-remediate',
      expires_at: prematureInput.expires_at,
    });
    const bindingParity = await pool.query(`SELECT
      public.ep_gate_execution_program_expected_binding(
        $1, $2, $3, $4, $5::timestamptz
      ) = $6::jsonb AS exact`, [
      'tenant:gate-v2', programDigest, 'remediate', 'occurrence:premature-remediate',
      prematureInput.expires_at, JSON.stringify(prematureBinding),
    ]);
    assert.equal(bindingParity.rows[0].exact, true, 'adapter and SQL binding constructors must agree');
    const prematureDependency = await store.reserveExecutionProgramAdmission({
      program_digest: programDigest,
      node_id: 'remediate',
      occurrence_id: 'occurrence:premature-remediate',
      admission: prematureInput,
    });
    assert.deepEqual(prematureDependency, { ok: false, reason: 'program_node_unreachable' });

    const inspectReserved = await reserveProgram('inspect', 'inspect');
    assert.equal(inspectReserved.ok, true);
    if (!inspectReserved.ok) assert.fail(inspectReserved.reason);
    const expectedBinding = createExecutionProgramAdmissionBinding({
      tenant_id: 'tenant:gate-v2',
      program_digest: programDigest,
      node_id: 'inspect',
      occurrence_id: 'occurrence:inspect',
      expires_at: inspectReserved.snapshot.body.expires_at,
    });
    assert.deepEqual(
      inspectReserved.snapshot.body.resource_reservations.filter(
        (resource) => resource.kind === 'execution_program',
      ),
      [expectedBinding],
    );
    assert.deepEqual(await store.beginInvocation(cas(inspectReserved)), {
      ok: false,
      reason: 'program_required',
    });
    assert.deepEqual(await store.release(cas(inspectReserved)), {
      ok: false,
      reason: 'program_required',
    });
    const preparedInvocationToken = `admission-invocation:v2:${Buffer.alloc(32, 29).toString('base64url')}`;
    const begun = await store.beginExecutionProgramInvocationWithPreparedToken({
      ...cas(inspectReserved),
      invocation_token: preparedInvocationToken,
    });
    assert.equal(begun.ok, true);
    if (!begun.ok) assert.fail(begun.reason);
    assert.equal(begun.invocation_token, preparedInvocationToken);
    assert.equal(begun.record.state, 'INVOKING');
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:inspect',
    }))?.state, 'INVOKING');
    const indeterminate = await store.recoverIndeterminate({
      tenant_id: 'tenant:gate-v2',
      admission_id: begun.record.admission_id,
      owner_token: inspectReserved.owner_token,
    });
    assert.equal(indeterminate.ok, true);
    if (!indeterminate.ok) assert.fail(indeterminate.reason);
    assert.equal(indeterminate.record.state, 'INDETERMINATE');
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:inspect',
    }))?.state, 'INDETERMINATE');
    const reconciled = await store.recordProviderOutcome({
      tenant_id: 'tenant:gate-v2',
      admission_id: indeterminate.record.admission_id,
      expected_revision: indeterminate.record.revision,
      owner_token: inspectReserved.owner_token,
      invocation_token: indeterminate.reconciliation_token,
      value: 'COMMITTED',
      evidence_digest: digestOf('inspect-provider-outcome'),
      observed_at: iso(Date.now()),
    });
    assert.equal(reconciled.ok, true);
    if (!reconciled.ok) assert.fail(reconciled.reason);
    assert.equal(reconciled.record.state, 'COMMITTED');
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:inspect',
    }))?.state, 'COMMITTED');

    assert.deepEqual(await reserveProgram('budget-heavy', 'heavy'), {
      ok: false,
      reason: 'program_budget_exhausted',
    });
    const remediateReserved = await reserveProgram('remediate', 'remediate');
    assert.equal(remediateReserved.ok, true);
    if (!remediateReserved.ok) assert.fail(remediateReserved.reason);
    const remediateBegun = await store.beginExecutionProgramInvocation(cas(remediateReserved));
    assert.equal(remediateBegun.ok, true);
    if (!remediateBegun.ok) assert.fail(remediateBegun.reason);
    const remediateOutcome = await store.recordProviderOutcome({
      tenant_id: 'tenant:gate-v2',
      admission_id: remediateBegun.record.admission_id,
      expected_revision: remediateBegun.record.revision,
      owner_token: remediateReserved.owner_token,
      invocation_token: remediateBegun.invocation_token,
      value: 'PROVEN_NOT_COMMITTED',
      evidence_digest: digestOf('remediate-provider-outcome'),
      observed_at: iso(Date.now()),
    });
    assert.equal(remediateOutcome.ok, true);
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:remediate',
    }))?.state, 'PROVEN_NOT_COMMITTED');

    const releaseReserved = await reserveProgram('release', 'releaseable');
    assert.equal(releaseReserved.ok, true);
    if (!releaseReserved.ok) assert.fail(releaseReserved.reason);
    const released = await store.releaseExecutionProgramAdmission(cas(releaseReserved));
    assert.equal(released.ok, true);
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:release',
    }))?.state, 'RELEASED');

    setProgramStatus('SUSPENDED');
    assert.deepEqual(await reserveProgram('status-suspended-reserve', 'releaseable'), {
      ok: false,
      reason: 'program_suspended',
    });
    assert.equal((await store.readExecutionProgram({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest,
    }))?.status, 'SUSPENDED');
    setProgramStatus('ACTIVE');
    const statusReserved = await reserveProgram('status-before-begin', 'releaseable');
    assert.equal(statusReserved.ok, true);
    if (!statusReserved.ok) assert.fail(statusReserved.reason);
    setProgramStatus('SUSPENDED');
    assert.deepEqual(await store.beginExecutionProgramInvocation(cas(statusReserved)), {
      ok: false,
      reason: 'program_suspended',
    });
    assert.equal((await store.read({
      tenant_id: 'tenant:gate-v2', admission_id: statusReserved.record.admission_id,
    }))?.state, 'RELEASED');
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2',
      program_digest: programDigest,
      occurrence_id: 'occurrence:status-before-begin',
    }))?.state, 'RELEASED');
    setProgramStatus('ACTIVE');

    const expiry = iso(Date.now() + 1_200);
    const expiringReserved = await reserveProgram('expiry', 'expirable', expiry);
    assert.equal(expiringReserved.ok, true);
    if (!expiringReserved.ok) assert.fail(expiringReserved.reason);
    await new Promise((resolve) => setTimeout(resolve, 1_350));
    const expired = await store.expireExecutionProgramAdmission(cas(expiringReserved));
    assert.equal(expired.ok, true);
    if (!expired.ok) assert.fail(expired.reason);
    assert.equal(expired.record.state, 'EXPIRED');
    assert.equal((await store.readExecutionProgramOccurrence({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest, occurrence_id: 'occurrence:expiry',
    }))?.state, 'RELEASED');

    const raceA = inputFor('race-a', 'race');
    const raceB = inputFor('race-b', 'race');
    await seedCurrentness(raceA);
    await seedCurrentness(raceB);
    const raceResults = await Promise.all([
      store.reserveExecutionProgramAdmission({
        program_digest: programDigest,
        node_id: 'race',
        occurrence_id: 'occurrence:race-a',
        admission: raceA,
      }),
      store.reserveExecutionProgramAdmission({
        program_digest: programDigest,
        node_id: 'race',
        occurrence_id: 'occurrence:race-b',
        admission: raceB,
      }),
    ]);
    assert.equal(raceResults.filter((result) => result.ok).length, 1);
    assert.deepEqual(
      raceResults.filter((result) => !result.ok).map((result) => result.reason),
      ['program_occurrence_exhausted'],
    );
    const raceWinner = raceResults.find((result) => result.ok);
    assert.ok(raceWinner?.ok);
    assert.equal((await store.releaseExecutionProgramAdmission(cas(raceWinner))).ok, true);

    const reportSnapshot = await store.readExecutionProgramReportSnapshot({
      tenant_id: 'tenant:gate-v2',
      program_digest: programDigest,
    });
    assert.ok(reportSnapshot);
    assert.equal(reportSnapshot['@version'], EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION);
    assert.equal(reportSnapshot.runtime_state.total_occurrences, reportSnapshot.occurrences.length);
    assert.ok(reportSnapshot.occurrences.some((entry) => entry.state === 'RELEASED'));
    assert.ok(reportSnapshot.occurrences.length <= baseProgram.max_total_occurrences);
    const { snapshot_marker: marker, ...snapshotBody } = reportSnapshot;
    assert.equal(marker, executionProgramReportSnapshotMarker(snapshotBody));
    assert.deepEqual(await store.readExecutionProgramReportSnapshot({
      tenant_id: 'tenant:gate-v2',
      program_digest: programDigest,
    }), reportSnapshot);
    await assert.rejects(store.readExecutionProgramReportSnapshot({
      tenant_id: 'tenant:other',
      program_digest: programDigest,
    }), /tenant_id does not match/);

    const rollbackAdmission = inputFor('rollback', 'rollback');
    await seedCurrentness(rollbackAdmission);
    const beforeRollback = await store.readExecutionProgram({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest,
    });
    await pool.query(`CREATE OR REPLACE FUNCTION public.ep_gate_test_fail_occurrence_insert()
      RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected occurrence insert failure'; END
      $$`);
    await pool.query(`CREATE TRIGGER ep_gate_test_fail_occurrence_insert
      BEFORE INSERT ON public.ep_gate_execution_program_occurrences
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_test_fail_occurrence_insert()`);
    await assert.rejects(store.reserveExecutionProgramAdmission({
      program_digest: programDigest,
      node_id: 'rollback',
      occurrence_id: 'occurrence:rollback',
      admission: rollbackAdmission,
    }), /injected occurrence insert failure/);
    await pool.query(`DROP TRIGGER ep_gate_test_fail_occurrence_insert
      ON public.ep_gate_execution_program_occurrences`);
    await pool.query('DROP FUNCTION public.ep_gate_test_fail_occurrence_insert()');
    assert.equal(await store.read({
      tenant_id: 'tenant:gate-v2', admission_id: rollbackAdmission.admission_id,
    }), null);
    assert.deepEqual((await store.readExecutionProgram({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest,
    }))?.budgets, beforeRollback?.budgets);

    await assert.rejects(store.readExecutionProgram({
      tenant_id: 'tenant:other', program_digest: programDigest,
    }), /tenant_id does not match/);
    await assert.rejects(pool.query(
      'SELECT public.ep_gate_execution_program_read($1, $2, $3)',
      ['deployment:gate-v2', 'tenant:other', programDigest],
    ), /binding mismatch/);

    const supersessionBlocker = await reserveProgram('supersession-blocker', 'releaseable');
    assert.equal(supersessionBlocker.ok, true);
    if (!supersessionBlocker.ok) assert.fail(supersessionBlocker.reason);
    const successorInput = {
      ...baseProgram,
      version: 2,
      authorization_digest: successorAuthorizationDigest,
      supersedes_program_digest: programDigest,
      issued_at: iso(Date.now() - 30_000),
      valid_from: iso(Date.now() - 20_000),
      expires_at: iso(Date.now() + 15 * 60_000),
    } satisfies BoundedExecutionProgramInput;
    const successorArtifact = signBoundedExecutionProgram(successorInput, signer);
    const successorDigest = executionProgramDigest(successorArtifact);
    const successorContext = {
      ...context,
      expected_authorization_digest: successorAuthorizationDigest,
    };
    assert.deepEqual(await store.supersedeExecutionProgram(
      successorArtifact, successorContext,
    ), { ok: false, reason: 'program_reserved_work_exists' });
    assert.equal((await store.releaseExecutionProgramAdmission(cas(supersessionBlocker))).ok, true);
    assert.deepEqual(await reserveProgram('total-occurrence-ceiling', 'releaseable'), {
      ok: false,
      reason: 'program_total_occurrence_exhausted',
    });
    const superseded = await store.supersedeExecutionProgram(
      successorArtifact, successorContext,
    );
    assert.equal(superseded.ok, true);
    if (!superseded.ok) assert.fail(superseded.reason);
    assert.equal(superseded.program.program_digest, successorDigest);
    assert.equal((await store.readExecutionProgram({
      tenant_id: 'tenant:gate-v2', program_digest: programDigest,
    }))?.superseded_by_program_digest, successorDigest);
    assert.equal((await store.readExecutionProgram({
      tenant_id: 'tenant:gate-v2', program_digest: successorDigest,
    }))?.status, 'ACTIVE');

    for (const [suffix, authorization] of [
      ['old-auth-fence', authorizationDigest],
      ['new-auth-fence', successorAuthorizationDigest],
    ] as const) {
      const ordinary = inputFor(suffix, 'inspect', authorization);
      await seedCurrentness(ordinary);
      assert.deepEqual(await store.reserve(ordinary), { ok: false, reason: 'program_required' });
    }

    assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
  } finally {
    await pool.query('DROP TRIGGER IF EXISTS ep_gate_test_fail_occurrence_insert ON public.ep_gate_execution_program_occurrences');
    await pool.query('DROP FUNCTION IF EXISTS public.ep_gate_test_fail_occurrence_insert()');
    await pool.query('DROP ROLE IF EXISTS gate_program_untrusted');
    await pool.query(`DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gate_program_runtime') THEN
        DROP OWNED BY gate_program_runtime;
        DROP ROLE gate_program_runtime;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gate_program_verifier') THEN
        DROP OWNED BY gate_program_verifier;
        DROP ROLE gate_program_verifier;
      END IF;
    END $$`);
    await pool.end();
  }
});
