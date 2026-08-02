// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createAdmissionPostgresStore,
  type AdmissionPostgresQuery,
} from './admission-store-postgres.js';
import {
  createAdmissionSnapshot,
  type AdmissionSnapshotInput,
} from './admission-store.js';

const HASH = (character: string) => `sha256:${character.repeat(64)}` as const;
const CAID = 'caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SQL_PATH = fileURLToPath(new URL('./sql/gate-qualification-v2.sql', import.meta.url));
const require = createRequire(import.meta.url);

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function canonical(value: Json): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(value[key])}`
  )).join(',')}}`;
}

function redigestSnapshot<T extends { body: Record<string, unknown>; snapshot_digest: string }>(
  snapshot: T,
): T {
  snapshot.snapshot_digest = `sha256:${crypto.createHash('sha256')
    .update('EP-GATE-ADMISSION-SNAPSHOT-v2:DIGEST')
    .update('\0')
    .update(canonical(snapshot.body as Json))
    .digest('hex')}`;
  return snapshot;
}

function iso(milliseconds: number): string {
  return new Date(milliseconds).toISOString();
}

function admissionInput(
  admissionId: string,
  operationId: string,
  now: number,
  overrides: Partial<AdmissionSnapshotInput> = {},
): AdmissionSnapshotInput {
  const admittedAt = iso(now - 60_000);
  const validUntil = iso(now + 10 * 60_000);
  const role = (
    name: AdmissionSnapshotInput['inputs'][number]['role'],
    index: number,
  ): AdmissionSnapshotInput['inputs'][number] => ({
    role: name,
    artifact_type: `artifact:${name}`,
    subject: `subject:${index}`,
    payload_digest: HASH(((index + 1) % 10).toString()),
    profile_digest: HASH(((index + 2) % 10).toString()),
    verifier_id: `verifier:${index}`,
    trust_configuration_digest: HASH('a'),
    valid_until: validUntil,
  });
  return {
    tenant_id: 'tenant:gate-v2',
    admission_id: admissionId,
    operation_id: operationId,
    candidate_manifest_digest: HASH('1'),
    runtime_measurement_digest: HASH('2'),
    candidate_custody: {
      request_construction: 'EXECUTOR_ADAPTER',
      mutation_credential_custody: 'EXECUTOR_ADAPTER',
      enforcement_placement: 'ACTUATOR',
      evidence_digest: HASH('3'),
    },
    assignment_digest: HASH('4'),
    qualification_policy_digest: HASH('5'),
    test_result_payload_digests: [HASH('6')],
    agent_evaluation_evidence_payload_digests: [HASH('7')],
    qualification_statement_payload_digest: HASH('8'),
    qualification_status: {
      authority_id: 'authority:qualification',
      sequence: 7,
      head_payload_digest: HASH('9'),
      observed_at: admittedAt,
      expires_at: validUntil,
    },
    caid: CAID,
    action_digest: HASH('b'),
    effect_request_digest: HASH('c'),
    provider: {
      provider_id: 'provider:payments',
      account_id: 'account:production',
      environment: 'production',
    },
    executor_adapter_digest: HASH('d'),
    idempotency_key: `idempotency:${operationId}`,
    authorization_policy_digest: HASH('e'),
    trust_epoch: 11,
    trust_configuration_digest: HASH('a'),
    configuration_epoch: 13,
    configuration_digest: HASH('f'),
    inputs: [
      { ...role('candidate_manifest', 0), payload_digest: HASH('1') },
      { ...role('runtime_measurement', 1), payload_digest: HASH('2') },
      { ...role('test_result', 2), payload_digest: HASH('6') },
      { ...role('agent_evaluation_evidence', 3), payload_digest: HASH('7') },
      { ...role('qualification_statement', 4), payload_digest: HASH('8') },
      { ...role('qualification_status', 5), payload_digest: HASH('9') },
      role('aeb', 6),
      role('aec', 7),
      role('local_policy', 8),
      role('authorization', 9),
    ],
    resource_reservations: [
      {
        kind: 'capability',
        resource_id: `capability:${operationId}`,
        reservation_id: `capability-reservation:${admissionId}`,
        digest: HASH('f'),
        expires_at: validUntil,
      },
      {
        kind: 'provider_operation',
        resource_id: operationId,
        reservation_id: `reservation:${admissionId}`,
        digest: HASH('0'),
        expires_at: validUntil,
      },
      {
        kind: 'external_lease',
        resource_id: `lease:${operationId}`,
        reservation_id: `lease-reservation:${admissionId}`,
        digest: HASH('1'),
        expires_at: validUntil,
      },
    ],
    admitted_at: admittedAt,
    expires_at: iso(now + 5 * 60_000),
    supersedes_admission_id: null,
    remedy_for: null,
    ...overrides,
  };
}

test('SQL contract is singleton-bound, append-only, and has permanent operation/resource fences', async () => {
  const sql = await readFile(SQL_PATH, 'utf8');
  assert.match(sql, /^BEGIN;/m);
  assert.match(sql, /COMMIT;\s*$/);
  assert.match(sql, /singleton boolean PRIMARY KEY DEFAULT true CHECK \(singleton\)/);
  assert.match(sql, /PRIMARY KEY \(deployment_id, operation_id\)/);
  assert.match(sql, /Gate Qualification v2 operation heads are permanent/);
  assert.match(sql, /consumed Gate resources cannot be released or transferred/);
  assert.match(sql, /ep_gate_admission_recover_indeterminate[\s\S]*p_owner_digest text[\s\S]*p_reconciliation_token_digest text/);
  assert.match(sql, /ep_gate_admission_reap_expired[\s\S]*p_expected_revision bigint/);
  assert.match(sql, /'ABANDONED_BEFORE_INVOCATION'/);
  assert.match(sql, /reserved_past_expiry/);
  assert.match(sql, /Recovery authority is the database EXECUTE privilege/);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.ep_gate_admission_reap_expired/);
  assert.match(sql, /'invocation_token_digest', p_reconciliation_token_digest/);
  assert.match(sql, /v_successor_body->>'operation_id' <> v_predecessor_snapshot->'body'->>'operation_id'/);
  assert.match(sql, /v_successor_body->>'effect_request_digest'/);
  assert.match(sql, /v_successor_body->'provider'/);
  assert.match(sql, /FOR UPDATE/);
  assert.match(sql, /unique_violation/);
  assert.match(sql, /ep_gate_protected_request_heads/);
  assert.match(sql, /ep_gate_evidence_heads/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS public\.ep_gate_monotonic_counters/);
  assert.match(sql, /CREATE OR REPLACE FUNCTION public\.ep_gate_provision_monotonic_counter/);
  assert.match(sql, /ep_gate_advance_monotonic_counters/);
  assert.match(sql, /UPDATE public\.ep_gate_monotonic_counters/);
  assert.doesNotMatch(
    sql.match(/CREATE OR REPLACE FUNCTION public\.ep_gate_advance_monotonic_counters[\s\S]*?\n\$\$;/)?.[0] ?? '',
    /INSERT INTO public\.ep_gate_monotonic_counters/,
  );
  assert.match(sql, /current_value\s*=\s*\(v_resource->>'expected_value'\)::bigint/);
  assert.match(sql, /c\.current_value < \(resource->>'next_value'\)::bigint/);
  assert.match(sql, /WHERE resource->>'kind' <> 'monotonic_counter'/);
  assert.match(sql, /maximum_observation_age_ms/);
  assert.match(sql, /ep_gate_jsonb_has_exact_keys/);
  assert.match(sql, /REVOKE ALL ON FUNCTION public\.ep_gate_canonical_json\(jsonb\) FROM PUBLIC/);
  assert.doesNotMatch(sql, /tenant_principal|tenant_map|current_user.*tenant/i);
});

test('adapter is explicitly durable, local_atomic, single-tenant, and deployment-bound', async () => {
  const query: AdmissionPostgresQuery = async () => ({ rowCount: 1, rows: [{ result: null }] });
  const store = createAdmissionPostgresStore({
    query,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
  });
  assert.equal(store.durable, true);
  assert.equal(store.guaranteeClass, 'local_atomic');
  assert.equal(store.singleTenant, true);
  assert.equal(store.deploymentBound, true);
  assert.equal(store.managedTenantPrincipalMapping, false);
  await assert.rejects(
    store.read({ tenant_id: 'tenant:other', admission_id: 'admission:x' }),
    /tenant_id does not match/,
  );
});

test('expiry recovery uses the dedicated deadline-gated RPC without an owner token', async () => {
  const calls: Array<{ text: string; params: readonly unknown[] }> = [];
  const query: AdmissionPostgresQuery = async (text, params) => {
    calls.push({ text, params });
    return {
      rowCount: 1,
      rows: [{ result: { ok: false, reason: 'state_conflict' } }],
    };
  };
  const store = createAdmissionPostgresStore({
    query,
    deploymentId: 'deployment:gate-v2',
    tenantId: 'tenant:gate-v2',
  });
  assert.deepEqual(await store.reapExpiredReservation({
    tenant_id: 'tenant:gate-v2',
    admission_id: 'admission:expired',
    expected_revision: 3,
  }), { ok: false, reason: 'state_conflict' });
  assert.equal(calls.length, 1);
  assert.match(calls[0].text, /ep_gate_admission_reap_expired/);
  assert.deepEqual(calls[0].params, [
    'deployment:gate-v2', 'tenant:gate-v2', 'admission:expired', 3,
  ]);
});

const postgresUrl = process.env.ADMISSION_STORE_POSTGRES_TEST_URL;

test('real PostgreSQL enforces reserve, supersession, currentness, crash recovery, and consumed truth', {
  skip: postgresUrl ? false : 'ADMISSION_STORE_POSTGRES_TEST_URL is not configured',
}, async () => {
  const { Pool } = require('pg') as {
    Pool: new (options: { connectionString: string | undefined; max: number }) => {
      query: (text: string, params?: unknown[]) => Promise<{
        rowCount: number | null;
        rows: Array<Record<string, unknown>>;
      }>;
      end: () => Promise<void>;
    };
  };
  const pool = new Pool({ connectionString: postgresUrl, max: 24 });
  const query: AdmissionPostgresQuery = async (text, params) => {
    const result = await pool.query(text, [...params]);
    return { rowCount: result.rowCount ?? 0, rows: result.rows };
  };
  try {
    await pool.query(await readFile(SQL_PATH, 'utf8'));
    await pool.query('DROP ROLE IF EXISTS gate_qv2_untrusted');
    await pool.query('CREATE ROLE gate_qv2_untrusted NOLOGIN');
    const publicExecutors = await pool.query(`SELECT p.oid::regprocedure::text AS function_name
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname LIKE 'ep_gate_%'
        AND has_function_privilege('gate_qv2_untrusted', p.oid, 'EXECUTE')
      ORDER BY p.oid::regprocedure::text`);
    assert.deepEqual(publicExecutors.rows, [], 'PUBLIC must not retain EXECUTE on Gate functions');
    await pool.query(`TRUNCATE
      public.ep_gate_admission_journal,
      public.ep_gate_resource_fences,
      public.ep_gate_operation_heads,
      public.ep_gate_admission_records,
      public.ep_gate_admission_snapshots,
      public.ep_gate_evidence_heads,
      public.ep_gate_protected_request_heads,
      public.ep_gate_candidate_runtime_heads,
      public.ep_gate_external_leases,
      public.ep_gate_monotonic_counters,
      public.ep_gate_qualification_status_heads,
      public.ep_gate_deployment_binding CASCADE`);
    const now = Date.now();
    await pool.query(`INSERT INTO public.ep_gate_deployment_binding (
      singleton, deployment_id, tenant_id, trust_epoch, trust_configuration_digest,
      configuration_epoch, configuration_digest, runtime_measurement_digest,
      candidate_match, currentness_observed_at
    ) VALUES (true, $1, $2, 11, $3, 13, $4, $5, 'EXACT_MATCH', clock_timestamp())`, [
      'deployment:gate-v2', 'tenant:gate-v2', HASH('a'), HASH('f'), HASH('2'),
    ]);
    await pool.query(`INSERT INTO public.ep_gate_qualification_status_heads (
      deployment_id, authority_id, sequence, head_payload_digest, observed_at, expires_at
    ) VALUES ($1, 'authority:qualification', 7, $2, clock_timestamp(), clock_timestamp() + interval '20 minutes')`, [
      'deployment:gate-v2', HASH('9'),
    ]);

    async function assertDirectReserveRejected(
      snapshot: { body: Record<string, unknown>; snapshot_digest: string },
      label: string,
    ): Promise<void> {
      const admissionId = String(snapshot.body.admission_id);
      const operationId = String(snapshot.body.operation_id);
      await assert.rejects(
        pool.query(
          'SELECT public.ep_gate_admission_reserve($1, $2, $3::jsonb, $4)',
          ['deployment:gate-v2', 'tenant:gate-v2', JSON.stringify(snapshot), HASH('e')],
        ),
        undefined,
        label,
      );
      const poisoned = await pool.query(`SELECT
        (SELECT count(*)::int FROM public.ep_gate_admission_snapshots
          WHERE deployment_id = $1 AND admission_id = $2) AS snapshots,
        (SELECT count(*)::int FROM public.ep_gate_admission_records
          WHERE deployment_id = $1 AND admission_id = $2) AS records,
        (SELECT count(*)::int FROM public.ep_gate_operation_heads
          WHERE deployment_id = $1 AND operation_id = $3) AS operations,
        (SELECT count(*)::int FROM public.ep_gate_resource_fences
          WHERE deployment_id = $1 AND admission_id = $2) AS resources`, [
        'deployment:gate-v2', admissionId, operationId,
      ]);
      assert.deepEqual(poisoned.rows[0], {
        snapshots: 0, records: 0, operations: 0, resources: 0,
      }, `${label} must not poison permanent fences`);
    }

    function hostileSnapshot(
      suffix: string,
      mutate: (snapshot: { body: Record<string, any>; snapshot_digest: string }) => void,
    ): { body: Record<string, any>; snapshot_digest: string } {
      const value = structuredClone(createAdmissionSnapshot(admissionInput(
        `admission:hostile-${suffix}`,
        `operation:hostile-${suffix}`,
        now,
      ))) as unknown as { body: Record<string, any>; snapshot_digest: string };
      mutate(value);
      return redigestSnapshot(value);
    }

    await assertDirectReserveRejected(hostileSnapshot('sparse', (snapshot) => {
      snapshot.body = {
        '@version': snapshot.body['@version'],
        tenant_id: snapshot.body.tenant_id,
        admission_id: snapshot.body.admission_id,
        operation_id: snapshot.body.operation_id,
        admitted_at: snapshot.body.admitted_at,
        expires_at: snapshot.body.expires_at,
        supersedes_admission_id: null,
        remedy_for: null,
        resource_reservations: snapshot.body.resource_reservations,
      };
    }), 'sparse snapshot');
    await assertDirectReserveRejected(hostileSnapshot('unknown', (snapshot) => {
      (snapshot as any).presenter_selected_mode = 'bypass';
      snapshot.body.presenter_selected_trust = HASH('0');
      snapshot.body.provider.presenter_selected_account = 'account:attacker';
    }), 'unknown snapshot members');
    await assertDirectReserveRejected(hostileSnapshot('malformed-provider', (snapshot) => {
      snapshot.body.provider = { provider_id: 'provider:payments' };
    }), 'malformed provider binding');
    await assertDirectReserveRejected(hostileSnapshot('missing-role', (snapshot) => {
      snapshot.body.inputs = snapshot.body.inputs.filter(
        (entry: { role: string }) => entry.role !== 'authorization',
      );
    }), 'missing required authorization role');
    await assertDirectReserveRejected(hostileSnapshot('duplicate-role', (snapshot) => {
      snapshot.body.inputs.push({
        ...snapshot.body.inputs.find((entry: { role: string }) => entry.role === 'aeb'),
        subject: 'subject:duplicate-aeb',
      });
    }), 'duplicate singleton AEB role');
    await assertDirectReserveRejected(hostileSnapshot('caid', (snapshot) => {
      snapshot.body.caid = 'caid:attacker';
    }), 'malformed CAID binding');
    await assertDirectReserveRejected(hostileSnapshot('action', (snapshot) => {
      snapshot.body.action_digest = 'sha256:short';
    }), 'malformed action binding');
    await assertDirectReserveRejected(hostileSnapshot('effect', (snapshot) => {
      delete snapshot.body.effect_request_digest;
    }), 'missing effect-request binding');
    await assertDirectReserveRejected(hostileSnapshot('status', (snapshot) => {
      snapshot.body.qualification_status = {
        ...snapshot.body.qualification_status,
        sequence: '7',
        presenter_selected_head: HASH('0'),
      };
    }), 'malformed qualification-status binding');
    await assertDirectReserveRejected(hostileSnapshot('trust', (snapshot) => {
      snapshot.body.trust_configuration_digest = HASH('0');
      snapshot.body.trust_epoch = -1;
    }), 'malformed trust binding');
    await assertDirectReserveRejected(hostileSnapshot('configuration', (snapshot) => {
      snapshot.body.configuration_epoch = 1.5;
    }), 'malformed configuration binding');
    await assertDirectReserveRejected(hostileSnapshot('capability', (snapshot) => {
      const capability = snapshot.body.resource_reservations.find(
        (resource: { kind: string }) => resource.kind === 'capability',
      );
      capability.presenter_selected_scope = '*';
    }), 'open capability reservation binding');
    await assertDirectReserveRejected(hostileSnapshot('binding', (snapshot) => {
      const candidate = snapshot.body.inputs.find(
        (entry: { role: string }) => entry.role === 'candidate_manifest',
      );
      candidate.payload_digest = HASH('0');
    }), 'candidate manifest input binding mismatch');
    await assertDirectReserveRejected(hostileSnapshot('expiry-ceiling', (snapshot) => {
      snapshot.body.inputs[0].valid_until = snapshot.body.admitted_at;
    }), 'expired input ceiling');

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
        value.configuration_epoch, value.configuration_digest,
        value.runtime_measurement_digest,
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
      for (const lease of value.resource_reservations.filter(
        (resource) => resource.kind === 'external_lease',
      )) {
        await pool.query(`INSERT INTO public.ep_gate_external_leases (
          deployment_id, resource_id, digest, observed_at, expires_at
        ) VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp() + interval '20 minutes')
        ON CONFLICT (deployment_id, resource_id) DO UPDATE SET
          digest = EXCLUDED.digest,
          observed_at = EXCLUDED.observed_at,
          expires_at = EXCLUDED.expires_at`, [
          'deployment:gate-v2', lease.resource_id, lease.digest,
        ]);
      }
    }

    async function assertCurrentnessRefused(
      suffix: string,
      mutateHead: (value: AdmissionSnapshotInput) => Promise<void>,
    ): Promise<void> {
      const value = admissionInput(
        `admission:currentness-${suffix}`,
        `operation:currentness-${suffix}`,
        now,
      );
      const snapshot = createAdmissionSnapshot(value);
      const ownerDigest = HASH('d');
      const reserved = await pool.query(
        'SELECT public.ep_gate_admission_reserve($1, $2, $3::jsonb, $4) AS result',
        ['deployment:gate-v2', 'tenant:gate-v2', JSON.stringify(snapshot), ownerDigest],
      );
      assert.equal(reserved.rows[0].result.ok, true, `${suffix}: direct reserve failed`);
      await seedCurrentness(value);
      await mutateHead(value);
      const begun = await pool.query(
        `SELECT public.ep_gate_admission_begin_invocation(
          $1, $2, $3, 0, $4, $5
        ) AS result`,
        ['deployment:gate-v2', 'tenant:gate-v2', value.admission_id, ownerDigest, HASH('c')],
      );
      assert.deepEqual(begun.rows[0].result, {
        ok: false, reason: 'currentness_refused',
      }, `${suffix}: invocation must fail closed`);
      const state = await pool.query(`SELECT
        (SELECT record_json->>'state' FROM public.ep_gate_admission_records
          WHERE deployment_id = $1 AND admission_id = $2) AS state,
        (SELECT count(*)::int FROM public.ep_gate_resource_fences
          WHERE deployment_id = $1 AND admission_id = $2) AS resources,
        (SELECT count(*)::int FROM public.ep_gate_operation_heads
          WHERE deployment_id = $1 AND operation_id = $3) AS operations`, [
        'deployment:gate-v2', value.admission_id, value.operation_id,
      ]);
      assert.deepEqual(state.rows[0], {
        state: 'RELEASED', resources: 0, operations: 1,
      }, `${suffix}: refusal must release resources without erasing the operation fence`);
    }

    await assertCurrentnessRefused('protected-request', async (value) => {
      await pool.query(`UPDATE public.ep_gate_protected_request_heads
        SET action_digest = $2 WHERE deployment_id = $1 AND operation_id = $3`, [
        'deployment:gate-v2', HASH('0'), value.operation_id,
      ]);
    });
    for (const role of ['aeb', 'aec', 'local_policy', 'authorization'] as const) {
      await assertCurrentnessRefused(`evidence-${role.replace('_', '-')}`, async () => {
        await pool.query(`UPDATE public.ep_gate_evidence_heads
          SET payload_digest = $2 WHERE deployment_id = $1 AND role = $3`, [
          'deployment:gate-v2', HASH('f'), role,
        ]);
      });
    }
    await assertCurrentnessRefused('candidate', async () => {
      await pool.query(`UPDATE public.ep_gate_candidate_runtime_heads
        SET candidate_manifest_digest = $2 WHERE deployment_id = $1`, [
        'deployment:gate-v2', HASH('0'),
      ]);
    });
    await assertCurrentnessRefused('runtime', async () => {
      await pool.query(`UPDATE public.ep_gate_candidate_runtime_heads
        SET runtime_measurement_digest = $2 WHERE deployment_id = $1`, [
        'deployment:gate-v2', HASH('0'),
      ]);
    });
    await assertCurrentnessRefused('qualification-status', async () => {
      await pool.query(`UPDATE public.ep_gate_qualification_status_heads
        SET head_payload_digest = $2 WHERE deployment_id = $1`, [
        'deployment:gate-v2', HASH('0'),
      ]);
    });
    await assertCurrentnessRefused('trust', async () => {
      await pool.query(`UPDATE public.ep_gate_deployment_binding
        SET trust_configuration_digest = $2 WHERE deployment_id = $1`, [
        'deployment:gate-v2', HASH('0'),
      ]);
    });
    await assertCurrentnessRefused('configuration', async () => {
      await pool.query(`UPDATE public.ep_gate_deployment_binding
        SET configuration_digest = $2 WHERE deployment_id = $1`, [
        'deployment:gate-v2', HASH('0'),
      ]);
    });
    await assertCurrentnessRefused('lease', async (value) => {
      await pool.query(`UPDATE public.ep_gate_external_leases
        SET digest = $2 WHERE deployment_id = $1 AND resource_id = $3`, [
        'deployment:gate-v2', HASH('0'), `lease:${value.operation_id}`,
      ]);
    });
    await assertCurrentnessRefused('stale-candidate', async () => {
      await pool.query(`UPDATE public.ep_gate_candidate_runtime_heads
        SET observed_at = clock_timestamp() - interval '10 minutes'
        WHERE deployment_id = $1`, ['deployment:gate-v2']);
    });
    await assertCurrentnessRefused('stale-evidence', async () => {
      await pool.query(`UPDATE public.ep_gate_evidence_heads
        SET observed_at = clock_timestamp() - interval '10 minutes'
        WHERE deployment_id = $1 AND role = 'aeb'`, ['deployment:gate-v2']);
    });
    await assertCurrentnessRefused('stale-trust-config', async () => {
      await pool.query(`UPDATE public.ep_gate_deployment_binding
        SET currentness_observed_at = clock_timestamp() - interval '10 minutes'
        WHERE deployment_id = $1`, ['deployment:gate-v2']);
    });

    const store = createAdmissionPostgresStore({
      query,
      deploymentId: 'deployment:gate-v2',
      tenantId: 'tenant:gate-v2',
      maxTransactionRetries: 6,
    });

    const reaperNow = Date.now();
    const abandonedInput = admissionInput(
      'admission:abandoned-before-invocation',
      'operation:abandoned-before-invocation',
      reaperNow,
      { expires_at: iso(reaperNow + 250) },
    );
    await seedCurrentness(abandonedInput);
    const abandoned = await store.reserve(abandonedInput);
    assert.ok(abandoned.ok);
    assert.deepEqual(await store.reapExpiredReservation({
      tenant_id: abandoned.record.tenant_id,
      admission_id: abandoned.record.admission_id,
      expected_revision: abandoned.record.revision,
    }), { ok: false, reason: 'state_conflict' });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const reaped = await store.reapExpiredReservation({
      tenant_id: abandoned.record.tenant_id,
      admission_id: abandoned.record.admission_id,
      expected_revision: abandoned.record.revision,
    });
    assert.ok(reaped.ok);
    assert.equal(reaped.record.state, 'EXPIRED');
    assert.equal(reaped.record.refusal_reason, 'abandoned_before_invocation');
    assert.equal((await store.journal({
      tenant_id: abandoned.record.tenant_id,
      admission_id: abandoned.record.admission_id,
    })).at(-1)?.event, 'ABANDONED_BEFORE_INVOCATION');

    const counterInput = (
      suffix: string,
      expectedValue: number,
      nextValue: number,
    ): AdmissionSnapshotInput => {
      const value = admissionInput(
        `admission:counter-${suffix}`,
        `operation:counter-${suffix}`,
        now,
      );
      value.resource_reservations.push({
        kind: 'monotonic_counter',
        resource_id: 'webauthn-sign-count:test-credential',
        reservation_id: `counter-reservation:${suffix}`,
        digest: HASH(suffix === 'first' ? '1' : suffix === 'clone' ? '2' : '3'),
        expires_at: value.expires_at,
        expected_value: expectedValue,
        next_value: nextValue,
      });
      return value;
    };
    const firstCounterInput = counterInput('first', 41, 42);
    const missingCounterInput = counterInput('missing-enrollment', 41, 42);
    missingCounterInput.resource_reservations = missingCounterInput.resource_reservations.map(
      (resource) => resource.kind === 'monotonic_counter'
        ? { ...resource, resource_id: 'webauthn-sign-count:missing-enrollment' }
        : resource,
    );
    await seedCurrentness(missingCounterInput);
    assert.deepEqual(await store.reserve(missingCounterInput), {
      ok: false,
      reason: 'resource_conflict',
    });
    const missingCounterHead = await pool.query(`SELECT current_value
      FROM public.ep_gate_monotonic_counters
      WHERE deployment_id = $1 AND resource_id = $2`, [
      'deployment:gate-v2', 'webauthn-sign-count:missing-enrollment',
    ]);
    assert.equal(missingCounterHead.rowCount, 0);

    await pool.query(
      'SELECT public.ep_gate_provision_monotonic_counter($1, $2, $3, $4)',
      ['deployment:gate-v2', 'tenant:gate-v2', 'webauthn-sign-count:test-credential', 41],
    );
    await assert.rejects(
      pool.query(
        'SELECT public.ep_gate_provision_monotonic_counter($1, $2, $3, $4)',
        ['deployment:gate-v2', 'tenant:gate-v2', 'webauthn-sign-count:test-credential', 41],
      ),
      /monotonic counter already provisioned/,
    );
    await seedCurrentness(firstCounterInput);
    const firstCounter = await store.reserve(firstCounterInput);
    assert.ok(firstCounter.ok);
    const clonedCounterInput = counterInput('clone', 41, 42);
    await seedCurrentness(clonedCounterInput);
    assert.deepEqual(await store.reserve(clonedCounterInput), {
      ok: false,
      reason: 'resource_conflict',
    });
    const nextCounterInput = counterInput('next', 42, 43);
    await seedCurrentness(nextCounterInput);
    assert.ok((await store.reserve(nextCounterInput)).ok);

    await pool.query(
      'SELECT public.ep_gate_provision_monotonic_counter($1, $2, $3, $4)',
      ['deployment:gate-v2', 'tenant:gate-v2', 'webauthn-sign-count:rollback-proof', 7],
    );
    const rollbackInput = counterInput('rollback-proof', 7, 8);
    rollbackInput.resource_reservations = rollbackInput.resource_reservations.map(
      (resource, index) => resource.kind === 'monotonic_counter'
        ? { ...resource, resource_id: 'webauthn-sign-count:rollback-proof' }
        : index === 0
          ? { ...firstCounterInput.resource_reservations[0] }
          : resource,
    );
    await seedCurrentness(rollbackInput);
    assert.deepEqual(await store.reserve(rollbackInput), {
      ok: false,
      reason: 'resource_conflict',
    });
    const rollbackHead = await pool.query<{ current_value: string }>(`SELECT current_value::text
      FROM public.ep_gate_monotonic_counters
      WHERE deployment_id = $1 AND resource_id = $2`, [
      'deployment:gate-v2', 'webauthn-sign-count:rollback-proof',
    ]);
    assert.equal(rollbackHead.rows[0]?.current_value, '7');
    await seedCurrentness(firstCounterInput);
    assert.ok((await store.beginInvocation({
      tenant_id: firstCounter.record.tenant_id,
      admission_id: firstCounter.record.admission_id,
      expected_revision: firstCounter.record.revision,
      owner_token: firstCounter.owner_token,
    })).ok);

    const raceOperation = 'operation:reserve-race';
    await seedCurrentness(admissionInput('admission:reserve-race', raceOperation, now));
    const reserves = await Promise.all(Array.from({ length: 24 }, () => (
      store.reserve(admissionInput('admission:reserve-race', raceOperation, now))
    )));
    assert.equal(reserves.filter((result) => result.ok).length, 1);
    assert.equal(reserves.filter((result) => !result.ok).every((result) => (
      result.reason === 'admission_exists' || result.reason === 'operation_exists'
    )), true);
    const reserved = reserves.find((result) => result.ok);
    assert.ok(reserved?.ok);

    const begins = await Promise.all(Array.from({ length: 24 }, () => store.beginInvocation({
      tenant_id: reserved.record.tenant_id,
      admission_id: reserved.record.admission_id,
      expected_revision: reserved.record.revision,
      owner_token: reserved.owner_token,
    })));
    assert.equal(begins.filter((result) => result.ok).length, 1);
    const begun = begins.find((result) => result.ok);
    assert.ok(begun?.ok);
    assert.equal(begun.record.resources.every((resource) => resource.state === 'CONSUMED'), true);

    assert.deepEqual(await store.recoverIndeterminate({
      tenant_id: begun.record.tenant_id,
      admission_id: begun.record.admission_id,
      owner_token: 'admission-owner:v2:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    }), { ok: false, reason: 'owner_conflict' });
    const recovered = await store.recoverIndeterminate({
      tenant_id: begun.record.tenant_id,
      admission_id: begun.record.admission_id,
      owner_token: reserved.owner_token,
    });
    assert.equal(recovered.ok, true);
    assert.ok(recovered.ok);
    assert.notEqual(recovered.reconciliation_token, begun.invocation_token);
    assert.equal(recovered.record.resources.every((resource) => resource.state === 'CONSUMED'), true);

    assert.deepEqual(await store.recordProviderOutcome({
      tenant_id: recovered.record.tenant_id,
      admission_id: recovered.record.admission_id,
      expected_revision: recovered.record.revision,
      owner_token: reserved.owner_token,
      invocation_token: begun.invocation_token,
      value: 'COMMITTED',
      evidence_digest: HASH('7'),
      observed_at: iso(now),
    }), { ok: false, reason: 'invocation_token_conflict' });
    const effect = await store.recordEffectRelation({
      tenant_id: recovered.record.tenant_id,
      admission_id: recovered.record.admission_id,
      expected_revision: recovered.record.revision,
      owner_token: reserved.owner_token,
      invocation_token: recovered.reconciliation_token,
      value: 'DIVERGED',
      evidence_digest: HASH('8'),
      observed_at: iso(now),
    });
    assert.equal(effect.ok, true);
    assert.ok(effect.ok);
    assert.equal(effect.record.provider_outcome?.value, 'INDETERMINATE');
    assert.equal(effect.record.effect_relation?.value, 'DIVERGED');
    const provider = await store.recordProviderOutcome({
      tenant_id: effect.record.tenant_id,
      admission_id: effect.record.admission_id,
      expected_revision: effect.record.revision,
      owner_token: reserved.owner_token,
      invocation_token: recovered.reconciliation_token,
      value: 'COMMITTED',
      evidence_digest: HASH('7'),
      observed_at: iso(now),
    });
    assert.equal(provider.ok, true);
    assert.ok(provider.ok);
    assert.equal(provider.record.effect_relation?.value, 'DIVERGED');
    assert.equal(provider.record.resources.every((resource) => resource.state === 'CONSUMED'), true);

    const supersedeOperation = 'operation:supersede';
    await seedCurrentness(admissionInput('admission:predecessor', supersedeOperation, now));
    const predecessor = await store.reserve(admissionInput('admission:predecessor', supersedeOperation, now));
    assert.ok(predecessor.ok);
    const successorInput = admissionInput('admission:successor', supersedeOperation, now, {
      resource_reservations: admissionInput('admission:successor', supersedeOperation, now)
        .resource_reservations.map((resource) => ({
          ...resource,
          reservation_id: resource.reservation_id.replace('predecessor', 'successor'),
        })),
    });
    const superseded = await store.supersede({
      tenant_id: predecessor.record.tenant_id,
      admission_id: predecessor.record.admission_id,
      expected_revision: predecessor.record.revision,
      owner_token: predecessor.owner_token,
      successor: successorInput,
    });
    assert.ok(superseded.ok);
    assert.equal(superseded.predecessor_record.operation_id, superseded.successor_record.operation_id);
    assert.equal(superseded.predecessor_record.state, 'SUPERSEDED');
    assert.equal((await store.readByOperation({
      tenant_id: 'tenant:gate-v2', operation_id: supersedeOperation,
    }))?.admission_id, 'admission:successor');

    const staleOperation = 'operation:stale-currentness';
    await seedCurrentness(admissionInput('admission:stale', staleOperation, now));
    const stale = await store.reserve(admissionInput('admission:stale', staleOperation, now));
    assert.ok(stale.ok);
    await pool.query(`UPDATE public.ep_gate_deployment_binding SET runtime_measurement_digest = $1`, [HASH('3')]);
    assert.deepEqual(await store.beginInvocation({
      tenant_id: stale.record.tenant_id,
      admission_id: stale.record.admission_id,
      expected_revision: stale.record.revision,
      owner_token: stale.owner_token,
    }), { ok: false, reason: 'currentness_refused' });
    assert.equal((await store.read({
      tenant_id: stale.record.tenant_id, admission_id: stale.record.admission_id,
    }))?.state, 'RELEASED');
    await pool.query(`UPDATE public.ep_gate_deployment_binding SET runtime_measurement_digest = $1`, [HASH('2')]);

    const crashOperation = 'operation:lost-begin-ack';
    await seedCurrentness(admissionInput('admission:lost-ack', crashOperation, now));
    let loseBeginAck = true;
    const lossyQuery: AdmissionPostgresQuery = async (text, params) => {
      const result = await query(text, params);
      if (loseBeginAck && text.includes('ep_gate_admission_begin_invocation')) {
        loseBeginAck = false;
        throw new Error('response lost after begin commit');
      }
      return result;
    };
    const lossyStore = createAdmissionPostgresStore({
      query: lossyQuery,
      deploymentId: 'deployment:gate-v2',
      tenantId: 'tenant:gate-v2',
    });
    const crashReserved = await lossyStore.reserve(admissionInput('admission:lost-ack', crashOperation, now));
    assert.ok(crashReserved.ok);
    const crashBegun = await lossyStore.beginInvocation({
      tenant_id: crashReserved.record.tenant_id,
      admission_id: crashReserved.record.admission_id,
      expected_revision: crashReserved.record.revision,
      owner_token: crashReserved.owner_token,
    });
    assert.ok(crashBegun.ok);
    assert.equal(crashBegun.record.state, 'INVOKING');

    const journal = await store.journal({
      tenant_id: provider.record.tenant_id,
      admission_id: provider.record.admission_id,
    });
    assert.deepEqual(journal.map((entry) => entry.sequence), [0, 1, 2, 3, 4]);
    assert.deepEqual(await store.checkInvariants(), { ok: true, violations: [] });
  } finally {
    await pool.query('DROP ROLE IF EXISTS gate_qv2_untrusted').catch(() => undefined);
    await pool.end();
  }
});
