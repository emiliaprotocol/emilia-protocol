// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { contract } from '../scripts/db-contract.manifest.mjs';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260725010000_consequence_actuator_store.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('consequence actuator production store migration', () => {
  it('creates a closed one-time envelope binding with replay and idempotency fences', () => {
    expect(migration).toContain(
      'CREATE TABLE public.consequence_actuator_envelopes',
    );
    for (const field of [
      'tenant_id',
      'attempt_id',
      'action_digest',
      'caid',
      'provider_account_id',
      'target_digest',
      'operation',
      'idempotency_key',
      'nonce',
      'issued_at',
      'expires_at',
      'envelope_digest',
    ]) {
      expect(migration).toContain(field);
    }
    expect(migration).toContain('PRIMARY KEY (tenant_id, nonce)');
    expect(migration).toContain(
      'UNIQUE (tenant_id, provider_account_id, operation, idempotency_key)',
    );
    expect(migration).toContain("state IN ('RESERVED', 'CONSUMED')");
    expect(migration).toContain(
      "outcome IN ('COMMITTED', 'INDETERMINATE')",
    );
    expect(migration).toContain(
      'pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 256',
    );
    expect(migration).toContain(
      'pg_catalog.octet_length(caid) BETWEEN 1 AND 512',
    );
    expect(migration).toContain(
      'pg_catalog.octet_length(nonce) BETWEEN 22 AND 128',
    );
    expect(migration.match(
      /execution envelope binding is malformed or unbounded/g,
    )).toHaveLength(2);
  });

  it('uses an owner separate from the tenant-bound runtime principal', () => {
    expect(migration).toContain(
      'CREATE ROLE consequence_actuator_store_owner NOLOGIN NOBYPASSRLS',
    );
    expect(migration).toContain(
      'CREATE ROLE consequence_actuator_executor NOLOGIN NOBYPASSRLS',
    );
    expect(migration).toContain(
      'ALTER ROLE consequence_actuator_store_owner NOLOGIN NOBYPASSRLS',
    );
    expect(migration).toContain(
      'ALTER ROLE consequence_actuator_executor NOLOGIN NOBYPASSRLS',
    );
    expect(migration).toContain(
      'ALTER TABLE public.consequence_actuator_envelopes OWNER TO consequence_actuator_store_owner',
    );
    expect(migration).toContain(
      'CREATE TABLE consequence_actuator_private.tenant_principals',
    );
    expect(migration).toContain(
      "pg_catalog.pg_has_role(SESSION_USER, 'consequence_actuator_executor', 'MEMBER')",
    );
    expect(migration).toContain(
      'principals.principal_name = SESSION_USER',
    );
    expect(migration).toContain('principals.tenant_id = p_tenant_id');
  });

  it('forces RLS and exposes no direct runtime or Supabase DML', () => {
    expect(migration).toContain(
      'ALTER TABLE public.consequence_actuator_envelopes ENABLE ROW LEVEL SECURITY',
    );
    expect(migration).toContain(
      'ALTER TABLE public.consequence_actuator_envelopes FORCE ROW LEVEL SECURITY',
    );
    expect(migration).toContain(
      'TO consequence_actuator_store_owner USING (TRUE) WITH CHECK (TRUE)',
    );
    expect(migration).toContain(
      'FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor',
    );
    expect(migration).not.toMatch(
      /GRANT\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE)\s+ON\s+(?:TABLE\s+)?public\.consequence_actuator_envelopes\s+TO\s+(?:service_role|consequence_actuator_executor)/i,
    );
  });

  it('promotes the RPC-only actuator table into the live schema contract', () => {
    expect(contract.requiredTables).toContain('consequence_actuator_envelopes');
    expect(contract.rlsRequired).toContain('consequence_actuator_envelopes');
    expect(contract.noAnonRead).toContain('consequence_actuator_envelopes');
    expect(contract.noAnonWrite).toContain('consequence_actuator_envelopes');
    expect(contract.tableGrantsNoPublic).toContain(
      'consequence_actuator_envelopes',
    );
    expect(contract.tableGrantsNoServiceRoleDirect).toContain(
      'consequence_actuator_envelopes',
    );
    expect(contract.requiredColumns.consequence_actuator_envelopes).toEqual(
      expect.arrayContaining([
        'tenant_id',
        'attempt_id',
        'action_digest',
        'caid',
        'provider_account_id',
        'target_digest',
        'operation',
        'idempotency_key',
        'nonce',
        'expires_at',
        'envelope_digest',
        'state',
        'outcome',
      ]),
    );
  });

  it('permits only atomic reserve and consume SECURITY DEFINER RPCs', () => {
    expect(migration).toContain(
      'CREATE FUNCTION consequence_actuator_private.reserve_envelope',
    );
    expect(migration).toContain(
      'CREATE FUNCTION consequence_actuator_private.consume_envelope',
    );
    expect(migration.match(
      /LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''/g,
    )).toHaveLength(3);
    expect(migration).toContain(
      'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA consequence_actuator_private',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION consequence_actuator_private.reserve_envelope',
    );
    expect(migration).toContain(
      'consequence_actuator_private.consume_envelope',
    );
    expect(migration).toContain('TO consequence_actuator_executor');
    expect(migration).not.toMatch(
      /GRANT EXECUTE[\s\S]+TO (?:service_role|anon|authenticated)/,
    );
  });

  it('consumes only the exact reserved envelope and never releases it', () => {
    expect(migration).toMatch(
      /UPDATE public\.consequence_actuator_envelopes[\s\S]+state = 'CONSUMED'[\s\S]+state = 'RESERVED'/,
    );
    for (const binding of [
      'attempt_id = p_attempt_id',
      'action_digest = p_action_digest',
      'caid = p_caid',
      'provider_account_id = p_provider_account_id',
      'target_digest = p_target_digest',
      'operation = p_operation',
      'idempotency_key = p_idempotency_key',
      'nonce = p_nonce',
      'envelope_digest = p_envelope_digest',
    ]) {
      expect(migration).toContain(binding);
    }
    expect(migration).not.toContain('release_envelope');
    expect(migration).not.toMatch(
      /DELETE\s+FROM\s+public\.consequence_actuator_envelopes/i,
    );
  });
});
