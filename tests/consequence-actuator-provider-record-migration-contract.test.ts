// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import { contract } from '../scripts/db-contract.manifest.mts';

const migrationPath = path.join(
  process.cwd(),
  'supabase/migrations/20260725143000_consequence_actuator_provider_records.sql',
);
const actuatorStoreMigrationPath = path.join(
  process.cwd(),
  'supabase/migrations/20260725010000_consequence_actuator_store.sql',
);

describe('consequence actuator provider-record migration contract', () => {
  it('registers the private store and exact actuator RPCs in the live schema contract', () => {
    expect(contract.requiredQualifiedTables).toContain(
      'consequence_actuator_private.provider_records',
    );
    expect(contract.requiredQualifiedRpcs).toEqual(expect.arrayContaining([
      'consequence_actuator_private.reserve_envelope(text,text,text,text,text,text,text,text,text,timestamp with time zone,timestamp with time zone,text)',
      'consequence_actuator_private.consume_envelope(text,text,text,text,text,text,text,text,text,text,text)',
      'consequence_actuator_private.record_provider_record(jsonb,text)',
      'consequence_actuator_private.read_provider_record(text,text,text,text,text,text,text,text,text)',
    ]));
  });

  it('is forward-only, private, tenant-bound, FORCE RLS, and append-only', () => {
    const migration = fs.readFileSync(migrationPath, 'utf8');

    expect(migration).toContain(
      'CREATE TABLE consequence_actuator_private.provider_records',
    );
    expect(migration).toMatch(
      /ALTER TABLE consequence_actuator_private\.provider_records\s+ENABLE ROW LEVEL SECURITY/,
    );
    expect(migration).toMatch(
      /ALTER TABLE consequence_actuator_private\.provider_records\s+FORCE ROW LEVEL SECURITY/,
    );
    expect(migration).toContain(
      'consequence_actuator_private.assert_tenant_principal',
    );
    expect(migration).toMatch(
      /FOREIGN KEY \(tenant_id, nonce\)[\s\S]+public\.consequence_actuator_envelopes/,
    );
    expect(migration).toContain(
      'CREATE TRIGGER consequence_actuator_provider_records_immutable',
    );
    expect(migration).toMatch(
      /BEFORE UPDATE OR DELETE[\s\S]+consequence_actuator_private\.provider_records/,
    );
    expect(migration).not.toMatch(
      /DROP\s+(?:TABLE|SCHEMA)\s+(?!IF EXISTS consequence_actuator_private\.provider_records)/i,
    );
    expect(migration).toContain('SET ROLE consequence_actuator_store_owner');
    const actuatorStoreMigration = fs.readFileSync(
      actuatorStoreMigrationPath,
      'utf8',
    );
    expect(actuatorStoreMigration).toContain(
      "pg_catalog.pg_has_role(SESSION_USER, 'consequence_actuator_executor', 'MEMBER')",
    );
  });

  it('exposes only exact append/read RPCs to the dedicated actuator service role', () => {
    const migration = fs.readFileSync(migrationPath, 'utf8');

    expect(migration).toContain(
      'consequence_actuator_private.record_provider_record',
    );
    expect(migration).toContain(
      'consequence_actuator_private.read_provider_record',
    );
    expect(migration).toContain(
      'TO consequence_actuator_executor',
    );
    expect(migration).toMatch(
      /REVOKE ALL ON consequence_actuator_private\.provider_records[\s\S]+FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor/,
    );
    expect(migration).not.toMatch(
      /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)[\s\S]+provider_records[\s\S]+TO\s+(?:anon|authenticated|service_role|consequence_actuator_executor)/i,
    );
  });

  it('requires exact idempotent replay and rejects conflicting terminal records', () => {
    const migration = fs.readFileSync(migrationPath, 'utf8');

    expect(migration).toContain('ON CONFLICT DO NOTHING');
    expect(migration).toContain('provider record conflict');
    expect(migration).toMatch(
      /provider_record_digest\s*=\s*p_provider_record_digest/,
    );
    expect(migration).toMatch(
      /provider_record\s*=\s*p_provider_record/,
    );
    expect(migration).toMatch(
      /outcome IN \('COMMITTED', 'NOT_COMMITTED'\)/,
    );
  });
});
