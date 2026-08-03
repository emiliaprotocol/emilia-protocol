// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260803020000_agent_record_v1.sql', import.meta.url),
  'utf8',
);

describe('Agent Record v1 migration source contract', () => {
  it('uses a dedicated least-privilege NOLOGIN owner and forced RLS', () => {
    expect(migration).toMatch(
      /CREATE ROLE agent_record_store_owner NOLOGIN[\s\S]*NOBYPASSRLS/,
    );
    expect(migration).toContain(
      'CREATE SCHEMA agent_record_private\n  AUTHORIZATION agent_record_store_owner;',
    );
    expect(migration.match(/FORCE ROW LEVEL SECURITY/g)).toHaveLength(2);
    expect(migration).toContain(
      'REVOKE ALL ON SCHEMA agent_record_private\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).toContain(
      'REVOKE ALL ON TABLE agent_record_private.records\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).toContain(
      'REVOKE ALL ON TABLE agent_record_private.revocations\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    expect(migration).not.toMatch(
      /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)[\s\S]{0,120}agent_record_private\.[\s\S]{0,120}(?:anon|authenticated|service_role)/i,
    );
  });

  it('exposes only exact create, owner-revoke, and opaque-id public-read RPCs', () => {
    const publicFunctions = [...migration.matchAll(
      /CREATE FUNCTION public\.([a-z0-9_]+)\(/g,
    )].map((match) => match[1]);
    expect(publicFunctions).toEqual([
      'create_agent_record',
      'revoke_agent_record',
      'read_agent_record_public',
    ]);
    expect(migration).not.toMatch(/agent_record_(?:list|search|feed|sitemap)|vanity|handle/i);
    expect(migration.match(/SECURITY DEFINER/g)?.length).toBeGreaterThanOrEqual(6);
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.read_agent_record_public(TEXT)\n  TO anon, authenticated, service_role;',
    );
  });

  it('makes record, refusal source, and owner credential hashes atomically unique', () => {
    expect(migration).toMatch(/record_id TEXT[\s\S]*PRIMARY KEY/);
    expect(migration).toMatch(/owner_token_hash TEXT[\s\S]*NOT NULL UNIQUE/);
    expect(migration).toMatch(/source_artifact_digest TEXT[\s\S]*NOT NULL UNIQUE/);
    expect(migration).toContain('refusal_digest = source_artifact_digest');
    expect(migration).toContain("v_owner_token := 'ear1_' ||");
    expect(migration).toContain(
      'agent_record_private.token_hash(v_owner_token)',
    );
    expect(migration).not.toMatch(/owner_token\s+TEXT[\s\S]*CREATE TABLE/i);
  });

  it('rechecks the active adoption and exact latest bond inside creation', () => {
    expect(migration).toMatch(
      /public\.read_agent_adoption_session\(\s*p_adoption_id,\s*p_adoption_session_token\s*\)/,
    );
    expect(migration).toContain("v_adoption ->> 'status' IS DISTINCT FROM 'active'");
    expect(migration).toContain(
      "v_adoption ->> 'latest_bond_id' IS DISTINCT FROM p_bond_id::TEXT",
    );
    expect(migration).toContain(
      "v_adoption ->> 'latest_bond_digest' IS DISTINCT FROM p_bond_digest",
    );
    expect(migration).toContain(
      "v_arena_projection -> 'attempt' ->> 'decision' IS DISTINCT FROM 'refuse'",
    );
    expect(migration).toContain(
      "v_arena_projection -> 'refusal_artifact' ->> '@version' IS DISTINCT FROM\n        'EP-ACTION-REFUSAL-STATEMENT-v1'",
    );
  });

  it('allows only the signed observation projection and exact 365-day public retention', () => {
    expect(migration).toContain(
      "p_retention_expires_at IS DISTINCT FROM p_observed_at + INTERVAL '365 days'",
    );
    expect(migration).toMatch(
      /p_public_projection ->> '@version' IS DISTINCT FROM\s*'EP-AGENT-RECORD-OBSERVATION-v1'/,
    );
    expect(migration).toContain(
      "p_public_projection -> 'record' ->> 'claim_boundary' IS DISTINCT FROM\n        'one_operator_observation_of_one_verified_signed_arena_refusal_only'",
    );
    expect(migration).toContain(
      "p_public_projection -> 'signature' ->> 'key_source' IS DISTINCT FROM\n        'operator-commit-signing-key'",
    );
    expect(migration).toContain(
      "(SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(p_public_projection)) <> 3",
    );
    expect(migration).toContain(
      "record.retention_expires_at > pg_catalog.clock_timestamp()",
    );
    expect(migration).toContain(
      'NOT EXISTS (\n      SELECT 1\n      FROM agent_record_private.revocations AS revocation',
    );
  });

  it('keeps public unknown, expired, and revoked responses uniform', () => {
    const readFunction = migration.match(
      /CREATE FUNCTION public\.read_agent_record_public[\s\S]*?\nEND\n\$read_agent_record_public\$;/,
    )?.[0];
    expect(readFunction).toBeDefined();
    expect(readFunction).toContain("RAISE EXCEPTION 'agent record not found'");
    expect(readFunction).toContain("USING ERRCODE = 'P0002'");
    expect(readFunction).not.toMatch(/revoked_at|retention_expires_at'|adoption_id|session|owner_token/);
    expect(readFunction).toContain("'record_id', p_record_id");
    expect(readFunction).toContain("'public_projection', v_public_projection");
  });

  it('stores an append-only revocation without modifying the source record', () => {
    expect(migration).toContain(
      'CREATE TRIGGER agent_record_revocations_immutable_trigger',
    );
    expect(migration).toContain(
      'BEFORE UPDATE OR DELETE ON agent_record_private.revocations',
    );
    expect(migration).toMatch(
      /INSERT INTO agent_record_private\.revocations[\s\S]*RETURN pg_catalog\.jsonb_build_object/,
    );
    expect(migration).not.toMatch(/UPDATE agent_record_private\.records[\s\S]*revok/i);
  });
});
