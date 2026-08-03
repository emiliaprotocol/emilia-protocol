// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260803020000_agent_record_v1.sql', import.meta.url),
  'utf8',
);
const awsDeploymentGuide = readFileSync(
  new URL('../docs/deployment/AWS-DEPLOYMENT-GUIDE.md', import.meta.url),
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

  it('exposes only read-only source preparation, exact create, owner-revoke, and opaque-id public-read RPCs', () => {
    const publicFunctions = [...migration.matchAll(
      /CREATE FUNCTION public\.([a-z0-9_]+)\(/g,
    )].map((match) => match[1]);
    expect(publicFunctions).toEqual([
      'read_agent_record_arena_source',
      'create_agent_record',
      'revoke_agent_record',
      'read_agent_record_public',
    ]);
    expect(migration).not.toMatch(/agent_record_(?:list|search|feed|sitemap)|vanity|handle/i);
    expect(migration.match(/SECURITY DEFINER/g)?.length).toBeGreaterThanOrEqual(6);
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.read_agent_record_public(TEXT)\n  TO service_role;',
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION public\.read_agent_record_public\(TEXT\)[\s\S]{0,60}(?:anon|authenticated)/,
    );
  });

  it('makes record, refusal source, and owner credential hashes atomically unique', () => {
    expect(migration).toMatch(/record_id TEXT[\s\S]*PRIMARY KEY/);
    expect(migration).toMatch(/owner_token_hash TEXT[\s\S]*NOT NULL UNIQUE/);
    expect(migration).toMatch(/source_artifact_digest TEXT[\s\S]*NOT NULL UNIQUE/);
    expect(migration).toContain('refusal_digest = source_artifact_digest');
    expect(migration).toContain("p_owner_token !~ '^ear1_[0-9a-f]{64}$'");
    expect(migration).toContain(
      'agent_record_private.token_hash(p_owner_token)',
    );
    expect(migration).toContain(
      'ON CONFLICT (record_id) DO NOTHING\n  RETURNING * INTO v_existing;',
    );
    expect(migration).toMatch(
      /WHERE record\.record_id = p_record_id[\s\S]*record\.owner_token_hash = agent_record_private\.token_hash\(p_owner_token\)[\s\S]*record\.arena_share_id = v_arena_share_id/,
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
    expect(migration).toMatch(
      /public\.read_agent_record_arena_source\(\s*p_arena_token_hash,\s*p_arena_session_id,\s*p_arena_attempt_id\s*\)/,
    );
    expect(migration).toContain(
      "v_arena_projection -> 'attempt' ->> 'decision' IS DISTINCT FROM 'refuse'",
    );
    expect(migration).toContain(
      "v_arena_projection -> 'refusal_artifact' ->> '@version' IS DISTINCT FROM\n        'EP-ACTION-REFUSAL-STATEMENT-v1'",
    );
  });

  it('publishes the Arena source only inside the Agent Record transaction', () => {
    const createFunction = migration.match(
      /CREATE FUNCTION public\.create_agent_record[\s\S]*?\nEND\n\$create_agent_record\$;/,
    )?.[0];
    expect(createFunction).toBeDefined();
    expect(createFunction).toContain(
      'v_publish := agent_record_control_private.publish_arena_source(',
    );
    expect(createFunction).toContain("v_publish ->> 'share_id'");
    expect(createFunction).toContain('INSERT INTO agent_record_private.records');
    expect(createFunction?.indexOf('v_publish := agent_record_control_private.publish_arena_source('))
      .toBeLessThan(createFunction?.indexOf('INSERT INTO agent_record_private.records') ?? -1);
    expect(createFunction).not.toMatch(/DELETE FROM public\.arena_shares|cleanup|compensat/i);
    expect(migration).toMatch(
      /CREATE FUNCTION agent_record_control_private\.publish_arena_source[\s\S]*FOR UPDATE OF session, attempt/,
    );
    expect(migration).toContain(
      "AND session.status = 'active'\n    AND session.expires_at > pg_catalog.clock_timestamp()",
    );
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION agent_record_control_private.publish_arena_source(TEXT, TEXT, TEXT)\n  FROM PUBLIC, anon, authenticated, service_role, agent_record_store_owner;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION agent_record_control_private.publish_arena_source(TEXT, TEXT, TEXT)\n  TO agent_record_store_owner;',
    );
  });

  it('removes stale service-role Arena write ACLs without removing reads or approved RPCs', () => {
    expect(migration).toContain(
      'REVOKE INSERT, UPDATE, DELETE\n  ON TABLE public.arena_shares\n  FROM service_role;',
    );
    expect(migration).not.toMatch(
      /REVOKE[\s\S]{0,80}SELECT[\s\S]{0,80}ON TABLE public\.arena_shares[\s\S]{0,40}service_role/i,
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.read_agent_record_arena_source(TEXT, TEXT, TEXT)\n  TO service_role, agent_record_store_owner;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.create_agent_record(UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ, JSONB)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.revoke_agent_record(TEXT, TEXT, TEXT)\n  TO service_role;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.read_agent_record_public(TEXT)\n  TO service_role;',
    );
  });

  it('keeps source preparation read-only and server-only', () => {
    const sourceReader = migration.match(
      /CREATE FUNCTION public\.read_agent_record_arena_source[\s\S]*?\nEND\n\$agent_record_arena_source\$;/,
    )?.[0];
    expect(sourceReader).toBeDefined();
    expect(sourceReader).toContain('STABLE');
    expect(sourceReader).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/);
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION public.read_agent_record_arena_source(TEXT, TEXT, TEXT)\n  FROM PUBLIC, anon, authenticated, service_role, agent_record_store_owner;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.read_agent_record_arena_source(TEXT, TEXT, TEXT)\n  TO service_role, agent_record_store_owner;',
    );
  });

  it('allows only the signed observation projection and exact 365-day public retention', () => {
    const projectionGuard = migration.match(
      /IF \(SELECT pg_catalog\.count\(\*\) FROM pg_catalog\.jsonb_object_keys\(p_public_projection\)\)[\s\S]*?RAISE EXCEPTION 'agent record public projection is invalid'/,
    )?.[0];
    expect(projectionGuard).toBeDefined();
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
    expect(projectionGuard).toContain(
      "FROM pg_catalog.jsonb_object_keys(p_public_projection -> 'record' -> 'source')\n    ) <> 2",
    );
    expect(projectionGuard).not.toContain("->> 'arena_share_id'");
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
    expect(migration).toContain(
      'PERFORM agent_record_control_private.revoke_arena_source(',
    );
    expect(migration).toContain(
      "AND (pg_catalog.to_jsonb(NEW) - 'revoked_at') IS NOT DISTINCT FROM",
    );
    expect(migration).toContain(
      "OLD.share_id IS NOT DISTINCT FROM\n      pg_catalog.current_setting('ep.agent_record_arena_share_revoke', TRUE)",
    );
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION agent_record_control_private.revoke_arena_source(TEXT, TIMESTAMPTZ)\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
  });

  it('requires atomic direct-Postgres application and remains Supabase-transaction compatible', () => {
    const schemaStep = awsDeploymentGuide.match(
      /## Step 2: Apply EP Schema[\s\S]*?(?=\n---\n\n## Step 3:)/,
    )?.[0];
    expect(schemaStep).toBeDefined();
    expect(schemaStep).toContain(
      'psql --single-transaction --set=ON_ERROR_STOP=1 \\\n    "$DATABASE_URL" --file "$f"',
    );
    expect(schemaStep).not.toContain('psql "$DATABASE_URL" -f "$f"');
    expect(migration).not.toMatch(
      /^\s*(?:BEGIN|START\s+TRANSACTION|COMMIT|ROLLBACK)\s*;/im,
    );
  });
});
