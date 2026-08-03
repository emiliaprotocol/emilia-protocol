// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
const migration = readFileSync(
  `${root}/supabase/migrations/20260802230000_agent_adoption_v1.sql`,
  'utf8',
);

const TABLES = [
  'adoption_sessions',
  'adoption_credentials',
  'adoption_challenges',
  'operating_bonds',
  'adoption_events',
  'adoption_revocations',
  'public_shares',
  'share_revocations',
] as const;

const PRIVATE_RPC_SIGNATURES = [
  'public.create_agent_adoption_session(TEXT, TEXT, TEXT, JSONB, JSONB)',
  'public.read_agent_adoption_session(UUID, TEXT)',
  'public.create_agent_adoption_registration_challenge(UUID, TEXT)',
  'public.complete_agent_adoption_registration(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT[], TEXT, BOOLEAN, BIGINT, BOOLEAN, TEXT, TEXT, TEXT)',
  'public.create_agent_adoption_assertion_challenge(UUID, TEXT, TEXT)',
  'public.complete_agent_adoption_assertion(UUID, TEXT, TEXT, TEXT, BIGINT, BOOLEAN, TEXT, BOOLEAN, TEXT)',
  'public.read_agent_operating_bond(UUID, TEXT, UUID)',
  'public.revoke_agent_adoption(UUID, TEXT, TEXT, TEXT)',
  'public.publish_agent_adoption_share(UUID, TEXT, UUID)',
  'public.revoke_agent_adoption_share(UUID, TEXT, TEXT, TEXT, TEXT)',
  'public.purge_expired_agent_adoptions(INTEGER)',
] as const;
const PUBLIC_READ_SIGNATURE = 'public.read_agent_adoption_share(TEXT)';

function functionBody(name: string, delimiter: string): string {
  const match = migration.match(
    new RegExp(
      `CREATE FUNCTION (?:public|agent_adoption_private)\\.${name}\\([\\s\\S]*?AS \\$${delimiter}\\$([\\s\\S]*?)\\$${delimiter}\\$;`,
    ),
  );
  expect(match, `${name} must have an inspectable, delimited body`).not.toBeNull();
  return match![1];
}

describe('Agent Adoption v1 migration contract', () => {
  it('restores the exact migration role before removing temporary owner membership', () => {
    expect(migration).toContain(
      "SELECT pg_catalog.set_config(\n  'ep.agent_adoption_migration_role',\n  CURRENT_USER,\n  TRUE\n);",
    );
    expect(migration).toContain(
      'GRANT agent_adoption_store_owner TO CURRENT_USER\n  WITH INHERIT FALSE, SET TRUE;',
    );
    expect(migration).toContain(
      "EXECUTE pg_catalog.format(\n    'SET ROLE %I',\n    pg_catalog.current_setting('ep.agent_adoption_migration_role')\n  );",
    );
    expect(migration).toContain(
      'REVOKE CREATE ON SCHEMA public FROM agent_adoption_store_owner;\nREVOKE agent_adoption_store_owner FROM CURRENT_USER;',
    );
  });

  it('uses a private least-privilege owner, forced RLS, owner-only policies, and no direct API-role ACLs', () => {
    expect(migration).toContain('CREATE SCHEMA agent_adoption_private\n  AUTHORIZATION agent_adoption_store_owner;');
    expect(migration).toContain(
      'REVOKE ALL ON SCHEMA agent_adoption_private\n  FROM PUBLIC, anon, authenticated, service_role;',
    );
    for (const table of TABLES) {
      expect(migration).toContain(
        `ALTER TABLE agent_adoption_private.${table}\n  ENABLE ROW LEVEL SECURITY;`,
      );
      expect(migration).toContain(
        `ALTER TABLE agent_adoption_private.${table}\n  FORCE ROW LEVEL SECURITY;`,
      );
      expect(migration).toContain(
        `ON agent_adoption_private.${table}\n  TO agent_adoption_store_owner USING (TRUE) WITH CHECK (TRUE);`,
      );
      expect(migration).toContain(
        `REVOKE ALL ON TABLE agent_adoption_private.${table}\n  FROM PUBLIC, anon, authenticated, service_role;`,
      );
      expect(migration).not.toMatch(
        new RegExp(`GRANT\\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE)[^;]*${table}`, 'i'),
      );
    }
  });

  it('keeps every RPC service-role-only, including the redacted share reader', () => {
    for (const signature of PRIVATE_RPC_SIGNATURES) {
      expect(migration).toContain(
        `REVOKE ALL ON FUNCTION ${signature}\n  FROM PUBLIC, anon, authenticated, service_role;`,
      );
      expect(migration).toContain(
        `GRANT EXECUTE ON FUNCTION ${signature}\n  TO service_role;`,
      );
    }
    expect(migration).toContain(
      `REVOKE ALL ON FUNCTION ${PUBLIC_READ_SIGNATURE}\n  FROM PUBLIC, anon, authenticated, service_role;`,
    );
    expect(migration).toContain(
      `GRANT EXECUTE ON FUNCTION ${PUBLIC_READ_SIGNATURE}\n  TO service_role;`,
    );
    const publicExecuteGrants =
      migration.match(/GRANT EXECUTE ON FUNCTION public\.[\s\S]*?;/g) ?? [];
    expect(publicExecuteGrants.some((value) => /TO\s+(?:anon|authenticated)/.test(value))).toBe(false);

    expect(migration.match(/CREATE FUNCTION public\./g)).toHaveLength(
      PRIVATE_RPC_SIGNATURES.length + 1,
    );
    const searchPaths = migration.match(/SET search_path\s*=\s*[^\n]+/gi) ?? [];
    expect(searchPaths.length).toBeGreaterThanOrEqual(PRIVATE_RPC_SIGNATURES.length + 1);
    expect(searchPaths.every((value) => value === "SET search_path = ''")).toBe(true);
    for (const name of [
      'create_agent_adoption_session',
      'create_agent_adoption_registration_challenge',
      'complete_agent_adoption_registration',
      'create_agent_adoption_assertion_challenge',
      'complete_agent_adoption_assertion',
      'revoke_agent_adoption',
      'publish_agent_adoption_share',
      'revoke_agent_adoption_share',
    ]) {
      expect(migration).toMatch(
        new RegExp(
          `CREATE FUNCTION public\\.${name}\\([\\s\\S]*?SECURITY DEFINER\\nSET search_path = ''\\nSET lock_timeout = '2s'\\nSET statement_timeout = '5s'`,
        ),
      );
    }
  });

  it('stores one bounded server-supplied core bond and its public projection in the immutable session', () => {
    const body = functionBody('create_agent_adoption_session', 'create_session');

    expect(migration).toContain('candidate_digest TEXT COLLATE "C" NOT NULL');
    expect(migration).toContain('bond_digest TEXT COLLATE "C" NOT NULL');
    expect(migration).toContain('operating_bond JSONB NOT NULL CHECK (');
    expect(migration).toContain('public_projection JSONB NOT NULL CHECK (');
    expect(migration).toContain('pg_catalog.pg_column_size(operating_bond) <= 32768');
    expect(migration).toContain('pg_catalog.pg_column_size(public_projection) <= 32768');
    expect(migration).toContain("operating_bond ->> '@version' = 'EP-OPERATING-BOND-v1'");
    expect(migration).toContain("public_projection ->> '@version' = 'EP-OPERATING-BOND-PUBLIC-v1'");
    expect(migration).toContain("operating_bond ->> 'candidate_digest' = candidate_digest");
    expect(migration).toContain("public_projection ->> 'bond_digest' = bond_digest");

    expect(body).toContain('v_tenant_id := pg_catalog.gen_random_uuid();');
    expect(body).toContain('v_adoption_id := pg_catalog.gen_random_uuid();');
    expect(body).toContain("v_session_token := 'eaa1_' ||");
    expect(body).toContain('agent_adoption_private.token_hash(v_session_token)');
    expect(body).toContain("p_operating_bond ->> '@version' IS DISTINCT FROM 'EP-OPERATING-BOND-v1'");
    expect(body).toContain("p_public_projection ->> '@version' IS DISTINCT FROM 'EP-OPERATING-BOND-PUBLIC-v1'");
    expect(body).toContain("p_operating_bond -> 'candidate' ->> 'label' IS DISTINCT FROM p_agent_label");
    expect(body).toContain("p_operating_bond ->> 'candidate_digest' IS DISTINCT FROM p_candidate_digest");
    expect(body).toContain("p_public_projection ->> 'bond_digest' IS DISTINCT FROM p_bond_digest");
    expect(body).toContain("p_public_projection -> 'candidate' ->> 'label' IS DISTINCT FROM p_agent_label");
    expect(body).toContain("'session_token', v_session_token");
    expect(body).toContain("v_expires_at := v_created_at + INTERVAL '30 days'");
    expect(body).toContain("'expires_at', agent_adoption_private.iso_ms(v_expires_at)");
    expect(migration).toContain('expires_at TIMESTAMPTZ NOT NULL');
    expect(migration).toContain("expires_at <= created_at + INTERVAL '30 days'");
    expect(migration).not.toMatch(/\bsession_token\s+TEXT\b/);
  });

  it('pins the core synthetic/no-egress boundary and cross-field projection consistency', () => {
    const body = functionBody('create_agent_adoption_session', 'create_session');
    expect(body).toContain("'scope', 'synthetic_no_egress_demonstration'");
    expect(body).toContain("'real_money', 'not_used_or_represented'");
    expect(body).toContain("'provider_credentials', 'not_collected_or_used'");
    expect(body).toContain("'civil_identity', 'not_verified_or_claimed'");
    expect(body).toContain("'certification', 'not_issued_or_claimed'");
    expect(body).toContain("'marketplace', 'not_offered_or_claimed'");
    expect(body).toContain("'production_execution', 'not_authorized_or_claimed'");
    expect(body).toContain("'source_metadata', 'url_is_metadata_only_never_fetched'");
    expect(body).toContain("p_operating_bond -> 'claim_boundaries' IS DISTINCT FROM v_claim_boundaries");
    expect(body).toContain("p_public_projection -> 'claim_boundaries' IS DISTINCT FROM v_claim_boundaries");
    expect(body).toContain("p_operating_bond -> 'constraints' ->> 'environment' IS DISTINCT FROM 'synthetic'");
    expect(body).toContain("p_operating_bond -> 'constraints' ->> 'network_egress' IS DISTINCT FROM 'forbidden'");
    expect(body).toContain("p_operating_bond -> 'constraints' ->> 'external_side_effects' IS DISTINCT FROM 'forbidden'");
    expect(body).toContain("'agent-adoption.synthetic.vendor-intake.1'");
    expect(body).toContain("'agent-adoption.synthetic.compute-allocate.1'");
    expect(body).toContain("'agent-adoption.synthetic.document-route.1'");
    expect(body).toContain("v_allowance_total := 200;");
    expect(body).toContain("v_allowance_total := 500;");
    expect(body).toContain("v_allowance_total := 1000;");
    expect(body).toContain("p_operating_bond -> 'job' IS DISTINCT FROM v_expected_job");
    expect(body).toContain(
      "p_operating_bond -> 'allowance' IS DISTINCT FROM v_expected_allowance",
    );
    expect(body).toContain(
      "p_operating_bond -> 'constraints' IS DISTINCT FROM v_expected_constraints",
    );
    expect(body).toContain(
      "p_public_projection -> 'operating_limits' IS DISTINCT FROM v_expected_limits",
    );
    expect(body).toContain("WHERE candidate_key.key_name NOT IN (");
    expect(body).toContain("p_public_projection -> 'candidate' IS DISTINCT FROM");
    expect(body).toContain(
      "p_public_projection -> 'operating_limits' -> 'allowed_action_types' IS DISTINCT FROM\n      p_operating_bond -> 'constraints' -> 'allowed_action_types'",
    );
  });

  it('stores the complete bounded adoption-only WebAuthn credential material privately', () => {
    const credentialDefinition = migration.match(
      /CREATE TABLE agent_adoption_private\.adoption_credentials \(([\s\S]*?)\n\);/,
    );
    expect(credentialDefinition).not.toBeNull();
    for (const field of [
      'public_key_cose TEXT',
      'public_key_spki TEXT',
      'algorithm TEXT',
      'curve TEXT',
      'transports TEXT[]',
      'device_type TEXT',
      'backed_up BOOLEAN',
      'sign_count BIGINT',
      'counter_supported BOOLEAN',
      'rp_id TEXT',
      'origin TEXT',
    ]) {
      expect(credentialDefinition![1]).toContain(field);
    }
    expect(credentialDefinition![1]).toContain("CHECK (algorithm = 'ES256')");
    expect(credentialDefinition![1]).toContain("CHECK (curve = 'P-256')");
    expect(credentialDefinition![1]).toContain(
      'CHECK (counter_supported = (sign_count > 0))',
    );
    expect(credentialDefinition![1]).toContain(
      'sign_count BETWEEN 0 AND 4294967295',
    );
    expect(credentialDefinition![1]).toContain(
      "claim_boundary = 'public_no_egress_agent_adoption_evidence_only_not_real_money_not_provider_credentials_not_civil_identity_not_certification_not_marketplace_not_production_execution'",
    );
    expect(credentialDefinition![1]).not.toMatch(/approver|class_a/i);
  });

  it('returns deterministic context times and exact private credential reconstruction material', () => {
    for (const [name, delimiter] of [
      ['create_agent_adoption_registration_challenge', 'registration_challenge'],
      ['create_agent_adoption_assertion_challenge', 'assertion_challenge'],
    ] as const) {
      const body = functionBody(name, delimiter);
      expect(body).toContain("'created_at', agent_adoption_private.iso_ms(v_created_at)");
      expect(body).toContain("'issued_at', agent_adoption_private.iso_ms(v_created_at)");
      expect(body).toContain("'expires_at', agent_adoption_private.iso_ms(v_expires_at)");
      expect(body).toContain("v_expires_at := v_created_at + INTERVAL '5 minutes';");
      expect(body).toContain("'candidate_digest', v_session.candidate_digest");
      expect(body).toContain("'bond_digest', v_session.bond_digest");
    }

    const assertion = functionBody(
      'create_agent_adoption_assertion_challenge',
      'assertion_challenge',
    );
    for (const field of [
      'claim_boundary',
      'credential_id',
      'public_key_cose',
      'public_key_spki',
      'algorithm',
      'curve',
      'transports',
      'device_type',
      'backed_up',
      'sign_count',
      'counter_supported',
      'rp_id',
      'origin',
    ]) {
      expect(assertion).toContain(`'${field}', v_credential.${field}`);
    }
  });

  it('binds every child row with composite tenant/adoption foreign keys and tenant-first indexes', () => {
    expect(migration).toContain('PRIMARY KEY (tenant_id, adoption_id)');
    for (const table of [
      'adoption_credentials',
      'adoption_challenges',
      'operating_bonds',
      'adoption_events',
      'adoption_revocations',
      'public_shares',
    ]) {
      const tableDefinition = migration.match(
        new RegExp(`CREATE TABLE agent_adoption_private\\.${table} \\(([\\s\\S]*?)\\n\\);`),
      );
      expect(tableDefinition, `${table} must exist`).not.toBeNull();
      expect(tableDefinition![1]).toContain('FOREIGN KEY (tenant_id, adoption_id)');
      expect(tableDefinition![1]).toContain(
        'REFERENCES agent_adoption_private.adoption_sessions (tenant_id, adoption_id)',
      );
      expect(tableDefinition![1]).toContain('ON DELETE RESTRICT');
    }
    expect(migration).toContain('FOREIGN KEY (tenant_id, adoption_id, credential_id)');
    expect(migration).toContain('FOREIGN KEY (tenant_id, adoption_id, share_id)');

    const indexes = migration.match(/CREATE (?:UNIQUE )?INDEX[\s\S]*?;/g) ?? [];
    expect(indexes.length).toBeGreaterThanOrEqual(8);
    for (const index of indexes.filter((value) => !value.includes('(share_id)'))) {
      expect(index).toMatch(/\(tenant_id,/);
    }
  });

  it('keeps one-time challenges, immutable bonds, and append-only terminal records', () => {
    expect(migration).toContain('nonce_hash TEXT COLLATE "C" NOT NULL UNIQUE');
    expect(migration).toContain('CREATE FUNCTION agent_adoption_private.adoption_challenge_guard()');
    expect(migration).toContain("OLD.consumed_at IS NULL\n    AND NEW.consumed_at IS NOT NULL");
    for (const table of [
      'operating_bonds',
      'adoption_events',
      'adoption_revocations',
      'public_shares',
      'share_revocations',
    ]) {
      expect(migration).toContain(`BEFORE UPDATE OR DELETE\nON agent_adoption_private.${table}`);
      expect(migration).toContain(`BEFORE TRUNCATE\nON agent_adoption_private.${table}`);
    }
    for (const [name, delimiter] of [
      ['complete_agent_adoption_registration', 'complete_registration'],
      ['complete_agent_adoption_assertion', 'complete_assertion'],
    ] as const) {
      const body = functionBody(name, delimiter);
      expect(body).toContain('FOR UPDATE;');
      expect(body).toContain('v_challenge.consumed_at IS NOT NULL');
      expect(body).toContain('v_completed_at := pg_catalog.clock_timestamp()');
      expect(body).toContain('v_challenge.expires_at <= v_completed_at');
      expect(body).toContain('SET consumed_at = v_completed_at');
    }
  });

  it('bounds session capabilities and challenge accumulation durably', () => {
    for (const [name, delimiter, purpose] of [
      ['create_agent_adoption_registration_challenge', 'registration_challenge', 'registration'],
      ['create_agent_adoption_assertion_challenge', 'assertion_challenge', 'assertion'],
    ] as const) {
      const body = functionBody(name, delimiter);
      expect(body).toContain('session.expires_at > pg_catalog.clock_timestamp()');
      expect(body).toContain(") >= 32 THEN");
      expect(body).toContain(`challenge.purpose = '${purpose}'`);
      expect(body).toContain('challenge.consumed_at IS NULL');
      expect(body).toContain('challenge.expires_at > pg_catalog.clock_timestamp()');
      expect(body).toContain(") >= 4 THEN");
    }
    const guardedSessionReads = migration.match(
      /session\.expires_at > pg_catalog\.clock_timestamp\(\)/g,
    ) ?? [];
    expect(guardedSessionReads).toHaveLength(10);
    expect(functionBody('read_agent_adoption_share', 'read_share')).toContain(
      'session.expires_at > pg_catalog.clock_timestamp()',
    );
  });

  it('atomically records the exact stored bond while keeping assertion and event digests separate', () => {
    const body = functionBody('complete_agent_adoption_assertion', 'complete_assertion');
    expect(body).toMatch(
      /FROM agent_adoption_private\.adoption_sessions[\s\S]*FOR UPDATE;[\s\S]*FROM agent_adoption_private\.adoption_credentials[\s\S]*FOR UPDATE;[\s\S]*FROM agent_adoption_private\.adoption_challenges[\s\S]*FOR UPDATE;/,
    );
    expect(body).toContain('(v_credential.sign_count = 0 AND p_new_counter = 0)');
    expect(body).toContain('p_new_counter > v_credential.sign_count');
    expect(body).toContain('p_counter_supported IS DISTINCT FROM (p_new_counter > 0)');
    expect(body).toContain('INSERT INTO agent_adoption_private.operating_bonds');
    expect(body).toContain('v_session.bond_digest');
    expect(body).toContain('v_session.operating_bond');
    expect(body).toContain('v_session.public_projection');
    expect(body).toContain("'assertion_digest', p_assertion_digest");
    expect(body).toContain("'event_hash', v_event_hash");
    expect(body).not.toContain("'EP-AGENT-OPERATING-BOND-v1'");
    expect(body).not.toContain("'EMILIA-AGENT-OPERATING-BOND-V1'");
    expect(migration).toContain('CREATE FUNCTION agent_adoption_private.adoption_credential_guard()');
    expect(migration).toContain("RAISE EXCEPTION 'credential counter must remain 0/0 or strictly advance'");
  });

  it('serializes the append-only event hash chain and terminal revocation', () => {
    const append = functionBody('append_event', 'append_event');
    expect(append).toMatch(
      /FROM agent_adoption_private\.adoption_sessions[\s\S]*tenant_id = p_tenant_id[\s\S]*adoption_id = p_adoption_id[\s\S]*FOR UPDATE;/,
    );
    expect(append).toContain('event_sequence DESC');
    expect(append).toContain("'previous_event_hash', v_previous_hash");
    expect(append).toContain('agent_adoption_private.sha256_json(');

    const revoke = functionBody('revoke_agent_adoption', 'revoke_adoption');
    expect(revoke).toMatch(/FROM agent_adoption_private\.adoption_sessions[\s\S]*FOR UPDATE;/);
    expect(revoke).toContain('INSERT INTO agent_adoption_private.adoption_revocations');
    expect(revoke).toContain("'adoption_revoked'");
    expect(revoke).toContain('IF v_existing.revocation_id IS NOT NULL THEN');
    for (const [name, delimiter] of [
      ['create_agent_adoption_registration_challenge', 'registration_challenge'],
      ['complete_agent_adoption_registration', 'complete_registration'],
      ['create_agent_adoption_assertion_challenge', 'assertion_challenge'],
      ['complete_agent_adoption_assertion', 'complete_assertion'],
      ['publish_agent_adoption_share', 'publish_share'],
    ] as const) {
      const body = functionBody(name, delimiter);
      expect(body).toContain('FROM agent_adoption_private.adoption_revocations');
      expect(body).toContain("RAISE EXCEPTION 'adoption is revoked'");
    }
  });

  it('publishes from the stored projection, preserves the exact bond digest, and never exposes credentials', () => {
    const publish = functionBody('publish_agent_adoption_share', 'publish_share');
    const read = functionBody('read_agent_adoption_share', 'read_share');
    expect(publish).toContain('v_projection := v_bond.public_projection || pg_catalog.jsonb_build_object(');
    expect(publish).toContain("'share_id', v_share_id");
    expect(publish).not.toContain("'adoption_id', v_session.adoption_id");
    expect(publish).toContain("'assertion_observation', pg_catalog.jsonb_build_object(");
    expect(publish).toContain("'assertion_digest', v_bond.assertion_digest");
    expect(publish).toContain("'bond_digest', v_bond.bond_digest");
    const projectionBuild = publish.match(
      /v_projection := v_bond\.public_projection \|\| pg_catalog\.jsonb_build_object\(([\s\S]*?)\n  \);\n  INSERT INTO agent_adoption_private\.public_shares/,
    );
    expect(projectionBuild).not.toBeNull();
    expect(projectionBuild![1]).not.toMatch(
      /public_key_cose|public_key_spki|credential_id|rp_id|origin|session_token_hash/,
    );
    expect(read).toContain('LEFT JOIN agent_adoption_private.adoption_revocations');
    expect(read).toContain('LEFT JOIN agent_adoption_private.share_revocations');
    expect(read).toContain("'revoked', v_share_revoked");
    expect(read).toContain("'projection', CASE WHEN v_share_revoked THEN NULL ELSE");
    expect(read).toContain('ELSE LEAST(');
    expect(read).not.toContain('pg_catalog.least(');
  });

  it('contains no egress, provider-secret, money-movement, identity, certification, marketplace, or execution capability', () => {
    expect(migration).not.toMatch(/net\.http|http_(?:get|post)|dblink|pg_sleep/i);
    expect(migration).not.toMatch(/provider_secret|api_key|bank_account|payment_intent/i);
    expect(migration).not.toMatch(/class_a_approver|certified_agent|production_execution_enabled/i);
  });
});
