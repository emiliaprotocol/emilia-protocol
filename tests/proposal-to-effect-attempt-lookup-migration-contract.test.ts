// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260723150000_proposal_to_effect_attempt_lookup.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('Proposal-to-Effect exact attempt lookup migration', () => {
  it('adds one forward-only, authenticated, read-only lookup RPC', () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION proposal_to_effect_private.lookup_attempt',
    );
    expect(migration).toContain(
      'proposal_to_effect_private.assert_tenant_principal(p_tenant_id, NULL)',
    );
    expect(migration).toContain('SECURITY DEFINER');
    expect(migration).toContain("SET search_path = ''");
    expect(migration).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/i);
  });

  it('matches the full server-derived provider tuple and request digest', () => {
    for (const predicate of [
      'attempts.tenant_id = p_tenant_id',
      'attempts.provider_id = p_provider_id',
      'attempts.provider_account_id = p_provider_account_id',
      'attempts.environment = p_environment',
      'attempts.request_digest = p_request_digest',
    ]) {
      expect(migration).toContain(predicate);
    }
    expect(migration).not.toContain('p_attempt_id');
  });

  it('returns only the public binding and explicitly rejects ambiguity', () => {
    expect(migration).toMatch(
      /RETURNS TABLE\(\s*tenant_id TEXT,\s*provider_id TEXT,\s*provider_account_id TEXT,\s*environment TEXT,\s*attempt_id TEXT,\s*request_digest TEXT\s*\)/,
    );
    expect(migration).toContain('PTE_ATTEMPT_LOOKUP_AMBIGUOUS');
    expect(migration).toContain("USING ERRCODE = '21000'");
    for (const forbidden of [
      'owner_digest',
      'owner_generation',
      'state TEXT',
      'operation_digest',
      'action_digest',
      'config_digest',
      'attempt_digest',
      'evidence_digest',
    ]) {
      expect(migration).not.toContain(forbidden);
    }
  });

  it('keeps the RPC off Supabase defaults and grants only dedicated principals', () => {
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION proposal_to_effect_private\.lookup_attempt\(\s*TEXT, TEXT, TEXT, TEXT, TEXT\s*\)\s+FROM anon, authenticated, PUBLIC, service_role;/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION proposal_to_effect_private\.lookup_attempt\(\s*TEXT, TEXT, TEXT, TEXT, TEXT\s*\)\s+TO proposal_to_effect_executor, proposal_to_effect_recovery;/,
    );
  });
});
