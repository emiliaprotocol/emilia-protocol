// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { contract } from '../scripts/db-contract.manifest.mjs';

const migration = readFileSync(
  new URL(
    '../supabase/migrations/20260826140000_strix_rls_and_lifecycle_fortress_db_security_invariants.sql',
    import.meta.url,
  ),
  'utf8',
);

const closedTables = [
  'alert_events', 'alert_rules', 'continuity_challenges', 'continuity_claims',
  'continuity_decisions', 'delegations', 'ep_gate_control_domain_events',
  'ep_gate_control_domains', 'eye_advisories', 'eye_observations',
  'eye_suppressions', 'guarded_receipt_consumptions', 'handshake_bindings',
  'handshake_consumptions', 'handshake_events', 'handshake_parties',
  'handshake_policies', 'handshake_presentations', 'handshake_results',
  'identity_bindings', 'merkle_batches', 'principal_delegation_signals',
  'principals', 'protocol_events', 'signoff_approval_velocity',
  'signoff_consumptions', 'signoff_events', 'tenant_control_events',
  'tenant_environments', 'tenant_members', 'trust_reports',
  'webhook_deliveries', 'zk_proofs',
];

function escaped(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

describe('STRIX public-table RLS closure migration', () => {
  it('explicitly enables and forces RLS and revokes public ACLs on all 33 tables', () => {
    expect(closedTables).toHaveLength(33);
    for (const table of closedTables) {
      const name = escaped(table);
      expect(migration).toMatch(new RegExp(
        `ALTER TABLE public\\.${name} ENABLE ROW LEVEL SECURITY;`,
      ));
      expect(migration).toMatch(new RegExp(
        `ALTER TABLE public\\.${name} FORCE ROW LEVEL SECURITY;`,
      ));
      expect(migration).toMatch(new RegExp(
        `REVOKE ALL ON TABLE public\\.${name} FROM PUBLIC, anon, authenticated;`,
      ));
      expect(migration).toContain(`'${table}'`);
      expect(contract.rlsRequired).toContain(table);
      expect(contract.forceRlsRequired).toContain(table);
      expect(contract.tableGrantsNoPublic).toContain(table);
    }
  });

  it('replaces each policy with an exact service-role-only policy', () => {
    expect(migration).toContain(
      "'DROP POLICY IF EXISTS service_role_bypass ON public.%I'",
    );
    expect(migration).toContain(
      "'CREATE POLICY service_role_bypass ON public.%I TO service_role USING (true) WITH CHECK (true)'",
    );
    expect(migration).toContain('FOREACH table_name IN ARRAY service_tables LOOP');
  });

  it('normalizes the legacy SAML response-signing field to the service-wide secure invariant', () => {
    expect(migration).toMatch(
      /UPDATE public\.sso_connections\s+SET saml_want_response_signed = true\s+WHERE saml_want_response_signed IS DISTINCT FROM true;/,
    );
    expect(migration).toMatch(
      /ALTER COLUMN saml_want_response_signed SET DEFAULT true;/,
    );
    expect(migration).toMatch(
      /ALTER COLUMN saml_want_response_signed SET NOT NULL;/,
    );
    expect(migration).toContain(
      'The ACS requires a signed SAML Response envelope regardless of this tenant field.',
    );
  });
});
