// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { contract } from '../scripts/db-contract.manifest.mjs';

const appendOnlyMigrationUrl = new URL(
  '../supabase/migrations/20260719125000_audit_events_append_only.sql',
  import.meta.url,
);
const serviceOnlyMigrationUrl = new URL(
  '../supabase/migrations/20260720060603_fortress_db_security_invariants.sql',
  import.meta.url,
);
const appendOnlyMigration = readFileSync(appendOnlyMigrationUrl, 'utf8');
const serviceOnlyMigration = readFileSync(serviceOnlyMigrationUrl, 'utf8');

describe('audit_events service-only migration', () => {
  it('lands after the append-only migration without weakening immutability', () => {
    const appendOnlyName = basename(fileURLToPath(appendOnlyMigrationUrl));
    const serviceOnlyName = basename(fileURLToPath(serviceOnlyMigrationUrl));

    expect(serviceOnlyName.localeCompare(appendOnlyName)).toBeGreaterThan(0);
    expect(appendOnlyMigration).toContain(
      'BEFORE UPDATE OR DELETE ON public.audit_events',
    );
    expect(appendOnlyMigration).toContain(
      'AUDIT_EVENT_IMMUTABILITY_VIOLATION',
    );
  });

  it('enables and forces RLS on audit_events', () => {
    expect(serviceOnlyMigration).toMatch(
      /ALTER TABLE public\.audit_events\s+ENABLE ROW LEVEL SECURITY;/,
    );
    expect(serviceOnlyMigration).toMatch(
      /ALTER TABLE public\.audit_events\s+FORCE ROW LEVEL SECURITY;/,
    );
  });

  it('recreates an explicit service_role-only policy with no public role', () => {
    expect(serviceOnlyMigration).toContain(
      'DROP POLICY IF EXISTS "service_role_bypass" ON public.audit_events;',
    );

    const policies = serviceOnlyMigration.match(/CREATE POLICY[\s\S]*?;/g) ?? [];

    expect(policies).toHaveLength(1);
    expect(policies[0]).toMatch(
      /CREATE POLICY "service_role_bypass" ON public\.audit_events\s+FOR ALL\s+TO service_role\s+USING \(true\)\s+WITH CHECK \(true\);/,
    );
    expect(policies[0]).not.toMatch(/\bTO\s+(?:PUBLIC|anon|authenticated)\b/i);
  });

  it('removes every public/client ACL and leaves service_role append-only', () => {
    expect(serviceOnlyMigration).toMatch(
      /REVOKE ALL PRIVILEGES\s+ON TABLE public\.audit_events\s+FROM PUBLIC, anon, authenticated;/,
    );
    expect(serviceOnlyMigration).toMatch(
      /REVOKE ALL PRIVILEGES\s+ON TABLE public\.audit_events\s+FROM service_role;/,
    );

    const tableGrants = [
      ...serviceOnlyMigration.matchAll(
        /GRANT\s+([^;]+?)\s+ON TABLE public\.audit_events\s+TO\s+([^;]+);/gi,
      ),
    ];

    expect(tableGrants).toHaveLength(1);
    expect(tableGrants[0][1].replace(/\s+/g, ' ').trim()).toBe(
      'SELECT, INSERT',
    );
    expect(tableGrants[0][2].trim()).toBe('service_role');
    expect(
      serviceOnlyMigration.indexOf(
        'FROM service_role;',
      ),
    ).toBeLessThan(
      serviceOnlyMigration.indexOf(
        'GRANT SELECT, INSERT ON TABLE public.audit_events TO service_role;',
      ),
    );
    expect(serviceOnlyMigration).not.toMatch(
      /GRANT[\s\S]*?ON TABLE public\.audit_events[\s\S]*?TO\s+(?:PUBLIC|anon|authenticated)\b/i,
    );
  });

  it('promotes the ledger posture into the live schema contract', () => {
    expect(contract.requiredTables).toContain('audit_events');
    expect(contract.rlsRequired).toContain('audit_events');
    expect(contract.noAnonRead).toContain('audit_events');
    expect(contract.noAnonWrite).toContain('audit_events');
    expect(contract.tableGrantsNoPublic).toContain('audit_events');
    expect(contract.serviceRolePoliciesRequired).toContain('audit_events');
  });
});
