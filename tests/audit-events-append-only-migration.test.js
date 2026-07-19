// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719125000_audit_events_append_only.sql', import.meta.url),
  'utf8',
);

describe('audit_events append-only migration', () => {
  it('blocks row mutation and removes direct service-role mutation privileges', () => {
    expect(migration).toContain('BEFORE UPDATE OR DELETE ON public.audit_events');
    expect(migration).toContain('AUDIT_EVENT_IMMUTABILITY_VIOLATION');
    expect(migration).toMatch(/REVOKE UPDATE, DELETE, TRUNCATE[\s\S]+FROM PUBLIC, anon, authenticated, service_role;/);
    expect(migration).toContain('GRANT SELECT, INSERT ON TABLE public.audit_events TO service_role');
  });
});
