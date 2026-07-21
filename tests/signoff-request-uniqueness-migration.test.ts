// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719124500_signoff_request_uniqueness.sql', import.meta.url),
  'utf8',
);

describe('signoff request uniqueness migration', () => {
  it('fails loudly on historical duplicates instead of silently choosing evidence', () => {
    expect(migration).toContain("RAISE EXCEPTION 'signoff_request_duplicates_present'");
    expect(migration).toContain('HAVING count(*) > 1');
  });

  it('atomically rejects duplicate single requests while preserving quorum fan-out', () => {
    expect(migration).toContain('CREATE UNIQUE INDEX IF NOT EXISTS guard_signoff_request_once');
    expect(migration).toMatch(
      /ON public\.audit_events\s*\(\s*target_id,\s*\(COALESCE\(after_state #>> '\{quorum,approver_id\}', ''\)\)\s*\)/,
    );
    expect(migration).toContain("event_type = 'guard.signoff.requested'");
    expect(migration).toContain("target_type = 'trust_receipt'");
  });
});
