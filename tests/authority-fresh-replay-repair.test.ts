// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const repair = readFileSync(
  new URL(
    '../supabase/migrations/20260629224357_authority_subject_columns_replay_repair.sql',
    import.meta.url,
  ),
  'utf8',
);
const successor = readFileSync(
  new URL(
    '../supabase/migrations/20260629224358_create_authorities_table.sql',
    import.meta.url,
  ),
  'utf8',
);

describe('authority fresh-replay repair', () => {
  it('precedes the journaled subject-index migration and supplies every indexed field', () => {
    for (const column of [
      'organization_id',
      'subject_type',
      'subject_ref',
      'assurance_class',
    ]) {
      expect(repair).toContain(`ADD COLUMN IF NOT EXISTS ${column}`);
    }
    expect(repair).toContain(
      'DROP CONSTRAINT IF EXISTS authorities_role_check',
    );
    expect(repair).not.toContain('pg_get_constraintdef');
    expect(repair).toContain('CREATE INDEX IF NOT EXISTS idx_authorities_subject');
    expect(successor).toContain('idx_authorities_subject');
  });
});
