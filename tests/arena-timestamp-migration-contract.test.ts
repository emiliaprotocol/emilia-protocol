// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
const migration = readFileSync(
  `${root}/supabase/migrations/20260802193000_arena_refusal_timestamp_normalization.sql`,
  'utf8',
);

describe('Arena refusal timestamp normalization migration', () => {
  it('replaces only the token-bound, service-role publication function', () => {
    expect(migration.match(/CREATE OR REPLACE FUNCTION public\.publish_arena_refusal/g)).toHaveLength(1);
    expect(migration).toContain('SECURITY DEFINER');
    expect(migration).toContain("SET search_path = ''");
    expect(migration).toMatch(
      /WHERE attempt\.attempt_id = p_attempt_id AND session\.token_hash = p_token_hash/,
    );
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)\n  FROM PUBLIC, anon, authenticated;',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)\n  TO service_role;',
    );
  });

  it('projects the refusal instant at the signed millisecond precision', () => {
    expect(migration).toContain("v_attempt.created_at AT TIME ZONE 'UTC'");
    expect(migration).toContain("'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'");
    expect(migration).not.toContain("'created_at', v_attempt.created_at\n");
  });

  it('keeps the public projection privacy-minimized', () => {
    const projection = migration.match(
      /v_projection := jsonb_build_object\(([\s\S]*?)\n  \);\n\n  INSERT INTO public\.arena_shares/,
    );
    expect(projection).not.toBeNull();
    expect(projection![1]).not.toMatch(
      /token_hash|private_key_encrypted|agent_name|allowance_profile|'limits'|tenant_id|session_id/,
    );
  });
});
