// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719130000_policy_rollout_rpc_only.sql', import.meta.url),
  'utf8',
);

describe('policy rollout RPC-only contract migration', () => {
  it('removes every direct write path while preserving service-role reads', () => {
    expect(migration).toMatch(
      /REVOKE INSERT, UPDATE, DELETE, TRUNCATE[\s\S]+FROM PUBLIC, anon, authenticated, service_role;/,
    );
    expect(migration).toMatch(
      /GRANT SELECT ON TABLE public\.policy_rollouts TO service_role;/,
    );
  });
});
