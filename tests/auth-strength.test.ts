// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { AUTH_STRENGTHS, resolveVerifiedAuthStrength } from '../lib/auth-strength.js';

const ROOT = path.resolve(import.meta.dirname, '..');
const AUTH_STRENGTH_MIGRATION = path.join(
  ROOT,
  'supabase/migrations/20260718170000_explicit_api_key_auth_strength.sql',
);

describe('verified authentication-strength boundary', () => {
  it('accepts only the server-derived top-level credential projection', () => {
    expect(resolveVerifiedAuthStrength({ auth_strength: AUTH_STRENGTHS.MFA })).toBe('mfa');
    expect(resolveVerifiedAuthStrength({ auth_strength: 'not-a-strength' })).toBe('password');
    expect(resolveVerifiedAuthStrength({ entity: { auth_strength: 'mfa' } })).toBe('password');
    expect(resolveVerifiedAuthStrength({})).toBe('password');
  });

  it('records the auth-strength column and constraint in the migration contract', () => {
    const sql = fs.readFileSync(AUTH_STRENGTH_MIGRATION, 'utf8');
    expect(sql).toContain('ADD COLUMN IF NOT EXISTS auth_strength');
    expect(sql).toContain('api_keys_auth_strength_check');
    expect(sql).toContain("'auth_strength', COALESCE(v_key_record.auth_strength, 'password')");
  });
});
