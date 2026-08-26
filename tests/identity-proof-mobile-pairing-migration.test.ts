// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = path.join(
  process.cwd(),
  'supabase/migrations/20260826150000_identity_proof_and_mobile_pairing_closure.sql',
);
const sql = fs.readFileSync(migrationPath, 'utf8');

describe('identity-proof and mobile-pairing migration contract', () => {
  it('makes explicit token.organization_id the sole SCIM organization provenance', () => {
    const start = sql.indexOf('-- BEGIN STRIX-40-SCIM-ORG-PROVENANCE');
    const end = sql.indexOf('-- END STRIX-40-SCIM-ORG-PROVENANCE');
    const closure = sql.slice(start, end);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(closure).toContain('entity.organization_id IS DISTINCT FROM entity.entity_id');
    expect(closure).toContain('SET revoked_at = COALESCE');
    expect(closure).toContain('organization_id = NULL');
    expect(closure).toContain('organization_id IS DISTINCT FROM tenant_id');
    expect(closure).toContain('token.organization_id = p_organization_id');
    expect(closure).not.toContain('token.tenant_id = p_organization_id');
    expect(closure).not.toMatch(/coalesce\([^)]*p_organization_id[^)]*p_tenant_id/i);
  });

  it('atomically binds pairing exchange to an active directory credential and monotonic counter', () => {
    expect(sql).toContain('exchange_mobile_pairing_verified');
    expect(sql).toContain("candidate.enrollment_basis = 'directory'");
    expect(sql).toContain('candidate.directory_user_id IS NOT NULL');
    expect(sql).toContain('candidate.organization_id = v_organization_id');
    expect(sql).toContain('candidate.approver_id = pairing.approver_id');
    expect(sql).toContain('credential.sign_count > 0 AND p_new_sign_count <= credential.sign_count');
    expect(sql.indexOf('FOR UPDATE;')).toBeLessThan(sql.indexOf('SET consumed_at = p_now'));
  });

  it('requires issuer proof vocabulary and rechecks the same authority UUID and key id under lock', () => {
    expect(sql).toContain("p_issuer_status IS DISTINCT FROM 'authority_signature_valid'");
    expect(sql).toContain('authority_id::text = p_authority_id');
    expect(sql).toContain('key_id = p_issuer_ref');
    expect(sql).toContain("v_authority_algorithm IS DISTINCT FROM 'Ed25519'");
    expect(sql).toMatch(/key_id = p_issuer_ref[\s\S]*FOR UPDATE;/);
    expect(sql).toContain('handshake_presentations_verified_issuer_proof');
  });

  it('quarantines legacy rows whose active key lookup was never proof of issuer participation', () => {
    expect(sql).toContain("issuer_status = 'legacy_issuer_unproven'");
    expect(sql).toContain("issuer_status IS DISTINCT FROM 'authority_signature_valid'");
  });
});
