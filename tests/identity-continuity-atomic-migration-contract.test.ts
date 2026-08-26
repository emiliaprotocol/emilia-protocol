// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migrationUrl = new URL(
  '../supabase/migrations/20260826130000_continuity_challenge_atomic.sql',
  import.meta.url,
);

function functionBody(sql: string, name: string): string {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION public.${name}(`);
  expect(start, `${name} definition missing`).toBeGreaterThanOrEqual(0);
  const next = sql.indexOf('CREATE OR REPLACE FUNCTION public.', start + 1);
  return sql.slice(start, next < 0 ? sql.length : next);
}

describe('continuity challenge atomic migration', () => {
  it('exists as a forward-only migration', () => {
    expect(existsSync(migrationUrl)).toBe(true);
  });

  it('files claims atomically under the same advisory lock used by active disputes', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const filing = sql.indexOf('CREATE OR REPLACE FUNCTION public.file_continuity_claim_atomic(');
    const filingBody = functionBody(sql, 'file_continuity_claim_atomic');
    const filingAdvisory = filingBody.indexOf('pg_catalog.pg_advisory_xact_lock');
    const affectedEntityLocks = filingBody.indexOf('FOR SHARE', filingAdvisory);
    const advisoryLocks = sql.match(/pg_catalog\.pg_advisory_xact_lock\([\s\S]*?ep-continuity-dispute:/g) || [];
    const disputeTrigger = sql.indexOf('CREATE TRIGGER continuity_active_dispute_guard');

    expect(filing).toBeGreaterThanOrEqual(0);
    expect(sql.indexOf('INSERT INTO public.continuity_claims', filing)).toBeGreaterThan(filing);
    expect(sql.indexOf("'continuity.filed'", filing)).toBeGreaterThan(filing);
    expect(filingAdvisory).toBeGreaterThanOrEqual(0);
    expect(affectedEntityLocks).toBeGreaterThan(filingAdvisory);
    expect(filingBody.slice(0, filingAdvisory)).not.toContain('FOR SHARE');
    expect(filingBody).toContain('p_actor_entity_id,');
    expect(filingBody).toContain('ORDER BY endpoint.entity_id');
    expect(advisoryLocks.length).toBeGreaterThanOrEqual(4);
    expect(sql).toContain('p_actor_entity_id TEXT');
    expect(sql).toContain('v_actor.principal_id IS DISTINCT FROM v_principal.id');
    expect(sql).toContain('v_actor.entity_id <> v_principal.principal_id');
    expect(sql).toContain('DROP FUNCTION IF EXISTS public.file_continuity_claim_atomic(');
    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.guard_active_dispute_continuity()');
    expect(disputeTrigger).toBeGreaterThan(filing);
    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.lock_continuity_dispute_entity()');
    expect(sql).toContain('BEFORE INSERT OR DELETE OR UPDATE OF status, entity_id');
    expect(sql).toContain('AFTER INSERT OR DELETE OR UPDATE OF status, entity_id');
    expect(sql).toContain("status = 'frozen_pending_dispute'");
  });

  it('serializes resolution with disputes and commits every consequence atomically', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'resolve_continuity_atomic');
    const advisoryLock = body.indexOf('pg_catalog.pg_advisory_xact_lock');
    const claimLock = body.indexOf('FROM public.continuity_claims', advisoryLock);
    const claimForUpdate = body.indexOf('FOR UPDATE', claimLock);
    const activeCount = body.indexOf('public.is_active_continuity_dispute_status(dispute.status)');
    const decisionInsert = body.indexOf('INSERT INTO public.continuity_decisions');
    const claimUpdate = body.indexOf('UPDATE public.continuity_claims');
    const entityLink = body.indexOf('UPDATE public.entities');
    const auditInsert = body.indexOf('INSERT INTO public.audit_events');

    expect(advisoryLock).toBeGreaterThanOrEqual(0);
    expect(claimLock).toBeGreaterThan(advisoryLock);
    expect(claimForUpdate).toBeGreaterThan(claimLock);
    expect(activeCount).toBeGreaterThan(claimForUpdate);
    expect(decisionInsert).toBeGreaterThan(activeCount);
    expect(claimUpdate).toBeGreaterThan(decisionInsert);
    expect(entityLink).toBeGreaterThan(claimUpdate);
    expect(auditInsert).toBeGreaterThan(entityLink);
    expect(body).toContain("p_decision NOT IN ('approved_full', 'approved_partial', 'rejected', 'rejected_laundering')");
    expect(body).toContain('ORDER BY endpoint.entity_id');
    expect(body).toContain('v_new_entity.principal_id IS NOT NULL');
    expect(body).toContain('v_new_entity.principal_id IS DISTINCT FROM v_claim.principal_id');
    expect(body).toContain('v_old_entity.principal_id IS DISTINCT FROM v_claim.principal_id');
    expect(body).toContain('(principal_id IS NULL OR principal_id = v_claim.principal_id)');
  });

  it('reconciles the complete active-dispute set before any unfreeze', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'reconcile_continuity_for_entity');

    expect(body).toContain('public.is_active_continuity_dispute_status(dispute.status)');
    expect(body).toContain('pg_catalog.min(dispute.dispute_id)');
    expect(body).toContain("claim.status IN ('pending', 'under_challenge', 'frozen_pending_dispute')");
    expect(body).toContain("status = 'frozen_pending_dispute'");
    expect(body).toContain("status = CASE");
    expect(body).toContain("challenge.status IN ('open', 'reviewed')");
    expect(body).toContain("ELSE 'pending'");
    expect(body).toContain('frozen_dispute_id = NULL');
    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.reconcile_continuity_dispute_atomic(');
  });

  it('uses one active-dispute predicate including appeals and backfills existing rows idempotently', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const activePredicate = functionBody(sql, 'is_active_continuity_dispute_status');

    expect(activePredicate).toContain("p_status IN ('open', 'under_review', 'appealed')");
    expect(sql.match(/public\.is_active_continuity_dispute_status\(dispute\.status\)/g)?.length)
      .toBeGreaterThanOrEqual(5);
    expect(sql).toContain('DO $continuity_backfill$');
    expect(sql).toContain('SELECT DISTINCT dispute.entity_id');
    expect(sql).toContain('ORDER BY dispute.entity_id');
    expect(sql).toContain('PERFORM public.reconcile_continuity_for_entity(');
  });

  it('locks and revalidates before inserting a challenge', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    const body = functionBody(sql, 'challenge_continuity_atomic');
    const claimLock = body.indexOf('FROM public.continuity_claims');
    const claimForUpdate = body.indexOf('FOR UPDATE', claimLock);
    const actorLookup = body.indexOf('FROM public.entities AS actor');
    const roleDerivation = body.indexOf('v_challenger_type :=');
    const challengeInsert = body.indexOf('INSERT INTO public.continuity_challenges');
    const claimUpdate = body.indexOf('UPDATE public.continuity_claims');
    const auditInsert = body.indexOf('INSERT INTO public.audit_events');

    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.challenge_continuity_atomic(');
    expect(claimLock).toBeGreaterThanOrEqual(0);
    expect(claimForUpdate).toBeGreaterThan(claimLock);
    expect(actorLookup).toBeGreaterThan(claimForUpdate);
    expect(roleDerivation).toBeGreaterThan(actorLookup);
    expect(challengeInsert).toBeGreaterThan(roleDerivation);
    expect(claimUpdate).toBeGreaterThan(challengeInsert);
    expect(auditInsert).toBeGreaterThan(claimUpdate);
    expect(body).toContain("v_claim.status NOT IN ('pending', 'under_challenge')");
    expect(body).toContain('v_claim.challenge_deadline <= v_now');
  });

  it('derives roles from authoritative relationships and rejects self-contest', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    expect(sql).toContain('actor.principal_id = v_claim.principal_id');
    expect(sql).toContain('actor.entity_id = v_claim_principal.principal_id');
    expect(sql).toContain('actor.is_operator');
    expect(sql).toContain('p_enterprise_admin_authorized');
    expect(sql).toContain('actor.organization_id');
    expect(sql).toContain('FROM public.disputes AS dispute');
    expect(sql).toContain('FROM public.identity_bindings AS binding');
    expect(sql).not.toMatch(/p_challenger_type/i);
  });

  it('makes the RPC service-role-only with a fixed search path', () => {
    const sql = readFileSync(migrationUrl, 'utf8');
    expect(sql.match(/LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/g)?.length).toBeGreaterThanOrEqual(7);
    for (const name of [
      'file_continuity_claim_atomic',
      'challenge_continuity_atomic',
      'resolve_continuity_atomic',
      'reconcile_continuity_dispute_atomic',
    ]) {
      expect(sql).toMatch(new RegExp(`REVOKE ALL ON FUNCTION public\\.${name}\\([\\s\\S]+FROM PUBLIC, anon, authenticated;`));
      expect(sql).toMatch(new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${name}\\([\\s\\S]+TO service_role;`));
    }
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION public\.reconcile_continuity_for_entity\(UUID, TIMESTAMPTZ\)\s+FROM PUBLIC, anon, authenticated, service_role;/);
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION public\.lock_continuity_dispute_entity\(\)\s+FROM PUBLIC, anon, authenticated;/);
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION public\.guard_active_dispute_continuity\(\)\s+FROM PUBLIC, anon, authenticated;/);
  });
});
