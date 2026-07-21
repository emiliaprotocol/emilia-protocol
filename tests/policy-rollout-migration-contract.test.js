// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const expandMigration = readFileSync(
  new URL('../supabase/migrations/20260719123000_policy_rollout_accountable_signoff.sql', import.meta.url),
  'utf8',
);
const migration = expandMigration;
// Route is migrating from .js to .ts; resolve whichever extension exists.
const routeTsUrl = new URL('../app/api/cloud/policies/[policyId]/rollout/route.ts', import.meta.url);
const routeUrl = existsSync(routeTsUrl)
  ? routeTsUrl
  : new URL('../app/api/cloud/policies/[policyId]/rollout/route.js', import.meta.url);
const route = readFileSync(routeUrl, 'utf8');

describe('policy rollout atomic Accountable Signoff migration contract', () => {
  it('records a unique receipt, action, execution reference, and authority', () => {
    for (const column of [
      'authorization_receipt_id TEXT',
      'authorization_action_hash TEXT',
      'authorization_execution_reference_id TEXT',
      'authorization_authority JSONB',
    ]) {
      expect(migration).toContain(column);
    }
    expect(migration).toContain('policy_rollouts_authorization_receipt_once');
  });

  it('serializes the target and reconstructs signed before/after state from locked rows', () => {
    expect(migration).toContain('pg_catalog.pg_advisory_xact_lock');
    expect(migration).toMatch(/FROM public\.handshake_policies hp[\s\S]+FOR UPDATE;/);
    expect(migration).toContain('INTO v_current_before');
    expect(migration).toContain('v_current_after := pg_catalog.jsonb_build_object');
    expect(migration).toContain('v_current_before IS DISTINCT FROM p_signed_before_state');
    expect(migration).toContain('v_current_after IS DISTINCT FROM p_signed_after_state');
    expect(migration.indexOf('v_consumed_count <> 0'))
      .toBeLessThan(migration.indexOf('v_current_before IS DISTINCT FROM p_signed_before_state'));
  });

  it('checks pending receipt, exact target, expiry, creator-bound Class-A approval, and authority facts', () => {
    for (const required of [
      "v_consumed_count <> 0",
      "v_created ->> 'organization_id' IS DISTINCT FROM p_tenant_id::text",
      "v_created ->> 'action_type' IS DISTINCT FROM 'policy_rollout'",
      "v_created ->> 'target_resource_id' IS DISTINCT FROM ('policy:' || p_policy_key)",
      "v_created ->> 'required_assurance' IS DISTINCT FROM 'A'",
      "v_created #>> '{canonical_action,rollout_policy_id}' IS DISTINCT FROM p_policy_id::text",
      "v_created #> '{canonical_action,rollout_policy_rules}' IS DISTINCT FROM v_policy_rules",
      "v_created #>> '{canonical_action,rollout_policy_mode}' IS DISTINCT FROM v_policy_mode",
      "v_created #>> '{canonical_action,rollout_policy_status}' IS DISTINCT FROM v_policy_status",
      "v_created #>> '{canonical_action,rollout_environment}' IS DISTINCT FROM p_environment",
      "v_created #>> '{canonical_action,rollout_strategy}' IS DISTINCT FROM p_strategy",
      "v_created #> '{canonical_action,rollout_metadata}'",
      "v_created #> '{canonical_action,rollout_before_state}' IS DISTINCT FROM p_signed_before_state",
      "v_created #> '{canonical_action,rollout_after_state}' IS DISTINCT FROM p_signed_after_state",
      'v_expires_at <= pg_catalog.now()',
      "req.actor_id = v_created_actor_id",
      'v_request_count <> 1 OR v_approved_count <> 1',
      "approved.after_state ->> 'key_class' = 'A'",
      'ac.credential_id = v_approved_credential_id',
      "ac.key_class = 'A'",
      'a.authority_id = ANY (p_authority_ids)',
      "a.subject_ref = v_approved_approver_id",
      "'policy_rollout' = ANY (a.action_scopes)",
      'FOR UPDATE',
    ]) {
      expect(migration).toContain(required);
    }
  });

  it('fails malformed null inputs explicitly instead of relying on SQL three-valued logic', () => {
    for (const required of [
      'p_policy_id IS NULL',
      'p_version IS NULL',
      'p_strategy IS NULL',
      'p_initiated_by IS NULL',
      'p_receipt_id IS NULL',
      'p_action_hash IS NULL',
      'p_authority_ids IS NULL',
    ]) {
      expect(migration).toContain(required);
    }
  });

  it('parses expiry safely and records authority facts reconstructed from locked rows', () => {
    expect(migration).toContain("pg_catalog.pg_input_is_valid(v_created ->> 'expires_at', 'timestamptz')");
    expect(migration).toContain("RAISE EXCEPTION 'policy_rollout_authorization_expired'");
    expect(migration).toContain("'authority_check', 'transactionally_reverified'");
    expect(migration).toContain("'credential_id', v_approved_credential_id");
    expect(migration).toContain("'authority', v_authority");
    expect(migration).not.toContain("'authority', p_authority");
  });

  it('validates quorum JSON before casts and pins every approval to its roster seat', () => {
    expect(expandMigration).toContain("p_quorum_policy ? 'window_sec'");
    expect(expandMigration).toContain(
      "jsonb_typeof(p_quorum_policy -> 'distinct_humans') <> 'boolean'",
    );
    expect(expandMigration).toContain(
      "count(DISTINCT (submitted ->> 'role', submitted ->> 'approver'))",
    );
    expect(expandMigration).toContain(
      "v_quorum_mode = 'ordered' AND v_quorum_required <> v_quorum_roster_count",
    );
    expect(expandMigration).toContain(
      "pg_catalog.pg_input_is_valid(p_quorum_policy ->> 'required', 'integer')",
    );
    expect(expandMigration).toContain("RAISE EXCEPTION 'policy_rollout_quorum_order_invalid'");
    expect(expandMigration).toMatch(
      /FOR v_approval IN[\s\S]+approved\.actor_id\)[\s\S]+req\.after_state #>> '\{quorum,approver_id\}'[\s\S]+jsonb_array_elements\(p_quorum_policy -> 'approvers'\)/,
    );
  });

  it('serializes legacy expand-window writes on the same target lock', () => {
    expect(expandMigration).toContain('CREATE OR REPLACE FUNCTION public.lock_policy_rollout_target()');
    expect(expandMigration).toContain('CREATE TRIGGER policy_rollouts_target_lock');
    expect(expandMigration).toContain(
      "OLD.tenant_id || ':' || hp.policy_key || ':' || OLD.environment",
    );
    expect(expandMigration).toContain(
      "NEW.tenant_id || ':' || hp.policy_key || ':' || NEW.environment",
    );
  });

  it('anchors request and approval time to the receipt lifetime and database clock', () => {
    expect(expandMigration).toContain('v_created_at TIMESTAMPTZ');
    expect(expandMigration).toContain('approved.created_at >= req.created_at');
    expect(expandMigration).toContain('req.created_at >= v_created_at');
    expect(expandMigration).toContain('approved.created_at <= LEAST(v_expires_at, pg_catalog.now())');
    expect(expandMigration).toContain("v_expires_at > v_created_at + interval '15 minutes'");
  });

  it('consumes and activates in one SECURITY DEFINER transaction during the expand window', () => {
    expect(expandMigration).toMatch(/LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/);
    expect(expandMigration).toContain("'guard.trust_receipt.consumed'");
    expect(expandMigration).toContain('UPDATE public.policy_rollouts pr');
    expect(expandMigration).toContain('INSERT INTO public.policy_rollouts');
    expect(expandMigration).not.toMatch(/REVOKE INSERT, UPDATE, DELETE, TRUNCATE[\s\S]+service_role/);
    expect(expandMigration).toMatch(/REVOKE ALL ON FUNCTION public\.activate_policy_rollout_authorized\([\s\S]+FROM PUBLIC, anon, authenticated;/);
    expect(expandMigration).toMatch(/GRANT EXECUTE ON FUNCTION public\.activate_policy_rollout_authorized\([\s\S]+TO service_role;/);
  });

  it('routes activation through the atomic RPC and never calls generic consume first', () => {
    expect(route).toContain(".rpc('activate_policy_rollout_authorized'");
    expect(route).not.toContain("/consume'");
    expect(route).not.toContain(".from('policy_rollouts').insert");
    expect(route).not.toContain(".from('policy_rollouts').update");
  });
});
