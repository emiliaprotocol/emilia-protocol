// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
const migration = readFileSync(
  `${root}/supabase/migrations/20260802120000_arena_synthetic_allowance.sql`,
  'utf8',
);
const writeGuard = readFileSync(`${root}/lib/write-guard.ts`, 'utf8');

const TABLES = ['arena_sessions', 'arena_attempts', 'arena_shares'] as const;
const RPC_SIGNATURES = [
  'public.provision_arena_session(TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BIGINT, TEXT[], JSONB, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)',
  'public.attempt_arena_action(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, TEXT)',
  'public.commit_arena_refusal(TEXT, TEXT, JSONB, TEXT)',
  'public.publish_arena_refusal(TEXT, TEXT)',
  'public.prune_arena_sessions(TIMESTAMPTZ)',
] as const;

function functionBody(name: string, delimiter: string): string {
  const match = migration.match(
    new RegExp(
      `CREATE OR REPLACE FUNCTION public\\.${name}\\([\\s\\S]*?AS \\$${delimiter}\\$([\\s\\S]*?)\\$${delimiter}\\$;`,
    ),
  );
  expect(match, `${name} must have an inspectable, delimited function body`).not.toBeNull();
  return match![1];
}

describe('Arena migration security contract', () => {
  it('has no duplicate function parameters or configuration clauses', () => {
    const provisionHeader = migration.match(
      /CREATE OR REPLACE FUNCTION public\.provision_arena_session\(([\s\S]*?)\) RETURNS JSONB/,
    );
    const commitDefinition = migration.match(
      /CREATE OR REPLACE FUNCTION public\.commit_arena_refusal\(([\s\S]*?)\$arena_refusal\$;/,
    );
    expect(provisionHeader).not.toBeNull();
    expect(provisionHeader![1].match(/p_issuer_id TEXT/g)).toHaveLength(1);
    expect(commitDefinition).not.toBeNull();
    expect(commitDefinition![1].match(/SET search_path = ''/g)).toHaveLength(1);
  });

  it('forces RLS and grants clients no table writes', () => {
    for (const table of TABLES) {
      expect(migration).toContain(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;`);
      expect(migration).toContain(`ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY;`);
      expect(migration).toContain(
        `REVOKE ALL ON TABLE public.${table} FROM PUBLIC, anon, authenticated;`,
      );
      expect(migration).toContain(`GRANT SELECT ON TABLE public.${table} TO service_role;`);
      expect(migration).not.toMatch(
        new RegExp(`GRANT\\s+(?:ALL|INSERT|UPDATE|DELETE)[^;]*public\\.${table}`, 'i'),
      );
    }
  });

  it('makes every RPC service-role-only and fixes its search path', () => {
    for (const signature of RPC_SIGNATURES) {
      expect(migration).toContain(`REVOKE ALL ON FUNCTION ${signature}\n  FROM PUBLIC, anon, authenticated;`);
      expect(migration).toContain(`GRANT EXECUTE ON FUNCTION ${signature}\n  TO service_role;`);
    }

    expect(migration.match(/SECURITY DEFINER\nSET search_path = ''/g)).toHaveLength(5);
    expect(migration).not.toMatch(/GRANT EXECUTE ON FUNCTION[\s\S]*?TO (?:PUBLIC|anon|authenticated)/i);
  });

  it('binds every denormalized tenant and session coordinate with composite foreign keys', () => {
    expect(migration).toContain(
      'UNIQUE (id, tenant_id, session_id, challenge_id, challenge_version)',
    );
    expect(migration).toContain(
      'FOREIGN KEY (session_row_id, tenant_id, session_id, challenge_id, challenge_version)',
    );
    expect(migration).toContain(
      'REFERENCES public.arena_sessions (id, tenant_id, session_id, challenge_id, challenge_version)',
    );
    expect(migration).toContain(
      'FOREIGN KEY (attempt_id, attempt_nonce, session_row_id, tenant_id, session_id, challenge_id, challenge_version)',
    );
    expect(migration).toContain(
      'REFERENCES public.arena_attempts (attempt_id, attempt_nonce, session_row_id, tenant_id, session_id, challenge_id, challenge_version)',
    );
  });

  it('serializes allowance debits and refuses operation or nonce equivocation', () => {
    const body = functionBody('attempt_arena_action', 'arena_attempt');

    expect(body).toMatch(
      /WHERE session_id = p_session_id AND token_hash = p_token_hash\s+FOR UPDATE;/,
    );
    expect(body).toContain('WHERE session_row_id = v_session.id AND operation_id = p_operation_id');
    expect(body).toContain('WHERE session_row_id = v_session.id AND attempt_nonce = p_attempt_nonce');
    expect(body).toContain('v_existing.caid <> p_caid');
    expect(body).toContain("'reason', 'allowance_operation_equivocation'");
    expect(body).toContain("'reason', 'allowance_attempt_nonce_replay'");
    expect(body).toMatch(
      /SET remaining_amount = remaining_amount - v_amount\s+WHERE id = v_session\.id AND remaining_amount >= v_amount\s+RETURNING remaining_amount INTO v_remaining;/,
    );
    expect(migration).toContain('UNIQUE (session_row_id, operation_id)');
    expect(migration).toContain('UNIQUE (session_row_id, attempt_nonce)');
  });

  it('caps each locked session at 25 distinct attempts after replay handling', () => {
    const body = functionBody('attempt_arena_action', 'arena_attempt');
    const operationLookup = body.indexOf(
      'WHERE session_row_id = v_session.id AND operation_id = p_operation_id',
    );
    const nonceLookup = body.indexOf(
      'WHERE session_row_id = v_session.id AND attempt_nonce = p_attempt_nonce',
    );
    const attemptCap = body.indexOf('IF v_attempt_count >= 25 THEN');

    expect(operationLookup).toBeGreaterThan(-1);
    expect(nonceLookup).toBeGreaterThan(operationLookup);
    expect(attemptCap).toBeGreaterThan(nonceLookup);
    expect(body).toContain("'status', 429, 'reason', 'arena_attempt_limit_exceeded'");
  });

  it('allows only the intended immutable-record state transition', () => {
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.arena_sessions_guard()');
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.arena_attempts_guard()');
    expect(migration).toContain('CREATE OR REPLACE FUNCTION public.arena_shares_immutable()');
    expect(migration).toContain('arena session identity and limits are immutable');
    expect(migration).toContain('arena attempt rows permit only pending-to-complete evidence commitment');
    expect(migration).toContain('arena share rows are immutable');
    expect(migration).toContain('BEFORE UPDATE OR DELETE ON public.arena_sessions');
    expect(migration).toContain('BEFORE UPDATE OR DELETE ON public.arena_attempts');
    expect(migration).toContain('BEFORE UPDATE OR DELETE ON public.arena_shares');
  });

  it('prunes only expired unpublished sessions through a service-only cascade', () => {
    expect(migration).toContain(
      'REFERENCES public.arena_sessions (id, tenant_id, session_id, challenge_id, challenge_version)\n    ON DELETE CASCADE',
    );
    const body = functionBody('prune_arena_sessions', 'arena_prune');
    expect(body).toContain('p_before > clock_timestamp()');
    expect(body).toContain('session.expires_at < p_before');
    expect(body).toContain('NOT EXISTS (');
    expect(body).toContain('FROM public.arena_shares AS share');
    expect(body).toContain('share.session_row_id = session.id');
    expect(body).toContain("set_config('emilia.arena_prune', '1', true)");
    expect(body).toContain("'deleted_sessions', v_deleted");
    expect(migration).toContain('arena published source rows cannot be pruned');
  });

  it('publishes only through an explicit token-bound RPC and stores a redacted projection', () => {
    const body = functionBody('publish_arena_refusal', 'arena_publish');

    expect(body).toMatch(/WHERE attempt\.attempt_id = p_attempt_id AND session\.token_hash = p_token_hash/);
    expect(body).toContain('FOR UPDATE OF attempt;');
    expect(body).toContain("v_attempt.decision <> 'refuse'");
    expect(body).toContain("v_attempt.evidence_status <> 'complete'");
    expect(body).toContain("'profile', 'EP-ARENA-PUBLIC-REFUSAL-v1'");
    expect(body).toContain("'claim_boundary', 'synthetic_challenge_not_identity_competence_certification_money_or_production_authority'");
    const projection = body.match(/v_projection := jsonb_build_object\(([\s\S]*?)\n  \);\n\n  INSERT INTO public\.arena_shares/);
    expect(projection).not.toBeNull();
    expect(projection![1]).not.toMatch(
      /token_hash|private_key_encrypted|agent_name|allowance_profile|'limits'|tenant_id|session_id/,
    );

    const shareInserts = migration.match(/INSERT INTO public\.arena_shares/g) ?? [];
    expect(shareInserts).toHaveLength(1);
  });

  it('binds the public allowance profile to every separately displayed field', () => {
    const body = functionBody('provision_arena_session', 'arena_provision');

    expect(body).toContain("p_allowance_profile->>'session_id' IS DISTINCT FROM p_session_id");
    expect(body).toContain("p_allowance_profile->>'agent_name' IS DISTINCT FROM btrim(p_agent_name)");
    expect(body).toContain("p_allowance_profile->>'currency' IS DISTINCT FROM 'CREDITS'");
    expect(body).toContain("p_allowance_profile->'allowed_targets' IS DISTINCT FROM to_jsonb(p_allowed_targets)");
    expect(body).toContain("(p_allowance_profile->>'total_amount')::BIGINT <> p_total_amount");
    expect(body).toContain("(p_allowance_profile->>'max_amount_per_action')::BIGINT <> p_max_amount_per_action");
    expect(body).toContain("p_allowance_profile->>'expires_at' IS DISTINCT FROM");
    expect(body).toContain("'synthetic_challenge_not_money_custody_settlement_identity_certification_or_production_authorization'");
  });

  it('keeps the challenge synthetic and contains no egress or provider credentials', () => {
    expect(migration).toContain("currency TEXT NOT NULL DEFAULT 'CREDITS' CHECK (currency = 'CREDITS')");
    expect(migration).toContain("p_action->>'action_type' IS DISTINCT FROM 'arena.resource.allocate.1'");
    expect(migration).not.toMatch(/https?:\/\//i);
    expect(migration).not.toMatch(/net\.http|http_(?:get|post)|provider_credential/i);
  });

  it('uses PostgreSQL-safe identifier regexes with separate 512-character bounds', () => {
    expect(migration).not.toContain('{0,511}');
    expect(migration).toContain('length(p_challenge_id) NOT BETWEEN 1 AND 512');
    expect(migration).toContain('length(p_operation_id) NOT BETWEEN 1 AND 512');
    expect(migration).toContain("length(p_action->>'target') NOT BETWEEN 1 AND 512");
  });

  it('puts all Arena tables behind the runtime write guard', () => {
    for (const table of TABLES) {
      expect(writeGuard).toContain(`'${table}'`);
    }
  });
});
