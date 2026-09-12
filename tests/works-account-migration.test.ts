// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const sql = readFileSync(new URL(
  '../supabase/migrations/20260907235809_works_accounts.sql', import.meta.url,
), 'utf8').toLowerCase();

describe('Works accounts PostgreSQL boundary', () => {
  it('keeps accounts, one-time challenges and sessions service-only with hashed secrets', () => {
    for (const table of ['works_accounts', 'works_account_email_challenges', 'works_account_sessions']) {
      expect(sql).toContain(`create table public.${table}`);
      expect(sql).toContain(`alter table public.${table} enable row level security`);
      expect(sql).toContain(`alter table public.${table} force row level security`);
    }
    expect(sql).toContain('email_digest');
    expect(sql).toContain('code_digest');
    expect(sql).toContain('session_token_digest');
    expect(sql).not.toContain('email_address');
    expect(sql).not.toContain('raw_code');
    expect(sql).not.toMatch(/grant[^;]+(?:anon|authenticated)/);
  });

  it('creates no broad API key and marks the mapped entity inactive and unverified', () => {
    const exchange = sql.slice(sql.indexOf('create function public.exchange_works_account_email_challenge'));
    expect(exchange).toContain('insert into public.entities');
    expect(exchange).toContain("'inactive'");
    expect(exchange).toContain('false');
    expect(exchange).not.toContain('insert into public.api_keys');
    expect(sql).not.toContain('verified = true');
  });

  it('atomically locks and consumes a delivered challenge with hard attempts and expiry', () => {
    const exchange = sql.slice(
      sql.indexOf('create function public.exchange_works_account_email_challenge'),
      sql.indexOf('create function public.read_works_account_session'),
    );
    expect(exchange).toContain('for update');
    expect(exchange).toContain('consumed_at');
    expect(exchange).toContain('attempt_count');
    expect(exchange).toContain('expires_at');
    expect(exchange).toContain('delivery_confirmed_at');
    expect(exchange).toContain('insert into public.works_account_sessions');
    for (const required of [
      'p_challenge_id is null',
      'p_email_digest is null',
      'p_code_digest is null',
      'p_session_token_digest is null',
      'p_session_expires_at is null',
    ]) expect(exchange).toContain(required);
  });

  it('rate limits challenge issuance by keyed email and client digests inside the transaction', () => {
    const begin = sql.slice(
      sql.indexOf('create function public.begin_works_account_email_challenge'),
      sql.indexOf('create function public.mark_works_account_email_delivery'),
    );
    expect(begin).toContain('email_digest');
    expect(begin).toContain('client_digest');
    expect(begin).toContain("interval '1 hour'");
    expect(begin).toContain("errcode = 'wa001'");
    for (const required of [
      'p_email_digest is null',
      'p_client_digest is null',
      'p_code_digest is null',
      'p_mode is null',
    ]) expect(begin).toContain(required);
  });
});
