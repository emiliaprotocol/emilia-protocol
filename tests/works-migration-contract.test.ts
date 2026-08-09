// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260809060000_works_records.sql', import.meta.url),
  'utf8',
).toLowerCase();

describe('Works records migration', () => {
  it('creates a bounded durable entity-owned record store', () => {
    expect(migration).toContain('create table public.works_records');
    expect(migration).toContain('owner_entity_id uuid not null');
    expect(migration).toContain('references public.entities(id)');
    expect(migration).toContain('record jsonb not null');
    expect(migration).toContain('pg_catalog.pg_column_size(record) <= 131072');
    expect(migration).toContain('primary key (collection, record_id)');
    expect(migration).toContain('works_records_owner_idx');
    expect(migration).toContain('works_records_public_submissions_idx');
  });

  it('forces RLS and grants table access only to the server service role', () => {
    expect(migration).toContain('enable row level security');
    expect(migration).toContain('force row level security');
    expect(migration).toMatch(
      /revoke all on table public\.works_records[\s\S]*from public, anon, authenticated, service_role/,
    );
    expect(migration).toContain(
      'grant select, insert, update on table public.works_records to service_role',
    );
    expect(migration).not.toMatch(/grant[^;]+(?:anon|authenticated)/);
    expect(migration).not.toContain('grant delete');
  });

  it('enforces reserved examples, VERIFIED refusal, attribution, and same-owner references in SQL', () => {
    expect(migration).toContain("record @> '{\"example\": false}'::jsonb");
    expect(migration).toContain('verified claims cannot be minted through works writes');
    expect(migration).toContain('works reference not found');
    expect(migration).toContain('works reference owner mismatch');
    expect(migration).toContain("new.collection = 'submissions'");
    expect(migration).toContain("new.collection = 'opportunities'");
    expect(migration).toContain('display_name');
    expect(migration).toContain('before insert or update on public.works_records');
  });

  it('models submission visibility as private by default with a public-only read index', () => {
    expect(migration).toContain("visibility text not null default 'private'");
    expect(migration).toContain("visibility in ('private', 'public')");
    expect(migration).toContain("where collection = 'submissions' and visibility = 'public'");
    expect(migration).toContain("record ->> 'visibility' is not distinct from new.visibility");
  });
});
