// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = fs.readFileSync(new URL(
  '../supabase/migrations/20260907235858_works_workflow.sql', import.meta.url,
), 'utf8').toLowerCase();

describe('Works workflow PostgreSQL contract', () => {
  it('adds workflow state beside the six unchanged record collections', () => {
    expect(migration).toContain('create table public.works_record_workflow');
    expect(migration).toContain('create table public.works_assignments');
    expect(migration).toContain('create table public.works_assignment_events');
    expect(migration).toContain('create table public.works_notifications');
    expect(migration).toContain('create table public.works_workflow_commands');
    expect(migration).not.toContain('alter table public.works_records add column');
  });

  it('keeps all workflow storage server mediated and forced through explicit RPCs', () => {
    for (const table of [
      'works_record_workflow', 'works_assignments', 'works_assignment_events',
      'works_notifications', 'works_workflow_commands',
    ]) {
      expect(migration).toContain(`alter table public.${table} enable row level security`);
      expect(migration).toContain(`alter table public.${table} force row level security`);
      expect(migration).toMatch(new RegExp(
        `revoke all on table public\\.${table}[\\s\\s]*?from public, anon, authenticated, service_role`,
      ));
    }
    expect(migration).toContain('security definer');
    expect(migration).toContain("set search_path = ''");
  });

  it('makes every mutation one atomic row-lock/CAS/idempotency transaction', () => {
    expect(migration).toContain('create function public.command_works_record');
    expect(migration).toContain('create function public.select_works_proposal');
    expect(migration).toContain('create function public.command_works_assignment');
    expect(migration).toContain('create function public.mark_works_notification_read');
    expect(migration).toContain('for update');
    expect(migration).toContain('expected_revision');
    expect(migration).toContain('idempotency_conflict');
    expect(migration).toContain('revision_conflict');
    expect(migration).toContain('request_digest');
    expect(migration).toContain('v_delivery_url is null or v_summary is null');
    expect(migration).toContain('or length(v_delivery_url) > 600');
    expect(migration).not.toMatch(/\{(?:25[6-9]|2[6-9]\d|[3-9]\d{2,}|\d{4,})(?:,|\})/);
    expect(migration).toContain('v_reason is null or length(v_reason) not between 1 and 2000');
  });

  it('fences generic proposal inserts to open jobs and emits durable notifications', () => {
    expect(migration).toContain('create function public.works_submission_workflow_guard');
    expect(migration).toContain('before insert on public.works_records');
    expect(migration).toContain('create function public.works_submission_notify');
    expect(migration).toContain('after insert on public.works_records');
    expect(migration).toContain("'proposal_received'");
  });

  it('prevents concurrent awards and preserves buyer acceptance as immutable history', () => {
    expect(migration).toContain('works_assignments_one_active_job_idx');
    expect(migration).toContain("'completed'");
    expect(migration).toContain("'completion_accepted'");
    expect(migration).toContain('works_assignment_events_immutable');
    expect(migration).toContain('before update or delete on public.works_assignment_events');
  });

  it('never couples assignment selection to Gate or payment authority', () => {
    expect(migration).not.toMatch(/gate_allowance|authorization_receipt|stripe|checkout|payout|escrow/);
  });
});
