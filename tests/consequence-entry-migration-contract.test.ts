// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const panic = readFileSync(resolve('supabase/migrations/20260803230000_tenant_panic_control.sql'), 'utf8');
const velocity = readFileSync(resolve('supabase/migrations/20260803231000_signoff_ceremony_velocity.sql'), 'utf8');

describe('consequence-entry migration contracts', () => {
  it('linearizes panic and consumption on the same tenant row', () => {
    const panicFunction = panic.slice(
      panic.indexOf('CREATE OR REPLACE FUNCTION public.guard_panic_tenant'),
      panic.indexOf('CREATE OR REPLACE FUNCTION public.guard_receipt_tenant_panic'),
    );
    const consumeFunction = panic.slice(
      panic.indexOf('CREATE OR REPLACE FUNCTION public.guard_receipt_tenant_panic'),
    );
    expect(panicFunction).toMatch(/FROM public\.tenants[\s\S]*WHERE tenant_id = p_tenant_id[\s\S]*FOR UPDATE;/);
    expect(consumeFunction).toMatch(/FROM public\.tenants[\s\S]*WHERE tenant_id = v_org::uuid[\s\S]*FOR UPDATE;/);
    expect(panicFunction).toContain("SET status = 'suspended'");
    expect(panicFunction).toMatch(/UPDATE public\.tenant_api_keys[\s\S]*revoked_at = COALESCE\(revoked_at, v_at\)/);
    expect(consumeFunction).toContain("RAISE EXCEPTION 'tenant_panic_invalidated_receipt'");
    expect(panic).toMatch(/CREATE TRIGGER guard_receipt_tenant_panic_trigger[\s\S]*BEFORE INSERT ON public\.audit_events/);
  });

  it('keeps control epochs immutable and non-public', () => {
    expect(panic).toMatch(/CREATE TRIGGER tenant_control_events_immutable_trigger[\s\S]*BEFORE UPDATE OR DELETE/);
    expect(panic).toContain('REVOKE ALL ON public.tenant_control_events FROM PUBLIC, anon, authenticated');
    expect(panic).toMatch(/REVOKE ALL ON FUNCTION public\.guard_panic_tenant\(UUID, TEXT, TEXT\)[\s\S]*FROM PUBLIC, anon, authenticated/);
  });

  it('atomically caps Class-A approval velocity and exposes no public mutation', () => {
    expect(velocity).toMatch(/PRIMARY KEY \(organization_id, approver_id, window_started_at\)/);
    expect(velocity).toMatch(/ON CONFLICT \(organization_id, approver_id, window_started_at\)[\s\S]*approval_count = public\.signoff_approval_velocity\.approval_count \+ 1[\s\S]*WHERE public\.signoff_approval_velocity\.approval_count < p_max_approvals/);
    expect(velocity).toContain('p_window_seconds <> 3600');
    expect(velocity).toContain('REVOKE ALL ON public.signoff_approval_velocity FROM PUBLIC, anon, authenticated');
    expect(velocity).toMatch(/REVOKE ALL ON FUNCTION public\.consume_signoff_approval_velocity\(TEXT, TEXT, INTEGER, INTEGER\)[\s\S]*FROM PUBLIC, anon, authenticated/);
  });
});
