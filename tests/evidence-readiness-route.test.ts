// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: vi.fn(),
}));
vi.mock('@/lib/cloud/authorize', () => ({
  requirePermission: vi.fn(),
}));
vi.mock('@/lib/cloud/guard-receipts', () => ({
  loadTenantGuardReceipts: vi.fn(),
}));
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: vi.fn(() => ({ kind: 'guarded-client' })),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: vi.fn(), warn: vi.fn() },
}));

import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { loadTenantGuardReceipts } from '@/lib/cloud/guard-receipts';
import { GET } from '../app/api/cloud/evidence-readiness/runs/route.js';

const tenancyMigration = readFileSync(
  new URL('../supabase/migrations/20260722020000_evidence_readiness_event_tenancy.sql', import.meta.url),
  'utf8',
);

const auth = {
  tenantId: '00000000-0000-4000-8000-000000000001',
  environment: 'production',
  permissions: ['read'],
  keyId: 'key-1',
};

function request(query = '') {
  return new Request(`https://www.emiliaprotocol.ai/api/cloud/evidence-readiness/runs${query}`, {
    headers: { authorization: 'Bearer ept_live_test' },
  });
}

describe('GET /api/cloud/evidence-readiness/runs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(authenticateCloudRequest).mockResolvedValue(auth);
    vi.mocked(requirePermission).mockImplementation(() => undefined);
    vi.mocked(loadTenantGuardReceipts).mockResolvedValue({
      error: null,
      truncated: false,
      receipts: [],
    });
  });

  it('requires Cloud authentication', async () => {
    vi.mocked(authenticateCloudRequest).mockResolvedValue(null);
    const response = await GET(request());
    expect(response.status).toBe(401);
    expect(loadTenantGuardReceipts).not.toHaveBeenCalled();
  });

  it('fails closed when read permission is absent', async () => {
    const error = new Error('Missing permission: read');
    error.name = 'CloudAuthorizationError';
    vi.mocked(requirePermission).mockImplementation(() => { throw error; });
    const response = await GET(request());
    expect(response.status).toBe(403);
    expect(loadTenantGuardReceipts).not.toHaveBeenCalled();
  });

  it('passes the authenticated environment into the tenant-scoped evidence query', async () => {
    vi.mocked(authenticateCloudRequest).mockResolvedValue({ ...auth, environment: 'staging' });
    const response = await GET(request());
    expect(response.status).toBe(200);
    expect(loadTenantGuardReceipts).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: auth.tenantId,
      environment: 'staging',
    }));
  });

  it('fails closed when authentication returns an unsupported environment', async () => {
    vi.mocked(authenticateCloudRequest).mockResolvedValue({ ...auth, environment: 'unknown' });
    const response = await GET(request());
    expect(response.status).toBe(403);
    expect(loadTenantGuardReceipts).not.toHaveBeenCalled();
  });

  it.each(['?limit=0', '?limit=1e2', '?limit=12junk', '?limit=101', '?date_from=not-a-date'])
  ('rejects malformed query parameters: %s', async (query) => {
    const response = await GET(request(query));
    expect(response.status).toBe(400);
    expect(loadTenantGuardReceipts).not.toHaveBeenCalled();
  });

  it('rejects reversed and overlong date windows', async () => {
    const reversed = await GET(request('?date_from=2026-07-20T00:00:00Z&date_to=2026-07-19T00:00:00Z'));
    expect(reversed.status).toBe(400);
    const overlong = await GET(request('?date_from=2026-01-01T00:00:00Z&date_to=2026-07-01T00:00:00Z'));
    expect(overlong.status).toBe(400);
  });

  it('derives tenant scope from auth and returns only an allowlisted projection', async () => {
    vi.mocked(loadTenantGuardReceipts).mockResolvedValue({
      error: null,
      truncated: false,
      receipts: [{
        receipt_id: 'tr_0123456789abcdef0123456789abcdef',
        created_at: '2026-07-20T12:00:00Z',
        action_type: 'payment.release',
        action_hash: `sha256:${'a'.repeat(64)}`,
        caid: null,
        organization_id: auth.tenantId,
        decision: 'ALLOW_WITH_SIGNOFF',
        enforcement_mode: 'enforce',
        policy_id: 'policy-1',
        authority_verdict: 'admissible',
        status: 'issued',
        adapter: 'fin',
        amount: 100,
        currency: 'USD',
        signoff_required: true,
        detail: { secret: 'must-never-leave-storage' },
      }],
    });

    const response = await GET(request('?limit=25&date_from=2026-07-01T00:00:00Z&date_to=2026-07-21T00:00:00Z'));
    expect(response.status).toBe(200);
    expect(loadTenantGuardReceipts).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: auth.tenantId,
      environment: 'production',
      limit: 25,
      dateFrom: '2026-07-01T00:00:00.000Z',
      dateTo: '2026-07-21T00:00:00.000Z',
    }));
    const body = await response.json();
    expect(body).toMatchObject({
      tenant_id: auth.tenantId,
      environment: 'production',
      returned: 1,
      source: 'audit_events.guard_trust_receipts',
    });
    expect(JSON.stringify(body)).not.toContain('must-never-leave-storage');
    expect(body.runs[0]).not.toHaveProperty('detail');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('returns no partial data when the bounded source fails', async () => {
    vi.mocked(loadTenantGuardReceipts).mockResolvedValue({
      receipts: [],
      error: 'relation unavailable',
      truncated: false,
    });
    const response = await GET(request());
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ detail: expect.stringContaining('no partial result') });
  });
});

describe('Evidence Readiness event-tenancy migration', () => {
  it('binds exact audit event ids to one constrained tenant/environment stream', () => {
    expect(tenancyMigration).toContain('CREATE TABLE IF NOT EXISTS public.guard_receipt_streams');
    expect(tenancyMigration).toContain('CREATE TABLE IF NOT EXISTS public.guard_receipt_event_bindings');
    expect(tenancyMigration).toContain('REFERENCES public.tenant_environments(tenant_id, name)');
    expect(tenancyMigration).toContain('REFERENCES public.audit_events(id) ON DELETE RESTRICT');
    expect(tenancyMigration).toContain('FOREIGN KEY (receipt_id, tenant_id, environment)');
    expect(tenancyMigration).toContain('AFTER INSERT ON public.audit_events');
  });

  it('locks writers, installs the trigger, and only then starts the backfill', () => {
    const lockOffset = tenancyMigration.indexOf(
      'LOCK TABLE public.audit_events IN SHARE ROW EXCLUSIVE MODE;',
    );
    const triggerOffset = tenancyMigration.indexOf(
      'CREATE TRIGGER bind_guard_receipt_event_scope',
    );
    const backfillOffset = tenancyMigration.indexOf('WITH eligible_created AS (');

    expect(lockOffset).toBeGreaterThan(-1);
    expect(triggerOffset).toBeGreaterThan(lockOffset);
    expect(backfillOffset).toBeGreaterThan(triggerOffset);
  });

  it('omits ambiguous legacy targets and rejects future receipt-id collisions', () => {
    expect(tenancyMigration).toContain('HAVING pg_catalog.count(*) = 1');
    expect(tenancyMigration).toContain("RAISE EXCEPTION 'guard_receipt_target_collision'");
    expect(tenancyMigration).toContain("request_binding.event_type = 'guard.signoff.requested'");
    expect(tenancyMigration).toContain("NEW.after_state ->> 'action_hash' IS DISTINCT FROM v_action_hash");
    expect(tenancyMigration).toMatch(
      /ELSIF NEW\.event_type = 'guard\.trust_receipt\.consumed'[\s\S]+NEW\.actor_id IS DISTINCT FROM v_created_actor/,
    );
  });

  it('keeps binding state append-only and service-role read-only', () => {
    expect(tenancyMigration).toContain('GUARD_RECEIPT_BINDING_IMMUTABILITY_VIOLATION');
    expect(tenancyMigration).toContain('FORCE ROW LEVEL SECURITY');
    expect(tenancyMigration).toContain(
      'GRANT SELECT ON TABLE public.guard_receipt_event_bindings TO service_role;',
    );
    expect(tenancyMigration).not.toMatch(
      /GRANT (?:INSERT|UPDATE|DELETE)[^;]+guard_receipt_event_bindings/i,
    );
  });
});
