// SPDX-License-Identifier: Apache-2.0
//
// Org-pinned quorum template binding — a receipt's multi-party quorum may EXCEED
// the organization's pinned policy for an action_type but never fall below it.
//
// THE GAP THIS PINS. packages/verify/quorum.js proves a quorum is internally
// consistent against WHATEVER policy it is handed, and that policy was, until
// this control, chosen by the receipt CREATOR. So a creator could declare
// `required: 1` (or a hand-picked roster) where the org rule is 2-of-3.
// lib/guard-quorum-template.js sources the EXPECTED quorum out-of-band from an
// org template (migration 124) and enforces meet-or-exceed at both create and
// consume. Separation-of-duties and key enrollment were never the weak point —
// this closes the policy-authenticity / assurance-downgrade gap.
//
// Regression for the three cases called out in the 2026-07-01 review:
//   1. creation rejects required:1 when the org template says 2
//   2. consume refuses a stored quorum_policy weaker than the org template
//   3. an out-of-roster approver is rejected against the org template

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mocks (mirror tests/v1-api.test.js boundaries) ─────────────────────────

const mockGetGuardedClient = vi.fn();
const mockAuthenticateRequest = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  authEntityId: (auth) => {
    const e = auth?.entity;
    if (typeof e === 'string') return e;
    return e?.entity_id || e?.id || '';
  },
  getServiceClient: vi.fn(),
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  evaluateQuorumAgainstTemplate,
  normalizeQuorumTemplate,
  effectiveQuorumParams,
} from '../lib/guard-quorum-template.js';
import { POST as createReceipt } from '../app/api/v1/trust-receipts/route.js';
import { POST as consumeReceipt } from '../app/api/v1/trust-receipts/[receiptId]/consume/route.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Extract the stable machine code from an epProblem (RFC 7807 `type` URL). */
function codeOf(problem) {
  return String(problem?.type || '').split('/').pop();
}

function req(body) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

/** A thenable Supabase query-builder chain resolving to `resolveValue`. */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

function makeSupabase(tables) {
  return {
    from: vi.fn((table) => {
      const cfg = tables[table] ?? { resolve: { data: null, error: null } };
      return makeChain(cfg.resolve);
    }),
  };
}

function authedAs(entity) {
  const normalized = typeof entity === 'string'
    ? { entity_id: entity, organization_id: 'org_1' }
    : entity;
  mockAuthenticateRequest.mockResolvedValue({ entity: normalized });
}

/** An org template row as it would come back from org_quorum_policies. */
function templateRow(overrides = {}) {
  return {
    organization_id: 'org_1',
    action_type: 'caseworker_override',
    min_required: 2,
    max_window_sec: 900,
    require_distinct_humans: true,
    quorum_required: false,
    allowed_approvers: [
      { role: 'supervisor', approver: 'ep:human:sup_a' },
      { role: 'supervisor', approver: 'ep:human:sup_b' },
      { role: 'director', approver: 'ep:human:dir_c' },
    ],
    allowed_modes: null,
    ...overrides,
  };
}

/** A well-formed 2-of-3 threshold policy drawn from the roster above. */
function strongPolicy(overrides = {}) {
  return {
    mode: 'threshold',
    required: 2,
    window_sec: 900,
    distinct_humans: true,
    approvers: [
      { role: 'supervisor', approver: 'ep:human:sup_a' },
      { role: 'supervisor', approver: 'ep:human:sup_b' },
      { role: 'director', approver: 'ep:human:dir_c' },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.EP_QUORUM_TEMPLATE_REQUIRED;
});

// ─── Pure comparator ─────────────────────────────────────────────────────────

describe('evaluateQuorumAgainstTemplate (pure)', () => {
  const tpl = normalizeQuorumTemplate(templateRow());

  it('accepts a policy that meets the template exactly', () => {
    expect(evaluateQuorumAgainstTemplate(strongPolicy(), tpl).ok).toBe(true);
  });

  it('accepts a STRONGER policy (higher threshold, tighter window)', () => {
    const r = evaluateQuorumAgainstTemplate(strongPolicy({ required: 3, window_sec: 300 }), tpl);
    expect(r.ok).toBe(true);
  });

  it('rejects a threshold below the org minimum', () => {
    const r = evaluateQuorumAgainstTemplate(strongPolicy({ required: 1 }), tpl);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('threshold_below_min');
  });

  it('rejects a window wider than the org ceiling', () => {
    const r = evaluateQuorumAgainstTemplate(strongPolicy({ window_sec: 86400 }), tpl);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('window_exceeds_max');
  });

  it('rejects distinct_humans disabled below the org floor', () => {
    const r = evaluateQuorumAgainstTemplate(strongPolicy({ distinct_humans: false }), tpl);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('distinct_humans_disabled');
  });

  it('rejects an out-of-roster approver', () => {
    const r = evaluateQuorumAgainstTemplate(
      strongPolicy({
        approvers: [
          { role: 'supervisor', approver: 'ep:human:sup_a' },
          { role: 'attacker', approver: 'ep:human:mallory' },
        ],
      }),
      tpl,
    );
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('approver_out_of_roster');
  });

  it('rejects a mode the template does not allow', () => {
    const orderedOnly = normalizeQuorumTemplate(templateRow({ allowed_modes: ['ordered'] }));
    const r = evaluateQuorumAgainstTemplate(strongPolicy({ mode: 'threshold' }), orderedOnly);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('mode_not_allowed');
  });

  it('treats a null template as no floor (nothing to enforce)', () => {
    expect(evaluateQuorumAgainstTemplate(strongPolicy({ required: 1 }), null).ok).toBe(true);
  });

  it('fails closed on a malformed policy when a template exists', () => {
    const r = evaluateQuorumAgainstTemplate(null, tpl);
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('invalid_quorum_policy');
  });

  it('ordered mode effective threshold is the roster size', () => {
    const { required } = effectiveQuorumParams({ mode: 'ordered', approvers: [{}, {}] });
    expect(required).toBe(2);
    // A 1-slot ordered policy cannot satisfy a min_required:2 template.
    const r = evaluateQuorumAgainstTemplate(
      { mode: 'ordered', approvers: [{ role: 'supervisor', approver: 'ep:human:sup_a' }] },
      tpl,
    );
    expect(r.ok).toBe(false);
    expect(r.violations).toContain('threshold_below_min');
  });
});

// ─── Creation route ──────────────────────────────────────────────────────────

describe('POST /api/v1/trust-receipts — quorum template gate', () => {
  it('rejects a per-receipt quorum weaker than the org threshold (required:1 vs org 2)', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: [templateRow()], error: null } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      quorum_policy: strongPolicy({ required: 1 }),
    }));

    expect(res.status).toBe(422);
    const j = await res.json();
    expect(codeOf(j)).toBe('quorum_policy_below_template');
  });

  it('rejects an out-of-roster approver at creation', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: [templateRow()], error: null } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      quorum_policy: strongPolicy({
        approvers: [
          { role: 'supervisor', approver: 'ep:human:sup_a' },
          { role: 'ghost', approver: 'ep:human:not_enrolled' },
        ],
      }),
    }));

    expect(res.status).toBe(422);
    const j = await res.json();
    expect(codeOf(j)).toBe('quorum_policy_below_template');
  });

  it('accepts a quorum that meets the org template', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: [templateRow()], error: null } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      quorum_policy: strongPolicy(),
    }));

    expect(res.status).toBe(201);
  });

  it('requires a quorum when the template mandates one (quorum_required)', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: [templateRow({ quorum_required: true })], error: null } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      // no quorum_policy
    }));

    expect(res.status).toBe(422);
    expect(codeOf(await res.json())).toBe('quorum_required');
  });

  it('does NOT block a non-quorum receipt when the template table is missing (un-migrated env)', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: null, error: { code: '42P01', message: 'relation "org_quorum_policies" does not exist' } } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
    }));

    expect(res.status).toBe(201);
  });

  it('fails closed on a real store fault when a quorum is submitted', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: null, error: { code: '08006', message: 'connection failure' } } },
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      quorum_policy: strongPolicy(),
    }));

    expect(res.status).toBe(503);
    expect(codeOf(await res.json())).toBe('quorum_template_unavailable');
  });

  it('EP_QUORUM_TEMPLATE_REQUIRED rejects a quorum receipt with no configured template', async () => {
    process.env.EP_QUORUM_TEMPLATE_REQUIRED = 'true';
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      org_quorum_policies: { resolve: { data: [], error: null } }, // no row
      audit_events: { resolve: { data: null, error: null } },
    }));

    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'caseworker_override',
      target_resource_id: 'case_42',
      quorum_policy: strongPolicy(),
    }));

    expect(res.status).toBe(422);
    expect(codeOf(await res.json())).toBe('quorum_template_missing');
  });
});

// ─── Consume route (defense in depth) ────────────────────────────────────────

describe('POST /api/v1/trust-receipts/:id/consume — quorum template gate', () => {
  const RECEIPT_ID = 'tr_' + 'a'.repeat(32);
  const ACTION_HASH = 'b'.repeat(64);

  function consumeEvents(quorumPolicy) {
    const created = {
      event_type: 'guard.trust_receipt.created',
      created_at: '2026-07-01T00:00:00.000Z',
      after_state: {
        organization_id: 'org_1',
        action_type: 'caseworker_override',
        action_hash: ACTION_HASH,
        expires_at: '2999-01-01T00:00:00.000Z',
        signoff_required: true,
        quorum_policy: quorumPolicy,
      },
    };
    // creator is the authenticated entity so canReadReceipt passes.
    return [{ ...created, actor_id: 'ent_creator' }];
  }

  it('refuses consume when the stored quorum_policy is weaker than the org template', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: consumeEvents(strongPolicy({ required: 1 })), error: null } },
      org_quorum_policies: { resolve: { data: [templateRow()], error: null } },
    }));

    const res = await consumeReceipt(
      req({ action_hash: ACTION_HASH, executing_system: 'sys_x' }),
      { params: Promise.resolve({ receiptId: RECEIPT_ID }) },
    );

    expect(res.status).toBe(403);
    expect(codeOf(await res.json())).toBe('quorum_policy_below_template');
  });

  it('fails closed at consume on a real template store fault', async () => {
    authedAs('ent_creator');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: consumeEvents(strongPolicy()), error: null } },
      org_quorum_policies: { resolve: { data: null, error: { code: '08006', message: 'connection failure' } } },
    }));

    const res = await consumeReceipt(
      req({ action_hash: ACTION_HASH, executing_system: 'sys_x' }),
      { params: Promise.resolve({ receiptId: RECEIPT_ID }) },
    );

    expect(res.status).toBe(503);
    expect(codeOf(await res.json())).toBe('quorum_template_unavailable');
  });
});
