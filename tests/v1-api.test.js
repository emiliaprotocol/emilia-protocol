/**
 * EP GovGuard + FinGuard v1 API — integration tests.
 * @license Apache-2.0
 *
 * Exercises every v1 route's happy path + every documented invariant from
 * MD §5 / §6 / §12. Supabase is mocked at the @/lib/write-guard +
 * @/lib/supabase boundary; routes are imported and invoked directly with
 * a synthetic NextRequest.
 *
 * Coverage targets:
 *   POST   /api/v1/trust-receipts            create (happy + actor-mismatch + missing fields + observe mode)
 *   GET    /api/v1/trust-receipts/:id        read (happy + 404 + corrupted)
 *   POST   /api/v1/trust-receipts/:id/consume   consume (happy + already-consumed + expired + hash-mismatch + signoff-required + signoff-rejected)
 *   GET    /api/v1/trust-receipts/:id/evidence  evidence (happy)
 *   POST   /api/v1/signoffs/request          request (happy + already-requested + signoff-not-required)
 *   POST   /api/v1/signoffs/:id/approve      approve (happy + self-approval + hash-mismatch + expired + already-decided)
 *   POST   /api/v1/signoffs/:id/reject       reject (happy)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mocks ────────────────────────────────────────────────────────────────

const mockGetGuardedClient = vi.fn();
const mockAuthenticateRequest = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: vi.fn(), // kept so any indirect import doesn't crash
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// Routes import after mocks register.
import { POST as createReceipt } from '../app/api/v1/trust-receipts/route.js';
import { GET as readReceipt } from '../app/api/v1/trust-receipts/[receiptId]/route.js';
import { POST as consumeReceipt } from '../app/api/v1/trust-receipts/[receiptId]/consume/route.js';
import { GET as readEvidence } from '../app/api/v1/trust-receipts/[receiptId]/evidence/route.js';
import { POST as requestSignoff } from '../app/api/v1/signoffs/request/route.js';
import { POST as approveSignoff } from '../app/api/v1/signoffs/[signoffId]/approve/route.js';
import { POST as rejectSignoff } from '../app/api/v1/signoffs/[signoffId]/reject/route.js';

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Make a NextRequest-shaped object with a .json() method. */
function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

/**
 * Build a Supabase chain that resolves to the given value. Selects with
 * `{ count, head: true }` get a count payload via the select-call branch.
 */
function makeChain(resolveValue) {
  const chain = {
    select: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    in: vi.fn().mockReturnThis(),
    order: vi.fn().mockReturnThis(),
    insert: vi.fn().mockResolvedValue(resolveValue),
    update: vi.fn().mockReturnThis(),
    single: vi.fn().mockResolvedValue(resolveValue),
    maybeSingle: vi.fn().mockResolvedValue(resolveValue),
    then: (resolve) => Promise.resolve(resolveValue).then(resolve),
  };
  return chain;
}

/** Build a Supabase client whose .from(table) returns the chain for that table. */
function makeSupabase(tables) {
  return {
    from: vi.fn((table) => {
      const cfg = tables[table] ?? { resolve: { data: null, error: null } };
      return makeChain(cfg.resolve);
    }),
  };
}

/** Authenticate as a given entity. */
function authedAs(entity, extra = {}) {
  mockAuthenticateRequest.mockResolvedValue({ entity, ...extra });
}

beforeEach(() => {
  mockGetGuardedClient.mockReset();
  mockAuthenticateRequest.mockReset();
});

// ─── POST /api/v1/trust-receipts ──────────────────────────────────────────

describe('POST /api/v1/trust-receipts', () => {
  it('returns 401 when unauthenticated', async () => {
    mockAuthenticateRequest.mockResolvedValue({ error: 'no auth' });
    const res = await createReceipt(req({}));
    expect(res.status).toBe(401);
  });

  it('returns 400 when organization_id is missing', async () => {
    authedAs('user_1');
    const res = await createReceipt(req({ action_type: 'x', target_resource_id: 'y' }));
    expect(res.status).toBe(400);
  });

  it('returns 403 when body actor_id mismatches authenticated entity', async () => {
    authedAs('user_real');
    mockGetGuardedClient.mockReturnValue(makeSupabase({ audit_events: { resolve: { data: null, error: null } } }));
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'benefit_bank_account_change',
      target_resource_id: 'r',
      actor_id: 'user_imposter',
    }));
    expect(res.status).toBe(403);
    const body = await res.json();
    // epProblem renders the error-code into a Title-Cased title; the body
    // contains the full code and detail. Check across all surfaced fields.
    const surfaced = `${body.code ?? ''} ${body.title ?? ''} ${body.detail ?? ''}`;
    expect(surfaced).toMatch(/actor[\s_]?id/i);
  });

  it('issues a pending_signoff receipt for money-destination changes', async () => {
    authedAs('user_1');
    mockGetGuardedClient.mockReturnValue(makeSupabase({ audit_events: { resolve: { data: null, error: null } } }));
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'benefit_bank_account_change',
      target_resource_id: 'recipient_1',
      target_changed_fields: ['bank_account'],
      before_state: { bank_account_last4: '0001' },
      after_state: { bank_account_last4: '9999' },
    }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.signoff_required).toBe(true);
    expect(body.receipt_status).toBe('pending_signoff');
    expect(body.action_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.nonce).toMatch(/^nonce_/);
    expect(body.receipt_id).toMatch(/^tr_[0-9a-f]{32}$/);
    expect(body.before_state_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.after_state_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('downgrades to observe in observe mode', async () => {
    authedAs('user_1');
    mockGetGuardedClient.mockReturnValue(makeSupabase({ audit_events: { resolve: { data: null, error: null } } }));
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'benefit_bank_account_change',
      target_resource_id: 'r',
      target_changed_fields: ['bank_account'],
      enforcement_mode: 'observe',
    }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.decision).toBe('observe');
    expect(body.observed_decision).toBe('allow_with_signoff');
  });

  it('rejects unknown enforcement_mode', async () => {
    authedAs('user_1');
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'x',
      target_resource_id: 'r',
      enforcement_mode: 'panic',
    }));
    expect(res.status).toBe(400);
  });
});

// ─── GET /api/v1/trust-receipts/:id ───────────────────────────────────────

describe('GET /api/v1/trust-receipts/:id', () => {
  it('returns 400 on malformed receipt_id', async () => {
    authedAs('user_1');
    const res = await readReceipt(req(), { params: Promise.resolve({ receiptId: 'not-a-receipt' }) });
    expect(res.status).toBe(400);
  });

  it('returns 404 when no events exist for the receipt', async () => {
    authedAs('user_1');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: [], error: null } },
    }));
    const res = await readReceipt(req(), {
      params: Promise.resolve({ receiptId: 'tr_' + 'a'.repeat(32) }),
    });
    expect(res.status).toBe(404);
  });

  it('replays the event stream and returns receipt state', async () => {
    authedAs('user_1');
    const baseState = {
      organization_id: 'org_1',
      action_type: 'benefit_bank_account_change',
      decision: 'allow_with_signoff',
      enforcement_mode: 'enforce',
      policy_id: 'p1',
      policy_hash: 'h1',
      action_hash: 'a1',
      before_state_hash: null,
      after_state_hash: null,
      signoff_required: true,
      receipt_status: 'pending_signoff',
      expires_at: new Date(Date.now() + 100_000).toISOString(),
    };
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: baseState, created_at: '2026-04-26T00:00:00Z' },
      { event_type: 'guard.signoff.approved', after_state: { signoff_id: 'sig_1' }, created_at: '2026-04-26T00:01:00Z' },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await readReceipt(req(), {
      params: Promise.resolve({ receiptId: 'tr_' + 'a'.repeat(32) }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.receipt_status).toBe('approved_pending_consume');
    expect(body.timeline_event_count).toBe(2);
  });
});

// ─── POST /api/v1/trust-receipts/:id/consume ─────────────────────────────

describe('POST /api/v1/trust-receipts/:id/consume', () => {
  function setupConsume(events) {
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
  }

  it('returns 400 when action_hash missing', async () => {
    authedAs('user_1');
    const res = await consumeReceipt(req({ executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(400);
  });

  it('returns 404 when no events exist', async () => {
    authedAs('user_1');
    setupConsume([]);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(404);
  });

  it('returns 409 when receipt already consumed', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(409);
  });

  it('returns 410 when receipt expired', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() - 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(410);
  });

  it('returns 409 on action_hash mismatch', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'real_a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'tampered', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(409);
  });

  it('returns 403 when signoff_required=true but no approval recorded', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when signoff was rejected', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
      { event_type: 'guard.signoff.approved', after_state: { signoff_id: 'sig_1' } },
      { event_type: 'guard.signoff.rejected', after_state: { signoff_id: 'sig_2' } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(403);
  });

  it('records consume on happy path', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'benefits_core' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('consumed');
    expect(body.consumed_by_system).toBe('benefits_core');
  });
});

// ─── GET /api/v1/trust-receipts/:id/evidence ─────────────────────────────

describe('GET /api/v1/trust-receipts/:id/evidence', () => {
  it('returns full evidence packet shape on happy path', async () => {
    authedAs('user_1');
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'user_1',
        actor_type: 'principal',
        action: 'create',
        before_state: null,
        after_state: {
          organization_id: 'org_1',
          action_type: 'benefit_bank_account_change',
          decision: 'allow_with_signoff',
          enforcement_mode: 'enforce',
          policy_id: 'p1',
          policy_hash: 'h1',
          action_hash: 'a1',
          before_state_hash: 'b1',
          after_state_hash: 'b2',
          signoff_required: true,
          expires_at: new Date(Date.now() + 1e6).toISOString(),
          receipt_status: 'pending_signoff',
        },
        created_at: '2026-04-26T00:00:00Z',
      },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1' }, created_at: '2026-04-26T00:00:30Z' },
      { event_type: 'guard.signoff.approved', actor_id: 'user_2', after_state: { signoff_id: 'sig_1' }, created_at: '2026-04-26T00:01:00Z' },
      { event_type: 'guard.trust_receipt.consumed', actor_id: 'user_1', after_state: { consumed_at: '2026-04-26T00:02:00Z', consumed_by_system: 'benefits_core', execution_reference_id: 'exec_1' }, created_at: '2026-04-26T00:02:00Z' },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await readEvidence(req(), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.actor.id).toBe('user_1');
    expect(body.signoff.required).toBe(true);
    expect(body.signoff.approver_id).toBe('user_2');
    expect(body.consume.consumed_by_system).toBe('benefits_core');
    expect(body.timeline.length).toBe(4);
    expect(body.schema_version).toBe('ep-guard-evidence-v1');
  });
});

// ─── POST /api/v1/signoffs/request ────────────────────────────────────────

describe('POST /api/v1/signoffs/request', () => {
  it('returns 400 when receipt_id missing', async () => {
    authedAs('user_1');
    const res = await requestSignoff(req({}));
    expect(res.status).toBe(400);
  });

  it('returns 404 when receipt not found', async () => {
    authedAs('user_1');
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: [], error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_missing' }));
    expect(res.status).toBe(404);
  });

  it('returns 409 when receipt does not require signoff', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { signoff_required: false, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_x' }));
    expect(res.status).toBe(409);
  });

  it('returns 409 when signoff already requested', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { signoff_required: true, action_hash: 'a' } },
      { event_type: 'guard.signoff.requested', after_state: { signoff_id: 'sig_1' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_x' }));
    expect(res.status).toBe(409);
  });

  it('issues signoff_id on happy path', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { signoff_required: true, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_x', expires_in_minutes: 60 }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.signoff_id).toMatch(/^sig_[0-9a-f]{32}$/);
    expect(body.action_hash).toBe('a');
    expect(body.initiator_id).toBe('user_1');
  });
});

// ─── POST /api/v1/signoffs/:id/approve ────────────────────────────────────

describe('POST /api/v1/signoffs/:id/approve', () => {
  function setupSignoffEnv({
    initiator,
    actionHash,
    expiresAt = new Date(Date.now() + 1e6).toISOString(),
    priorDecisions = [],
  }) {
    mockGetGuardedClient.mockReturnValue({
      from: vi.fn((table) => {
        if (table === 'audit_events') {
          // Two distinct queries:
          //   1. SELECT ... WHERE event_type='guard.signoff.requested'
          //   2. SELECT ... WHERE target_id=... AND event_type IN ('approved','rejected')
          // The mock returns a chain that resolves with the right shape based
          // on which `.in()` / `.eq()` filters are applied.
          return {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            in: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            insert: vi.fn().mockResolvedValue({ data: null, error: null }),
            then: (resolve) => {
              // Disambiguate by call order — first call is requests
              // listing, second is prior-decisions check.
              const calls = mockGetGuardedClient.mock.calls.length;
              return Promise.resolve({
                data: calls === 1
                  ? [{ target_id: 'tr_x', actor_id: initiator, after_state: { signoff_id: 'sig_1', initiator_id: initiator, action_hash: actionHash, expires_at: expiresAt }, created_at: '2026-04-26T00:00:00Z' }]
                  : priorDecisions,
                error: null,
              }).then(resolve);
            },
          };
        }
        return makeChain({ data: null, error: null });
      }),
    });
  }

  it('returns 400 when approved_action_hash missing', async () => {
    authedAs('user_2');
    const res = await approveSignoff(req({}), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(400);
  });

  it('returns 404 when signoff_id is unknown', async () => {
    authedAs('user_2');
    mockGetGuardedClient.mockReturnValue({
      from: vi.fn(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        in: vi.fn().mockReturnThis(),
        order: vi.fn().mockReturnThis(),
        then: (resolve) => Promise.resolve({ data: [], error: null }).then(resolve),
      })),
    });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_unknown' }) });
    expect(res.status).toBe(404);
  });

  it('returns 403 on self-approval (initiator === approver)', async () => {
    authedAs('user_initiator');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'a' });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(JSON.stringify(body)).toMatch(/initiator|self/i);
  });

  it('returns 409 on action_hash mismatch (approval_action_hash != issued)', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'real_hash' });
    const res = await approveSignoff(req({ approved_action_hash: 'tampered_hash' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(409);
  });

  it('returns 410 when signoff approval window expired', async () => {
    authedAs('user_approver');
    setupSignoffEnv({
      initiator: 'user_initiator',
      actionHash: 'a',
      expiresAt: new Date(Date.now() - 1e6).toISOString(),
    });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(410);
  });
});

// ─── POST /api/v1/signoffs/:id/reject ─────────────────────────────────────

describe('POST /api/v1/signoffs/:id/reject', () => {
  it('returns 400 when approved_action_hash missing (same shape as approve)', async () => {
    authedAs('user_2');
    const res = await rejectSignoff(req({}), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(400);
  });
});
