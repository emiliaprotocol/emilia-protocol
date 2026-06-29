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
  // Real implementation, not a stub: routes derive the actor's string id
  // through this; string-mocked entities pass through unchanged.
  authEntityId: (auth) => {
    const e = auth?.entity;
    if (typeof e === 'string') return e;
    return e?.entity_id || e?.id || '';
  },
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
import { POST as attestExecution } from '../app/api/v1/trust-receipts/[receiptId]/execution/route.js';
import { POST as registerApproverOptions } from '../app/api/v1/approvers/webauthn/register-options/route.js';
import { POST as registerApproverVerify } from '../app/api/v1/approvers/webauthn/register-verify/route.js';
import { executedActionHash } from '../lib/execution/integrity.js';
import { buildExecutionBindingContract } from '../lib/execution/binding-contract.js';

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Make a real Request so body-limit defenses are exercised in route tests. */
function req(body) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

function oversizedReq(bytes) {
  const body = JSON.stringify({ blob: 'x'.repeat(bytes) });
  return new Request('https://www.emiliaprotocol.ai/api/v1/test', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
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
    limit: vi.fn().mockReturnThis(),
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
  const normalized = typeof entity === 'string'
    ? { entity_id: entity, organization_id: 'org_1' }
    : entity;
  mockAuthenticateRequest.mockResolvedValue({ entity: normalized, ...extra });
}

const VALID_RECEIPT_ID = 'tr_' + 'c'.repeat(32);

beforeEach(() => {
  mockGetGuardedClient.mockReset();
  mockAuthenticateRequest.mockReset();
});

describe('v1 guard rail body limits', () => {
  it('rejects oversized trust-receipt create bodies before DB work', async () => {
    authedAs('user_1');
    const res = await createReceipt(oversizedReq(257 * 1024));
    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects oversized consume bodies before DB work', async () => {
    authedAs('user_1');
    const res = await consumeReceipt(oversizedReq(33 * 1024), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects oversized signoff-request bodies before DB work', async () => {
    authedAs('user_1');
    const res = await requestSignoff(oversizedReq(65 * 1024));
    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects oversized bearer signoff decision bodies before DB work', async () => {
    authedAs('user_1');
    const approve = await approveSignoff(oversizedReq(33 * 1024), {
      params: Promise.resolve({ signoffId: 'sig_1' }),
    });
    const reject = await rejectSignoff(oversizedReq(33 * 1024), {
      params: Promise.resolve({ signoffId: 'sig_1' }),
    });

    expect(approve.status).toBe(413);
    expect(reject.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects oversized execution-attestation bodies before DB work', async () => {
    authedAs('user_1');
    const res = await attestExecution(oversizedReq(257 * 1024), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('rejects oversized Class-A enrollment bodies before DB work', async () => {
    authedAs('user_1');
    const options = await registerApproverOptions(oversizedReq(33 * 1024));
    const verify = await registerApproverVerify(oversizedReq(257 * 1024));

    expect(options.status).toBe(413);
    expect(verify.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });
});

// ─── POST /api/v1/trust-receipts ──────────────────────────────────────────

describe('POST /api/v1/trust-receipts', () => {
  it('returns 401 when unauthenticated', async () => {
    mockAuthenticateRequest.mockResolvedValue({ error: 'no auth' });
    const res = await createReceipt(req({}));
    expect(res.status).toBe(401);
  });

  it('returns 400 when a required action field is missing', async () => {
    authedAs('user_1');
    const res = await createReceipt(req({ target_resource_id: 'y' }));
    expect(res.status).toBe(400);
  });

  it('returns 403 when the authenticated entity is not org-bound', async () => {
    authedAs({ entity_id: 'user_1' });
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'benefit_bank_account_change',
      target_resource_id: 'recipient_1',
    }));
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(`${body.code ?? ''} ${body.type ?? ''}`).toMatch(/entity_not_org_bound/);
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
    expect(body.canonical_action.target_changed_fields).toEqual(['bank_account']);
    expect(body.execution_binding.required).toBe(true);
    expect(body.execution_binding.required_fields).toContain('target_changed_fields');
    expect(body.execution_binding.required_fields).toContain('after_state_hash');
  });

  it('binds payment material into the canonical action and execution contract', async () => {
    authedAs('user_1');
    mockGetGuardedClient.mockReturnValue(makeSupabase({ audit_events: { resolve: { data: null, error: null } } }));
    const res = await createReceipt(req({
      organization_id: 'org_1',
      action_type: 'large_payment_release',
      target_resource_id: 'payment_1',
      amount: 82000,
      currency: 'USD',
      counterparty_name: 'Acme Widgets',
    }));

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.canonical_action.amount).toBe(82000);
    expect(body.canonical_action.currency).toBe('USD');
    expect(body.execution_binding.required).toBe(true);
    expect(body.execution_binding.field_values).toMatchObject({
      amount: 82000,
      currency: 'USD',
      counterparty_name: 'Acme Widgets',
      target_resource_id: 'payment_1',
    });
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
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: baseState, created_at: '2026-04-26T00:00:00Z' },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1', approver_id: 'user_2' }, created_at: '2026-04-26T00:00:30Z' },
      { event_type: 'guard.signoff.approved', actor_id: 'user_2', after_state: { signoff_id: 'sig_1', approver_id: 'user_2' }, created_at: '2026-04-26T00:01:00Z' },
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
    expect(body.timeline_event_count).toBe(3);
  });
});

// ─── POST /api/v1/trust-receipts/:id/consume ─────────────────────────────

describe('POST /api/v1/trust-receipts/:id/consume', () => {
  function setupConsume(events, authorityRows = []) {
    const scopedEvents = events.map((e) => {
      if (e.event_type !== 'guard.trust_receipt.created') return e;
      return {
        actor_id: 'user_1',
        ...e,
        after_state: {
          organization_id: 'org_1',
          ...(e.after_state || {}),
        },
      };
    });
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: scopedEvents, error: null } },
      authorities: { resolve: { data: authorityRows, error: null } },
    }));
  }

  it('returns 400 when action_hash missing', async () => {
    authedAs('user_1');
    const res = await consumeReceipt(req({ executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(400);
  });

  it('returns 400 when receipt_id is malformed', async () => {
    authedAs('user_1');
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    expect(res.status).toBe(400);
    expect((await res.json()).type).toContain('invalid_receipt_id');
  });

  it('returns 404 when no events exist', async () => {
    authedAs('user_1');
    setupConsume([]);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(404);
  });

  it('returns 409 when receipt already consumed', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(409);
  });

  it('returns 410 when receipt expired', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() - 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(410);
  });

  it('returns 409 on action_hash mismatch', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'real_a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'tampered', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(409);
  });

  it('returns 404 when an unbound non-creator tries to consume another org receipt', async () => {
    authedAs({ entity_id: 'attacker_unbound' });
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'victim_creator',
        after_state: {
          organization_id: 'org_victim',
          action_hash: 'a',
          expires_at: new Date(Date.now() + 1e6).toISOString(),
          signoff_required: false,
        },
      },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(404);
  });

  it('returns 404 when an org-bound caller tries to consume another org receipt', async () => {
    authedAs({ entity_id: 'user_2', organization_id: 'org_2' });
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'victim_creator',
        after_state: {
          organization_id: 'org_1',
          action_hash: 'a',
          expires_at: new Date(Date.now() + 1e6).toISOString(),
          signoff_required: false,
        },
      },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(404);
  });

  it('returns 403 when signoff_required=true but no approval recorded', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when a loose approval is not tied to a creator-bound signoff request', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
      { event_type: 'guard.signoff.requested', actor_id: 'attacker', after_state: { signoff_id: 'sig_attacker', initiator_id: 'attacker', approver_id: 'attacker_approver', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString() } },
      { event_type: 'guard.signoff.approved', actor_id: 'attacker_approver', after_state: { signoff_id: 'sig_attacker', approver_id: 'attacker_approver' } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when approval approver does not match the requested approver', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1', initiator_id: 'user_1', approver_id: 'expected_approver', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString() } },
      { event_type: 'guard.signoff.approved', actor_id: 'wrong_approver', after_state: { signoff_id: 'sig_1', approver_id: 'wrong_approver' } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when signoff was rejected', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
      { event_type: 'guard.signoff.approved', after_state: { signoff_id: 'sig_1' } },
      { event_type: 'guard.signoff.rejected', after_state: { signoff_id: 'sig_2' } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when a Class-A receipt has only a Class-C approval', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { organization_id: 'org_1', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true, required_assurance: 'A' } },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1', initiator_id: 'user_1', approver_id: 'ap_controller', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), required_assurance: 'A' } },
      { event_type: 'guard.signoff.approved', actor_id: 'ap_controller', after_state: { signoff_id: 'sig_1', approver_id: 'ap_controller', key_class: 'C' } },
    ];
    setupConsume(events, [{ authority_id: 'auth_1', status: 'active', subject_ref: 'ap_controller', role: null, assurance_class: 'A' }]);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('insufficient_assurance');
  });

  it('returns 403 when an approved signoff has no active authority record', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { organization_id: 'org_1', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true } },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1', initiator_id: 'user_1', approver_id: 'ap_controller', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString() } },
      { event_type: 'guard.signoff.approved', actor_id: 'ap_controller', after_state: { signoff_id: 'sig_1', approver_id: 'ap_controller', key_class: 'C' } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('authority_invalid');
  });

  it('records consume when a Class-A approval has an active sufficient authority', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { organization_id: 'org_1', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: true, required_assurance: 'A' } },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1', initiator_id: 'user_1', approver_id: 'ap_controller', action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), required_assurance: 'A' } },
      { event_type: 'guard.signoff.approved', actor_id: 'ap_controller', after_state: { signoff_id: 'sig_1', approver_id: 'ap_controller', key_class: 'A' } },
    ];
    setupConsume(events, [{
      authority_id: 'auth_1',
      status: 'active',
      subject_ref: 'ap_controller',
      role: null,
      assurance_class: 'A',
      valid_from: '2020-01-01T00:00:00.000Z',
      valid_to: '2999-01-01T00:00:00.000Z',
      revoked_at: null,
    }]);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    expect(res.status).toBe(200);
  });

  it('does not treat an unbound quorum rejection as the receipt rejection', async () => {
    authedAs('user_1');
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'user_1',
        after_state: {
          action_hash: 'a',
          expires_at: new Date(Date.now() + 1e6).toISOString(),
          signoff_required: false,
          quorum_policy: {
            mode: 'threshold',
            required: 1,
            approvers: [{ role: 'controller', approver: 'real_approver' }],
          },
        },
      },
      {
        event_type: 'guard.signoff.requested',
        actor_id: 'attacker',
        after_state: {
          signoff_id: 'sig_attacker',
          initiator_id: 'attacker',
          quorum: { role: 'controller', approver_id: 'attacker_approver' },
          action_hash: 'a',
          expires_at: new Date(Date.now() + 1e6).toISOString(),
        },
      },
      {
        event_type: 'guard.signoff.rejected',
        actor_id: 'attacker_approver',
        after_state: { signoff_id: 'sig_attacker', approver_id: 'attacker_approver' },
      },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'sys' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
    const body = await res.json();
    expect(res.status).toBe(403);
    expect(body.type).toContain('quorum_not_satisfied');
  });

  it('records consume on happy path', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', after_state: { action_hash: 'a', expires_at: new Date(Date.now() + 1e6).toISOString(), signoff_required: false } },
    ];
    setupConsume(events);
    const res = await consumeReceipt(req({ action_hash: 'a', executing_system: 'benefits_core' }), { params: Promise.resolve({ receiptId: VALID_RECEIPT_ID }) });
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

  it('does NOT sign a receipt with no canonical_action (honest fallback, backward compat)', async () => {
    authedAs('user_1');
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'user_1',
        actor_type: 'principal',
        after_state: {
          organization_id: 'org_1',
          action_type: 'benefit_bank_account_change',
          decision: 'allow_with_signoff',
          signoff_required: true,
          // No canonical_action — an older receipt. Must not be signed.
          expires_at: new Date(Date.now() + 1e6).toISOString(),
          receipt_status: 'pending_signoff',
        },
        created_at: '2026-04-26T00:00:00Z',
      },
      { event_type: 'guard.signoff.approved', actor_id: 'user_2', after_state: { signoff_id: 'sig_1' }, created_at: '2026-04-26T00:01:00Z' },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await readEvidence(req(), { params: Promise.resolve({ receiptId: 'tr_x' }) });
    const body = await res.json();
    expect(body.signed).toBe(false);
    expect(body.document).toBeNull();
    expect(body.public_key).toBeNull();
    // Unsigned packet still fully present (backward compat).
    expect(body.schema_version).toBe('ep-guard-evidence-v1');
  });

  it('serves a signed EP-RECEIPT-v1 document that verifies offline under @emilia-protocol/verify', async () => {
    authedAs('user_1');
    const canonicalAction = {
      organization_id: 'org_treasury',
      actor_id: 'user_1',
      action_type: 'vendor_bank_account_change',
      target_resource_id: 'vendor:VEND-9821',
      before_state_hash: 'sha256:aaa',
      after_state_hash: 'sha256:bbb',
      policy_id: 'policy_default_vendor_bank_account_change',
      policy_hash: 'sha256:ccc',
      nonce: 'nonce_deadbeef',
      expires_at: new Date(Date.now() + 1e6).toISOString(),
      requested_at: '2026-04-26T00:00:00Z',
    };
    const events = [
      {
        event_type: 'guard.trust_receipt.created',
        actor_id: 'user_1',
        actor_type: 'principal',
        after_state: {
          organization_id: 'org_treasury',
          action_type: 'vendor_bank_account_change',
          decision: 'allow_with_signoff',
          enforcement_mode: 'enforce',
          policy_id: 'policy_default_vendor_bank_account_change',
          policy_hash: 'sha256:ccc',
          action_hash: 'sha256:ddd',
          before_state_hash: 'sha256:aaa',
          after_state_hash: 'sha256:bbb',
          signoff_required: true,
          expires_at: canonicalAction.expires_at,
          receipt_status: 'pending_signoff',
          canonical_action: canonicalAction,
        },
        created_at: '2026-04-26T00:00:00Z',
      },
      { event_type: 'guard.signoff.requested', actor_id: 'user_1', after_state: { signoff_id: 'sig_1' }, created_at: '2026-04-26T00:00:30Z' },
      { event_type: 'guard.signoff.approved', actor_id: 'ap_controller_jane', after_state: { signoff_id: 'sig_1', approver_id: 'ap_controller_jane', decided_at: '2026-04-26T00:01:00Z', key_class: 'C' }, created_at: '2026-04-26T00:01:00Z' },
      { event_type: 'guard.trust_receipt.consumed', actor_id: 'user_1', after_state: { consumed_at: '2026-04-26T00:02:00Z', consumed_by_system: 'vendor_master_data_svc', execution_reference_id: 'exec_9' }, created_at: '2026-04-26T00:02:00Z' },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await readEvidence(req(), { params: Promise.resolve({ receiptId: 'tr_signed' }) });
    expect(res.status).toBe(200);
    const body = await res.json();

    // The headline: a signed, offline-verifiable receipt is present.
    expect(body.signed).toBe(true);
    expect(body.document['@version']).toBe('EP-RECEIPT-v1');
    expect(typeof body.public_key).toBe('string');
    expect(body.document.payload.claim.canonical_action).toEqual(canonicalAction);
    expect(body.document.payload.authorization.approver_id).toBe('ap_controller_jane');
    expect(body.document.payload.authorization.status).toBe('consumed');

    // ROUND-TRIP: the offline verifier (the EXACT module grok_guard.py's
    // emilia_verify is a port of) accepts the document + public key.
    const { verifyReceipt } = await import('../packages/verify/index.js');
    const result = verifyReceipt(body.document, body.public_key);
    expect(result.valid).toBe(true);
    expect(result.checks.version).toBe(true);
    expect(result.checks.signature).toBe(true);

    // TAMPER: flip a deeply-nested field in the signed payload and the
    // signature MUST break — proving the whole canonical action is bound.
    const tampered = JSON.parse(JSON.stringify(body.document));
    tampered.payload.claim.canonical_action.after_state_hash = 'sha256:tampered';
    expect(verifyReceipt(tampered, body.public_key).valid).toBe(false);
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
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'b'.repeat(32) }));
    expect(res.status).toBe(404);
  });

  it('returns 409 when receipt does not require signoff', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { signoff_required: false, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'a'.repeat(32) }));
    expect(res.status).toBe(409);
  });

  it('returns 409 when signoff already requested', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { signoff_required: true, action_hash: 'a' } },
      { event_type: 'guard.signoff.requested', after_state: { signoff_id: 'sig_1' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'a'.repeat(32) }));
    expect(res.status).toBe(409);
  });

  it('returns 403 when a different actor requests signoff for someone else’s receipt', async () => {
    authedAs('attacker');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'victim_creator', after_state: { signoff_required: true, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'a'.repeat(32), approver_id: 'attacker_approver' }));
    expect(res.status).toBe(403);
  });

  it('returns 400 when single-signoff receipt omits intended approver_id', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { signoff_required: true, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'a'.repeat(32) }));
    expect(res.status).toBe(400);
  });

  it('issues signoff_id on happy path', async () => {
    authedAs('user_1');
    const events = [
      { event_type: 'guard.trust_receipt.created', actor_id: 'user_1', after_state: { signoff_required: true, action_hash: 'a' } },
    ];
    mockGetGuardedClient.mockReturnValue(makeSupabase({
      audit_events: { resolve: { data: events, error: null } },
    }));
    const res = await requestSignoff(req({ receipt_id: 'tr_' + 'a'.repeat(32), approver_id: 'user_approver', expires_in_minutes: 60 }));
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.signoff_id).toMatch(/^sig_[0-9a-f]{32}$/);
    expect(body.action_hash).toBe('a');
    expect(body.initiator_id).toBe('user_1');
    expect(body.approver_id).toBe('user_approver');
  });
});

// ─── POST /api/v1/signoffs/:id/approve ────────────────────────────────────

describe('POST /api/v1/signoffs/:id/approve', () => {
  function setupSignoffEnv({
    initiator,
    actionHash,
    approver = 'user_approver',
    expiresAt = new Date(Date.now() + 1e6).toISOString(),
    priorDecisions = [],
    insertError = null,
    requiredAssurance = null,
  }) {
    mockGetGuardedClient.mockReturnValue({
      from: vi.fn((table) => {
        if (table === 'audit_events') {
          // Two distinct queries per request, disambiguated by shape:
          //   1. requests listing — .eq(event_type='guard.signoff.requested').limit(1)
          //   2. prior-decisions check — .in('event_type', [approved, rejected])
          // A fresh chain per from() call tracks whether .in() was used, so
          // the resolver returns the right rows regardless of call order.
          const requestsRow = [{ target_id: 'tr_x', actor_id: initiator, after_state: { signoff_id: 'sig_1', initiator_id: initiator, approver_id: approver, action_hash: actionHash, expires_at: expiresAt, required_assurance: requiredAssurance }, created_at: '2026-04-26T00:00:00Z' }];
          let usedIn = false;
          const chain = {
            select: vi.fn().mockReturnThis(),
            eq: vi.fn().mockReturnThis(),
            order: vi.fn().mockReturnThis(),
            limit: vi.fn().mockReturnThis(),
            in: vi.fn(() => { usedIn = true; return chain; }),
            insert: vi.fn().mockResolvedValue({ data: null, error: insertError }),
            then: (resolve) => Promise.resolve({
              data: usedIn ? priorDecisions : requestsRow,
              error: null,
            }).then(resolve),
          };
          return chain;
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
        limit: vi.fn().mockReturnThis(),
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

  // Regression for commit 7c5cfcf: in production auth.entity is the full
  // entity ROW, not an id string. The old `auth.entity === initiatorId`
  // compared object-to-string — always false — so self-approval was never
  // blocked on the live path, even though the string-mocked test above
  // passed. This feeds the production object shape; it fails on the old code
  // and passes only because authEntityId() now derives the id.
  it('blocks self-approval when auth.entity is the entity ROW (production shape)', async () => {
    authedAs({ id: 'uuid-init', entity_id: 'user_initiator', api_key_hash: 'secret_hash', private_key_encrypted: 'secret_pk' });
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'a' });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(403);
    const body = await res.json();
    // And the secret-bearing row must never echo into the response.
    expect(JSON.stringify(body)).not.toMatch(/secret_hash|secret_pk/);
  });

  it('returns 409 on action_hash mismatch (approval_action_hash != issued)', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'real_hash' });
    const res = await approveSignoff(req({ approved_action_hash: 'tampered_hash' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(409);
  });

  it('returns 403 when authenticated approver is not the signoff-bound approver', async () => {
    authedAs('wrong_approver');
    setupSignoffEnv({ initiator: 'user_initiator', approver: 'user_approver', actionHash: 'a' });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(403);
  });

  it('returns 403 when bearer-key approval attempts a Class-A-required receipt', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', approver: 'user_approver', actionHash: 'a', requiredAssurance: 'A' });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('insufficient_assurance');
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

  // Happy path — a distinct approver, matching hash, valid window, no prior
  // decision: reaches the insert and records the decision. This is the bulk
  // of the handler that no prior test exercised (lines past the guards).
  it('records an approval (200) and labels the decision key_class C', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'a' });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.decision).toBe('approved');
    expect(body.approver_id).toBe('user_approver');
  });

  it('returns 409 when the signoff was already decided', async () => {
    authedAs('user_approver');
    setupSignoffEnv({
      initiator: 'user_initiator',
      actionHash: 'a',
      priorDecisions: [{ event_type: 'guard.signoff.approved', after_state: { signoff_id: 'sig_1' } }],
    });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(409);
  });

  it('returns 409 when a concurrent decision wins the unique index (23505)', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'a', insertError: { code: '23505' } });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(409);
  });

  it('returns 500 on a non-race insert error', async () => {
    authedAs('user_approver');
    setupSignoffEnv({ initiator: 'user_initiator', actionHash: 'a', insertError: { code: '42000', message: 'boom' } });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(500);
  });

  it('returns 401 when the request is unauthenticated', async () => {
    mockAuthenticateRequest.mockResolvedValue({ error: 'Missing API key', status: 401 });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(401);
  });

  it('returns 500 when the data client throws (catch path)', async () => {
    authedAs('user_approver');
    mockGetGuardedClient.mockImplementation(() => { throw new Error('client init boom'); });
    const res = await approveSignoff(req({ approved_action_hash: 'a' }), { params: Promise.resolve({ signoffId: 'sig_1' }) });
    expect(res.status).toBe(500);
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

// ─── POST /api/v1/trust-receipts/:id/execution (#6 enforcement adapter) ──────
describe('POST /api/v1/trust-receipts/:id/execution', () => {
  const EXECUTED = { action_type: 'payment.release', target: 'acct_9f12', amount: 50000 };
  const APPROVED_HASH = executedActionHash(EXECUTED); // 'match' when stored action_hash === this
  const HIGH_RISK_EXECUTED = {
    organization_id: 'org_1',
    actor_id: 'sys',
    action_type: 'large_payment_release',
    target_resource_id: 'payment_1',
    policy_id: 'policy_default_large_payment_release',
    policy_hash: 'sha256:policy',
    amount: 50000,
    currency: 'USD',
  };
  const HIGH_RISK_HASH = executedActionHash(HIGH_RISK_EXECUTED);
  const HIGH_RISK_BINDING = buildExecutionBindingContract({
    canonicalAction: HIGH_RISK_EXECUTED,
    decision: { signoffRequired: true, requiredAssurance: 'A' },
  });
  const RECEIPT_ID = 'tr_' + 'e'.repeat(32);
  const P = { params: Promise.resolve({ receiptId: RECEIPT_ID }) };

  function timeline(events) {
    mockGetGuardedClient.mockReturnValue(makeSupabase({ audit_events: { resolve: { data: events, error: null } } }));
  }

  function created(overrides = {}) {
    return {
      event_type: 'guard.trust_receipt.created',
      actor_id: overrides.actor_id || 'sys',
      after_state: { organization_id: 'org_1', action_hash: APPROVED_HASH, ...(overrides.after_state || {}) },
    };
  }

  it('returns 401 when unauthenticated', async () => {
    mockAuthenticateRequest.mockResolvedValue({ error: 'no auth' });
    expect((await attestExecution(req({}), P)).status).toBe(401);
  });

  it('returns 400 without executed_action', async () => {
    authedAs('sys');
    expect((await attestExecution(req({ executing_system: 's' }), P)).status).toBe(400);
  });

  it('returns 409 when the receipt was never consumed (blocked-until-consume half)', async () => {
    authedAs('sys');
    timeline([created()]);
    const res = await attestExecution(req({ executed_action: EXECUTED, executing_system: 's' }), P);
    expect(res.status).toBe(409);
    expect((await res.json()).detail).toMatch(/consumed/i);
  });

  it('attests a matching execution (binding_status: match)', async () => {
    authedAs('sys');
    timeline([
      created(),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ]);
    const res = await attestExecution(req({ executed_action: EXECUTED, executing_system: 's', execution_id: 'ex_1' }), P);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.binding_status).toBe('match');
    expect(body.executed_action_hash).toBe(body.approved_action_hash);
  });

  it('attests a high-risk execution only when observed fields match the contract', async () => {
    authedAs('sys');
    timeline([
      created({ after_state: { action_hash: HIGH_RISK_HASH, execution_binding: HIGH_RISK_BINDING } }),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ]);
    const res = await attestExecution(req({
      executed_action: HIGH_RISK_EXECUTED,
      observed_action: HIGH_RISK_EXECUTED,
      executing_system: 'payments_core',
      execution_id: 'ex_2',
    }), P);

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.binding_status).toBe('match');
    expect(body.execution_binding_check.ok).toBe(true);
    expect(body.execution_binding_check.required).toBe(true);
  });

  it('rejects high-risk execution when system-observed fields drift from the receipt', async () => {
    authedAs('sys');
    timeline([
      created({ after_state: { action_hash: HIGH_RISK_HASH, execution_binding: HIGH_RISK_BINDING } }),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ]);
    const res = await attestExecution(req({
      executed_action: HIGH_RISK_EXECUTED,
      observed_action: { ...HIGH_RISK_EXECUTED, amount: 75000 },
      executing_system: 'payments_core',
      execution_id: 'ex_drift',
    }), P);

    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.type).toContain('execution_binding_mismatch');
    expect(body.execution_binding_check.ok).toBe(false);
    expect(body.execution_binding_check.mismatched_fields).toContain('amount');
  });

  it('records EXECUTION DRIFT when the executed action differs from approved', async () => {
    authedAs('sys');
    timeline([
      created({ after_state: { action_hash: 'sha256:not-the-executed-action' } }),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ]);
    const res = await attestExecution(req({ executed_action: EXECUTED, executing_system: 's' }), P);
    expect(res.status).toBe(201);
    expect((await res.json()).binding_status).toBe('drift');
  });

  it('returns 409 when an execution attestation already exists', async () => {
    authedAs('sys');
    timeline([
      created(),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
      { event_type: 'guard.trust_receipt.executed', after_state: {} },
    ]);
    expect((await attestExecution(req({ executed_action: EXECUTED, executing_system: 's' }), P)).status).toBe(409);
  });

  it('refuses execution attestation from a different organization even when the receipt id is known', async () => {
    authedAs({ entity_id: 'evil_sys', organization_id: 'org_2' });
    timeline([
      created({ actor_id: 'victim_sys' }),
      { event_type: 'guard.trust_receipt.consumed', after_state: {} },
    ]);
    const res = await attestExecution(req({ executed_action: EXECUTED, executing_system: 'evil' }), P);
    expect(res.status).toBe(404);
  });
});
