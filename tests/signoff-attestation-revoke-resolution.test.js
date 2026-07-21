// SPDX-License-Identifier: Apache-2.0
//
// Attestation revocation via the challenge route — resolution of challenge_id
// to the caller's signoff_id.
//
// THE BUG THIS PINS. POST /api/signoff/[challengeId]/revoke has only a
// challengeId (a URL param). It called revokeAttestation({challengeId, ...}),
// but revokeAttestation identified the row by `signoffId` — a distinct UUID
// minted by createAttestation (crypto.randomUUID) and stored alongside
// challenge_id. signoffId was therefore never resolvable at the route, so
// EVERY attestation revoke threw MISSING_SIGNOFF_ID and returned an error.
// The whole path was dead: no test caught it because none drove the route.
//
// Naively passing signoffId: challengeId only moves the failure to a 404 —
// the two identifiers are different values, not different names for one value.
//
// The resolution is scoped to (challenge_id, human_entity_ref) rather than
// challenge_id alone because a challenge does NOT have "an" attestation:
// EP-QUORUM-v1 (migration 098) reuses the one-challenge-many-attestations
// model, and challenge_id carries an index but NO unique constraint. Verified
// against live prod (project xmiiwehtivksdjbultym): signoff_attestations
// exposes challenge_id, and a control probe for a nonexistent column returns
// 42703, so the positive result is meaningful.
//
// Cases pinned here:
//   1. an approved attestation is actually revoked end to end through the route
//   2. the resolved signoff_id — never undefined — is what the UPDATE targets
//   3. no attestation for this caller on this challenge → 404, not 500
//   4. more than one match → 409 fail-closed, never an arbitrary pick
//   5. an explicit signoffId belonging to a different challenge → 404
//   6. refusals surface their real status instead of collapsing to 500

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mocks ──────────────────────────────────────────────────────────────────

const mockGetServiceClient = vi.fn();
const mockAuthenticateRequest = vi.fn();
const mockRequireSignoffEvent = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));
vi.mock('../lib/supabase.js', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));
vi.mock('../lib/signoff/events.js', () => ({
  requireSignoffEvent: (...args) => mockRequireSignoffEvent(...args),
}));
vi.mock('@/lib/signoff/events.js', () => ({
  requireSignoffEvent: (...args) => mockRequireSignoffEvent(...args),
}));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { revokeAttestation } from '../lib/signoff/revoke.js';
import { POST as revokeRoute } from '../app/api/signoff/[challengeId]/revoke/route.ts';

// ─── Helpers ────────────────────────────────────────────────────────────────

const CHALLENGE_ID = '11111111-1111-4111-8111-111111111111';
const SIGNOFF_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_SIGNOFF_ID = '33333333-3333-4333-8333-333333333333';
const ACTOR = { entity_id: 'entity-alice' };

/** Extract the stable machine code from an epProblem (RFC 7807 `type` URL). */
function codeOf(problem) {
  return String(problem?.type || '').split('/').pop();
}

function approvedAttestation(overrides = {}) {
  return {
    signoff_id: SIGNOFF_ID,
    challenge_id: CHALLENGE_ID,
    handshake_id: 'hs-1',
    human_entity_ref: 'entity-alice',
    status: 'approved',
    ...overrides,
  };
}

/**
 * Supabase mock covering the three distinct chains revokeAttestation drives:
 *   resolve : .select('signoff_id').eq(challenge_id).eq(human_entity_ref) → list
 *   fetch   : .select('*').eq(signoff_id).maybeSingle()                   → row
 *   write   : .update({...}).eq(signoff_id).select().single()             → row
 *
 * Records every predicate so a test can assert WHICH signoff_id was written —
 * the difference between a real fix and one that happens to return a row.
 */
function makeSupabaseMock({
  rows = [],
  rowsError = null,
  attestation = null,
  attestationError = null,
  updated = null,
  updateError = null,
  order = null,
} = {}) {
  const calls = { resolveEq: [], fetchEq: [], updateEq: [] };

  const single = vi.fn().mockResolvedValue({ data: updated, error: updateError });
  const selectAfterUpdate = vi.fn().mockReturnValue({ single });
  const eqUpdate = vi.fn().mockImplementation((col, val) => {
    calls.updateEq.push([col, val]);
    return { select: selectAfterUpdate };
  });
  const updateFn = vi.fn().mockImplementation(() => {
    if (order) order.push('update');
    return { eq: eqUpdate };
  });

  const selectFn = vi.fn().mockImplementation(() => ({
    eq: vi.fn().mockImplementation((col, val) => ({
      // A second .eq() means the resolution list query.
      eq: vi.fn().mockImplementation((col2, val2) => {
        calls.resolveEq.push([col, val], [col2, val2]);
        return Promise.resolve({ data: rows, error: rowsError });
      }),
      maybeSingle: vi.fn().mockImplementation(() => {
        calls.fetchEq.push([col, val]);
        return Promise.resolve({ data: attestation, error: attestationError });
      }),
    })),
  }));

  return { from: vi.fn().mockImplementation(() => ({ select: selectFn, update: updateFn })), calls };
}

function revokeRequest(body) {
  return new Request('https://ep.test/api/signoff/x/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function callRoute(body, challengeId = CHALLENGE_ID) {
  return revokeRoute(revokeRequest(body), { params: Promise.resolve({ challengeId }) });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRequireSignoffEvent.mockResolvedValue({ event_id: 'ev-1' });
  mockAuthenticateRequest.mockResolvedValue({ entity: { entity_id: 'entity-alice', id: 'entity-alice' } });
});

// ─── 1 + 2: the path works end to end ───────────────────────────────────────

describe('attestation revoke — end to end through the route', () => {
  it('revokes the caller\'s approved attestation given only a challengeId', async () => {
    const supabase = makeSupabaseMock({
      rows: [{ signoff_id: SIGNOFF_ID }],
      attestation: approvedAttestation(),
      updated: { ...approvedAttestation(), status: 'revoked', revocation_reason: 'key compromise' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({ revokeAttestation: true, reason: 'key compromise' });
    const json = await res.json();

    // Before the fix this was an error response, never a revoked attestation.
    expect(res.status).toBe(200);
    expect(json.status).toBe('revoked');
    expect(json.revocation_reason).toBe('key compromise');
  });

  it('targets the RESOLVED signoff_id in the write, never an undefined predicate', async () => {
    const supabase = makeSupabaseMock({
      rows: [{ signoff_id: SIGNOFF_ID }],
      attestation: approvedAttestation(),
      updated: { ...approvedAttestation(), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await callRoute({ revokeAttestation: true, reason: 'test' });

    // The UPDATE must be scoped to the resolved attestation. An undefined
    // predicate here is the difference between revoking one signature and
    // issuing an unscoped write against the attestation table.
    expect(supabase.calls.updateEq).toEqual([['signoff_id', SIGNOFF_ID]]);
    expect(supabase.calls.updateEq[0][1]).toBeDefined();
    // Resolution is scoped to the caller, not the challenge alone.
    expect(supabase.calls.resolveEq).toEqual([
      ['challenge_id', CHALLENGE_ID],
      ['human_entity_ref', 'entity-alice'],
    ]);
  });

  it('attributes the attestation_revoked event to the resolved signoff_id', async () => {
    const supabase = makeSupabaseMock({
      rows: [{ signoff_id: SIGNOFF_ID }],
      attestation: approvedAttestation(),
      updated: { ...approvedAttestation(), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await callRoute({ revokeAttestation: true, reason: 'test' });

    expect(mockRequireSignoffEvent).toHaveBeenCalledWith(expect.objectContaining({
      eventType: 'attestation_revoked',
      signoffId: SIGNOFF_ID,
      challengeId: CHALLENGE_ID,
      actorEntityRef: 'entity-alice',
    }));
  });

  it('writes the event BEFORE the state change (event-first ordering)', async () => {
    const order = [];
    mockRequireSignoffEvent.mockImplementation(async () => {
      order.push('event');
      return { event_id: 'ev-1' };
    });
    const supabase = makeSupabaseMock({
      order,
      rows: [{ signoff_id: SIGNOFF_ID }],
      attestation: approvedAttestation(),
      updated: { ...approvedAttestation(), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    await callRoute({ revokeAttestation: true, reason: 'test' });

    expect(order).toEqual(['event', 'update']);
  });
});

// ─── 3 + 4 + 5: fail-closed resolution ──────────────────────────────────────

describe('attestation revoke — resolution refusals', () => {
  it('returns 404 when the caller holds no attestation on this challenge', async () => {
    const supabase = makeSupabaseMock({ rows: [] });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({ revokeAttestation: true, reason: 'test' });

    expect(res.status).toBe(404);
    expect(codeOf(await res.json())).toBe('attestation_not_found');
    // Nothing was written.
    expect(supabase.calls.updateEq).toEqual([]);
  });

  it('fails closed with 409 when more than one attestation matches', async () => {
    // One-attestation-per-human is enforced in application logic
    // (quorum-session canAccept → duplicate_human), never by a DB constraint.
    // Picking an arbitrary row would silently under-revoke a signer.
    const supabase = makeSupabaseMock({
      rows: [{ signoff_id: SIGNOFF_ID }, { signoff_id: OTHER_SIGNOFF_ID }],
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({ revokeAttestation: true, reason: 'test' });

    expect(res.status).toBe(409);
    expect(codeOf(await res.json())).toBe('ambiguous_attestation');
    expect(supabase.calls.updateEq).toEqual([]);
  });

  it('accepts an explicit signoffId to disambiguate, skipping resolution', async () => {
    const supabase = makeSupabaseMock({
      attestation: approvedAttestation({ signoff_id: OTHER_SIGNOFF_ID }),
      updated: { ...approvedAttestation({ signoff_id: OTHER_SIGNOFF_ID }), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({
      revokeAttestation: true,
      reason: 'test',
      signoffId: OTHER_SIGNOFF_ID,
    });

    expect(res.status).toBe(200);
    expect(supabase.calls.resolveEq).toEqual([]);
    expect(supabase.calls.updateEq).toEqual([['signoff_id', OTHER_SIGNOFF_ID]]);
  });

  it('returns 404 when an explicit signoffId belongs to a different challenge', async () => {
    // Otherwise the URL segment is decorative and a caller could revoke an
    // attestation on challenge B by POSTing to challenge A's revoke endpoint.
    const supabase = makeSupabaseMock({
      attestation: approvedAttestation({ challenge_id: 'a-different-challenge' }),
      updated: { ...approvedAttestation(), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({
      revokeAttestation: true,
      reason: 'test',
      signoffId: SIGNOFF_ID,
    });

    expect(res.status).toBe(404);
    expect(supabase.calls.updateEq).toEqual([]);
  });

  it('surfaces a resolution DB failure as 500 DB_ERROR without writing', async () => {
    const supabase = makeSupabaseMock({ rowsError: { message: 'connection reset' } });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({ revokeAttestation: true, reason: 'test' });

    expect(res.status).toBe(500);
    expect(supabase.calls.updateEq).toEqual([]);
  });
});

// ─── 6: refusals keep their real status ─────────────────────────────────────

describe('attestation revoke — refusals are not collapsed into 500', () => {
  it('reports an already-consumed attestation as 409, not 500', async () => {
    const supabase = makeSupabaseMock({
      rows: [{ signoff_id: SIGNOFF_ID }],
      attestation: approvedAttestation({ status: 'consumed' }),
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({ revokeAttestation: true, reason: 'test' });

    // A consumed attestation is a state refusal on a revocation path. Reporting
    // it as a server fault tells the caller to retry something that can never
    // succeed, and hides a real invariant from the audit trail.
    expect(res.status).toBe(409);
    expect(codeOf(await res.json())).toBe('invalid_state_for_revocation');
  });

  it('reports a foreign actor as 403, not 500', async () => {
    const supabase = makeSupabaseMock({
      attestation: approvedAttestation({ human_entity_ref: 'entity-mallory' }),
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const res = await callRoute({
      revokeAttestation: true,
      reason: 'test',
      signoffId: SIGNOFF_ID,
    });

    expect(res.status).toBe(403);
    expect(codeOf(await res.json())).toBe('forbidden');
  });

  it('reports a missing reason as 400, not 500', async () => {
    mockGetServiceClient.mockReturnValue(makeSupabaseMock());

    const res = await callRoute({ revokeAttestation: true });

    expect(res.status).toBe(400);
    expect(codeOf(await res.json())).toBe('missing_reason');
  });
});

// ─── Library contract: existing signoffId callers keep working ──────────────

describe('revokeAttestation — library contract', () => {
  it('still accepts a bare signoffId (lib/protocol-write.js caller)', async () => {
    const supabase = makeSupabaseMock({
      attestation: approvedAttestation(),
      updated: { ...approvedAttestation(), status: 'revoked' },
    });
    mockGetServiceClient.mockReturnValue(supabase);

    const result = await revokeAttestation({ signoffId: SIGNOFF_ID, reason: 'x', actor: ACTOR });

    expect(result.status).toBe('revoked');
    expect(supabase.calls.resolveEq).toEqual([]);
  });

  it('throws MISSING_SIGNOFF_ID when neither identifier is supplied', async () => {
    await expect(revokeAttestation({ reason: 'x', actor: ACTOR }))
      .rejects.toMatchObject({ code: 'MISSING_SIGNOFF_ID', status: 400 });
  });
});
