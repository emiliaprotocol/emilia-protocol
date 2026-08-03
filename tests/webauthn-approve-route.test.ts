// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  buildCeremonyBinding,
  signoffCeremonyPolicy,
  signoffConfirmationPhrase,
} from '../lib/signoff/ceremony-policy.js';

const mockGetGuardedClient = vi.fn();
const mockLoadSignoffForSigning = vi.fn();
const mockVerifyAuthenticationResponse = vi.fn();

const CHALLENGE_BYTES = Buffer.from('signed-context-challenge');
const CHALLENGE = CHALLENGE_BYTES.toString('base64url');
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const ACTION_TYPE = 'large_payment_release';
const REVIEW_STARTED_AT = '2026-08-03T12:00:00.000Z';
const ISSUED_AT = '2026-08-03T12:00:10.000Z';

function ceremonyBinding() {
  return buildCeremonyBinding({
    policy: signoffCeremonyPolicy(),
    phrase: signoffConfirmationPhrase(ACTION_TYPE, ACTION_HASH),
    reviewStartedAt: REVIEW_STARTED_AT,
  });
}

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock('@/lib/webauthn-signoff', () => ({
  loadSignoffForSigning: (...args) => mockLoadSignoffForSigning(...args),
}));

vi.mock('@simplewebauthn/server', () => ({
  verifyAuthenticationResponse: (...args) => mockVerifyAuthenticationResponse(...args),
}));

vi.mock('@/lib/webauthn', () => ({
  getRpConfig: () => ({ rpID: 'example.com', origin: 'https://example.com' }),
  contextHashBytes: () => CHALLENGE_BYTES,
  APPROVER_ID_PATTERN: /^[A-Za-z0-9:_.@-]{3,128}$/,
  SIGNOFF_ID_PATTERN: /^sig_[a-f0-9]{32}$/,
}));

vi.mock('@/lib/signoff/quorum-session.js', () => ({
  canAccept: () => ({ ok: true }),
}));

vi.mock('@/lib/signoff/attestation-members.js', () => ({
  decisionToMember: () => ({}),
  decisionsToMembers: () => [],
}));

const { POST } = await import('../app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js');

function req(body) {
  return { json: () => Promise.resolve(body ?? {}) };
}

function oversizedReq(bytes) {
  return new Request('https://www.emiliaprotocol.ai/api/v1/signoffs/sig_x/approve-webauthn', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blob: 'x'.repeat(bytes) }),
  });
}

function clientDataJson(challenge = CHALLENGE) {
  return Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: 'https://example.com',
  })).toString('base64url');
}

function loadedSignoff(approverId = 'cfo@example.com') {
  return {
    signoffId: 'sig_' + 'a'.repeat(32),
    receiptId: 'tr_' + 'b'.repeat(32),
    organizationId: 'org_1',
    requestEvent: { after_state: { approver_id: approverId, required_assurance: 'A' } },
    createdState: {
      organization_id: 'org_1',
      action_type: ACTION_TYPE,
      action_hash: ACTION_HASH,
      required_assurance: 'A',
    },
    initiatorId: 'ep_entity_initiator',
    actionHash: ACTION_HASH,
    requestExpiresAt: '2999-01-01T00:00:00.000Z',
    alreadyDecided: false,
  };
}

function makeClient({ contextDecision = 'approved', credential = {}, ceremony = ceremonyBinding(), velocity = { ok: true } } = {}) {
  const calls = { updates: [], selects: [], inserts: [], upserts: [], rpcs: [] };
  function builder(table) {
    const state = { table, eq: {}, is: {}, operation: 'select' };
    const b = {
      select(columns) { state.select = columns; return b; },
      eq(k, v) { state.eq[k] = v; return b; },
      is(k, v) { state.is[k] = v; return b; },
      in() { return b; },
      order() { return b; },
      limit() { return b; },
      update(patch) { state.operation = 'update'; calls.updates.push({ table, patch, state }); return b; },
      insert(payload) {
        calls.inserts.push({ table, payload });
        return Promise.resolve({ data: null, error: null });
      },
      upsert(payload) {
        calls.upserts.push({ table, payload });
        return Promise.resolve({ data: null, error: null });
      },
      single() { return Promise.resolve({ data: null, error: null }); },
      then(resolve, reject) {
        try {
          calls.selects.push({ ...state });
          if (table === 'webauthn_challenges') {
            if (state.operation === 'update') {
              return resolve({ data: [{ id: 'ch_1' }], error: null });
            }
            return resolve({
              data: [{
                id: 'ch_1',
                challenge: CHALLENGE,
                context: {
                  action_hash: ACTION_HASH,
                  display_hash: 'sha256:display',
                  decision: contextDecision,
                  issued_at: ISSUED_AT,
                  ceremony,
                },
                context_hash: 'sha256:context',
                expires_at: '2999-01-01T00:00:00.000Z',
              }],
              error: null,
            });
          }
          if (table === 'approver_credentials') {
            return resolve({
              data: [{
                credential_id: 'cred_1',
                public_key_cose: Buffer.from('cose').toString('base64url'),
                public_key_spki: 'spki',
                sign_count: 0,
                transports: ['internal'],
                approver_id: 'cfo@example.com',
                approver_name: 'CFO',
                enrollment_basis: 'operator_attested',
                valid_from: null,
                valid_to: null,
                organization_id: 'org_1',
                ...credential,
              }],
              error: null,
            });
          }
          return resolve({ data: [], error: null });
        } catch (e) {
          return reject(e);
        }
      },
    };
    return b;
  }
  return {
    client: {
      from: (table) => builder(table),
      rpc: vi.fn((name, args) => {
        calls.rpcs.push({ name, args });
        return Promise.resolve({ data: velocity, error: null });
      }),
    },
    calls,
  };
}

describe('POST /api/v1/signoffs/:id/approve-webauthn — red-team ceremony hardening', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    mockLoadSignoffForSigning.mockReset();
    mockVerifyAuthenticationResponse.mockReset();
    mockLoadSignoffForSigning.mockResolvedValue(loadedSignoff());
  });

  it('rejects oversized approval assertions before DB work', async () => {
    const res = await POST(oversizedReq(257 * 1024), {
      params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }),
    });

    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
    expect(mockLoadSignoffForSigning).not.toHaveBeenCalled();
  });

  it('does not consume the challenge when an attacker posts a junk assertion for the right challenge', async () => {
    const { client, calls } = makeClient();
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockRejectedValue(new Error('bad signature'));

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(400);
    expect(calls.selects.find((s) => s.table === 'webauthn_challenges').eq)
      .toMatchObject({ organization_id: 'org_1', challenge: CHALLENGE });
    expect(calls.updates).toHaveLength(0);
  });

  it('refuses to relabel a device-signed denial as approval', async () => {
    const { client, calls } = makeClient({ contextDecision: 'denied' });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      decision: 'approved',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('decision_mismatch');
    expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(calls.updates).toHaveLength(0);
  });

  it('refuses an approval whose signed ceremony does not match the current policy', async () => {
    const { client, calls } = makeClient({ ceremony: null });
    mockGetGuardedClient.mockReturnValue(client);

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      decision: 'approved',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(409);
    expect((await res.json()).type).toContain('ceremony_binding_invalid');
    expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(calls.rpcs).toHaveLength(0);
  });

  it('records a verified denial from the signed context as a terminal rejection event', async () => {
    const { client, calls } = makeClient({ contextDecision: 'denied' });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      decision: 'rejected',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ decision: 'rejected', signed_decision: 'denied', key_class: 'A' });
    const recorded = calls.inserts.find((call) => call.table === 'audit_events')?.payload;
    expect(recorded.event_type).toBe('guard.signoff.rejected');
    expect(recorded.after_state.context.decision).toBe('denied');
    expect(recorded.after_state.key_class).toBe('A');
  });

  it('rejects a case-variant operator-attested credential identity', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loadedSignoff('Alice@corp'));
    const { client, calls } = makeClient({
      credential: {
        approver_id: 'alice@corp',
        enrollment_basis: 'operator_attested',
      },
    });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    const res = await POST(req({
      approver_id: 'Alice@corp',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('credential_not_enrolled');
    expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(calls.updates).toHaveLength(0);
  });

  it('accepts a normalized alias for a directory-backed credential', async () => {
    mockLoadSignoffForSigning.mockResolvedValue(loadedSignoff('Alice@corp'));
    const { client, calls } = makeClient({
      credential: {
        approver_id: 'alice@corp',
        enrollment_basis: 'directory',
      },
    });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    const res = await POST(req({
      approver_id: 'Alice@corp',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(200);
    const credentialSelect = calls.selects.find((call) => call.table === 'approver_credentials');
    expect(credentialSelect.select).toContain('enrollment_basis');
    expect(credentialSelect.select).toContain('valid_from');
    expect(credentialSelect.select).toContain('valid_to');
    expect(credentialSelect.is).toMatchObject({ revoked_at: null });
    expect(calls.rpcs).toHaveLength(1);
    expect(calls.rpcs[0]).toMatchObject({
      name: 'consume_signoff_approval_velocity',
      args: { p_organization_id: 'org_1', p_max_approvals: 5, p_window_seconds: 3600 },
    });
  });

  it('fails closed after a valid assertion when the durable approval velocity is exhausted', async () => {
    const { client, calls } = makeClient({ velocity: { ok: false, reason: 'approval_velocity_exceeded' } });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      decision: 'approved',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(429);
    expect((await res.json()).type).toContain('approval_velocity_exceeded');
    expect(calls.rpcs).toHaveLength(1);
    expect(calls.inserts.find((call) => call.table === 'audit_events')).toBeUndefined();
  });

  it.each([
    ['expired', { valid_to: '2000-01-01T00:00:00.000Z' }],
    ['not-yet-valid', { valid_from: '2999-01-01T00:00:00.000Z' }],
  ])('rejects a %s credential at decision time', async (_label, credential) => {
    const { client, calls } = makeClient({ credential });
    mockGetGuardedClient.mockReturnValue(client);
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    const res = await POST(req({
      approver_id: 'cfo@example.com',
      assertion: {
        id: 'cred_1',
        response: {
          clientDataJSON: clientDataJson(),
          authenticatorData: 'auth',
          signature: 'sig',
        },
      },
    }), { params: Promise.resolve({ signoffId: 'sig_' + 'a'.repeat(32) }) });

    expect(res.status).toBe(403);
    expect((await res.json()).type).toContain('credential_not_enrolled');
    expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    expect(calls.updates).toHaveLength(0);
  });
});
