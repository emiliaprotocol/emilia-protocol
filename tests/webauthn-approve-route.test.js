// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetGuardedClient = vi.fn();
const mockLoadSignoffForSigning = vi.fn();
const mockVerifyAuthenticationResponse = vi.fn();

const CHALLENGE_BYTES = Buffer.from('signed-context-challenge');
const CHALLENGE = CHALLENGE_BYTES.toString('base64url');

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

function clientDataJson(challenge = CHALLENGE) {
  return Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: 'https://example.com',
  })).toString('base64url');
}

function makeClient() {
  const calls = { updates: [], selects: [] };
  function builder(table) {
    const state = { table, eq: {}, is: {} };
    const b = {
      select() { return b; },
      eq(k, v) { state.eq[k] = v; return b; },
      is(k, v) { state.is[k] = v; return b; },
      order() { return b; },
      limit() { return b; },
      update(patch) { calls.updates.push({ table, patch, state }); return b; },
      then(resolve, reject) {
        try {
          calls.selects.push({ ...state });
          if (table === 'webauthn_challenges') {
            return resolve({
              data: [{
                id: 'ch_1',
                challenge: CHALLENGE,
                context: { action_hash: 'sha256:approved-action', display_hash: 'sha256:display' },
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
                organization_id: 'org_1',
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
  return { client: { from: (table) => builder(table) }, calls };
}

describe('POST /api/v1/signoffs/:id/approve-webauthn — red-team ceremony hardening', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
    mockLoadSignoffForSigning.mockReset();
    mockVerifyAuthenticationResponse.mockReset();
    mockLoadSignoffForSigning.mockResolvedValue({
      signoffId: 'sig_' + 'a'.repeat(32),
      receiptId: 'tr_' + 'b'.repeat(32),
      organizationId: 'org_1',
      requestEvent: { after_state: { approver_id: 'cfo@example.com', required_assurance: 'A' } },
      createdState: { organization_id: 'org_1', action_hash: 'sha256:approved-action' },
      initiatorId: 'ep_entity_initiator',
      actionHash: 'sha256:approved-action',
      requestExpiresAt: '2999-01-01T00:00:00.000Z',
      alreadyDecided: false,
    });
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
});
