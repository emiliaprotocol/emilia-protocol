// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  canonicalEvaluate: vi.fn(),
  verifyDelegation: vi.fn(),
  getGuardedClient: vi.fn(),
  protocolWrite: vi.fn(),
  authorizeHandshakeVerify: vi.fn(),
  consumeHandshake: vi.fn(),
}));

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: mocks.authenticateRequest,
  authEntityId: (auth) => auth?.entity?.entity_id || auth?.entity?.id || auth?.entity || '',
}));

vi.mock('@/lib/canonical-evaluator', () => ({
  canonicalEvaluate: mocks.canonicalEvaluate,
}));

vi.mock('@/lib/delegation', () => ({
  verifyDelegation: mocks.verifyDelegation,
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: mocks.getGuardedClient,
}));

vi.mock('@/lib/protocol-write', () => ({
  protocolWrite: mocks.protocolWrite,
  COMMAND_TYPES: { ISSUE_COMMIT: 'issue_commit' },
}));

vi.mock('@/lib/handshake-auth', () => ({
  authorizeHandshakeVerify: mocks.authorizeHandshakeVerify,
}));

vi.mock('@/lib/handshake/consume', () => ({
  consumeHandshake: mocks.consumeHandshake,
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/trust/gate/route.js');

function request(body) {
  return new Request('https://www.emiliaprotocol.ai/api/trust/gate', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ep_live_test',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function readClient({ handshake = null, binding = null } = {}) {
  return {
    from(table) {
      const result = table === 'handshakes' ? handshake : binding;
      return {
        select() { return this; },
        eq() { return this; },
        async maybeSingle() { return { data: result, error: null }; },
      };
    },
  };
}

const verifiedHandshake = {
  handshake_id: '11111111-1111-4111-8111-111111111111',
  status: 'verified',
  action_type: 'transact',
  resource_ref: null,
  action_hash: null,
  policy_hash: 'policy-hash',
};

const liveBinding = {
  binding_hash: 'binding-hash',
  consumed_at: null,
  expires_at: '2099-01-01T00:00:00.000Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.authenticateRequest.mockResolvedValue({ entity: { entity_id: 'caller-1' } });
  mocks.canonicalEvaluate.mockResolvedValue({
    entity_id: 'agent-1',
    display_name: 'Agent One',
    effectiveEvidence: 80,
    confidence: 'confident',
    profile: { behavioral: { dispute_rate: 0 } },
    establishment: { established: true },
  });
  mocks.verifyDelegation.mockResolvedValue({
    valid: true,
    action_permitted: true,
    agent_entity_id: 'caller-1',
    principal_id: 'agent-1',
  });
  mocks.authorizeHandshakeVerify.mockResolvedValue(undefined);
  mocks.consumeHandshake.mockResolvedValue({ id: 'consumption-1' });
  mocks.getGuardedClient.mockReturnValue(readClient());
  mocks.protocolWrite.mockResolvedValue({
    commit_id: 'epc_gate_allow',
    decision: 'allow',
  });
});

describe('POST /api/trust/gate security boundary', () => {
  it('refuses when commit issuance fails instead of returning an unbacked allow', async () => {
    mocks.protocolWrite.mockRejectedValue(new Error('database unavailable'));

    const response = await POST(request({ entity_id: 'caller-1', action: 'transact' }));
    const body = await response.json();

    expect(body.decision).toBe('deny');
    expect(body.commit_ref).toBeUndefined();
    expect(body.reasons.join(' ')).toMatch(/pre-authorization could not be issued/i);
  });

  it('refuses unknown policy labels instead of silently using standard', async () => {
    const response = await POST(request({
      entity_id: 'caller-1',
      action: 'transact',
      policy: 'looks-strict-but-is-not',
    }));

    expect(response.status).toBe(400);
    expect(mocks.canonicalEvaluate).not.toHaveBeenCalled();
    expect(mocks.protocolWrite).not.toHaveBeenCalled();
  });

  it('binds the gate commit to every material action field', async () => {
    const response = await POST(request({
      entity_id: 'agent-1',
      action: 'transact',
      principal_id: 'human-1',
      counterparty_entity_id: 'merchant-1',
      delegation_id: 'delegation-1',
      scope: { currency: 'USD', purpose: 'invoice-42' },
      value_usd: 250,
      context: { region: 'us' },
      policy: 'strict',
    }));

    expect(response.status).toBe(200);
    expect(mocks.protocolWrite).toHaveBeenCalledWith(expect.objectContaining({
      input: expect.objectContaining({
        scope: expect.objectContaining({
          gate_binding_version: 'EP-GATE-COMMIT-BINDING-v1',
          gate_binding_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        }),
      }),
    }));
  });

  it('refuses when the issued commit is not an allow decision', async () => {
    mocks.protocolWrite.mockResolvedValue({
      commit_id: 'epc_gate_review',
      decision: 'review',
    });

    const response = await POST(request({ entity_id: 'caller-1', action: 'transact' }));
    const body = await response.json();

    expect(body.decision).toBe('deny');
    expect(body.commit_ref).toBeUndefined();
    expect(body.reasons.join(' ')).toMatch(/did not authorize/i);
  });

  it('authorizes the caller against a supplied handshake before using it', async () => {
    mocks.getGuardedClient.mockReturnValue(readClient({
      handshake: verifiedHandshake,
      binding: liveBinding,
    }));
    mocks.authorizeHandshakeVerify.mockRejectedValue(new Error('not a verifier'));

    const response = await POST(request({
      entity_id: 'caller-1',
      action: 'transact',
      handshake_id: verifiedHandshake.handshake_id,
    }));
    const body = await response.json();

    expect(mocks.authorizeHandshakeVerify).toHaveBeenCalledWith(
      expect.anything(),
      'caller-1',
      verifiedHandshake.handshake_id,
    );
    expect(body.decision).toBe('deny');
    expect(mocks.consumeHandshake).not.toHaveBeenCalled();
    expect(mocks.protocolWrite).not.toHaveBeenCalled();
  });

  it('refuses a verified handshake that has no binding record', async () => {
    mocks.getGuardedClient.mockReturnValue(readClient({
      handshake: verifiedHandshake,
      binding: null,
    }));

    const response = await POST(request({
      entity_id: 'caller-1',
      action: 'transact',
      handshake_id: verifiedHandshake.handshake_id,
    }));
    const body = await response.json();

    expect(body.decision).toBe('deny');
    expect(body.reasons.join(' ')).toMatch(/binding not found/i);
    expect(mocks.protocolWrite).not.toHaveBeenCalled();
  });

  it('atomically consumes a handshake before minting its gate commit', async () => {
    mocks.getGuardedClient.mockReturnValue(readClient({
      handshake: verifiedHandshake,
      binding: liveBinding,
    }));

    const response = await POST(request({
      entity_id: 'caller-1',
      action: 'transact',
      handshake_id: verifiedHandshake.handshake_id,
    }));
    const body = await response.json();

    expect(body.decision).toBe('allow');
    expect(body.commit_ref).toBe('epc_gate_allow');
    expect(mocks.consumeHandshake).toHaveBeenCalledWith(expect.objectContaining({
      handshake_id: verifiedHandshake.handshake_id,
      binding_hash: liveBinding.binding_hash,
      consumed_by_type: 'trust_gate',
      actor: { entity_id: 'caller-1' },
    }));
    expect(mocks.consumeHandshake.mock.invocationCallOrder[0])
      .toBeLessThan(mocks.protocolWrite.mock.invocationCallOrder[0]);
  });

  it('allows only one concurrent request to mint from a one-time handshake', async () => {
    mocks.getGuardedClient.mockImplementation(() => readClient({
      handshake: verifiedHandshake,
      binding: liveBinding,
    }));
    mocks.consumeHandshake
      .mockResolvedValueOnce({ id: 'consumption-1' })
      .mockRejectedValueOnce(new Error('ALREADY_CONSUMED'));

    const makeRequest = () => POST(request({
      entity_id: 'caller-1',
      action: 'transact',
      handshake_id: verifiedHandshake.handshake_id,
    }));
    const responses = await Promise.all([makeRequest(), makeRequest()]);
    const bodies = await Promise.all(responses.map((response) => response.json()));

    expect(bodies.map((body) => body.decision).sort()).toEqual(['allow', 'deny']);
    expect(mocks.protocolWrite).toHaveBeenCalledTimes(1);
  });
});
