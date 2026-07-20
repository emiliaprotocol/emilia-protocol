// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  authEntityId: vi.fn(),
  getGuardedClient: vi.fn(),
  authenticateMobileToken: vi.fn(),
  listMobileActionHistory: vi.fn(),
  withdrawMobileAction: vi.fn(),
  consumeMobileAction: vi.fn(),
  resolveMobileOperation: vi.fn(),
  markMobileActionIndeterminate: vi.fn(),
  reconcileMobileActionOperation: vi.fn(),
  registerMobileExecutorKey: vi.fn(),
  recordMobileActionAlignment: vi.fn(),
  supersedeMobileAction: vi.fn(),
  checkRateLimit: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock('@/lib/supabase.js', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
  authEntityId: (...args) => mocks.authEntityId(...args),
}));
vi.mock('@/lib/write-guard.js', () => ({
  getGuardedClient: (...args) => mocks.getGuardedClient(...args),
}));
vi.mock('@/lib/mobile/store.js', () => ({
  authenticateMobileToken: (...args) => mocks.authenticateMobileToken(...args),
  listMobileActionHistory: (...args) => mocks.listMobileActionHistory(...args),
  withdrawMobileAction: (...args) => mocks.withdrawMobileAction(...args),
  consumeMobileAction: (...args) => mocks.consumeMobileAction(...args),
  resolveMobileOperation: (...args) => mocks.resolveMobileOperation(...args),
  markMobileActionIndeterminate: (...args) => mocks.markMobileActionIndeterminate(...args),
  reconcileMobileActionOperation: (...args) => mocks.reconcileMobileActionOperation(...args),
  registerMobileExecutorKey: (...args) => mocks.registerMobileExecutorKey(...args),
  recordMobileActionAlignment: (...args) => mocks.recordMobileActionAlignment(...args),
  supersedeMobileAction: (...args) => mocks.supersedeMobileAction(...args),
}));
vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: (...args) => mocks.checkRateLimit(...args),
  getClientIP: () => '203.0.113.8',
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: (...args) => mocks.loggerError(...args) },
}));

const historyRoute = await import('@/app/api/v1/mobile/history/route.js');
const passportRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/passport/route.js');
const withdrawRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/withdraw/route.js');
const consumeRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/consume/route.js');
const outcomeRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/outcomes/route.js');
const executorRoute = await import('@/app/api/v1/mobile/executors/route.js');
const alignmentRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/alignments/route.js');
const supersedeRoute = await import('@/app/api/v1/mobile/actions/[actionReference]/supersede/route.js');

const ACTION_REFERENCE = `mobact_${'1'.repeat(32)}`;
const context = { params: Promise.resolve({ actionReference: ACTION_REFERENCE }) };
const token = `Bearer ep_mobile_${'a'.repeat(43)}`;

function request(path, body, bearer = 'ep_live_test') {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      authorization: `Bearer ${bearer}`,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

describe('mobile Action Evidence Boundary routes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getGuardedClient.mockReturnValue({ service: true });
    mocks.checkRateLimit.mockResolvedValue({ allowed: true });
    mocks.authenticateRequest.mockResolvedValue({
      entity: { entity_id: 'entity-1' },
      permissions: ['admin'],
    });
    mocks.authEntityId.mockReturnValue('entity-1');
    mocks.authenticateMobileToken.mockResolvedValue({
      entity_ref: 'entity-1',
      session_id: 'session-1',
      approver_id: 'approver-1',
    });
    mocks.listMobileActionHistory.mockResolvedValue([]);
    mocks.withdrawMobileAction.mockResolvedValue({ ok: true, state: 'withdrawn' });
    mocks.consumeMobileAction.mockResolvedValue({
      ok: true,
      operation_id: 'operation-42',
      state: 'consumed',
      action_caid: `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
      consumption_nonce: 'mconsume-test',
    });
    mocks.resolveMobileOperation.mockResolvedValue({
      operation_id: 'operation-42',
      action_caid: `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: `sha256:${'a'.repeat(64)}`,
      consumption_nonce: 'mconsume-test',
      executor_id: 'provider-1',
      executor_key_id: `ep:executor-key:sha256:${'b'.repeat(64)}`,
      status: 'consumed',
    });
    mocks.markMobileActionIndeterminate.mockResolvedValue({
      ok: true,
      state: 'indeterminate',
      retry_safe: false,
    });
    mocks.reconcileMobileActionOperation.mockResolvedValue({ ok: true, state: 'executed', retry_safe: false });
    mocks.registerMobileExecutorKey.mockResolvedValue(true);
    mocks.recordMobileActionAlignment.mockResolvedValue(true);
    mocks.supersedeMobileAction.mockResolvedValue({
      ok: true,
      group_id: `mag_${'2'.repeat(32)}`,
      revision: 2,
      identity: { action_caid: 'caid:test', fingerprint: 'AAAA-BBBB-CCCC-DDDD' },
      changes: [{ field: 'amount', change: 'changed', before: '10', after: '11' }],
    });
  });

  it('returns paired history and a bounded passport without exposing raw evidence', async () => {
    const passport = {
      '@version': 'EP-MOBILE-DECISION-PASSPORT-v1',
      decision: { evidence_digest: `sha256:${'b'.repeat(64)}` },
    };
    mocks.listMobileActionHistory.mockResolvedValue([{
      action_reference: ACTION_REFERENCE,
      presentation: {
        title: 'Release funds',
        summary: 'Release exact funds.',
        risk: 'high',
        material_fields: { amount: '$10' },
      },
      status: 'approved',
      identity: { action_caid: 'caid:test', fingerprint: 'AAAA-BBBB-CCCC-DDDD' },
      continuity: { state: 'AUTHORIZED', retry_safe: true },
      quorum: { approved: 1, required: 1, denied: 0, withdrawn: 0 },
      changes: [],
      alignments: [],
      events: [],
      passport,
    }]);
    const history = await historyRoute.GET(new Request(
      'https://www.emiliaprotocol.ai/api/v1/mobile/history',
      { headers: { authorization: token } },
    ));
    expect(history.status).toBe(200);
    expect(await history.json()).toMatchObject({
      approver_id: 'approver-1',
      actions: [{ continuity: { state: 'AUTHORIZED' }, passport }],
    });
    const response = await passportRoute.GET(new Request(
      `https://www.emiliaprotocol.ai/api/v1/mobile/actions/${ACTION_REFERENCE}/passport`,
      { headers: { authorization: token } },
    ), context);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ passport });
  });

  it('withdraws only the paired approver before consumption and reports the race as 409', async () => {
    const withdrawn = await withdrawRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/withdraw`,
      {},
      `ep_mobile_${'a'.repeat(43)}`,
    ), context);
    expect(withdrawn.status).toBe(200);
    expect(mocks.withdrawMobileAction).toHaveBeenCalledWith({ service: true }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      actionReference: ACTION_REFERENCE,
    });
    mocks.withdrawMobileAction.mockResolvedValueOnce({ ok: false, reason: 'already_consumed' });
    const raced = await withdrawRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/withdraw`,
      {},
      `ep_mobile_${'a'.repeat(43)}`,
    ), context);
    expect(raced.status).toBe(409);
  });

  it('atomically consumes once, marks timeout indeterminate, and refuses blind replay semantics', async () => {
    const consumed = await consumeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/consume`,
      { operation_id: 'operation-42', executor_id: 'provider-1' },
    ), context);
    expect(consumed.status).toBe(201);
    expect(mocks.consumeMobileAction).toHaveBeenCalledWith({ service: true }, expect.objectContaining({
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      operationId: 'operation-42',
      executorId: 'provider-1',
      consumptionNonce: expect.stringMatching(/^mconsume_/),
    }));
    const uncertain = await outcomeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/outcomes`,
      { operation_id: 'operation-42', state: 'indeterminate' },
    ), context);
    expect(uncertain.status).toBe(200);
    expect(await uncertain.json()).toMatchObject({ state: 'indeterminate', retry_safe: false });
    mocks.consumeMobileAction.mockResolvedValueOnce({ ok: false, reason: 'already_consumed' });
    const replay = await consumeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/consume`,
      { operation_id: 'operation-43', executor_id: 'provider-1' },
    ), context);
    expect(replay.status).toBe(409);
  });

  it('requires authenticated provider evidence before a terminal reconciliation', async () => {
    const missing = await outcomeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/outcomes`,
      { operation_id: 'operation-42', state: 'reconcile' },
    ), context);
    expect(missing.status).toBe(400);
    expect(mocks.reconcileMobileActionOperation).not.toHaveBeenCalled();

    const evidence = { executor_id: 'provider-1', proof: { signature_b64u: 'signed' } };
    const reconciled = await outcomeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/outcomes`,
      { operation_id: 'operation-42', state: 'reconcile', evidence },
    ), context);
    expect(reconciled.status).toBe(200);
    expect(mocks.reconcileMobileActionOperation).toHaveBeenCalledWith({ service: true }, {
      entityRef: 'entity-1',
      operation: expect.objectContaining({ operation_id: 'operation-42' }),
      evidence,
    });
  });

  it('pins real Ed25519 executor keys with admin authority', async () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const keyId = `ep:executor-key:sha256:${crypto.createHash('sha256')
      .update(Buffer.from(publicKey, 'base64url')).digest('hex')}`;
    const response = await executorRoute.POST(request('/api/v1/mobile/executors', {
      executor_id: 'provider-1',
      key_id: keyId,
      public_key: publicKey,
    }));
    expect(response.status).toBe(201);
    expect(mocks.registerMobileExecutorKey).toHaveBeenCalledWith({ service: true }, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
      keyId,
      publicKey,
    });
  });

  it('records only evidence-backed positive cross-system alignments', async () => {
    const missing = await alignmentRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/alignments`,
      {
        system: 'AgentROA',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        profile_id: 'ep:map:agentroa:v1',
        profile_hash: `sha256:${'a'.repeat(64)}`,
        native_verified: true,
      },
    ), context);
    expect(missing.status).toBe(400);
    const acceptedBody = {
      system: 'AgentROA',
      verdict: 'EQUIVALENT_UNDER_PROFILE',
      profile_id: 'ep:map:agentroa:v1',
      profile_hash: `sha256:${'a'.repeat(64)}`,
      native_verified: true,
      evidence_digest: `sha256:${'b'.repeat(64)}`,
    };
    const accepted = await alignmentRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/alignments`,
      acceptedBody,
    ), context);
    expect(accepted.status).toBe(201);
    expect(mocks.recordMobileActionAlignment).toHaveBeenCalledWith({ service: true }, {
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      alignment: acceptedBody,
    });
  });

  it('accepts a full successor action but returns only server-computed identity and diff', async () => {
    const response = await supersedeRoute.POST(request(
      `/api/v1/mobile/actions/${ACTION_REFERENCE}/supersede`,
      {
        assignments: [{ action_reference: `mobact_${'3'.repeat(32)}`, approver_id: 'approver-1' }],
        initiator_id: 'agent-1',
        action: { action_type: 'payment.release.1', amount: '11.00' },
        presentation: {
          '@version': 'EP-MOBILE-PRESENTATION-v1',
          title: 'Release funds',
          summary: 'Release exact funds.',
          risk: 'high',
          consequence: 'Funds move.',
          material_fields: { amount: '11.00' },
        },
        policy: { policy_id: 'policy-1', required_approvals: 1 },
        policy_id: 'policy-1',
        expires_at: '2099-01-01T00:00:00.000Z',
      },
    ), context);
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      superseded: true,
      revision: 2,
      identity: { fingerprint: 'AAAA-BBBB-CCCC-DDDD' },
      changes: [{ field: 'amount', change: 'changed' }],
    });
  });
});
