// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateRequest: vi.fn(),
  authEntityId: vi.fn(),
  getServiceClient: vi.fn(),
  checkRateLimit: vi.fn(),
  createPairing: vi.fn(),
  exchangePairing: vi.fn(),
  authenticateMobileToken: vi.fn(),
  listMobileActions: vi.fn(),
  revokeMobileSession: vi.fn(),
  createDemoAction: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock('@/lib/supabase.js', () => ({
  authenticateRequest: (...args) => mocks.authenticateRequest(...args),
  authEntityId: (...args) => mocks.authEntityId(...args),
  getServiceClient: (...args) => mocks.getServiceClient(...args),
}));
vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: (...args) => mocks.checkRateLimit(...args),
  getClientIP: () => '203.0.113.7',
}));
vi.mock('@/lib/mobile/store.js', () => ({
  createPairing: (...args) => mocks.createPairing(...args),
  exchangePairing: (...args) => mocks.exchangePairing(...args),
  authenticateMobileToken: (...args) => mocks.authenticateMobileToken(...args),
  listMobileActions: (...args) => mocks.listMobileActions(...args),
  revokeMobileSession: (...args) => mocks.revokeMobileSession(...args),
  createDemoAction: (...args) => mocks.createDemoAction(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: (...args) => mocks.loggerError(...args) },
}));

const pairingRoute = await import('@/app/api/v1/mobile/pairings/route.js');
const exchangeRoute = await import('@/app/api/v1/mobile/pairings/exchange/route.js');
const inboxRoute = await import('@/app/api/v1/mobile/inbox/route.js');
const sessionRoute = await import('@/app/api/v1/mobile/session/route.js');
const demoRoute = await import('@/app/api/v1/mobile/demo/actions/route.js');
const appleAssociation = await import('@/app/.well-known/apple-app-site-association/route.js');
const androidAssociation = await import('@/app/.well-known/assetlinks.json/route.js');

function post(path, body, token = null) {
  const headers = { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.1, 203.0.113.7' };
  if (token) headers.authorization = token;
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

describe('native app association surfaces', () => {
  const previous = process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256;

  afterEach(() => {
    if (previous === undefined) delete process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256;
    else process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256 = previous;
  });

  it('serves the permanent Apple Team ID and bundle identity', async () => {
    const response = appleAssociation.GET();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      applinks: {
        details: [{
          appIDs: ['5M2Z48UQQY.ai.emiliaprotocol.approver'],
          components: [{
            '/': '/mobile/pair',
            '?': { code: '?*' },
            comment: 'Open one-time EMILIA Approver pairing links',
          }],
        }],
      },
      webcredentials: { apps: ['5M2Z48UQQY.ai.emiliaprotocol.approver'] },
    });
  });

  it('fails closed until the Play signing fingerprint is configured', async () => {
    delete process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256;
    expect(androidAssociation.GET().status).toBe(503);
    process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256 = Array(32).fill('AB').join(':');
    const response = androidAssociation.GET();
    expect(response.status).toBe(200);
    const [statement] = await response.json();
    expect(statement.relation).toEqual([
      'delegate_permission/common.get_login_creds',
      'delegate_permission/common.handle_all_urls',
    ]);
    expect(statement.target.package_name).toBe('ai.emiliaprotocol.approver');
    expect(statement.target.sha256_cert_fingerprints).toHaveLength(1);
  });
});

describe('native pairing, inbox, and terminal session routes', () => {
  const previousDemo = process.env.MOBILE_DEMO_ENABLED;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getServiceClient.mockReturnValue({ service: true });
    mocks.checkRateLimit.mockResolvedValue({ allowed: true });
    process.env.MOBILE_DEMO_ENABLED = 'true';
    mocks.authenticateRequest.mockResolvedValue({ entity: { entity_id: 'entity-1' }, permissions: ['write'] });
    mocks.authEntityId.mockReturnValue('entity-1');
    mocks.createPairing.mockResolvedValue(true);
    mocks.exchangePairing.mockResolvedValue({
      ok: true,
      expires_at: '2026-08-15T00:00:00.000Z',
      approver_id: 'ep:approver:supervisor',
      profile_id: 'emilia.high-assurance.mobile.v1',
    });
    mocks.authenticateMobileToken.mockResolvedValue({
      session_id: 'session-1',
      entity_ref: 'entity-1',
      approver_id: 'ep:approver:supervisor',
    });
    mocks.listMobileActions.mockResolvedValue([]);
    mocks.revokeMobileSession.mockResolvedValue(true);
    mocks.createDemoAction.mockResolvedValue('mobact_1');
  });

  afterEach(() => {
    if (previousDemo === undefined) delete process.env.MOBILE_DEMO_ENABLED;
    else process.env.MOBILE_DEMO_ENABLED = previousDemo;
  });

  it('creates a one-time app-scoped pairing only after API authentication', async () => {
    const response = await pairingRoute.POST(post('/api/v1/mobile/pairings', {
      approver_id: 'ep:approver:supervisor',
    }));
    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.pairing_code).toMatch(/^[2-9A-HJ-NP-Z]{4}(?:-[2-9A-HJ-NP-Z]{4}){2}$/);
    expect(body.enabled_platforms).toEqual(['ios']);
    expect(mocks.createPairing).toHaveBeenCalledWith({ service: true }, expect.objectContaining({
      entityRef: 'entity-1',
      allowedApps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
    }));

    const injected = await pairingRoute.POST(post('/api/v1/mobile/pairings', {
      approver_id: 'ep:approver:supervisor',
      allowed_apps: ['attacker.app'],
    }));
    expect(injected.status).toBe(400);

    mocks.authenticateRequest.mockResolvedValueOnce({ entity: { entity_id: 'entity-1' }, permissions: ['read'] });
    const readOnly = await pairingRoute.POST(post('/api/v1/mobile/pairings', {
      approver_id: 'ep:approver:supervisor',
    }));
    expect(readOnly.status).toBe(403);
  });

  it('rate limits the unauthenticated pairing exchange and returns one scoped token', async () => {
    const response = await exchangeRoute.POST(post('/api/v1/mobile/pairings/exchange', {
      pairing_code: '2345-6789-ABCD',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
    }));
    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.access_token).toMatch(/^ep_mobile_[A-Za-z0-9_-]{43}$/);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');

    mocks.checkRateLimit.mockResolvedValueOnce({ allowed: false });
    const limited = await exchangeRoute.POST(post('/api/v1/mobile/pairings/exchange', {
      pairing_code: '2345-6789-ABCD',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
    }));
    expect(limited.status).toBe(429);
  });

  it('lists only the paired approver inbox and revokes the exact session', async () => {
    const request = new Request('https://www.emiliaprotocol.ai/api/v1/mobile/inbox', {
      headers: { authorization: `Bearer ep_mobile_${'a'.repeat(43)}` },
    });
    const inbox = await inboxRoute.GET(request);
    expect(inbox.status).toBe(200);
    expect(mocks.listMobileActions).toHaveBeenCalledWith({ service: true }, {
      entityRef: 'entity-1',
      approverId: 'ep:approver:supervisor',
    });

    const revokeRequest = new Request('https://www.emiliaprotocol.ai/api/v1/mobile/session', {
      method: 'DELETE',
      headers: { authorization: `Bearer ep_mobile_${'a'.repeat(43)}` },
    });
    const revoked = await sessionRoute.DELETE(revokeRequest);
    expect(revoked.status).toBe(200);
    expect(mocks.revokeMobileSession).toHaveBeenCalledWith({ service: true }, {
      sessionId: 'session-1',
      entityRef: 'entity-1',
    });
  });

  it('rate limits paired reads and writes before touching protected state', async () => {
    const token = `Bearer ep_mobile_${'a'.repeat(43)}`;
    mocks.checkRateLimit.mockResolvedValueOnce({ allowed: false, reset: 30 });
    const networkLimited = await inboxRoute.GET(new Request(
      'https://www.emiliaprotocol.ai/api/v1/mobile/inbox',
      { headers: { authorization: token } },
    ));
    expect(networkLimited.status).toBe(429);
    expect(networkLimited.headers.get('cache-control')).toBe('no-store');
    expect(mocks.authenticateMobileToken).not.toHaveBeenCalled();

    mocks.checkRateLimit
      .mockResolvedValueOnce({ allowed: true })
      .mockResolvedValueOnce({ allowed: false, reset: 30 });
    const sessionLimited = await sessionRoute.DELETE(new Request(
      'https://www.emiliaprotocol.ai/api/v1/mobile/session',
      { method: 'DELETE', headers: { authorization: token } },
    ));
    expect(sessionLimited.status).toBe(429);
    expect(mocks.revokeMobileSession).not.toHaveBeenCalled();
    expect(mocks.checkRateLimit).toHaveBeenLastCalledWith('session:session-1', 'mobile_write');
  });

  it('seeds a bounded, authenticated critical-action demo without accepting caller action bytes', async () => {
    const response = await demoRoute.POST(post('/api/v1/mobile/demo/actions', {
      approver_id: 'ep:approver:supervisor',
      scenario: 'grid',
    }));
    expect(response.status).toBe(201);
    const inserted = mocks.createDemoAction.mock.calls[0][1];
    expect(inserted.entity_ref).toBe('entity-1');
    expect(inserted.action['@type']).toBe('grid.datacenter.curtailment');
    expect(inserted.action.requested_reduction_mw).toBe(18);
    expect(inserted.presentation.material_fields.reduction).toBe('18 MW');
    expect(mocks.checkRateLimit).toHaveBeenCalledWith('entity-1', 'protocol_write');

    process.env.MOBILE_DEMO_ENABLED = 'false';
    const disabled = await demoRoute.POST(post('/api/v1/mobile/demo/actions', {
      approver_id: 'ep:approver:supervisor',
      scenario: 'grid',
    }));
    expect(disabled.status).toBe(404);
  });

  it('rejects non-JSON pairing surfaces before authentication or storage', async () => {
    const request = new Request('https://www.emiliaprotocol.ai/api/v1/mobile/pairings/exchange', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    });
    expect((await exchangeRoute.POST(request)).status).toBe(415);
    expect(mocks.exchangePairing).not.toHaveBeenCalled();
  });
});
