// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getServiceClient: vi.fn(),
  authenticateMobileToken: vi.fn(),
  checkRateLimit: vi.fn(),
  getClientIP: vi.fn(),
  getMobileConfig: vi.fn(),
  directoryActive: vi.fn(),
  createMobileStateBackend: vi.fn(),
  createMobileCounterStore: vi.fn(),
  createMobileAuditLog: vi.fn(),
  createMobileEnrollmentDirectory: vi.fn(),
  commitMobileActionDecision: vi.fn(),
  registerMobileActionChallenge: vi.fn(),
  resolveMobileAction: vi.fn(),
  createDurableChallengeStore: vi.fn(),
  createGovernmentMobileController: vi.fn(),
  createMobileCeremonyService: vi.fn(),
  createMobileEnrollmentService: vi.fn(),
  createMobileHttpHandler: vi.fn(),
  createMobileRelianceProfile: vi.fn(),
  createGooglePlayIntegrityDecoder: vi.fn(),
  createPlatformEnrollmentVerifier: vi.fn(),
  createProductionAttestationVerifier: vi.fn(),
  verifyMobilePasskeyRegistration: vi.fn(),
  loggerError: vi.fn(),
  httpHandler: vi.fn(),
  captured: {},
}));

vi.mock('@/lib/supabase.js', () => ({
  getServiceClient: (...args) => mocks.getServiceClient(...args),
}));
vi.mock('@/lib/rate-limit.js', () => ({
  checkRateLimit: (...args) => mocks.checkRateLimit(...args),
  getClientIP: (...args) => mocks.getClientIP(...args),
}));
vi.mock('@/lib/mobile/config.js', () => ({
  getMobileConfig: (...args) => mocks.getMobileConfig(...args),
}));
vi.mock('@/lib/mobile/store.js', () => ({
  authenticateMobileToken: (...args) => mocks.authenticateMobileToken(...args),
  commitMobileActionDecision: (...args) => mocks.commitMobileActionDecision(...args),
  createMobileAuditLog: (...args) => mocks.createMobileAuditLog(...args),
  createMobileCounterStore: (...args) => mocks.createMobileCounterStore(...args),
  createMobileEnrollmentDirectory: (...args) => mocks.createMobileEnrollmentDirectory(...args),
  createMobileStateBackend: (...args) => mocks.createMobileStateBackend(...args),
  registerMobileActionChallenge: (...args) => mocks.registerMobileActionChallenge(...args),
  resolveMobileAction: (...args) => mocks.resolveMobileAction(...args),
}));
vi.mock('@/packages/gate/challenge-store.js', () => ({
  createDurableChallengeStore: (...args) => mocks.createDurableChallengeStore(...args),
}));
vi.mock('@/packages/mobile/index.js', () => ({
  createGovernmentMobileController: (options) => {
    mocks.captured.controller = options;
    return mocks.createGovernmentMobileController(options);
  },
  createMobileCeremonyService: (options) => {
    mocks.captured.ceremony = options;
    return mocks.createMobileCeremonyService(options);
  },
  createMobileEnrollmentService: (options) => {
    mocks.captured.enrollment = options;
    return mocks.createMobileEnrollmentService(options);
  },
  createMobileHttpHandler: (options) => {
    mocks.captured.http = options;
    mocks.createMobileHttpHandler(options);
    return mocks.httpHandler;
  },
  createMobileRelianceProfile: (options) => {
    mocks.captured.profile = options;
    return mocks.createMobileRelianceProfile(options);
  },
}));
vi.mock('@/lib/mobile/attestation.js', () => ({
  createGooglePlayIntegrityDecoder: (...args) => mocks.createGooglePlayIntegrityDecoder(...args),
  createPlatformEnrollmentVerifier: (options) => {
    mocks.captured.enrollmentVerifier = options;
    return mocks.createPlatformEnrollmentVerifier(options);
  },
  createProductionAttestationVerifier: (options) => {
    mocks.captured.attestationVerifier = options;
    return mocks.createProductionAttestationVerifier(options);
  },
  verifyMobilePasskeyRegistration: (...args) => mocks.verifyMobilePasskeyRegistration(...args),
}));
vi.mock('@/lib/logger.js', () => ({
  logger: { error: (...args) => mocks.loggerError(...args) },
}));

const runtime = await import('@/lib/mobile/runtime.js');
const mobileRoute = await import('@/lib/mobile/route.js');

const IOS_SESSION = {
  session_id: 'session-1',
  entity_ref: 'entity-1',
  approver_id: 'ep:approver:supervisor',
  profile_id: 'profile-1',
  platform: 'ios',
  app_id: 'ai.emiliaprotocol.approver',
  device_key_id: 'device-1',
};

function config(overrides = {}) {
  return {
    profileId: 'profile-1',
    rpId: 'www.emiliaprotocol.ai',
    iosOrigin: 'https://www.emiliaprotocol.ai',
    androidOrigins: ['android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
    iosBundleId: 'ai.emiliaprotocol.approver',
    androidPackageName: 'ai.emiliaprotocol.approver',
    androidConfigured: true,
    maxChallengeAgeMs: 300_000,
    ...overrides,
  };
}

function request(path = '/api/v1/mobile/challenges') {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ep_mobile_${'a'.repeat(43)}`,
      'content-type': 'application/json',
    },
    body: '{}',
  });
}

describe('mobile production runtime composition', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.captured = {};
    mocks.getServiceClient.mockReturnValue({ service: true });
    mocks.authenticateMobileToken.mockResolvedValue(IOS_SESSION);
    mocks.getClientIP.mockReturnValue('203.0.113.9');
    mocks.checkRateLimit.mockResolvedValue({ allowed: true, reset: 60 });
    mocks.getMobileConfig.mockReturnValue(config());
    mocks.createMobileStateBackend.mockReturnValue({ durable: true });
    mocks.createDurableChallengeStore.mockReturnValue({ register: vi.fn(), consume: vi.fn(), durable: true });
    mocks.createMobileCounterStore.mockImplementation((_db, domain) => ({ domain, advance: vi.fn() }));
    mocks.createMobileAuditLog.mockReturnValue({ append: vi.fn() });
    mocks.createMobileEnrollmentDirectory.mockReturnValue({
      active: mocks.directoryActive,
      enrollAtomically: vi.fn(),
      platformKey: vi.fn(),
      durable: true,
    });
    mocks.directoryActive.mockResolvedValue([]);
    mocks.createMobileEnrollmentService.mockReturnValue({ issue: vi.fn(), complete: vi.fn() });
    mocks.createMobileCeremonyService.mockReturnValue({ issue: vi.fn(), verifyAndConsume: vi.fn() });
    mocks.createMobileRelianceProfile.mockReturnValue({ profile_id: 'profile-1', profile_hash: 'hash-1' });
    mocks.createGovernmentMobileController.mockReturnValue({ issue: vi.fn(), verify: vi.fn() });
    mocks.createPlatformEnrollmentVerifier.mockReturnValue(vi.fn());
    mocks.createProductionAttestationVerifier.mockReturnValue(vi.fn());
    mocks.createGooglePlayIntegrityDecoder.mockReturnValue(vi.fn());
    mocks.httpHandler.mockResolvedValue(new Response('{"ok":true}', { status: 200 }));
    mocks.commitMobileActionDecision.mockResolvedValue({ committed: true, audit_record: { record_id: 'rec-1' } });
    mocks.registerMobileActionChallenge.mockResolvedValue(true);
    mocks.resolveMobileAction.mockResolvedValue(null);
  });

  it('binds every session field, including null device enrollment', () => {
    expect(runtime.mobileSessionAuthorizes(IOS_SESSION, IOS_SESSION)).toBe(true);
    expect(runtime.mobileSessionAuthorizes(null, IOS_SESSION)).toBe(false);
    for (const field of ['approver_id', 'profile_id', 'platform', 'app_id', 'device_key_id']) {
      expect(runtime.mobileSessionAuthorizes(IOS_SESSION, { ...IOS_SESSION, [field]: 'wrong' })).toBe(false);
    }
    expect(runtime.mobileSessionAuthorizes(
      { ...IOS_SESSION, device_key_id: null },
      { ...IOS_SESSION, device_key_id: null },
    )).toBe(true);
    expect(runtime.mobileSessionAuthorizes(
      { ...IOS_SESSION, device_key_id: 'device-1' },
      { ...IOS_SESSION, device_key_id: null },
    )).toBe(false);
  });

  it('refuses missing sessions, wrong app identities, and unconfigured Android verification', async () => {
    mocks.authenticateMobileToken.mockResolvedValueOnce(null);
    await expect(runtime.createMobileRuntime({ request: request() })).resolves.toEqual({ session: null, handler: null });

    mocks.authenticateMobileToken.mockResolvedValueOnce({ ...IOS_SESSION, app_id: 'attacker.app' });
    await expect(runtime.createMobileRuntime({ request: request() })).resolves.toEqual({ session: null, handler: null });

    mocks.authenticateMobileToken.mockResolvedValueOnce({ ...IOS_SESSION, platform: 'android' });
    mocks.getMobileConfig.mockReturnValueOnce(config({ androidConfigured: false }));
    await expect(runtime.createMobileRuntime({ request: request() })).rejects.toThrow('Android mobile verification is not fully configured');
  });

  it('constructs the enrollment-only runtime and keeps Google decode fail closed when unconfigured', async () => {
    const unenrolledSession = { ...IOS_SESSION, device_key_id: null };
    mocks.authenticateMobileToken.mockResolvedValue(unenrolledSession);
    const created = await runtime.createMobileRuntime({ request: request(), env: {} });
    expect(created.session).toEqual(unenrolledSession);
    expect(created.handler).toBe(mocks.httpHandler);
    expect(await mocks.captured.http.controller.issue()).toMatchObject({
      ok: false,
      verdict: 'refuse_profile_mismatch',
    });
    expect(await mocks.captured.http.controller.verify()).toMatchObject({
      valid: false,
      verdict: 'refuse_profile_mismatch',
    });
    expect(mocks.captured.enrollment.authorizeEnrollment({
      ...unenrolledSession,
      approver_id: unenrolledSession.approver_id,
      profile_id: unenrolledSession.profile_id,
      platform: unenrolledSession.platform,
      app_id: unenrolledSession.app_id,
    })).toBe(true);
    expect(mocks.captured.enrollment.authorizeEnrollment({
      ...IOS_SESSION,
      approver_id: 'ep:approver:other',
    })).toBe(false);
    expect(mocks.captured.http.resolveEnrollmentIdentity({ approver_id: 'ep:approver:supervisor' })).toEqual({
      userName: 'ep:approver:supervisor@entity-1',
      displayName: 'ep:approver:supervisor',
    });
    await expect(mocks.captured.enrollmentVerifier.playDecoder()).rejects.toThrow('not configured');
    expect(mocks.captured.http.enrollmentConfig.origins.android).toContain('android:apk-key-hash:');
  });

  it('composes enrolled ceremony callbacks into the durable system of record', async () => {
    const enrolled = { approver_id: IOS_SESSION.approver_id, public_key_spki: 'spki' };
    mocks.directoryActive.mockResolvedValue([enrolled, { approver_id: 'ep:approver:other' }]);
    const farExpiry = new Date(Date.now() + 3_600_000).toISOString();
    mocks.resolveMobileAction.mockResolvedValue({
      action: { '@type': 'treasury.disbursement.release' },
      presentation: {
        '@version': 'EP-MOBILE-PRESENTATION-v1',
        title: 'Release funds',
        summary: 'Release the pending treasury disbursement.',
        risk: 'high',
        consequence: 'Funds will be transferred to the approved destination.',
        material_fields: { amount: '$125,000' },
      },
      policy: { human_approval: 'class_a' },
      policy_id: 'policy-1',
      initiator_id: 'ep:agent:treasury',
      approver_id: IOS_SESSION.approver_id,
      expires_at: farExpiry,
    });

    await runtime.createMobileRuntime({
      request: request(),
      env: { GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: '{"client_email":"x","private_key":"y"}' },
    });
    expect(mocks.captured.profile.enrollments).toEqual([enrolled]);
    expect(mocks.createGooglePlayIntegrityDecoder).toHaveBeenCalledWith(expect.objectContaining({
      packageName: 'ai.emiliaprotocol.approver',
    }));

    expect(mocks.captured.controller.authorize({ ...IOS_SESSION })).toBe(true);
    expect(mocks.captured.controller.authorize({ ...IOS_SESSION, app_id: 'attacker.app' })).toBe(false);
    await expect(mocks.captured.controller.registerChallenge({
      action_reference: 'action-1',
      approver_id: IOS_SESSION.approver_id,
      challenge_id: 'challenge-1',
      action_hash: 'hash',
      decision: 'approved',
      expires_at: farExpiry,
    })).resolves.toBe(true);
    expect(mocks.registerMobileActionChallenge).toHaveBeenCalledWith({ service: true }, expect.objectContaining({
      entityRef: 'entity-1',
      sessionId: 'session-1',
      actionReference: 'action-1',
    }));

    const resolved = await mocks.captured.controller.resolveRequest({
      action_reference: 'action-1',
      approver_id: IOS_SESSION.approver_id,
    });
    expect(resolved.action['@type']).toBe('treasury.disbursement.release');
    expect(Date.parse(resolved.expires_at)).toBeLessThanOrEqual(Date.now() + 300_500);
    mocks.resolveMobileAction.mockResolvedValueOnce(null);
    await expect(mocks.captured.controller.resolveRequest({
      action_reference: 'missing',
      approver_id: IOS_SESSION.approver_id,
    })).resolves.toBeNull();

    const decisionEvidence = {
      context: { decision: 'approved' },
      signoff: { key_class: 'A' },
    };
    const committed = await mocks.captured.ceremony.commitDecision({
      challenge: { challenge_id: 'challenge-1', action_hash: 'hash' },
      result: {
        decision: 'approved',
        verdict: 'verified',
        decision_evidence: decisionEvidence,
        class_a: { legacy_alias: true },
      },
      auditEntry: { record_id: 'rec-1' },
    });
    expect(committed.audit_record.record_id).toBe('rec-1');
    expect(mocks.commitMobileActionDecision).toHaveBeenCalledWith({ service: true }, expect.objectContaining({
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-1',
      actionHash: 'hash',
      decisionEvidence,
    }));
  });

  it('commits the original signed denial envelope without a class_a authorization alias', async () => {
    mocks.directoryActive.mockResolvedValue([{
      approver_id: IOS_SESSION.approver_id,
      public_key_spki: 'spki',
    }]);
    await runtime.createMobileRuntime({ request: request() });

    const auditEntry = {
      profile_hash: `sha256:${'b'.repeat(64)}`,
      approver_id: IOS_SESSION.approver_id,
      device_key_id: IOS_SESSION.device_key_id,
      context_hash: `sha256:${'c'.repeat(64)}`,
    };
    const decisionEvidence = {
      context: {
        action_hash: `sha256:${'a'.repeat(64)}`,
        decision: 'denied',
        approver: IOS_SESSION.approver_id,
        mobile_binding: {
          profile_hash: auditEntry.profile_hash,
          device_key_id: IOS_SESSION.device_key_id,
        },
      },
      signoff: {
        context_hash: auditEntry.context_hash,
        key_class: 'A',
        approver_key_id: IOS_SESSION.device_key_id,
        webauthn: {
          authenticator_data: 'YXV0aC1kYXRh',
          client_data_json: 'Y2xpZW50LWRhdGE',
          signature: 'c2lnbmF0dXJl',
        },
      },
    };
    await expect(mocks.captured.ceremony.commitDecision({
      challenge: {
        challenge_id: 'challenge-denied-1',
        action_hash: `sha256:${'a'.repeat(64)}`,
      },
      result: {
        valid: true,
        decision: 'denied',
        verdict: 'verified',
        approver_id: IOS_SESSION.approver_id,
        device_key_id: IOS_SESSION.device_key_id,
        context_hash: auditEntry.context_hash,
        decision_evidence: decisionEvidence,
      },
      auditEntry,
    })).resolves.toMatchObject({ committed: true });

    const stored = mocks.commitMobileActionDecision.mock.calls.at(-1)[1];
    expect(stored.decisionEvidence).toEqual(decisionEvidence);
    expect(Object.hasOwn(stored.decisionEvidence, 'class_a')).toBe(false);
    expect(stored.decisionEvidence.signoff.webauthn.signature).toBe('c2lnbmF0dXJl');
  });

  it('fails closed at both network and paired-session rate boundaries', async () => {
    mocks.checkRateLimit.mockResolvedValueOnce({ allowed: false, reset: 7 });
    const network = await runtime.handleMobileRuntimeRequest(request());
    expect(network.status).toBe(429);
    expect(network.headers.get('retry-after')).toBe('7');
    expect(mocks.authenticateMobileToken).not.toHaveBeenCalled();

    mocks.checkRateLimit.mockResolvedValueOnce({ allowed: false, error: 'redis unavailable', reset: 2 });
    expect((await runtime.handleMobileRuntimeRequest(request())).status).toBe(503);

    mocks.authenticateMobileToken.mockResolvedValueOnce(null);
    mocks.checkRateLimit.mockResolvedValueOnce({ allowed: true });
    const unauthorized = await runtime.handleMobileRuntimeRequest(request());
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get('cache-control')).toBe('no-store');

    mocks.checkRateLimit
      .mockResolvedValueOnce({ allowed: true })
      .mockResolvedValueOnce({ allowed: false, reset: 11 });
    const sessionLimited = await runtime.handleMobileRuntimeRequest(request());
    expect(sessionLimited.status).toBe(429);
    expect(sessionLimited.headers.get('retry-after')).toBe('11');

    mocks.checkRateLimit.mockResolvedValue({ allowed: true });
    expect((await runtime.handleMobileRuntimeRequest(request())).status).toBe(200);
  });

  it('converts unexpected production-runtime failure into a private no-store refusal', async () => {
    const success = await mobileRoute.handleMobilePost(request());
    expect(success.status).toBe(200);

    mocks.getServiceClient.mockImplementationOnce(() => { throw new Error('database down'); });
    const refused = await mobileRoute.handleMobilePost(request());
    expect(refused.status).toBe(503);
    expect(refused.headers.get('cache-control')).toBe('no-store');
    expect(await refused.json()).toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/refuse_store_unavailable',
      status: 503,
    });
    expect(mocks.loggerError).toHaveBeenCalled();
  });
});
