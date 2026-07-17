// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  MOBILE_ANDROID_DEBUG_KEY_HASH,
  getMobileConfig,
  mobileAndroidOrigin,
  normalizeAndroidSigningCertificate,
} from '@/lib/mobile/config.js';
import {
  authenticateMobileToken,
  commitMobileActionDecision,
  createDemoAction,
  createGraceMobileActionGroup,
  createMobileAuditLog,
  createMobileCounterStore,
  createMobileEnrollmentDirectory,
  createMobileStateBackend,
  createPairing,
  exchangePairing,
  listMobileActions,
  registerMobileActionChallenge,
  resolveMobileAction,
  revokeMobileSession,
  sha256Hex,
} from '@/lib/mobile/store.js';
import { mobileSessionAuthorizes } from '@/lib/mobile/runtime.js';
import { verifyEvidenceRecord } from '@/packages/gate/evidence.js';
import { hashCanonical } from '@/packages/mobile/index.js';

const RELEASE_CERTIFICATE_HEX = '05'.repeat(32);
const PRESENTATION = Object.freeze({
  '@version': 'EP-MOBILE-PRESENTATION-v1',
  title: 'Release funds',
  summary: 'Release the pending treasury disbursement.',
  risk: 'high',
  consequence: 'Funds will be transferred to the approved destination.',
  material_fields: Object.freeze({ amount: '$125,000' }),
});

function signedDecisionEvidence({
  decision = 'approved',
  actionHash = `sha256:${'a'.repeat(64)}`,
  profileHash = `sha256:${'b'.repeat(64)}`,
  approverId = 'approver-1',
  deviceKeyId = 'device-1',
} = {}) {
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: actionHash,
    policy_id: 'policy-1',
    policy_hash: null,
    initiator: 'agent-1',
    approver: approverId,
    approver_index: 1,
    required_approvals: 1,
    nonce: 'sig_0123456789abcdef0123456789abcdef',
    issued_at: '2026-07-16T20:00:00.000Z',
    expires_at: '2026-07-16T20:05:00.000Z',
    decision,
    display_hash: `sha256:${'d'.repeat(64)}`,
    mobile_binding: {
      profile: 'EP-MOBILE-CHALLENGE-v1',
      profile_hash: profileHash,
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: deviceKeyId,
      credential_id: 'Y3JlZGVudGlhbC0x',
      attestation_key_id: 'apple-key-1',
    },
  };
  return {
    context,
    signoff: {
      context_hash: hashCanonical(context),
      key_class: 'A',
      approver_key_id: deviceKeyId,
      signed_at: context.issued_at,
      webauthn: {
        authenticator_data: 'YXV0aC1kYXRh',
        client_data_json: 'Y2xpZW50LWRhdGE',
        signature: 'c2lnbmF0dXJl',
      },
    },
  };
}

function decisionAuditEntry(evidence, challengeId = 'challenge-0001') {
  return {
    event_type: 'mobile.ceremony.decision',
    challenge_id: challengeId,
    action_hash: evidence.context.action_hash,
    profile_hash: evidence.context.mobile_binding.profile_hash,
    verdict: 'verified',
    decision: evidence.context.decision,
    approver_id: evidence.context.approver,
    device_key_id: evidence.context.mobile_binding.device_key_id,
    context_hash: evidence.signoff.context_hash,
  };
}

function chain(result) {
  const value = {};
  for (const method of ['insert', 'update', 'select', 'eq', 'is', 'gt', 'gte', 'lte', 'order', 'limit']) {
    value[method] = vi.fn(() => value);
  }
  value.maybeSingle = vi.fn(async () => result);
  value.single = vi.fn(async () => result);
  value.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
  return value;
}

describe('mobile production configuration', () => {
  it('pins the permanent app identities and the directly served www relying party', () => {
    const config = getMobileConfig({ env: {}, production: false });
    expect(config.iosBundleId).toBe('ai.emiliaprotocol.approver');
    expect(config.androidPackageName).toBe('ai.emiliaprotocol.approver');
    expect(config.rpId).toBe('www.emiliaprotocol.ai');
    expect(config.iosOrigin).toBe('https://www.emiliaprotocol.ai');
    expect(config.androidOrigins).toEqual([mobileAndroidOrigin(MOBILE_ANDROID_DEBUG_KEY_HASH)]);
    expect(config.appleEnvironment).toBe('development');
  });

  it('does not silently trust a debug Android identity in production', () => {
    expect(() => getMobileConfig({ env: {}, production: true })).toThrow(/MOBILE_ANDROID_SIGNING_CERT_SHA256/);
  });

  it('derives every Android trust surface from one normalized signing certificate', () => {
    const normalized = normalizeAndroidSigningCertificate(RELEASE_CERTIFICATE_HEX);
    const config = getMobileConfig({
      env: { MOBILE_ANDROID_SIGNING_CERT_SHA256: normalized.assetLinks },
      production: true,
    });
    expect(config.androidSigningCertificateSha256Hex).toBe(normalized.hex);
    expect(config.androidKeyHashes).toEqual([normalized.base64url]);
    expect(config.androidCertificateDigests).toEqual([normalized.base64url]);
    expect(config.androidOrigins).toEqual([mobileAndroidOrigin(normalized.base64url)]);
    expect(config.androidAssetLinksFingerprints).toEqual([normalized.assetLinks]);
    for (const legacyName of [
      'MOBILE_ANDROID_APK_KEY_HASHES',
      'MOBILE_ANDROID_CERTIFICATE_DIGESTS',
      'MOBILE_ANDROID_ASSETLINKS_CERT_SHA256',
    ]) {
      expect(() => getMobileConfig({
        env: {
          MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
          [legacyName]: '06'.repeat(32),
        },
        production: true,
      })).toThrow(/does not match/);
    }
  });

  it('rejects malformed platform pins', () => {
    expect(() => mobileAndroidOrigin()).toThrow(/APK key hash/);
    expect(() => mobileAndroidOrigin('short')).toThrow(/APK key hash/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_TEAM_ID: 'bad' } })).toThrow(/Team ID/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'http://example.com' } })).toThrow(/HTTPS/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_APK_KEY_HASHES: 'bad' } })).toThrow(/MOBILE_ANDROID_APK_KEY_HASHES/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_CERTIFICATE_DIGESTS: '!' } })).toThrow(/MOBILE_ANDROID_CERTIFICATE_DIGESTS/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_BUNDLE_ID: 'not-a-bundle' } })).toThrow(/reverse-domain/);
    expect(() => getMobileConfig({ env: { MOBILE_RP_ID: 'HTTPS://EXAMPLE.COM' } })).toThrow(/lowercase DNS/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'https://www.emiliaprotocol.ai/path' } })).toThrow(/HTTPS origin/);
    expect(() => getMobileConfig({ env: { MOBILE_CHALLENGE_TTL_MS: '999999999' } })).toThrow(/MOBILE_CHALLENGE_TTL_MS/);
    expect(() => getMobileConfig({ env: { MOBILE_PROFILE_ID: 'bad profile!' } })).toThrow(/PROFILE_ID/);
    expect(() => getMobileConfig({ env: { MOBILE_IOS_ORIGIN: 'not a URL' } })).toThrow(/HTTPS origin/);
    expect(() => getMobileConfig({ env: { MOBILE_ANDROID_ALLOWED_VERSION_CODES: '0' } })).toThrow(/positive safe integers/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '7' } })).toThrow(/reserved or unknown/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_ALLOWED_BUNDLE_VERSIONS: 'bad version' } })).toThrow(/invalid version/);
    expect(() => getMobileConfig({ env: { MOBILE_APPLE_REQUIRE_RUNTIME_SIGNALS: 'sometimes' } })).toThrow(/true or false/);
  });

  it('parses explicit boolean and version-list policy without weakening pins', () => {
    const strict = getMobileConfig({
      env: {
        MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
        MOBILE_APPLE_REQUIRE_RUNTIME_SIGNALS: 'true',
        MOBILE_ANDROID_REQUIRE_PLAY_PROTECT: 'false',
        MOBILE_ANDROID_ALLOWED_VERSION_CODES: '1,2,2',
        MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '2,4',
      },
      production: true,
    });
    expect(strict.appleRequireRuntimeSignals).toBe(true);
    expect(strict.androidRequirePlayProtect).toBe(false);
    expect(strict.androidAllowedVersionCodes).toEqual([1, 2]);
  });

  it('retains mandatory app-version and validation-category pins when an environment value is blank', () => {
    const config = getMobileConfig({
      env: {
        MOBILE_ANDROID_SIGNING_CERT_SHA256: RELEASE_CERTIFICATE_HEX,
        MOBILE_ANDROID_ALLOWED_VERSION_CODES: '',
        MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES: '',
      },
      production: true,
    });
    expect(config.androidAllowedVersionCodes).toEqual([1]);
    expect(config.appleAllowedValidationCategories).toEqual([2, 4]);
  });
});

describe('mobile session authorization', () => {
  const session = {
    approver_id: 'approver-1',
    profile_id: 'profile-1',
    platform: 'ios',
    app_id: 'ai.emiliaprotocol.approver',
    device_key_id: 'ep:key:device-1',
  };

  it('binds every ceremony to the exact enrolled device and session identity', () => {
    expect(mobileSessionAuthorizes(session, {
      approver_id: 'approver-1',
      profile_id: 'profile-1',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: 'ep:key:device-1',
    })).toBe(true);
    for (const mutation of [
      { approver_id: 'attacker' },
      { profile_id: 'weaker-profile' },
      { platform: 'android' },
      { app_id: 'attacker.app' },
      { device_key_id: 'ep:key:device-2' },
      { device_key_id: null },
    ]) {
      expect(mobileSessionAuthorizes(session, {
        approver_id: 'approver-1',
        profile_id: 'profile-1',
        platform: 'ios',
        app_id: 'ai.emiliaprotocol.approver',
        device_key_id: 'ep:key:device-1',
        ...mutation,
      })).toBe(false);
    }
  });

  it('permits enrollment only while the paired session is still unbound', () => {
    const unbound = { ...session, device_key_id: null };
    const input = {
      approver_id: 'approver-1',
      profile_id: 'profile-1',
      platform: 'ios',
      app_id: 'ai.emiliaprotocol.approver',
      device_key_id: null,
    };
    expect(mobileSessionAuthorizes(unbound, input)).toBe(true);
    expect(mobileSessionAuthorizes(session, input)).toBe(false);
    expect(mobileSessionAuthorizes(null, input)).toBe(false);
  });
});

describe('durable mobile storage adapters', () => {
  let from;
  let rpc;

  beforeEach(() => {
    from = vi.fn();
    rpc = vi.fn();
  });

  it('uses compare-and-set state and refuses database ambiguity', async () => {
    const found = chain({ data: { state_key: 'challenge:1' }, error: null });
    from.mockReturnValueOnce(found);
    rpc
      .mockResolvedValueOnce({ data: true, error: null })
      .mockResolvedValueOnce({ data: true, error: null });
    const backend = createMobileStateBackend({ from, rpc });
    expect(backend.durable).toBe(true);
    expect(await backend.addIfAbsent('challenge:0123456789', 'issued')).toBe(true);
    expect(await backend.compareAndSet('challenge:0123456789', 'issued', 'consumed')).toBe(true);
    expect(await backend.has('challenge:0123456789')).toBe(true);
    expect(rpc).toHaveBeenNthCalledWith(1, 'mobile_state_add_if_absent', {
      p_state_key: 'challenge:0123456789',
      p_state_value: 'issued',
    });
    expect(rpc).toHaveBeenNthCalledWith(2, 'mobile_state_compare_and_set', expect.objectContaining({
      p_state_key: 'challenge:0123456789',
      p_expected: 'issued',
      p_replacement: 'consumed',
    }));

    const duplicate = createMobileStateBackend({ from, rpc: vi.fn().mockResolvedValue({ data: false, error: null }) });
    expect(await duplicate.addIfAbsent('challenge:0123456789', 'issued')).toBe(false);
    const broken = createMobileStateBackend({
      from,
      rpc: vi.fn().mockResolvedValue({ data: null, error: { code: '08006', message: 'down' } }),
    });
    await expect(broken.addIfAbsent('challenge:0123456789', 'issued')).rejects.toThrow(/mobile state insert failed/);
  });

  it('advances hardware counters and appends the verifier-native portable record', async () => {
    let persisted = null;
    rpc.mockImplementation(async (name, args) => {
      if (name === 'advance_mobile_counter') return { data: true, error: null };
      if (name === 'append_mobile_evidence_record') {
        persisted = structuredClone(args.p_record);
        return { data: true, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    expect(await createMobileCounterStore({ rpc }).advance('device-1', 4)).toBe(true);
    expect(await createMobileCounterStore({ rpc }).advance('', -1)).toBe(false);
    const event = { event_type: 'mobile.test', nested: { stable: true } };
    const record = await createMobileAuditLog({ rpc, from }, 'entity-1').record(event);
    expect(record.record_id).toMatch(/^mar_[0-9a-f]{32}$/);
    expect(record.seq).toBe(0);
    expect(record.prev_hash).toBe('genesis');
    expect(verifyEvidenceRecord(record, { atomicRequired: true, expectedEntry: event })).toBe(true);
    expect(rpc).toHaveBeenCalledWith('append_mobile_evidence_record', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_expected_hash: null,
      p_record: record,
      p_canonical_body: expect.any(String),
    }));
  });

  it('loads only active enrollments and preserves each platform public key', async () => {
    const active = chain({ data: [{ device_key_id: 'device-1' }], error: null });
    const apple = chain({ data: { platform_public_key: 'pem', status: 'active' }, error: null });
    from.mockReturnValueOnce(active).mockReturnValueOnce(apple);
    rpc.mockResolvedValueOnce({ data: true, error: null });
    const directory = createMobileEnrollmentDirectory({ from, rpc }, 'entity-1', 'session-1');
    expect(await directory.active()).toEqual([{ device_key_id: 'device-1' }]);
    expect((await directory.platformKey('apple-key', 'ios')).platform_public_key).toBe('pem');
    expect(await directory.enrollAtomically({ enrollment: {}, event: {} })).toBe(true);
    expect(rpc).toHaveBeenCalledWith('enroll_mobile_device', expect.objectContaining({ p_session_id: 'session-1' }));
  });

  it('hashes pairings and mobile bearer tokens without storing either secret', async () => {
    const sessionLookup = chain({
      data: {
        session_id: '00000000-0000-0000-0000-000000000001',
        entity_ref: 'entity-1',
        approver_id: 'approver-1',
        profile_id: 'profile-1',
        platform: 'ios',
        app_id: 'ai.emiliaprotocol.approver',
        device_key_id: 'ep:key:mobile-device-1',
        expires_at: '2026-08-15T00:00:00.000Z',
      },
      error: null,
    });
    from.mockReturnValueOnce(sessionLookup);
    rpc.mockImplementation(async (name) => {
      if (name === 'create_mobile_pairing') return { data: true, error: null };
      if (name === 'exchange_mobile_pairing') {
        return { data: { ok: true, approver_id: 'approver-1' }, error: null };
      }
      if (name === 'touch_mobile_session') return { data: true, error: null };
      throw new Error(`unexpected RPC ${name}`);
    });
    const supabase = { from, rpc };
    await createPairing(supabase, {
      code: 'ABCD-EFGH-JKLM',
      entityRef: 'entity-1',
      approverId: 'approver-1',
      profileId: 'profile-1',
      allowedApps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
      expiresAt: '2026-07-15T01:00:00.000Z',
      sessionExpiresAt: '2026-08-15T00:00:00.000Z',
    });
    expect(rpc).toHaveBeenCalledWith('create_mobile_pairing', expect.objectContaining({
      p_code_hash: sha256Hex('ABCD-EFGH-JKLM'),
      p_allowed_apps: { ios: ['ai.emiliaprotocol.approver'], android: [] },
    }));
    const exchanged = await exchangePairing(supabase, {
      code: 'ABCD-EFGH-JKLM',
      token: `ep_mobile_${'a'.repeat(43)}`,
      platform: 'ios',
      appId: 'ai.emiliaprotocol.approver',
    });
    expect(exchanged.ok).toBe(true);
    expect(rpc).toHaveBeenCalledWith('exchange_mobile_pairing', expect.objectContaining({
      p_token_hash: sha256Hex(`ep_mobile_${'a'.repeat(43)}`),
    }));
    expect(await authenticateMobileToken(supabase, `Bearer ep_mobile_${'a'.repeat(43)}`)).toMatchObject({ entity_ref: 'entity-1' });
    expect(rpc).toHaveBeenCalledWith('touch_mobile_session', expect.objectContaining({
      p_token_hash: sha256Hex(`ep_mobile_${'a'.repeat(43)}`),
    }));
    expect(await authenticateMobileToken(supabase, 'Bearer attacker-token')).toBeNull();
  });

  it('refuses a token when its session is revoked between lookup and touch', async () => {
    from.mockReturnValueOnce(chain({
      data: {
        session_id: '00000000-0000-0000-0000-000000000001',
        entity_ref: 'entity-1',
        expires_at: '2999-01-01T00:00:00.000Z',
      },
      error: null,
    }));
    rpc.mockResolvedValueOnce({ data: false, error: null });
    expect(await authenticateMobileToken(
      { from, rpc },
      `Bearer ep_mobile_${'a'.repeat(43)}`,
    )).toBeNull();
  });

  it('revokes sessions and atomically binds then commits terminal action decisions', async () => {
    let persisted = null;
    rpc
      .mockResolvedValueOnce({ data: true, error: null })
      .mockResolvedValueOnce({ data: true, error: null })
      .mockImplementationOnce(async (name, args) => {
        expect(name).toBe('commit_mobile_action_decision');
        persisted = structuredClone(args.p_record);
        return { data: { ok: true }, error: null };
      });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const supabase = { from, rpc };
    expect(await revokeMobileSession(supabase, { sessionId: 'session-1', entityRef: 'entity-1' })).toBe(true);
    expect(rpc).toHaveBeenNthCalledWith(1, 'revoke_mobile_session', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_session_id: 'session-1',
    }));
    expect(await registerMobileActionChallenge(supabase, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      actionReference: 'action-0001',
      approverId: 'approver-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      expiresAt: '2026-07-15T01:00:00.000Z',
    })).toBe(true);
    const decisionEvidence = signedDecisionEvidence();
    const committed = await commitMobileActionDecision(supabase, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(committed).toMatchObject({ committed: true, audit_record: persisted });
    expect(persisted.session_id).toBe('session-1');
    expect(verifyEvidenceRecord(committed.audit_record, { atomicRequired: true })).toBe(true);
  });

  it('recovers an atomic action/evidence commit when the database response is lost', async () => {
    let persisted = null;
    rpc.mockImplementationOnce(async (_name, args) => {
      persisted = structuredClone(args.p_record);
      return { data: null, error: { code: '08006', message: 'response lost after commit' } };
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toMatchObject({ committed: true, audit_record: persisted });
  });

  it('commits full signed denial evidence while refusing it for an approval', async () => {
    let persisted = null;
    rpc.mockImplementationOnce(async (name, args) => {
      expect(name).toBe('commit_mobile_action_decision');
      persisted = structuredClone(args.p_record);
      return { data: { ok: true }, error: null };
    });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockImplementationOnce(() => chain({ data: { record: persisted }, error: null }));
    const denialEvidence = signedDecisionEvidence({ decision: 'denied' });
    const auditEntry = decisionAuditEntry(denialEvidence, 'challenge-denied-1');
    const input = {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: auditEntry.challenge_id,
      actionHash: denialEvidence.context.action_hash,
      decision: 'denied',
      verdict: 'verified',
      decisionEvidence: denialEvidence,
      auditEntry,
    };

    const committed = await commitMobileActionDecision({ from, rpc }, input);
    expect(committed).toMatchObject({ committed: true, audit_record: persisted });
    expect(rpc).toHaveBeenCalledWith('commit_mobile_action_decision', expect.objectContaining({
      p_decision: 'denied',
      p_decision_evidence: denialEvidence,
      p_record: expect.objectContaining({ decision_evidence: denialEvidence }),
    }));

    await expect(commitMobileActionDecision({ from, rpc }, {
      ...input,
      decision: 'approved',
      auditEntry: { ...auditEntry, decision: 'approved' },
    })).rejects.toThrow(/stored approved mobile decision evidence is malformed/);
    expect(rpc).toHaveBeenCalledTimes(1);
  });

  it('distinguishes a terminal action conflict from evidence-head contention', async () => {
    rpc
      .mockResolvedValueOnce({ data: { ok: false, reason: 'head_changed' }, error: null })
      .mockResolvedValueOnce({ data: { ok: false, reason: 'action_conflict' }, error: null });
    from
      .mockReturnValueOnce(chain({ data: null, error: null }))
      .mockReturnValueOnce(chain({ data: null, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toBe(false);
    expect(rpc).toHaveBeenCalledTimes(2);
  });

  it('refuses an otherwise valid terminal decision after its bound session is revoked', async () => {
    rpc.mockResolvedValueOnce({ data: { ok: false, reason: 'session_inactive' }, error: null });
    from.mockReturnValueOnce(chain({ data: null, error: null }));
    const decisionEvidence = signedDecisionEvidence();
    const result = await commitMobileActionDecision({ from, rpc }, {
      entityRef: 'entity-1',
      sessionId: 'session-1',
      challengeId: 'challenge-0001',
      actionHash: `sha256:${'a'.repeat(64)}`,
      decision: 'approved',
      verdict: 'verified',
      decisionEvidence,
      auditEntry: decisionAuditEntry(decisionEvidence),
    });
    expect(result).toBe(false);
    expect(rpc).toHaveBeenCalledWith('commit_mobile_action_decision', expect.objectContaining({
      p_session_id: 'session-1',
      p_record: expect.objectContaining({ session_id: 'session-1' }),
    }));
  });

  it('reads and creates only entity-scoped action inbox records', async () => {
    const listed = chain({ data: [{ action_reference: 'action-1', presentation: PRESENTATION }], error: null });
    const resolved = chain({ data: { action_reference: 'action-1', presentation: PRESENTATION, status: 'pending', expires_at: '2999-01-01T00:00:00.000Z' }, error: null });
    const expired = chain({ data: { action_reference: 'action-1', presentation: PRESENTATION, status: 'approved', expires_at: '2999-01-01T00:00:00.000Z' }, error: null });
    from.mockReturnValueOnce(listed).mockReturnValueOnce(resolved).mockReturnValueOnce(expired);
    rpc.mockResolvedValueOnce({ data: true, error: null });
    const supabase = { from, rpc };
    expect(await listMobileActions(supabase, { entityRef: 'entity-1', approverId: 'approver-1' })).toHaveLength(1);
    expect(await resolveMobileAction(supabase, { entityRef: 'entity-1', approverId: 'approver-1', actionReference: 'action-1' })).toMatchObject({ status: 'pending' });
    expect(await resolveMobileAction(supabase, { entityRef: 'entity-1', approverId: 'approver-1', actionReference: 'action-1' })).toBeNull();
    const demo = {
      action_reference: `mobact_${'2'.repeat(32)}`,
      entity_ref: 'entity-1',
      approver_id: 'approver-1',
      initiator_id: 'agent-1',
      action: { kind: 'release' },
      presentation: PRESENTATION,
      policy: { policy_id: 'policy-1' },
      policy_id: 'policy-1',
      expires_at: '2999-01-01T00:00:00.000Z',
    };
    expect(await createDemoAction(supabase, demo)).toBe(demo.action_reference);
    expect(rpc).toHaveBeenCalledWith('create_mobile_demo_action', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_action_reference: demo.action_reference,
    }));
  });

  it('creates a GRACE approval group through one atomic RPC using snapshots', async () => {
    rpc.mockResolvedValueOnce({ data: true, error: null });
    const assignments = [
      { action_reference: `mobact_${'1'.repeat(32)}`, approver_id: 'ep:approver:grid' },
      { action_reference: `mobact_${'2'.repeat(32)}`, approver_id: 'ep:approver:facility' },
    ];
    const result = await createGraceMobileActionGroup({ rpc }, {
      assignments,
      entityRef: 'entity-1',
      initiatorId: 'ep:agent:grid',
      action: { '@version': 'EP-GRACE-CURTAILMENT-ACTION-v1', action_type: 'grid.curtailment' },
      presentation: {
        ...PRESENTATION,
        title: 'Reduce load',
        summary: 'Reduce facility load for the requested grid interval.',
        consequence: 'Facility power use will be curtailed during the interval.',
      },
      policy: {
        policy_id: 'ep:grace:v1',
        required_approvals: 2,
        approvers: assignments.map((item) => item.approver_id),
      },
      policyId: 'ep:grace:v1',
      expiresAt: '2099-07-15T21:45:00.000Z',
    });
    assignments[0].approver_id = 'attacker';
    expect(result[0].approver_id).toBe('ep:approver:grid');
    expect(rpc).toHaveBeenCalledWith('create_grace_mobile_action_group', expect.objectContaining({
      p_entity_ref: 'entity-1',
      p_assignments: expect.arrayContaining([
        expect.objectContaining({ approver_id: 'ep:approver:grid' }),
      ]),
    }));
  });
});
